#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 7: открытие замка (TLV 425/426).

Мок домофона повторяет поведение прошивки:
- логин (stream-стиль, как референс: deviceId=0, flag=0, mask=1,
  streamMode=1, dataType=2) → эхо TLV 40 (5.0) + TLV 42 result=1 + TLV 70;
- TLV 203 (формат) и поток кадров/аудио;
- на TLV 425 (LockRequest): проверяет структуру payload — 40 байт,
  deviceId=0, lockPwd = XOR «lbtech»+25 (только байты пароля, остаток
  нули, поле 32 байта), channel 1-based (для прошивки 5.0 — см.
  remoteLock: newVersion=1 → chanIndex+1), action, delayTime — и
  отвечает TLV 426 result=1.

Проверяются оба способа команды:
- фаза 1: работающий шлюз + HTTP-контроль POST /unlock → {"ok": true};
  GET /status показывает живой канал; GET /events содержит unlock;
- фаза 2: one-shot CLI --unlock → код возврата 0, «замок ... принят».
"""
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, ".")
from slinex_rtsp import ENC_KEY, owsp_packet, parse_owsp_packets  # noqa: E402

OWSP_PORT = 21007
HTTP_PORT = 28055
RTSP_PORT = 28557

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = (b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS
       + b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 4)
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x22" * 700

USER, PASSWORD = "admin", "888888"


def lock_pwd_field(pwd: bytes) -> bytes:
    field = bytearray(32)
    for i in range(min(len(pwd), 32)):
        field[i] = pwd[i] ^ ((ENC_KEY[i % len(ENC_KEY)] + 25) & 0xFF)
    return bytes(field)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def mock_doorphone(stop, state):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(4)
    print("[mock] слушает :%d" % OWSP_PORT, flush=True)

    def handle_conn(conn, idx):
        conn.settimeout(15)
        try:
            # --- логин ---
            logged_in = False
            while not stop.is_set() and not logged_in:
                hdr = recv_exact(conn, 8)
                plen = struct.unpack(">I", hdr[:4])[0]
                seq = struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                for tlvs in parse_owsp_packets(hdr + body)[0]:
                    for t, v in tlvs:
                        if t == 41:
                            assert len(v) == 68, "LoginRequestEx 68 байт"
                            user = v[1:33].rstrip(b"\x00")
                            devid, flag = struct.unpack_from("<II", v, 49)
                            mask = struct.unpack_from("<I", v, 60)[0]
                            sm, dt = v[64], v[65]
                            print("[mock] логин (%d): user=%r devid=%d flag=%d "
                                  "mask=%#x sm=%d dt=%d"
                                  % (idx, user, devid, flag, mask, sm, dt),
                                  flush=True)
                            state["logins"].append((devid, flag, mask, sm, dt))
                            logged_in = (user.decode() == USER
                                         and devid == 0 and flag == 0
                                         and mask == 1 and sm == 1 and dt == 2)
            if not logged_in:
                return
            # эхо версии + логин ок + инфо (как STM83xx: ЭХО TLV 40)
            conn.sendall(owsp_packet([
                (40, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, b"MOCK|1|DOOR".ljust(64, b"\x00")),
            ], seq + 1))
            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([15, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], seq + 2))

            # --- читатель: TLV 425 → проверка → ответ 426 ---
            def drain():
                rbuf = b""
                conn.settimeout(0.2)
                while not stop.is_set():
                    try:
                        d = conn.recv(65536)
                        if not d:
                            return
                        rbuf += d
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    packets, rbuf = parse_owsp_packets(rbuf)
                    for tlvs in packets:
                        for t, v in tlvs:
                            if t == 425:
                                assert len(v) == 40, \
                                    "TLV 425: payload должен быть 40 байт, %d" % len(v)
                                devid = struct.unpack_from("<I", v, 0)[0]
                                pwd = v[4:36]
                                chan, action, delay, res = v[36], v[37], v[38], v[39]
                                print("[mock] TLV 425: devid=%d chan=%d action=%d "
                                      "delay=%d res=%d pwd_ok=%s"
                                      % (devid, chan, action, delay, res,
                                         pwd == lock_pwd_field(PASSWORD.encode())),
                                      flush=True)
                                ok = (devid == 0
                                      and pwd == lock_pwd_field(PASSWORD.encode())
                                      and chan == 1 and action == 1
                                      and delay == 1 and res == 0)
                                state["lock_reqs"].append(ok)
                                conn.sendall(owsp_packet(
                                    [(426, struct.pack("<HH", 1, 0))], 900))
            threading.Thread(target=drain, daemon=True).start()

            # --- писатель: кадры + аудио ---
            frame_idx = 0
            while not stop.is_set():
                frame = IDR if frame_idx % 15 == 0 else PFRAME
                t = 100 if frame_idx % 15 == 0 else 101
                fb = struct.pack("<HH", 99, 12) + struct.pack(
                    "<BBHII", 1, 0, 0, frame_idx, frame_idx * 66)
                fb += struct.pack("<HH", t, 0) + frame
                conn.sendall(struct.pack(">I", 4 + len(fb))
                             + struct.pack("<I", 100 + frame_idx) + fb)
                frame_idx += 1
                time.sleep(0.066)
        except (ConnectionError, OSError, struct.error):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        idx = 0
        while not stop.is_set():
            srv.settimeout(0.5)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            idx += 1
            state["conn_count"] = idx
            print("[mock] принято соединение %d" % idx, flush=True)
            handle_conn(conn, idx)
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass
        print("[mock] остановлен, соединений: %d, TLV 425: %s"
              % (idx, state["lock_reqs"]), flush=True)


def http_json(method, url, timeout=30):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main():
    state = {"logins": [], "lock_reqs": [], "conn_count": 0}
    stop = threading.Event()
    threading.Thread(target=mock_doorphone, args=(stop, state),
                     daemon=True).start()

    # ---- фаза 1: шлюз + HTTP-контроль ----
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", USER, "--password", PASSWORD,
         "--rtsp-port", str(RTSP_PORT), "--http-port", str(HTTP_PORT),
         "--lock-password", PASSWORD],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(3.5)  # логин + первый I-кадр
        code, body = http_json("GET", "http://127.0.0.1:%d/status" % HTTP_PORT)
        assert code == 200, (code, body)
        ch = body["channels"][0]
        assert ch["channel"] == 1 and ch["login_ok"] and ch["frames"] > 0, ch
        print("[http] /status: канал 1 жив, кадров %d" % ch["frames"])

        code, body = http_json("POST",
                               "http://127.0.0.1:%d/unlock?ch=1&delay=1"
                               % HTTP_PORT)
        assert code == 200 and body.get("ok") is True, (code, body)
        assert "result=1" in body.get("msg", ""), body
        print("[http] /unlock: ok — %s" % body["msg"])

        code, body = http_json("GET", "http://127.0.0.1:%d/events" % HTTP_PORT)
        assert code == 200, (code, body)
        evs = [e for e in body["events"] if e["kind"] == "unlock"]
        assert evs and evs[-1]["ok"] is True, body
        print("[http] /events: unlock зафиксирован: %s" % evs[-1])
        assert state["lock_reqs"] and all(state["lock_reqs"]), \
            "мок не получил корректный TLV 425"
        assert state["logins"] and state["logins"][0] == (0, 0, 1, 1, 2), \
            ("поля логина не как в референсе", state["logins"])
        print("[http] TLV 425: структура верна (devid=0, pwd XOR, chan=1, "
              "action=1, delay=1)")
    finally:
        gw.terminate()
        try:
            out, _ = gw.communicate(timeout=5)
            print("--- вывод шлюза (фаза 1) ---")
            print(out.strip())
        except subprocess.TimeoutExpired:
            gw.kill()

    # ---- фаза 2: one-shot CLI --unlock ----
    time.sleep(1.0)  # слот прошивки освобождается не мгновенно
    cli = subprocess.run(
        [sys.executable, "slinex_rtsp.py", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", USER, "--password", PASSWORD,
         "--unlock", "--lock-password", PASSWORD, "--lock-delay", "1"],
        capture_output=True, text=True, timeout=60)
    print("--- вывод CLI --unlock ---")
    print(cli.stdout.strip())
    if cli.stderr.strip():
        print("--- stderr ---")
        print(cli.stderr.strip())
    assert cli.returncode == 0, ("код возврата %d" % cli.returncode, cli.stdout)
    assert "замок" in cli.stdout and "принята" in cli.stdout, cli.stdout
    assert len(state["lock_reqs"]) == 2 and all(state["lock_reqs"]), \
        ("второй TLV 425 не получен/некорректен", state["lock_reqs"])
    assert state["conn_count"] == 2, state["conn_count"]
    print("TEST7 PASSED: открытие замка (HTTP /unlock и --unlock) работает")


if __name__ == "__main__":
    main()
