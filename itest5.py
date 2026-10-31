#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 5: (а) гонка логина — версия и код ответа приходят разными сегментами
с задержкой 0.4 с; шлюз обязан отправить РОВНО ОДИН логин в соединение
(баг 28.10: двойной логин поднимал на прошивке «битую» сессию — тишину либо
мусор в потоке). (б) мусор в потоке — после 777 байт шума парсер обязан
выровняться по маркеру TLV 99 и продолжить стрим (без ресинка каскад
десинка не прекращается, картинка «рассыпается»)."""
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import (owsp_packet, encrypt_password,  # noqa: E402
                         parse_owsp_packets)

OWSP_PORT = 21005
RTSP_PORT = 28559

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = (b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS
       + b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 8)
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x33" * 700

GARBAGE = (b"\xde\xad\xbe\xef" * 200)[:777]  # BE u32 0xDEADBEEF > лимита пакета


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def mock_doorphone(stop, logins, handshake_ok):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(4)
    print("[mock] слушает :%d" % OWSP_PORT, flush=True)

    def handle_conn(conn):
        conn.settimeout(10)
        try:
            logged_in = False
            while not stop.is_set() and not logged_in:
                hdr = recv_exact(conn, 8)
                plen, seq = struct.unpack(">I", hdr[:4])[0], struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                for tlvs in parse_owsp_packets(hdr + body)[0]:
                    for t, v in tlvs:
                        if t != 41:
                            continue
                        logins.append(time.monotonic())
                        print("[mock] получен логин №%d (len=%d)"
                              % (len(logins), len(v)), flush=True)
                        if len(v) == 68:
                            devid, flag = struct.unpack_from("<II", v, 49)
                            mask = struct.unpack_from("<I", v, 60)[0]
                            ok = (v[1:33].rstrip(b"\x00") == b"admin"
                                  and v[33:49] == encrypt_password(b"888888")
                                  and devid == 0 and flag == 0 and mask == 1)
                            if not ok:
                                print("[mock] НЕВЕРНЫЕ ПОЛЯ ЛОГИНА!", flush=True)
                            # (а) гонка: ЭХО версии отправляем СРАЗУ, а код
                            # ответа — с задержкой 0.4 с отдельным сегментом.
                            # Прежний код успевал слать второй логин в этот
                            # же сокет.
                            conn.sendall(owsp_packet(
                                [(40, struct.pack("<HH", 5, 0))], seq + 1))
                            time.sleep(0.4)
                            if len(logins) > 1:
                                handshake_ok[0] = False
                            conn.sendall(owsp_packet(
                                [(42, struct.pack("<HH", 1, 0)),
                                 (70, b"MOCK|1|DOOR".ljust(64, b"\x00"))],
                                seq + 2))
                            logged_in = True
                if logged_in:
                    break
            if not logged_in:
                return

            def drain():
                rbuf = b""
                conn.settimeout(0.3)
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
                    _, rbuf = parse_owsp_packets(rbuf) if rbuf else ([], rbuf)
            threading.Thread(target=drain, daemon=True).start()

            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([15, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], 9))
            frame_idx = 0
            while not stop.is_set():
                frame = IDR if frame_idx % 10 == 0 else PFRAME
                t = 100 if frame_idx % 10 == 0 else 101
                body = struct.pack("<HH", 99, 12) + struct.pack(
                    "<BBHII", 1, 0, 0, frame_idx, frame_idx * 66)
                body += struct.pack("<HH", t, len(frame)) + frame
                conn.sendall(struct.pack(">I", 4 + len(body))
                             + struct.pack("<I", 100 + frame_idx) + body)
                frame_idx += 1
                if frame_idx == 60:
                    # (б) мусор в середине потока (клиент уже смотрит)
                    print("[mock] инъекция %d байт мусора" % len(GARBAGE), flush=True)
                    conn.sendall(GARBAGE)
                time.sleep(0.066)
        except (ConnectionError, OSError, struct.error) as exc:
            print("[mock] соединение закрыто: %r" % exc, flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        while not stop.is_set():
            srv.settimeout(0.5)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            print("[mock] принято соединение", flush=True)
            threading.Thread(target=handle_conn, args=(conn,),
                             daemon=True).start()
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass
        print("[mock] остановлен, логинов: %d" % len(logins), flush=True)


def rtsp_client():
    time.sleep(2.5)
    s = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
    s.settimeout(10)
    cseq = 0

    def req(method, url, headers=None):
        nonlocal cseq
        cseq += 1
        out = "%s %s RTSP/1.0\r\nCSeq: %d\r\n" % (method, url, cseq)
        for k, v in (headers or {}).items():
            out += "%s: %s\r\n" % (k, v)
        s.sendall((out + "\r\n").encode())
        rbuf = b""
        while b"\r\n\r\n" not in rbuf:
            rbuf += s.recv(4096)
        head, _ = rbuf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        code = int(lines[0].split()[1])
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.lower()] = v.strip()
        return code, hdrs

    base = "rtsp://127.0.0.1:%d/camera" % RTSP_PORT
    code, _ = req("OPTIONS", "*")
    assert code == 200
    code, _ = req("DESCRIBE", base)
    assert code == 200, code
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.5)
    cport = udp.getsockname()[1]
    code, hdrs = req("SETUP", base + "/trackID=0",
                     {"Transport": "RTP/AVP;unicast;client_port=%d-%d"
                      % (cport, cport + 1)})
    assert code == 200, code
    code, _ = req("PLAY", base, {"Session": hdrs.get("session", "").split(";")[0]})
    assert code == 200, code
    print("[client] PLAY ok — сбор RTP", flush=True)

    total = []
    late = []
    t0 = time.time()
    end = t0 + 9
    while time.time() < end:
        try:
            data, _ = udp.recvfrom(65536)
            assert data[0] >> 6 == 2 and (data[1] & 0x7F) == 96
            total.append(data)
            if time.time() - t0 > 5:
                late.append(data)
        except socket.timeout:
            pass
    seqs = [struct.unpack(">H", p[2:4])[0] for p in total]
    assert all((b - a) % 0x10000 in (0, 1) for a, b in zip(seqs, seqs[1:])), seqs
    assert len(total) >= 40, ("поток прервался (мусор не пережит)", len(total))
    assert len(late) >= 15, ("хвост потока пуст — десинк не восстановился",
                             len(late))
    sps_late = sum(1 for p in late if p[12] == 0x67)
    assert sps_late >= 1, "после мусора нет I-кадров"
    print("[client] RTP: всего %d, после мусора %d (из них I-кадры: %d)"
          % (len(total), len(late), sps_late), flush=True)
    req("TEARDOWN", base, {"Session": hdrs.get("session", "").split(";")[0]})
    print("TEST5 PASSED: гонка логина + ресинк после мусора")


def main():
    logins = []
    handshake_ok = [True]
    stop = threading.Event()
    t = threading.Thread(target=mock_doorphone,
                          args=(stop, logins, handshake_ok), daemon=True)
    t.start()
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--rtsp-port", str(RTSP_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    gw_out = ""
    rc = 0
    try:
        rtsp_client()
        assert len(logins) == 1, ("логинов отправлено больше одного!",
                                  len(logins))
        assert handshake_ok[0], "второй логин пришёл до ответа первого (гонка!)"
        print("[client] логин ровно один, без гонки", flush=True)
    except AssertionError as exc:
        print("TEST5 FAILED:", exc)
        rc = 1
    except Exception as exc:  # noqa: BLE001
        print("TEST5 ERROR: %r" % exc)
        rc = 1
    finally:
        stop.set()
        gw.terminate()
        try:
            out, _ = gw.communicate(timeout=5)
            gw_out = out or ""
        except subprocess.TimeoutExpired:
            gw.kill()
        print("--- вывод шлюза ---")
        print(gw_out)
        if rc == 0:
            assert "мусор протокола" in gw_out, \
                "ресинк не сработал (мусор не обнаружен парсером?)"
            print("[client] ресинк по маркеру отработал (см. лог шлюза)")
    sys.exit(rc)


if __name__ == "__main__":
    main()
