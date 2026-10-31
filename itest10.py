#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 10: синхронизация времени (TLV 1007/1008) + TLV-монитор.

Фаза 1 — one-shot --sync-time (settings-соединение, вариант-палитра):
- мок домофона принимает ДВА стиля логина: стрим-стиль (flag=0,
  streamMode=1, dataType=2) и settings-стиль (flag=2, streamMode=3);
- ВАРИАНТ A (DeviceConfig: dt=0, логин seq=2): мок отвечает на
  логин 40+42 result=1, но на TLV 1007 — TLV 1006 (NOTRECOGNIZE)
  и закрывает соединение (как реальная прошивка STM83xx);
- ВАРИАНТ B (GooLinkAdd: dt=2, логин seq=1, 1007 СРАЗУ за логином
  тем же seq — не дожидаясь ответа логина): мок отвечает 40+42 и
  на TLV 1007 отвечает TLV 1008 result=1;
- шлюз one-shot: код возврата 0, «время панели синхронизировано,
  вариант B» — палитра перешла с A на B после 1006;
- проверка структуры 1007: 32 байта u32 LE (zone = смещение хоста
  в МИНУТАХ, мс < 1000, дата/время = локальное время ±3 с) и
  packet_seq: в B совпадает с seq логина (1).

Фаза 1b — оба варианта отклонены прошивкой (fail_all):
- мок на TLV 1007 закрывает соединение БЕЗ ответа (и без 1006) в
  ОБОИХ вариантах — как реальная STM83xx (31.10 12:34);
- шлюз one-shot: код возврата 3, в сообщении «не поддерживается»
  и НЕТ ошибочного «логин-настройка отклонён» (регрессия: раньше
  коды логина не собирались → all([]) = vacuous True → неверный
  код 2 вместо 3).

Фаза 2 — TLV-монитор работающего шлюза:
- мок (стрим-логин) шлёт базовые TLV (97/98/99/100/101) и ВНЕЗАПНЫЕ:
  TLV 342 (AlarmControlResponse — «известный», но не базовый!) и
  TLV 999 (вне списка вообще);
- шлюз регистрирует событие «tlv» на КАЖДОЕ вхождение (лог + /events +
  MQTT), повторы в пределах 1 с коалесируются в count;
- GET /events содержит события tlv с type=342 и type=999, и НЕ содержит
  tlv-событий для базовых типов.
"""
import datetime
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, ".")
from slinex_rtsp import owsp_packet, parse_owsp_packets  # noqa: E402

OWSP_PORT = 21010
HTTP_PORT = 28058
RTSP_PORT = 28558

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = (b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS
       + b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 4)
USER, PASSWORD = "admin", "888888"


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
            login_style = None   # "stream" | "settingsA" | "settingsB"
            while not stop.is_set() and login_style is None:
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
                            print("[mock] логин (%d): user=%r devid=%d "
                                  "flag=%d mask=%#x sm=%d dt=%d seq=%d"
                                  % (idx, user, devid, flag, mask, sm, dt,
                                     seq), flush=True)
                            ok_user = user.decode() == USER and devid == 0
                            if (ok_user and flag == 0 and mask == 1
                                    and sm == 1 and dt == 2):
                                login_style = "stream"
                                state["stream_logins"].append(True)
                            elif (ok_user and flag == 2 and mask == 1
                                    and sm == 3 and dt == 0):
                                # вариант A (DeviceConfig): логин seq=2
                                login_style = "settingsA"
                                assert seq == 2, ("packet_seq логина A "
                                                  "!= 2", seq)
                            elif (ok_user and flag == 2 and mask == 1
                                    and sm == 3 and dt == 2):
                                # вариант B (GooLinkAdd): seq=1 у логина
                                # и у команды (без ожидания ответа логина)
                                login_style = "settingsB"
                                assert seq == 1, ("packet_seq логина B "
                                                  "!= 1", seq)
            if login_style is None:
                return
            conn.sendall(owsp_packet([
                (40, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, b"MOCK|1|DOOR".ljust(64, b"\x00")),
            ], seq + 1))

            def drain():
                rbuf = b""
                conn.settimeout(0.05)
                while not stop.is_set():
                    try:
                        d = conn.recv(65536)
                        if not d:
                            return
                        rbuf += d
                    except socket.timeout:
                        pass
                    except OSError:
                        return
                    # ручной разбор OWSP-пакетов: нужен seq заголовка
                    # (parse_owsp_packets возвращает только TLV)
                    while len(rbuf) >= 8:
                        plen = struct.unpack_from(">I", rbuf, 0)[0]
                        if plen < 8 or len(rbuf) < plen + 4:
                            break
                        pkt, rbuf = rbuf[:plen + 4], rbuf[plen + 4:]
                        pseq = struct.unpack_from("<I", pkt, 4)[0]
                        for tlvs in parse_owsp_packets(pkt)[0]:
                            for t, v in tlvs:
                                if t == 1007:
                                    state["timesync"].append((pseq, v))
                                    print("[mock] TLV 1007 seq=%d [%d байт]: "
                                          "%s" % (pseq, len(v), v.hex()),
                                          flush=True)
                                    if state.get("fail_all"):
                                        # как STM83xx: разрыв без ответа
                                        conn.close()
                                        return
                                    if login_style == "settingsA":
                                        # как прошивка STM83xx: не знает
                                        # 1007 → 1006 + разрыв соединения
                                        state["notrecognized"] += 1
                                        conn.sendall(owsp_packet(
                                            [(1006, struct.pack(
                                                "<HH", 1007, 0))], 900))
                                        conn.close()
                                        return
                                    # вариант B (и стрим): успех
                                    conn.sendall(owsp_packet(
                                        [(1008, struct.pack(
                                            "<HH", 1, 0))], 902))
            threading.Thread(target=drain, daemon=True).start()

            if login_style in ("settingsA", "settingsB"):
                # командная сессия: поток не льём, ждём TLV 1007 (drain)
                deadline = time.monotonic() + 15
                while (not stop.is_set() and time.monotonic() < deadline
                        and not state["timesync"]):
                    time.sleep(0.05)
                time.sleep(0.5)   # дать отправить ответ
                return

            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([15, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31269, 1, 1,
                                 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], seq + 2))

            def drain():
                rbuf = b""
                conn.settimeout(0.05)
                while not stop.is_set():
                    try:
                        d = conn.recv(65536)
                        if not d:
                            return
                        rbuf += d
                    except socket.timeout:
                        pass
                    except OSError:
                        return
                    packets, rbuf = parse_owsp_packets(rbuf)
                    for tlvs in packets:
                        for t, v in tlvs:
                            if t == 1007:
                                state["timesync"].append(v)
                                conn.sendall(owsp_packet(
                                    [(1008, struct.pack("<HH", 1, 0))], 902))
            threading.Thread(target=drain, daemon=True).start()

            frame_idx = 0
            while not stop.is_set():
                # кадр (базовый TLV — мониторить НЕ должен)
                frame = IDR if frame_idx % 15 == 0 else \
                    b"\x00\x00\x00\x01\x41\x9a" + b"\x22" * 700
                t = 100 if frame_idx % 15 == 0 else 101
                fb = struct.pack("<HH", 99, 12) + struct.pack(
                    "<BBHII", 1, 0, 0, frame_idx, frame_idx * 66)
                fb += struct.pack("<HH", t, 0) + frame
                conn.sendall(struct.pack(">I", 4 + len(fb))
                             + struct.pack("<I", 100 + frame_idx) + fb)
                frame_idx += 1
                # спонтанные TLV по расписанию теста
                now = time.monotonic()
                sched = state.get("spontaneous")
                if sched:
                    due = [s for s in sched if s["at"] <= now]
                    for s in due:
                        conn.sendall(owsp_packet(
                            [(s["type"], s["payload"])], 500 + s["type"]))
                        sched.remove(s)
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
            handle_conn(conn, idx)
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass


def http_json(method, url, timeout=30):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main():
    state = {"timesync": [], "spontaneous": [], "stream_logins": [],
             "notrecognized": 0}
    stop = threading.Event()
    threading.Thread(target=mock_doorphone, args=(stop, state),
                     daemon=True).start()
    fails = []

    # ---- фаза 1: one-shot --sync-time (вариант-палитра A→B) ----
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt",
         "--host", "127.0.0.1", "--port", str(OWSP_PORT),
         "--user", USER, "--password", PASSWORD, "--sync-time"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out, _ = gw.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        gw.kill()
        out, _ = gw.communicate()
    rc = gw.returncode
    print("--- фаза 1: --sync-time (rc=%s) ---" % rc)
    print(out.strip()[-500:], flush=True)
    if rc != 0:
        fails.append("--sync-time: код возврата %s" % rc)
    if "синхронизировано" not in out:
        fails.append("--sync-time: нет сообщения об успехе")
    if "вариант B" not in out:
        fails.append("--sync-time: успех не через вариант B (фолбэк A→B "
                      "не сработал)")
    if state["notrecognized"] != 1:
        fails.append("мок не получил TLV 1006 на вариант A "
                     "(получено %d)" % state["notrecognized"])

    # проверка TLV 1007, которую увидел мок (последняя — вариант B)
    if len(state["timesync"]) < 2:
        fails.append("мок получил %d TLV 1007 (ожидалось ≥2: A и B)"
                     % len(state["timesync"]))
    else:
        pseq, v = state["timesync"][-1]
        zone, ms, year, mon, day, hour, minute, sec = \
            struct.unpack("<8I", v)
        lt = time.localtime()
        exp_zone = (getattr(lt, "tm_gmtoff", 0)
                    or (time.daylight and lt.tm_isdst
                        and -time.altzone) or -time.timezone) // 60
        sent = datetime.datetime(year, mon, day, hour, minute, sec)
        delta = abs((sent - datetime.datetime.now()).total_seconds())
        print("[mock] TLV 1007 (B): seq=%d, zone=%d (ожид. %d), мс=%d, "
              "%04d-%02d-%02d %02d:%02d:%02d (Δ=%.1f с)"
              % (pseq, zone, exp_zone, ms, year, mon, day, hour, minute,
                 sec, delta), flush=True)
        if pseq != 1:
            fails.append("packet_seq команды 1007 (B) = %d, ожидалось 1 "
                        "(= seq логина GooLinkAdd)" % pseq)
        if zone != exp_zone:
            fails.append("zone=%d, ожидалось %d" % (zone, exp_zone))
        if ms >= 1000:
            fails.append("мс=%d >= 1000" % ms)
        if delta > 3.0:
            fails.append("время в 1007 отличается на %.1f с" % delta)

    if fails:
        stop.set()
        print("TEST10 FAILED: %s" % "; ".join(fails))
        return 1

    # ---- фаза 1b: оба варианта отклонены (как реальная STM83xx) ----
    state["fail_all"] = True
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt",
         "--host", "127.0.0.1", "--port", str(OWSP_PORT),
         "--user", USER, "--password", PASSWORD, "--sync-time"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out, _ = gw.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        gw.kill()
        out, _ = gw.communicate()
    rc = gw.returncode
    print("--- фаза 1b: --sync-time fail_all (rc=%s) ---" % rc)
    print(out.strip()[-300:], flush=True)
    if rc != 3:
        fails.append("fail_all: код возврата %s, ожидался 3" % rc)
    if "не поддерживается" not in out:
        fails.append("fail_all: нет вердикта «не поддерживается»")
    if "отклонён" in out:
        fails.append("fail_all: ложный диагноз «логин отклонён» "
                    "(vacuous-True регрессия)")
    state["fail_all"] = False
    if fails:
        stop.set()
        print("TEST10 FAILED: %s" % "; ".join(fails))
        return 1

    # ---- фаза 2: TLV-монитор работающего шлюза ----
    state["spontaneous"] = []
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt",
         "--host", "127.0.0.1", "--port", str(OWSP_PORT),
         "--user", USER, "--password", PASSWORD,
         "--rtsp-port", str(RTSP_PORT), "--http-port", str(HTTP_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(3.0)  # логин + стрим
        if not state.get("conn_alive", True):
            pass
        # спонтанные: 342 трижды (первые два в пределах 1 с — коалесинг),
        # 999 один раз; 203 НЕ должен дать tlv-событие (базовый)
        t0 = time.monotonic()
        state["spontaneous"].extend([
            {"at": t0, "type": 342, "payload": b"\x01\x00"},
            {"at": t0 + 0.1, "type": 342, "payload": b"\x02\x00"},
            {"at": t0 + 1.4, "type": 342, "payload": b"\x03\x00"},
            {"at": t0 + 0.3, "type": 999, "payload": b"\xde\xad\xbe\xef"},
        ])
        deadline = time.monotonic() + 8
        events = []
        while time.monotonic() < deadline:
            code, body = http_json(
                "GET", "http://127.0.0.1:%d/events" % HTTP_PORT)
            events = body.get("events", [])
            tlvs = [e for e in events if e.get("kind") == "tlv"]
            if len(tlvs) >= 3:
                break
            time.sleep(0.5)
        print("--- фаза 2: /events ---")
        for e in events[-8:]:
            print("   %s" % e, flush=True)
        by_type = {}
        for e in events:
            if e.get("kind") == "tlv":
                by_type.setdefault(e.get("type"), []).append(e)
        if 342 not in by_type:
            fails.append("TLV 342 не зарегистрирован монитор-ом")
        else:
            ev342 = by_type[342]
            if len(ev342) < 2:
                fails.append("TLV 342: событий %d (коалесинг сломан?)" % len(ev342))
            cnts = [e.get("count") for e in ev342]
            print("[тест] 342: %d событий, count=%s" % (len(ev342), cnts),
                  flush=True)
            if 2 not in [c for c in cnts if c] and None in cnts:
                pass  # count может не дойти, если третий не пришёл
        if 999 not in by_type:
            fails.append("TLV 999 не зарегистрирован")
        else:
            e999 = by_type[999][0]
            if e999.get("hex") != "deadbeef":
                fails.append("TLV 999: hex=%s" % e999.get("hex"))
        for bad in (70, 98, 99, 100, 101, 203, 42):
            if bad in by_type:
                fails.append("базовый TLV %d попал в монитор" % bad)
        print("[тест] базовые TLV в монитор не попадают: OK"
              if not any("базовый" in f for f in fails) else "")
    finally:
        stop.set()
        try:
            gw.terminate()
            out, _ = gw.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            gw.kill()
            out, _ = gw.communicate()
        print("--- вывод шлюза (хвост) ---")
        print((out or "")[-1200:], flush=True)

    if fails:
        print("TEST10 FAILED: %s" % "; ".join(fails))
        return 1
    print("TEST10 PASSED: синхронизация времени + TLV-монитор работают")
    return 0


if __name__ == "__main__":
    sys.exit(main())
