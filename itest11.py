#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 11: громкая связь (talk): TLV 331/332 + поток 97/98 вверх.

Мок домофона (itest7-модель):
- логин stream-стиль → эхо TLV 40 (5.0) + TLV 42 result=1 + TLV 70 +
  TLV 203 + поток кадров;
- на TLV 331 (TalkRequest, 8 Б): проверка структуры (deviceId=0,
  action 1=старт/2=стоп, chn=1 1-based, reserve=0) → ответ TLV 332
  (24 Б, раскладка по ЖЕЛЕЗУ: result u16, reserve u16, srate u32 @4,
  abr u32 @8, waveFormat u16 @12 … — result=1 + 8 кГц µ-law);
- пакеты с TLV 97+98 (аудио вверх, AudioInfoRequestPack): проверка
  TLV 97 (channelId=1, reserve=0, checksum=0, time=200) и копирование
  payload TLV 98 в журнал.

Фазы:
1. юнит: таблицы µ-law — round-trip энкодера, симметрия знака,
   известное значение сдвига (>>2);
2. HTTP POST /talk: файл 40000 Б (5 с) → {"ok": true, bytes=40000,
   sent=40000} — backpressure доигрывает ЦЕЛИКОМ (регрессия на баг
   31.10: выброс старого доиграл 16960 из 40000); мок: 331 start →
   125 чанков по 320 Б байт-в-байт → 331 stop; /events: talk start/end;
3. RTSP ANNOUNCE+SETUP+RECORD (как ffmpeg -f rtsp -rtsp_transport
   tcp): сырой RTSP-клиент: ANNOUNCE (SDP m=audio PCMU/8000) → 200;
   SETUP interleaved=0-1 → 200 (Transport в ответе); RECORD → 200;
   затем interleaved-RTP ($) 10 × 160 Б PCMU; закрытие → мок видит
   331 stop; контент совпал;
3b. RTSP backchannel (как go2rtc/ONVIF Profile T): DESCRIBE → SDP с
   trackID=0 a=recvonly и talk-треком trackID=2 a=sendonly PCMU
   (направления — с точки зрения КЛИЕНТА, как у Dahua/Hikvision —
   go2rtc по sendonly узнаёт backchannel); SETUP trackID=0 + trackID=2
   (interleaved=2-3, mode=record) + PLAY + RECORD на одном соединении;
   TalkSession ЛЕНИВАЯ: SETUP trackID=2 не занимает канал (проверка
   /status), сессию открывает первый interleaved-RTP на канале 2;
   контент совпал, старт/стоп по закрытию;
4. эксклюзивность: /talk с недосланным телом держит канал → второй
   POST /talk отвечает 409; после завершения — снова 200.
5. отказ старта: мок отвечает TLV 332 result=23 («talk занят» — как
   железо 31.10 15:21 после потерянного в мусоре 332) → /talk отвечает
   ok=false c диагнозом, sent=0, и шлюз ЧИСТИТ состояние панели
   331 action=2 (мок видит стоп без старта); повторный /talk — штатно.
Пост-мортем: в логе шлюза «talk-формат: 8000 Гц … wave=0x7A25» —
парсер 332 по раскладке железа.
"""
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, ".")
from slinex_rtsp import (ULAW_LINEAR, ULAW_ENCODE,  # noqa: E402
                         owsp_packet, parse_owsp_packets,
                         ulaw_gain_shift)

OWSP_PORT = 21011
HTTP_PORT = 28061
RTSP_PORT = 28563

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = (b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS
       + b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 4)
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x22" * 700

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
            logged_in = False
            while not stop.is_set() and not logged_in:
                hdr = recv_exact(conn, 8)
                plen = struct.unpack(">I", hdr[:4])[0]
                seq = struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                for tlvs in parse_owsp_packets(hdr + body)[0]:
                    for t, v in tlvs:
                        if t == 41:
                            user = v[1:33].rstrip(b"\x00")
                            devid, flag = struct.unpack_from("<II", v, 49)
                            mask = struct.unpack_from("<I", v, 60)[0]
                            sm, dt = v[64], v[65]
                            print("[mock] логин (%d): user=%r devid=%d "
                                  "flag=%d mask=%#x sm=%d dt=%d"
                                  % (idx, user, devid, flag, mask, sm, dt),
                                  flush=True)
                            logged_in = (user.decode() == USER
                                         and devid == 0 and flag == 0
                                         and mask == 1 and sm == 1 and dt == 2)
            if not logged_in:
                return
            conn.sendall(owsp_packet([
                (40, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, b"MOCK|1|DOOR".ljust(64, b"\x00")),
            ], seq + 1))
            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([15, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31269, 1, 1,
                                 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], seq + 2))

            # TLV 332: result=1 + 8 кГц µ-law, раскладка по ЖЕЛЕЗУ
            # (31.10 15:31, hex=01000000401f000000300000257a0100e8031000
            #  19000000: reserve u16 @2, поля со сдвигом +2 Б относительно
            #  APK; abr=12288, blockAlign=1000, bits=16, frameInterval=25)
            talk_rsp = struct.pack("<HHII5H2x", 1, 0, 8000, 12288,
                                   31269, 1, 1000, 16, 25)

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
                        saw97 = None
                        for t, v in tlvs:
                            if t == 331:
                                devid = struct.unpack_from("<I", v, 0)[0]
                                action, chn = v[4], v[5]
                                print("[mock] TLV 331: devid=%d action=%d "
                                      "chn=%d" % (devid, action, chn),
                                      flush=True)
                                ok = (len(v) == 8 and devid == 0
                                      and action in (1, 2) and chn == 1)
                                state["talk_reqs_ok"].append(ok)
                                if action == 2:
                                    state["talk_stops"] += 1
                                    conn.sendall(owsp_packet(
                                        [(332, talk_rsp)], 910))
                                elif state.pop("refuse_talk", False):
                                    # фаза 5: панель отказывает старту
                                    # (железо 31.10 15:21: result=23 —
                                    # «talk занят» после потерянного 332)
                                    print("[mock] TLV 331: отказ "
                                          "result=23 (refuse_talk)",
                                          flush=True)
                                    conn.sendall(owsp_packet(
                                        [(332, struct.pack(
                                            "<HHII5H2x", 23, 0, 8000,
                                            12288, 31269, 1, 1000, 16,
                                            25))], 910))
                                else:
                                    state["talk_starts"] += 1
                                    conn.sendall(owsp_packet(
                                        [(332, talk_rsp)], 910))
                            elif t == 97:
                                ok = (len(v) == 8 and v[0] == 1 and v[1] == 0
                                      and struct.unpack_from("<H", v, 2)[0]
                                      == 0
                                      and struct.unpack_from("<I", v, 4)[0]
                                      == 200)
                                state["info97_ok"].append(ok)
                                saw97 = ok
                            elif t == 98 and saw97 is not None:
                                state["talk_chunks"].append(bytes(v))
            threading.Thread(target=drain, daemon=True).start()

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
            handle_conn(conn, idx)
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass


def http_json(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except (ValueError, UnicodeDecodeError):
            return e.code, {}


def rtsp_round(sock, method, url, headers, body=b""):
    req = ("%s %s RTSP/1.0\r\nCSeq: %d\r\n" % (method, url, rtsp_round.cseq))
    rtsp_round.cseq += 1
    for k, v in headers.items():
        req += "%s: %s\r\n" % (k, v)
    if body:
        req += "Content-Length: %d\r\nContent-Type: application/sdp\r\n" \
               % len(body)
    req += "\r\n"
    sock.sendall(req.encode() + body)
    rbuf = b""
    while b"\r\n\r\n" not in rbuf:
        d = sock.recv(4096)
        if not d:
            raise ConnectionError("rtsp eof")
        rbuf += d
    head, rest = rbuf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    clen = int(hdrs.get("content-length", "0") or 0)
    while len(rest) < clen:
        rest += sock.recv(4096)
    return int(lines[0].split()[1]), hdrs, rest[:clen]


rtsp_round.cseq = 1


def main():
    state = {"talk_reqs_ok": [], "talk_starts": 0, "talk_stops": 0,
             "talk_chunks": [], "info97_ok": []}
    stop = threading.Event()
    threading.Thread(target=mock_doorphone, args=(stop, state),
                     daemon=True).start()
    fails = []

    # ---- фаза 1: юнит таблиц µ-law --------------------------------------
    print("--- фаза 1: таблицы µ-law ---")
    allbytes = bytes(range(256))
    if ulaw_gain_shift(allbytes, 0) != allbytes:
        fails.append("gain_shift 0 должен быть тождественным")
    for b in (0x00, 0x7F, 0x80, 0xFF, 0x55, 0xAA):
        lin = ULAW_LINEAR[b]
        enc = ULAW_ENCODE[(lin + 32768) & 0xFFFF]
        if ULAW_LINEAR[enc] != lin:
            fails.append("round-trip энкодера нарушен для 0x%02X" % b)
    v = ULAW_LINEAR[ulaw_gain_shift(b"\x80", 2)[0]]
    if not 7000 < v < 9000:
        fails.append(">>2 от +32124 даёт %d (ожидалось ~8031)" % v)
    vneg = ULAW_LINEAR[ulaw_gain_shift(b"\x00", 2)[0]]
    if vneg != -v:
        fails.append("симметрия знака нарушена: %d vs %d" % (vneg, -v))
    print("[тест] таблицы: %s" % ("OK" if not fails else fails), flush=True)

    # ---- запуск шлюза -----------------------------------------------------
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt",
         "--host", "127.0.0.1", "--port", str(OWSP_PORT),
         "--user", USER, "--password", PASSWORD,
         "--rtsp-port", str(RTSP_PORT), "--http-port", str(HTTP_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 25
        ready = False
        while time.monotonic() < deadline and not ready:
            try:
                code, body = http_json("GET",
                                       "http://127.0.0.1:%d/status" % HTTP_PORT)
                ready = (code == 200 and body.get("channels")
                         and body["channels"][0].get("login_ok"))
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            time.sleep(0.3)
        if not ready:
            fails.append("шлюз не поднялся за 25 с")

        # ---- фаза 2: HTTP POST /talk (файл 40000 Б = 5 с) ---------------
        # 31.10 на железе: прежний «кап с выбросом старого» доиграл только
        # 16960 из 40000 Б — регрессия на полный файл
        print("--- фаза 2: HTTP POST /talk 40000 Б ---")
        audio = (bytes(range(256)) * 157)[:40000]
        code, body = http_json(
            "POST", "http://127.0.0.1:%d/talk?ch=1" % HTTP_PORT, data=audio,
            headers={"Content-Type": "audio/basic"})
        print("[http] /talk → %s %s" % (code, body), flush=True)
        if code != 200 or not body.get("ok"):
            fails.append("POST /talk: %s %s" % (code, body))
        if body.get("bytes") != 40000 or body.get("sent") != 40000:
            fails.append("POST /talk: bytes=%s sent=%s (ожидалось "
                         "40000/40000)" % (body.get("bytes"),
                                           body.get("sent")))
        time.sleep(0.5)
        got = b"".join(state["talk_chunks"])
        if state["talk_starts"] != 1:
            fails.append("фаза 2: talk_starts=%s (ожидалось 1)"
                         % state["talk_starts"])
        if state["talk_stops"] != 1:
            fails.append("фаза 2: talk_stops=%s (ожидалось 1)"
                         % state["talk_stops"])
        if got != audio:
            fails.append("фаза 2: контент до панели не совпал (%d Б)"
                         % len(got))
        if not all(state["info97_ok"]):
            fails.append("фаза 2: TLV 97 неверен (%s)"
                         % state["info97_ok"][:5])
        if not all(state["talk_reqs_ok"]):
            fails.append("фаза 2: TLV 331 неверен")
        code, body = http_json("GET",
                               "http://127.0.0.1:%d/events" % HTTP_PORT)
        talks = [e for e in body.get("events", [])
                 if e.get("kind") == "talk"]
        if not any(e.get("state") == "start" for e in talks) \
                or not any(e.get("state") == "end" for e in talks):
            fails.append("фаза 2: /events без talk start/end: %s" % talks)

        # ---- фаза 3: RTSP ANNOUNCE + SETUP + RECORD ---------------------
        print("--- фаза 3: RTSP ANNOUNCE/SETUP/RECORD ---")
        chunks_before = len(state["talk_chunks"])
        sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=talk\r\n"
               "c=IN IP4 127.0.0.1\r\nt=0 0\r\n"
               "m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000/1\r\n"
               "a=control:trackID=0\r\n")
        base = "rtsp://127.0.0.1:%d/camera/talk" % RTSP_PORT
        rs = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
        try:
            code, hdrs, _ = rtsp_round(rs, "ANNOUNCE", base, {},
                                      sdp.encode())
            if code != 200:
                fails.append("ANNOUNCE → %s" % code)
            sid = hdrs.get("session", "")
            code, hdrs, _ = rtsp_round(
                rs, "SETUP", base + "/trackID=0",
                {"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1;"
                              "mode=record", "Session": sid})
            if code != 200 or "interleaved=0-1" not in \
                    hdrs.get("transport", "").replace(" ", ""):
                fails.append("SETUP talk → %s %s" % (code, hdrs))
            code, _, _ = rtsp_round(rs, "RECORD", base, {"Session": sid})
            if code != 200:
                fails.append("RECORD → %s" % code)
            # 10 RTP-пакетов PCMU по 160 Б (20 мс) через interleaved
            payload = bytes(range(160)) * 10
            for i in range(10):
                rtp = (struct.pack(">BBHII", 0x80, 0x80, 1000 + i,
                                   160 * i, 0x12345678)
                       + payload[i * 160:(i + 1) * 160])
                rs.sendall(b"$" + struct.pack(">BH", 0, len(rtp)) + rtp)
            time.sleep(1.0)
        finally:
            rs.close()
        time.sleep(1.5)      # cleanup соединения → talk.stop() → 331/2
        new_chunks = state["talk_chunks"][chunks_before:]
        got = b"".join(new_chunks)
        if state["talk_starts"] != 2:
            fails.append("фаза 3: talk_starts=%s (ожидалось 2)"
                         % state["talk_starts"])
        if state["talk_stops"] != 2:
            fails.append("фаза 3: talk_stops=%s (ожидалось 2)"
                         % state["talk_stops"])
        if got != payload:
            fails.append("фаза 3: RTP-контент до панели не совпал "
                         "(%d Б)" % len(got))

        # ---- фаза 3b: RTSP backchannel (go2rtc / ONVIF Profile T) --------
        # DESCRIBE выдаёт talk-трек trackID=2 a=sendonly (направления в
        # SDP источника — С ТОЧКИ ЗРЕНИЯ КЛИЕНТА, как у Dahua/Hikvision;
        # воспроизведение a=recvonly); SETUP обоих треков + PLAY + RECORD
        # на одном соединении. TalkSession ЛЕНИВАЯ: SETUP trackID=2 НЕ
        # занимает канал (go2rtc держит backchannel всю сессию просмотра —
        # регрессия 31.10: eager-создание давало 409 чужому /talk);
        # сессию открывает первый RTP с микрофона
        print("--- фаза 3b: RTSP backchannel trackID=2 ---")
        chunks_before = len(state["talk_chunks"])
        rb = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
        try:
            base2 = "rtsp://127.0.0.1:%d/camera" % RTSP_PORT
            code, hdrs, sdp2 = rtsp_round(rb, "DESCRIBE", base2, {})
            sdp2 = sdp2.decode("latin-1", "replace")
            if code != 200:
                fails.append("фаза 3b: DESCRIBE → %s" % code)
            if "a=control:trackID=0\r\na=recvonly" not in sdp2:
                fails.append("фаза 3b: trackID=0 не a=recvonly")
            if "a=control:trackID=2\r\na=sendonly" not in sdp2:
                fails.append("фаза 3b: SDP без talk-трека trackID=2 "
                             "a=sendonly")
            elif "PCMU/8000" not in sdp2[sdp2.rfind("m=audio"):]:
                fails.append("фаза 3b: talk-трек не PCMU: %r"
                             % sdp2[sdp2.rfind("m=audio"):][:120])
            sid = hdrs.get("session", "")
            code, hdrs, _ = rtsp_round(
                rb, "SETUP", base2 + "/trackID=0",
                {"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1",
                 "Session": sid})
            if code != 200:
                fails.append("фаза 3b: SETUP trackID=0 → %s" % code)
            code, hdrs, _ = rtsp_round(
                rb, "SETUP", base2 + "/trackID=2",
                {"Transport": "RTP/AVP/TCP;unicast;interleaved=2-3;"
                              "mode=record", "Session": sid})
            if code != 200 or "interleaved=2-3" not in \
                    hdrs.get("transport", "").replace(" ", ""):
                fails.append("фаза 3b: SETUP trackID=2 → %s %s"
                             % (code, hdrs))
            # регрессия 31.10: SETUP backchannel НЕ занимает talk-слот
            code, body = http_json("GET",
                                   "http://127.0.0.1:%d/status" % HTTP_PORT)
            if code == 200 and body.get("talk"):
                fails.append("фаза 3b: после SETUP trackID=2 в /status "
                             "есть talk-сессия: %s" % body.get("talk"))
            code, _, _ = rtsp_round(rb, "PLAY", base2, {"Session": sid})
            if code != 200:
                fails.append("фаза 3b: PLAY → %s" % code)
            code, _, _ = rtsp_round(rb, "RECORD", base2, {"Session": sid})
            if code != 200:
                fails.append("фаза 3b: RECORD → %s" % code)
            payload2 = bytes((160 + i * 3) % 256 for i in range(160)) * 10
            for i in range(10):
                rtp = (struct.pack(">BBHII", 0x80, 0x80, 2000 + i,
                                   160 * i, 0x23456789)
                       + payload2[i * 160:(i + 1) * 160])
                rb.sendall(b"$" + struct.pack(">BH", 2, len(rtp)) + rtp)
            time.sleep(1.0)
        finally:
            rb.close()
        time.sleep(1.5)
        got2 = b"".join(state["talk_chunks"][chunks_before:])
        if state["talk_starts"] != 3:
            fails.append("фаза 3b: talk_starts=%s (ожидалось 3)"
                         % state["talk_starts"])
        if state["talk_stops"] != 3:
            fails.append("фаза 3b: talk_stops=%s (ожидалось 3)"
                         % state["talk_stops"])
        if got2 != payload2:
            fails.append("фаза 3b: RTP-контент до панели не совпал "
                         "(%d Б)" % len(got2))

        # ---- фаза 4: эксклюзивность канала -------------------------------
        print("--- фаза 4: эксклюзивность ---")
        h1 = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=10)
        half = (bytes(range(255, -1, -1)) * 16)[:3200]
        req = ("POST /talk?ch=1 HTTP/1.1\r\nHost: x\r\n"
               "Content-Type: audio/basic\r\nContent-Length: 3200\r\n"
               "\r\n").encode()
        h1.sendall(req + half[:1600])       # полтела — сессия держит канал
        time.sleep(1.0)                     # пейсер успевает стартовать 331
        code, body = http_json(
            "POST", "http://127.0.0.1:%d/talk?ch=1" % HTTP_PORT, data=b"x",
            headers={"Content-Type": "audio/basic"})
        if code != 409:
            fails.append("второй /talk должен быть 409, а не %s" % code)
        h1.sendall(half[1600:])             # досылаем тело
        resp = b""
        h1.settimeout(20)
        try:
            while b"\r\n\r\n" not in resp:
                resp += h1.recv(4096)
            head, rest = resp.split(b"\r\n\r\n", 1)
            clen = 0
            for ln in head.decode("latin-1").split("\r\n"):
                if ln.lower().startswith("content-length:"):
                    clen = int(ln.split(":")[1])
            while len(rest) < clen:
                rest += h1.recv(4096)
            body1 = json.loads(rest.decode())
        except (socket.timeout, ConnectionError):
            body1 = {}
        finally:
            h1.close()
        if not body1.get("ok") or body1.get("sent") != 3200:
            fails.append("первый /talk после досылки: %s" % body1)
        if state["talk_starts"] != 4 or state["talk_stops"] != 4:
            fails.append("фаза 4: starts=%s stops=%s (ожидалось 4/4)"
                         % (state["talk_starts"], state["talk_stops"]))

        # ---- фаза 5: отказ старта (result=23) → cleanup 331/2 ----------
        # Железо 31.10 15:21: 332 потерялась в мусоре протокола, панель
        # держала talk занятым и отказала соседнему каналу result=23.
        # Шлюз при провале старта должен послать 331 action=2 (очистка
        # состояния панели), а /talk — ответить ok=false с диагнозом
        print("--- фаза 5: отказ старта + cleanup ---")
        state["refuse_talk"] = True
        refuse = (bytes(range(64)) * 50)[:3200]
        code, body = http_json(
            "POST", "http://127.0.0.1:%d/talk?ch=1" % HTTP_PORT, data=refuse,
            headers={"Content-Type": "audio/basic"})
        print("[http] /talk (отказ) → %s %s" % (code, body), flush=True)
        if code != 200 or body.get("ok"):
            fails.append("фаза 5: /talk при отказе должен быть ok=false: "
                         "%s %s" % (code, body))
        if "23" not in str(body.get("error")):
            fails.append("фаза 5: в ошибке нет result=23: %s"
                         % body.get("error"))
        if body.get("sent") != 0:
            fails.append("фаза 5: sent=%s (ожидалось 0)" % body.get("sent"))
        time.sleep(0.5)
        if state["talk_stops"] != 5:
            fails.append("фаза 5: cleanup 331/2 не отправлен "
                         "(stops=%s, ожидалось 5)" % state["talk_stops"])
        if state["talk_starts"] != 4:
            fails.append("фаза 5: starts=%s (ожидалось 4 — старт не должен "
                         "считаться)" % state["talk_starts"])
        # после очистки панели повторный /talk проходит штатно
        code, body = http_json(
            "POST", "http://127.0.0.1:%d/talk?ch=1" % HTTP_PORT, data=refuse,
            headers={"Content-Type": "audio/basic"})
        if code != 200 or not body.get("ok") or body.get("sent") != 3200:
            fails.append("фаза 5: повторный /talk после отказа: %s %s"
                         % (code, body))
        if state["talk_starts"] != 5 or state["talk_stops"] != 6:
            fails.append("фаза 5: итог starts=%s stops=%s (ожидалось 5/6)"
                         % (state["talk_starts"], state["talk_stops"]))
    finally:
        gw.terminate()
        try:
            out, _ = gw.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            gw.kill()
            out, _ = gw.communicate()
        stop.set()
        print("--- вывод шлюза (хвост) ---")
        print("\n".join(out.strip().splitlines()[-25:]), flush=True)
        # раскладка TLV 332 по реальному железу (reserve u16 @2): парсер
        # должен видеть 8000 Гц и 0x7A25 (G.711 µ-law)
        if "talk-формат: 8000 Гц" not in out or "wave=0x7A25" not in out:
            fails.append("парсинг 332: в логе нет «8000 Гц»/«0x7A25» — "
                         "раскладка не совпала")

    if fails:
        print("TEST11 FAILED: %s" % "; ".join(fails))
        return 1
    print("TEST11 PASSED: громкая связь (HTTP /talk + RTSP ANNOUNCE/RECORD,"
          " 331/332, пейсер 97+98, эксклюзив) работает")
    return 0


if __name__ == "__main__":
    sys.exit(main())
