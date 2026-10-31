#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Интеграционный тест: мок домофона (OWSP) -> slinex_rtsp.py -> RTSP-клиент."""
import base64
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import (owsp_packet, encrypt_password,  # noqa: E402
                        parse_owsp_packets)

OWSP_PORT = 21000
RTSP_PORT = 28554

# --- синтетический H264: SPS/PPS + IDR + P (валидные заголовки, мусорный payload) ---
SPS = bytes.fromhex("6742001e9554050177d0000300090f")  # синтетический, содержимое неважно
PPS = bytes.fromhex("68ce3c80")
IDR = b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS + \
      b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 16   # большой IDR
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x22" * 700


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def mock_doorphone(stop, ka_log, ack_log, ack_times, conn_count, sample_seq):
    """Мок: принимает НЕСКОЛЬКО соединений (ротация!), на каждом — логин
    (новый формат), версия 5.0 + result=1, затем льёт TLV 203 + кадры.
    Читатель считает keep-alive (TLV 49) и аудио-ACK (TLV 97) от клиента."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(8)
    print("[mock] домофон слушает :%d" % OWSP_PORT, flush=True)

    def handle_conn(conn):
        conn.settimeout(10)
        try:
            logged_in = False
            while not stop.is_set() and not logged_in:
                hdr = recv_exact(conn, 8)
                plen, seq = struct.unpack(">I", hdr[:4])[0], struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                pos = 0
                login_ok = False
                while pos + 4 <= len(body):
                    t, l = struct.unpack_from("<HH", body, pos)
                    val = body[pos + 4: pos + 4 + l]
                    if t == 41 and l == 68:  # LoginRequestEx
                        uname = val[1:33].rstrip(b"\x00").decode()
                        pwd = val[33:49]
                        ok = (uname == "admin"
                              and pwd == encrypt_password(b"888888"))
                        # поля по референсному дампу slinex.pcap
                        devid, flag = struct.unpack_from("<II", val, 49)
                        mask = struct.unpack_from("<I", val, 60)[0]
                        sm, dt = val[64], val[65]
                        fields_ok = (devid == 0 and flag == 0 and mask == 1
                                     and sm == 1 and dt == 2
                                     and val[57:60] == b"\x00\x00\x00")
                        print("[mock] логин user=%r pwd_ok=%s seq=%d dev=%d "
                              "flag=%d mask=%d sm=%d dt=%d поля:%s"
                              % (uname, ok, seq, devid, flag, mask, sm, dt,
                                 "ok" if fields_ok else "НЕ СОВПАДАЮТ"),
                              flush=True)
                        login_meta.append((seq, fields_ok))
                        login_ok = ok and fields_ok
                    elif t == 41 and l == 56:
                        login_ok = val[:32].rstrip(b"\x00").decode() == "admin"
                    pos += 4 + l
                if login_ok:
                    # реальное устройство отвечает ЭХОМ TLV 40 (не TLV 39!)
                    resp = owsp_packet([
                        (40, struct.pack("<HH", 5, 0)),
                        (42, struct.pack("<HH", 1, 0)),
                        (70, b"MOCK|1|DOOR".ljust(64, b"\x00")),
                    ], seq + 1)
                    conn.sendall(resp)
                    # формат потока
                    fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                           + bytes([15, 0, 0, 0])
                           + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0))
                    conn.sendall(owsp_packet([(203, fmt)], seq + 2))
                    logged_in = True
            if not logged_in:
                return

            # фоновый читатель: осушает сокет и считает keep-alive/ACK
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
                    packets, rbuf = parse_owsp_packets(rbuf) if rbuf else ([], rbuf)
                    for tlvs in packets:
                        for t, v in tlvs:
                            if t == 49:
                                ka_log.append(time.monotonic())
                            elif t == 97:
                                ack_log.append(time.monotonic())
                                ack_times.append(struct.unpack_from("<I", v, 4)[0])
            threading.Thread(target=drain, daemon=True).start()
            # льём поток (таймстампы аудио — из общего счётчика, чтобы
            # ACK-времена были монотонны и между соединениями)
            frame_idx = 0
            while not stop.is_set():
                frame = IDR if frame_idx % 15 == 0 else PFRAME
                is_idr = frame_idx % 15 == 0
                t = 100 if is_idr else 101
                body = struct.pack("<HH", 99, 12) + struct.pack("<BBHII", 1, 0, 0,
                                                                frame_idx, frame_idx * 66)
                body += struct.pack("<HH", t, 0) + frame  # len=0 — как у больших I-кадров
                pkt = struct.pack(">I", 4 + len(body)) + struct.pack("<I", 100 + frame_idx) + body
                conn.sendall(pkt)
                audio_ts = next(sample_seq) * 320
                conn.sendall(owsp_packet([
                    (97, struct.pack("<BBHI", 0, 0, 0, audio_ts)),
                    (98, b"\x55" * 160)], 1000 + frame_idx))
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
        while not stop.is_set():
            srv.settimeout(0.5)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            conn_count.append(time.monotonic())
            print("[mock] принято соединение №%d" % len(conn_count), flush=True)
            threading.Thread(target=handle_conn, args=(conn,),
                             daemon=True).start()
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass
        print("[mock] остановлен, соединений: %d" % len(conn_count), flush=True)


def rtsp_client():
    """Мини-клиент: DESCRIBE -> SETUP x2 (UDP) -> PLAY -> приём RTP."""
    time.sleep(2.5)  # дать шлюзу подключиться к моку
    s = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
    s.settimeout(10)
    cseq = 0

    def req(method, url, headers=None):
        nonlocal cseq
        cseq += 1
        out = "%s %s RTSP/1.0\r\nCSeq: %d\r\n" % (method, url, cseq)
        for k, v in (headers or {}).items():
            out += "%s: %s\r\n" % (k, v)
        out += "\r\n"
        s.sendall(out.encode())
        rbuf = b""
        while b"\r\n\r\n" not in rbuf:
            rbuf += s.recv(4096)
        head, rest = rbuf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        code = int(lines[0].split()[1])
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.lower()] = v.strip()
        clen = int(hdrs.get("content-length", "0") or 0)
        while len(rest) < clen:
            rest += s.recv(4096)
        body, _ = rest[:clen], rest[clen:]
        return code, hdrs, body

    base = "rtsp://127.0.0.1:%d/camera" % RTSP_PORT
    code, hdrs, body = req("OPTIONS", "*")
    assert code == 200, code
    print("[client] OPTIONS ok:", hdrs.get("public"))

    code, hdrs, body = req("DESCRIBE", base)
    assert code == 200, (code, body)
    sdp = body.decode()
    print("[client] DESCRIBE ok, SDP:")
    print("\n".join("    " + ln for ln in sdp.splitlines()))
    assert "H264/90000" in sdp and "trackID=0" in sdp
    assert "PCMA/8000/1" in sdp and "trackID=1" in sdp
    m = None
    for ln in sdp.splitlines():
        if ln.startswith("a=fmtp:96"):
            import re as _re
            m = _re.search(r"sprop-parameter-sets=([^,]+),([^;\r\n]+)", ln)
    assert m, "нет sprop-parameter-sets в SDP!"
    sps_b64, pps_b64 = m.group(1), m.group(2)
    assert base64.b64decode(sps_b64) == SPS, "SPS не совпал!"
    assert base64.b64decode(pps_b64) == PPS, "PPS не совпал!"
    print("[client] sprop-parameter-sets совпадают с потоком мока")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(10)
    cport = udp.getsockname()[1]
    code, hdrs, _ = req("SETUP", base + "/trackID=0",
                        {"Transport": "RTP/AVP;unicast;client_port=%d-%d" % (cport, cport + 1)})
    assert code == 200, code
    print("[client] SETUP video ok:", hdrs.get("transport"))
    udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp2.bind(("127.0.0.1", 0))
    aport = udp2.getsockname()[1]
    code, hdrs, _ = req("SETUP", base + "/trackID=1",
                        {"Transport": "RTP/AVP;unicast;client_port=%d-%d" % (aport, aport + 1),
                         "Session": hdrs.get("session", "").split(";")[0]})
    assert code == 200, code
    code, hdrs, _ = req("PLAY", base, {"Session": hdrs.get("session", "").split(";")[0]})
    assert code == 200, code
    assert "rtp-info" in hdrs
    print("[client] PLAY ok:", hdrs.get("rtp-info"))

    # принимаем RTP
    video_pkts = []
    audio_pkts = []
    end = time.time() + 4
    udp.settimeout(1)
    udp2.settimeout(1)
    while time.time() < end:
        try:
            data, _ = udp.recvfrom(65536)
            assert data[0] >> 6 == 2 and (data[1] & 0x7F) == 96, data[:2].hex()
            video_pkts.append(data)
        except socket.timeout:
            pass
        try:
            data, _ = udp2.recvfrom(65536)
            assert (data[1] & 0x7F) == 8 and (data[0] >> 6) == 2
            audio_pkts.append(data)
        except socket.timeout:
            pass
    assert len(video_pkts) >= 10, len(video_pkts)
    assert len(audio_pkts) >= 20, len(audio_pkts)
    # пересборка кадра из FU-A не требуется; проверяем согласованность заголовков
    seqs = [struct.unpack(">H", p[2:4])[0] for p in video_pkts]
    assert all((b - a) % 0x10000 in (0, 1) for a, b in zip(seqs, seqs[1:])), seqs
    assert any(p[1] & 0x80 for p in video_pkts), "нет маркера конца кадра"
    # первый пакет после PLAY должен быть IDR (SPS первым NAL)
    first_payload = video_pkts[0][12:]
    assert first_payload[0] in (0x67, 0x7C), first_payload[:1].hex()  # SPS или FU-A
    got_idr_start = any(p[12] == 0x67 for p in video_pkts[:5])
    assert got_idr_start, "SPS не пришёл в начале потока"
    # аудио: 160 байт PCMA
    assert all(len(p) - 12 == 160 for p in audio_pkts)
    # ts монотонные
    ats = [struct.unpack(">I", p[4:8])[0] for p in audio_pkts]
    assert all(b > a for a, b in zip(ats, ats[1:]))
    print("[client] получено %d видео-RTP и %d аудио-RTP пакетов" %
          (len(video_pkts), len(audio_pkts)))
    print("[client] видео-секвенции монотонны, SPS идёт первым, аудио PCMA 160б/20мс")
    # keep-alive: шлюз шлёт TLV 49 периодически с интервалом 1 с
    time.sleep(4)
    assert len(ka_log) >= 3, ("keep-alive не отправляется", len(ka_log))
    gaps = [b - a for a, b in zip(ka_log, ka_log[1:])]
    assert all(0.1 <= g <= 4.0 for g in gaps), ("интервалы keep-alive", gaps)
    print("[client] keep-alive: %d пакетов, интервалы %s с"
          % (len(ka_log), ["%.1f" % g for g in gaps]))
    # аудио-ACK (TLV 97): шлюз обязан подтверждать каждую метку устройства
    assert len(ack_log) >= 10, ("аудио-ACK не отправляются", len(ack_log))
    # и ACK должен эхать РАСТУЩИЙ таймстамп (позиция потребления),
    # а не застрять на константе (200) — иначе прошивка закрывает сессию
    assert len(ack_times) >= 10, len(ack_times)
    assert all(b > a for a, b in zip(ack_times, ack_times[1:])), \
        ("ACK-таймстампы не растут", ack_times[:8])
    assert ack_times[-1] > 1000, ("ACK не отразил позицию потока", ack_times[-1])
    print("[client] аудио-ACK (TLV 97): %d шт., time: %d → %d (растёт)"
          % (len(ack_log), ack_times[0], ack_times[-1]))
    # соединение ОДНО на всё время стрима: ротация удалена, шлюз не
    # должен рвать сессию (мок считает все OWSP-подключения)
    assert len(conn_count) == 1, ("лишние OWSP-соединения (ротация удалена?)",
                                  len(conn_count))
    assert len(video_pkts) >= 10, ("поток прервался", len(video_pkts))
    sps_seen = sum(1 for p in video_pkts if p[12] == 0x67)
    assert sps_seen >= 2, ("I-кадры не приходят", sps_seen)
    print("[client] одно OWSP-соединение на весь стрим, RTP-секвенции "
          "непрерывны, I-кадров получено %d" % sps_seen)
    # логин: поля должны совпадать с референсным дампом slinex.pcap
    assert login_meta, "мок не видел логина"
    for seq, fields_ok in login_meta:
        assert seq == 0, ("packet_seq логина != 0", seq)
        assert fields_ok, "поля логина не совпадают с референсом"
    print("[client] логин: seq=0, deviceId=0, flag=0, mask=1, "
          "streamMode=1, dataType=2 — как в референсе")
    req("TEARDOWN", base, {"Session": hdrs.get("session", "").split(";")[0]})
    print("INTEGRATION TEST PASSED")


ka_log = []
ack_log = []
ack_times = []
conn_count = []
login_meta = []


def main():
    import itertools
    sample_seq = itertools.count()
    stop = threading.Event()
    t = threading.Thread(target=mock_doorphone,
                         args=(stop, ka_log, ack_log, ack_times, conn_count,
                               sample_seq), daemon=True)
    t.start()
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--rtsp-port", str(RTSP_PORT),
         # опциональные механизмы: держим включёнными, чтобы тест
         # продолжал их проверять (по умолчанию они все выключены —
         # как в референсном приложении)
         "--keepalive", "1", "--audio-ack"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        rtsp_client()
        rc = 0
    except AssertionError as exc:
        print("INTEGRATION TEST FAILED:", exc)
        rc = 1
    except Exception as exc:  # noqa: BLE001
        print("INTEGRATION TEST ERROR: %r" % exc)
        rc = 1
    finally:
        stop.set()
        gw.terminate()
        try:
            out, _ = gw.communicate(timeout=5)
            print("--- вывод шлюза ---")
            print(out)
        except subprocess.TimeoutExpired:
            gw.kill()
    sys.exit(rc)


if __name__ == "__main__":
    main()
