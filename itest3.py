#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Интеграционный тест 3: мультика­мерность (2 канала).
Мок домофона принимает НЕСКОЛЬКО соединений; каждое логинится маской своего
канала (как в оригинальном приложении). RTSP-клиент проверяет, что
/camera и /camera2 дают РАЗНЫЕ потоки (разные SPS) и что канальный путь
/camN работает лениво."""
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import owsp_packet, encrypt_password  # noqa: E402

OWSP_PORT = 21002
RTSP_PORT = 28556

SPS = {
    1: bytes.fromhex("6742001e95540501aa"),   # «камера» 1
    2: bytes.fromhex("6742001e95540a02bb"),   # «камера» 2
}
PPS = {1: bytes.fromhex("68ce3c80"), 2: bytes.fromhex("68ce3c81")}

# формат потока: у канала 2 другое разрешение, чтобы видеть разделение
FMT = {
    1: (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 640, 480)
        + bytes([15, 0, 0, 0])
        + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0)),
    2: (struct.pack("<BBBBIIHH", 2, 2, 2, 0, 1, 1000000, 320, 240)
        + bytes([12, 0, 0, 0])
        + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0)),
}


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("eof")
        buf += c
    return buf


def build_device_info(channels):
    return (b"MOCK-CO".ljust(16, b"\x00")          # companyIdentity
            + b"MOCKID01".ljust(16, b"\x00")       # equipmentIdentity
            + b"SL10-MOCK".ljust(16, b"\x00")      # equipmentName
            + b"1.0.0".ljust(16, b"\x00")         # equipmentVersion
            + struct.pack("<H", 2026)              # year
            + bytes([1, 1, channels, 0, 0, 0]))    # m d ch alarm type res


def handle_connection(conn, conn_id, logins, stop):
    """Одно OWSP-подключение: логин (маска канала) → стрим этого канала."""
    conn.settimeout(10)
    channel = None
    seq = 1
    try:
        while not stop.is_set() and channel is None:
            hdr = recv_exact(conn, 8)
            plen, pseq = struct.unpack(">I", hdr[:4])[0], struct.unpack("<I", hdr[4:])[0]
            body = recv_exact(conn, plen - 4)
            pos = 0
            while pos + 4 <= len(body):
                t, l = struct.unpack_from("<HH", body, pos)
                val = body[pos + 4: pos + 4 + l]
                if t == 41 and l == 68:
                    mask = struct.unpack_from("<I", val, 60)[0]
                    assert val[1:33].rstrip(b"\x00") == b"admin"
                    assert val[33:49] == encrypt_password(b"888888")
                    # маска должна содержать ровно один бит
                    assert mask in (1, 2, 4, 8), "неожиданная маска: %d" % mask
                    channel = mask.bit_length()          # 1→1, 2→2, 4→3...
                    with logins_lock:
                        logins.append((conn_id, channel))
                    print("[mock] соед.%d: логин, маска=0x%X → канал %d"
                          % (conn_id, mask, channel), flush=True)
                pos += 4 + l
            if channel is None:
                continue
            conn.sendall(owsp_packet([
                (39, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, build_device_info(2)),
            ], pseq + 1))
            conn.sendall(owsp_packet([(203, FMT[channel])], pseq + 2))
        # стрим
        fno = 0
        idr = (b"\x00\x00\x00\x01" + SPS[channel] + b"\x00\x00\x00\x01" + PPS[channel]
               + b"\x00\x00\x00\x01" + b"\x65" + b"\x11" * 300)
        pframe = b"\x00\x00\x00\x01" + b"\x41\x9a" + (b"\x22" * 300)
        while not stop.is_set():
            frame = idr if fno % 10 == 0 else pframe
            t = 100 if fno % 10 == 0 else 101
            body = struct.pack("<HH", 99, 12) + \
                struct.pack("<BBHII", channel, 0, 0, fno, fno * 66)
            body += struct.pack("<HH", t, len(frame)) + frame
            conn.sendall(struct.pack(">I", 4 + len(body))
                         + struct.pack("<I", seq) + body)
            if fno % 5 == 0:  # аудио только у активного потока
                conn.sendall(owsp_packet([(98, b"\x55" * 160)], seq + 1))
            seq += 2
            fno += 1
            time.sleep(0.07)
    except (ConnectionError, OSError, AssertionError) as exc:
        print("[mock] соед.%d завершено: %r" % (conn_id, exc), flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def mock_doorphone(stop, logins):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(8)
    srv.settimeout(1)
    print("[mock] домофон на 2 канала слушает :%d" % OWSP_PORT, flush=True)
    conn_id = 0
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn_id += 1
        threading.Thread(target=handle_connection,
                         args=(conn, conn_id, logins, stop),
                         daemon=True).start()
    srv.close()


logins_lock = threading.Lock()


def rtsp_probe(path):
    """Мини RTSP-клиент: DESCRIBE → (код, sprop SPS из SDP)."""
    s = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
    s.settimeout(10)
    base = "rtsp://127.0.0.1:%d%s" % (RTSP_PORT, path)
    s.sendall(("DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\n\r\n" % base).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    head, _, rest = buf.partition(b"\r\n\r\n")
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
    s.close()
    sps = None
    if code == 200:
        import base64 as b64
        import re as _re
        m = _re.search(rb"sprop-parameter-sets=([^,;\r\n]+)", rest)
        if m:
            sps = b64.b64decode(m.group(1))
    return code, sps


def main():
    stop = threading.Event()
    logins = []
    t = threading.Thread(target=mock_doorphone, args=(stop, logins), daemon=True)
    t.start()
    # запускаем шлюз только с каналом 1 — второй должен открыться лениво
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--rtsp-port", str(RTSP_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rc = 0
    try:
        time.sleep(3)
        code1, sps1 = rtsp_probe("/camera")
        assert code1 == 200, ("DESCRIBE /camera", code1)
        assert sps1 == SPS[1], "SPS канала 1 не совпал"
        print("[client] /camera → канал 1 (SPS ок)")

        # ленивое открытие канала 2 через /camera2
        code2, sps2 = rtsp_probe("/camera2")
        assert code2 == 200, ("DESCRIBE /camera2", code2)
        assert sps2 == SPS[2], "SPS канала 2 не совпал: %s" % (sps2 or b"").hex()
        assert sps1 != sps2, "потоки каналов должны различаться"
        print("[client] /camera2 → канал 2 (SPS ок, поток отличается от канала 1)")

        # алиасы путей
        code3, sps3 = rtsp_probe("/cam2")
        assert code3 == 200 and sps3 == SPS[2], (code3, (sps3 or b"").hex())
        code4, sps4 = rtsp_probe("/ch2")
        assert code4 == 200 and sps4 == SPS[2]
        print("[client] алиасы /cam2 и /ch2 работают")

        time.sleep(1)
        with logins_lock:
            chans = sorted(set(ch for _, ch in logins))
            n_conns = len(set(cid for cid, _ in logins))
        assert chans == [1, 2], chans
        assert n_conns >= 2, "должно быть минимум 2 соединения (по одному на канал)"
        print("[client] мок подтвердил: %d соединений, логины с масками каналов %s"
              % (n_conns, chans))
        print("TEST3 PASSED: мультиканальность (2 камеры) работает")
    except AssertionError as exc:
        print("TEST3 FAILED:", exc)
        rc = 1
    except Exception as exc:  # noqa: BLE001
        print("TEST3 ERROR: %r" % exc)
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
