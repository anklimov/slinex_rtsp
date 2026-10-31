#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест сторожа простоя: мок замолкает после логина — шлюз должен
заметить «зомби»-сессию и пересоздать соединение (--idle-timeout)."""
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import owsp_packet  # noqa: E402

OWSP_PORT = 21060

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS + \
      b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 4

conn_count = []
logins = []


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def silent_mock(stop):
    """Каждое соединение: логин → пара кадров → ТИШИНА навсегда."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(8)
    print("[mock] слушаю :%d (режим «замолкает после логина»)" % OWSP_PORT,
          flush=True)

    def handle(conn):
        try:
            conn.settimeout(10)
            hdr = recv_exact(conn, 8)
            plen, seq = struct.unpack(">I", hdr[:4])[0], \
                struct.unpack("<I", hdr[4:8])[0]
            body = recv_exact(conn, plen - 4)
            logins.append(len(body))
            assert body[:4] == b"\x29\x00\x44\x00", "ожидается TLV 41[68]"
            conn.sendall(owsp_packet([
                (40, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, b"M".ljust(64, b"\x00")),
            ], seq + 1))
            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([5, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31269, 1, 1, 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], seq + 2))
            # два кадра — и молчим (зомби)
            for idx in range(2):
                fbody = struct.pack("<HH", 99, 12) + \
                    struct.pack("<BBHII", 1, 0, 0, idx, idx * 200)
                fbody += struct.pack("<HH", 100, 0) + IDR
                conn.sendall(struct.pack(">I", 4 + len(fbody))
                            + struct.pack("<I", 10 + idx) + fbody)
                time.sleep(0.1)
            print("[mock] соединение №%d замолчало (зомби)" % len(conn_count),
                  flush=True)
            # держим сокет открытым, пока клиент не закроет сам
            conn.settimeout(30)
            while not stop.is_set():
                try:
                    if not conn.recv(4096):
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
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
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        srv.close()


def main():
    stop = threading.Event()
    threading.Thread(target=silent_mock, args=(stop,), daemon=True).start()
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--rtsp-port", "28560", "--idle-timeout", "2"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rc = 1
    try:
        # 12 секунд: логин (~1 с) + зомби-детект (2 с) + реконнекты
        time.sleep(12)
        n = len(conn_count)
        print("соединений за 12 с: %d (ожидается >= 3: логин + зомби-детект "
              "+ реконнект)" % n)
        assert n >= 3, ("сторож простоя не сработал", n)
        assert len(logins) == n, ("логинов меньше соединений", len(logins))
        print("WATCHDOG TEST PASSED: зомби-сессии пересоздаются")
        rc = 0
    except AssertionError as exc:
        print("WATCHDOG TEST FAILED:", exc)
    finally:
        stop.set()
        gw.terminate()
        try:
            out, _ = gw.communicate(timeout=5)
            print("--- вывод шлюза (хвост) ---")
            print("\n".join(out.splitlines()[-12:]))
        except subprocess.TimeoutExpired:
            gw.kill()
    sys.exit(rc)


if __name__ == "__main__":
    main()
