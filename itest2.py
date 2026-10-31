#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 2: RTP/TCP interleaved + мок старой прошивки (<5.0) с авто-fallback логина."""
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import owsp_packet, encrypt_password  # noqa: E402

OWSP_PORT = 21001
RTSP_PORT = 28555

IDR = (b"\x00\x00\x00\x01" + bytes.fromhex("6742001e9554050177d0000300090f")
       + b"\x00\x00\x00\x01" + bytes.fromhex("68ce3c80")
       + b"\x00\x00\x00\x01" + b"\x65" + b"\x11" * 300)
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x22" * 300


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("eof")
        buf += c
    return buf


def mock_old_doorphone(stop):
    """Старая прошивка: отвечает версией 3.7, ждёт СТАРЫЙ логин (56 байт)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(1)
    srv.settimeout(10)
    conn, _ = srv.accept()
    conn.settimeout(10)
    frames = 0
    try:
        # первое соединение — шлюз пошлёт новый логин; отвечаем версией 3.7
        hdr = recv_exact(conn, 8)
        plen = struct.unpack(">I", hdr[:4])[0]
        recv_exact(conn, plen - 4)
        conn.sendall(owsp_packet([(39, struct.pack("<HH", 3, 7))], 2))
        time.sleep(0.5)
        conn.close()
        # второе соединение — старый логин
        conn2, _ = srv.accept()
        conn2.settimeout(10)
        hdr = recv_exact(conn2, 8)
        plen = struct.unpack(">I", hdr[:4])[0]
        body = recv_exact(conn2, plen - 4)
        t, l = struct.unpack_from("<HH", body, 0)
        assert t == 40 and struct.unpack("<HH", body[4:8]) == (3, 7), "ожидалась версия 3.7"
        t2, l2 = struct.unpack_from("<HH", body, 8)
        assert t2 == 41 and l2 == 56, "ожидался СТАРЫЙ логин 56 байт, got t=%d l=%d" % (t2, l2)
        login = body[12:12 + 56]
        assert login[32:48] == encrypt_password(b"888888"), "пароль"
        print("[mock-old] старый логин принят (версия 3.7, LoginRequest 56b)", flush=True)
        conn2.sendall(owsp_packet([(39, struct.pack("<HH", 3, 7)),
                                   (42, struct.pack("<HH", 1, 0))], 2))
        fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 500000, 320, 240)
               + bytes([12, 0, 0, 0])
               + struct.pack("<IIHHHHHH", 8000, 64000, 31257, 1, 1, 8, 20, 0))
        conn2.sendall(owsp_packet([(203, fmt)], 3))
        while not stop.is_set():
            frame = IDR if frames % 12 == 0 else PFRAME
            body = struct.pack("<HH", 99, 12) + struct.pack("<BBHII", 1, 0, 0, frames, frames * 80)
            body += struct.pack("<HH", 100 if frames % 12 == 0 else 101, len(frame)) + frame
            conn2.sendall(struct.pack(">I", 4 + len(body)) + struct.pack("<I", 50 + frames) + body)
            frames += 1
            time.sleep(0.08)
    except (ConnectionError, OSError, AssertionError) as exc:
        print("[mock-old] завершение: %r" % exc, flush=True)
    finally:
        try:
            srv.close()
        except OSError:
            pass
        print("[mock-old] остановлен, кадров: %d" % frames, flush=True)


def client():
    time.sleep(3)
    s = socket.create_connection(("127.0.0.1", RTSP_PORT), timeout=10)
    base = "rtsp://127.0.0.1:%d/cam" % RTSP_PORT
    rbuf = bytearray()

    def read_more():
        chunk = s.recv(65536)
        if not chunk:
            raise ConnectionError("eof")
        rbuf.extend(chunk)

    def recv_rtsp():
        while b"\r\n\r\n" not in rbuf:
            read_more()
        head, _, rest = bytes(rbuf).partition(b"\r\n\r\n")
        del rbuf[:len(head) + 4]
        lines = head.decode().split("\r\n")
        code = int(lines[0].split()[1])
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.lower()] = v.strip()
        clen = int(hdrs.get("content-length", "0") or 0)
        while len(rbuf) < clen:
            read_more()
        body = bytes(rbuf[:clen])
        del rbuf[:clen]
        return code, hdrs, body

    def req(method, url, headers=None):
        out = "%s %s RTSP/1.0\r\nCSeq: %d\r\n" % (method, url, req.n)
        req.n += 1
        for k, v in (headers or {}).items():
            out += "%s: %s\r\n" % (k, v)
        s.sendall((out + "\r\n").encode())
        # пропускаем возможные interleaved-кадры до начала RTSP-ответа
        while not rbuf or not rbuf[0:1] in (b"R",):
            if rbuf and rbuf[0:1] == b"$":
                while len(rbuf) < 4:
                    read_more()
                plen = struct.unpack(">H", rbuf[2:4])[0]
                while len(rbuf) < 4 + plen:
                    read_more()
                del rbuf[:4 + plen]
            else:
                read_more()
        return recv_rtsp()
    req.n = 1

    code, hdrs, body = req("DESCRIBE", base)
    assert code == 200 and b"trackID=0" in body, ("DESCRIBE", code, body)
    code, hdrs, _ = req("SETUP", base + "/trackID=0",
                        {"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"})
    assert code == 200 and "interleaved=0-1" in hdrs["transport"], ("SETUP", code, hdrs)
    print("[client] SETUP TCP-interleaved ok:", hdrs["transport"])
    sess = hdrs["session"].split(";")[0]
    code, hdrs, _ = req("PLAY", base, {"Session": sess})
    assert code == 200, ("PLAY", code)

    # читаем interleaved RTP из того же буфера
    pkts = []
    end = time.time() + 3
    s.settimeout(0.2)
    while time.time() < end and len(pkts) < 20:
        try:
            read_more()
        except socket.timeout:
            pass
        while rbuf[:1] == b"$" and len(rbuf) >= 4:
            chan, plen = struct.unpack(">BH", rbuf[1:4])
            if len(rbuf) < 4 + plen:
                break
            pkts.append((chan, bytes(rbuf[4:4 + plen])))
            del rbuf[:4 + plen]
        if rbuf[:1] not in (b"$", b""):
            print("[client] мусор в буфере:", bytes(rbuf[:16]))
            del rbuf[:]
    assert len(pkts) >= 10, ("кол-во пакетов", len(pkts))
    assert all(ch == 0 for ch, _ in pkts), ("канал", [ch for ch, _ in pkts[:5]])
    assert pkts[0][1][12] == 0x67, ("первый NAL", hex(pkts[0][1][12]))
    seqs = [struct.unpack(">H", p[2:4])[0] for _, p in pkts]
    assert all((b - a) % 0x10000 == 1 for a, b in zip(seqs, seqs[1:])), ("seq", seqs)
    print("[client] получено %d interleaved RTP-пакетов, SPS первым, seq монотонен" % len(pkts))
    print("TEST2 PASSED: старая прошивка + interleaved TCP")


def main():
    stop = threading.Event()
    t = threading.Thread(target=mock_old_doorphone, args=(stop,), daemon=True)
    t.start()
    import subprocess
    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--rtsp-port", str(RTSP_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rc = 0
    try:
        client()
    except Exception as exc:  # noqa: BLE001
        print("TEST2 FAILED: %r" % exc)
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
