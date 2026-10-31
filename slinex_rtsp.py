#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slinex_rtsp.py — RTSP-шлюз для видеодомофона Slinex SL-10PT (и других
устройств на платформе Gooclient/Goolink "Mobile Eye Door").

Реверс-инжиниринг протокола OWSP выполнен по APK com.gooclient.mobileeyedoor.plus
(см. PROTOCOL.md). Домофон отдаёт H.264 + G.711 (A-law или µ-law — по TLV 203)
по проприетарному OWSP/TLV поверх TCP; шлюз конвертирует это в обычный RTSP
(RTP/UDP и TCP interleaved).

Зависимости: только стандартная библиотека Python 3.8+.

Мультика­мерность: как и в оригинальном приложении (4-экранный обзор),
на каждый канал открывается своё OWSP-соединение (логин с маской своего
канала). Каждому каналу соответствует свой RTSP-URL.

Примеры:
    # найти домофон в LAN (UDP broadcast, порт 1500)
    ./slinex_rtsp.py --discover

    # запустить шлюз (порт OWSP по умолчанию 100), канал 1
    ./slinex_rtsp.py --host 192.168.1.50 --user admin --password 888888
    #   → rtsp://<host>:8554/camera

    # устройство с несколькими камерами/панелями: открыть 4 канала сразу
    ./slinex_rtsp.py --host 192.168.1.50 --channels 1,2,3,4
    #   → rtsp://<host>:8554/camera (=1), /camera2, /camera3, /camera4

    # или открыть все каналы, узнав их число у домофона (TLV 70)
    ./slinex_rtsp.py --host 192.168.1.50 --channels all

    # путь /camN (равноценно /cameraN) можно запрашивать и «лениво» —
    # соединение с нужным каналом откроется при первом обращении

    # затем в VLC / ffplay:
    #   ffplay -rtsp_transport tcp rtsp://127.0.0.1:8554/camera2
    #   vlc rtsp://127.0.0.1:8554/camera

    # отладка: сохранить элементарный поток в файл (по файлу на канал)
    ./slinex_rtsp.py --host 192.168.1.50 --record dump_ch{ch}.h264

    # открыть замок (кнопка «замок» в приложении = TLV 425 в стрим-сессии)
    ./slinex_rtsp.py --host 192.168.1.50 --unlock
    # то же из РАБОТАЮЩЕГО шлюза — HTTP-контроль (порт --http-port, 8555):
    #   curl -X POST 'http://<host>:8555/unlock?ch=1&delay=1'
    #   curl -X POST 'http://<host>:8555/volume?ch=1&dir=down&steps=3'
    #   curl 'http://<host>:8555/status'   # состояние каналов
    #   curl 'http://<host>:8555/events'   # события (замок, звонок, TLV)

    # события звонка (ring-детектор по аудио) + команды через MQTT:
    #   конфиг slinex_gateway.conf ([mqtt]: брокер/креды/топики),
    #   публикация {base}/events/ring|unlock|volume, подписка
    #   {base}/cmd/unlock и {base}/cmd/volume; --no-mqtt выключает

    # громкая связь (talk) — ингресс тремя способами:
    #   HTTP:  curl -X POST --data-binary @speech.ulaw \
    #             -H 'Content-Type: audio/basic' http://host:8555/talk?ch=1
    #   RTSP:  ffmpeg -f avfoundation -i :0 -acodec pcm_mulaw -ar 8000 \
    #             -ac 1 -f rtsp -rtsp_transport tcp rtsp://host:8554/camera/talk
    #   go2rtc/ONVIF Profile T backchannel: DESCRIBE выдаёт talk-трек
    #   trackID=2 a=sendonly (направления — с точки зрения клиента, как
    #   у Dahua/Hikvision) → SETUP trackID=2 в сессии PLAY — go2rtc
    #   включает кнопку микрофона (two-way audio); сессия панели
    #   открывается лениво по первому RTP с микрофона
    #   (сессия стартует по первому аудио-пакету, конец — TLV 331 action=2;
    #    файлы доигрываются целиком — backpressure; события talk
    #    start/end → лог + /events + MQTT)

    # синхронизация времени панели (TLV 1007, локальное время хоста):
    ./slinex_rtsp.py --host 192.168.1.50 --sync-time          # one-shot
    ./slinex_rtsp.py --host 192.168.1.50 --sync-time-every 24  # периодически

Замечание: у домофона есть лимит одновременных подключений (в приложении
ошибка 5 = «превышено число пользователей», обычно ~4-5). Учтите это,
если параллельно пользуесь мобильным приложением.
"""

import argparse
import base64
import bisect
import collections
import configparser
import json
import math
import os
import queue
import random
import re
import socket
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# OWSP протокол (см. PROTOCOL.md)
# ---------------------------------------------------------------------------

ENC_KEY = b"lbtech"  # ключ "шифрования" пароля из com.libao.encryp.Encrypt

TLV_VERSION_REQ = 40
TLV_VERSION_RSP = 39
TLV_LOGIN_REQ = 41
TLV_LOGIN_RSP = 42
TLV_KEEPALIVE = 49
TLV_DEVICE_INFO = 70
TLV_AUDIO_INFO = 97           # аудио-метка от устройства / ACK от клиента
TLV_AUDIO_DATA = 98
TLV_VIDEO_FRAME_INFO = 99
TLV_VIDEO_IFRAME = 100
TLV_VIDEO_PFRAME = 101
TLV_STREAM_FORMAT = (199, 200, 203)
TLV_REBOOT_REQ = 465         # DeviceRestartRequest (4 байта нулей)
TLV_REBOOT_RSP = 466         # DeviceRestartResponse
TLV_LOCK_REQ = 425           # LockRequest (открытие замка)
TLV_LOCK_RSP = 426           # LockResponse (result u16, 1 = успех)
TLV_VOLUME_REQ = 1054         # VolumeConfigRequest (громкость локального динамика)
TLV_VOLUME_RSP = 1055         # VolumeConfigResponse (result u16, 1 = успех)
TLV_TIMESYNC_REQ = 1007        # TimeSyncRequest (дата/время панели)
TLV_TIMESYNC_RSP = 1008       # TimeSyncResponse (result u16, 1 = успех)
TLV_NOT_RECOGNIZE = 1006      # NotRecognize — прошивка не знает команду
TLV_TALK_REQ = 331            # TalkRequest (8 Б: старт/стоп громкой связи)
TLV_TALK_RSP = 332            # TalkResponse (24 Б: result + формат аудио)

# «Тихий» набор: базовые TLV стрима (хендшейк/медиа/формат) и ответы на
# наши команды (имеют собственные события). Всё, что НЕ входит в набор,
# мониторится как потенциальное спонтанное событие прошивки (см.
# _handle_tlvs): событие «tlv» на каждое вхождение → лог + /events + MQTT.
TLV_QUIET_TLVS = frozenset((
    39, 40, 41, 42, 49,              # version/login/keepalive
    70, 71,                          # device info
    97, 98, 99, 100, 101,            # аудио/видео медиа
    199, 200, 203,                   # формат потока
    426, 1055, 1008, 332,            # ответы замка/громкости/времени/talk
))

WAVE_FORMAT_G711A = 31257
WAVE_FORMAT_G711U = 31269

OWSP_MAX_PACKET = 196605  # 0x30005, ограничение из приложения

# Полный список TLV-типов из Command.java (APK). Всё, что придёт от
# устройства и НЕ входит в этот список — потенциально событие (вызов?,
# датчик, ...) — логируется и попадает в /events.
OWSP_KNOWN_TLVS = frozenset((
    39, 40, 41, 42, 44, 45, 47, 48, 49, 51, 52, 57, 64, 65, 66, 67,
    70, 71, 72, 73, 75, 76, 97, 98, 99, 100, 101, 102, 199, 200, 203,
    213, 214, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311,
    312, 313, 331, 332, 333, 334, 335, 336, 337, 338, 339, 341, 342,
    343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354,
    401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
    414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426,
    427, 428, 429, 430, 433, 434, 435, 436, 449, 450, 465, 466, 467,
    468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478,
    1006, 1007, 1008, 1054, 1055, 65535,
))


def encrypt_password(pwd: bytes) -> bytes:
    """enc[i] = pwd[i] ^ ((key[i % 6] + 25) & 0xFF); добить нулями до 16 байт."""
    field = bytearray(16)
    for i in range(min(len(pwd), 16)):
        field[i] = pwd[i] ^ ((ENC_KEY[i % len(ENC_KEY)] + 25) & 0xFF)
    return bytes(field)


def owsp_packet(tlvs, seq: int) -> bytes:
    """Собрать OWSP-пакет: BE u32 length, LE u32 seq, TLV-записи (LE)."""
    body = bytearray()
    for tlv_type, value in tlvs:
        body += struct.pack("<HH", tlv_type, len(value))
        body += value
    packet_length = 4 + len(body)  # магический "+4" из оригинального клиента
    return struct.pack(">I", packet_length) + struct.pack("<I", seq) + bytes(body)


def parse_owsp_packets(buf: bytes):
    """Разобрать TCP-буфер на (список TLV, остаток)."""
    packets = []
    pos = 0
    while len(buf) - pos >= 8:
        packet_length = struct.unpack_from(">I", buf, pos)[0]
        if packet_length < 8 or packet_length > OWSP_MAX_PACKET:
            raise ValueError("bad OWSP packet_length=%d" % packet_length)
        total = packet_length + 4  # полный размер пакета в потоке
        if len(buf) - pos < total:
            break
        body = buf[pos + 8: pos + total]
        pos += total

        tlvs = []
        ileft = len(body)
        off = 0
        while ileft >= 4:  # >= 4: пустые TLV (len=0, напр. TLV 49) тоже валидны
            tlv_type, tlv_len = struct.unpack_from("<HH", body, off)
            # Фиксап длины видеокадров: поле TLV len — u16 и не влезает
            # в большие I-кадры; клиент пересчитывает длину из packet_length
            # (24 = 4 + заголовок TLV99(4) + его значение(12) + заголовок TLV100(4)).
            if tlv_type in (TLV_VIDEO_IFRAME, TLV_VIDEO_PFRAME):
                if packet_length - tlv_len > 24:
                    tlv_len = packet_length - 24
            if tlv_len + 4 > ileft:
                tlv_len = max(ileft - 4, 0)
            tlvs.append((tlv_type, body[off + 4: off + 4 + tlv_len]))
            off += 4 + tlv_len
            ileft -= 4 + tlv_len
        packets.append(tlvs)
    return packets, buf[pos:]


VIDEO_SYNC_MARKER = b"\x63\x00\x0c\x00"  # заголовок TLV 99 (VideoFrameInfo, 12 байт)


def resync_owsp(buf):
    """Найти вероятное начало следующего OWSP-пакета после мусора в потоке.

    Каждый видеокадр STM83xx начинается с TLV 99 (VideoFrameInfo, 12 байт,
    заголовок 63 00 0C 00) сразу за 8-байтным заголовком OWSP. Ищем такой
    маркер, проверяем правдоподобность поля length пакета перед ним и
    возвращаем смещение (всегда > 0 — гарантия прогресса) либо None.

    Без ресинка «дроп всего буфера» не выравнивает поток обратно: TCP не
    сохраняет границы пакетов, следующий recv начинается с середины кадра
    → каскад мусора (наблюдалось 28.10 на канале 4 после перезагрузки
    домофона: картина «рассыпается», парсер отбрасывал весь поток).
    """
    pos = 1
    while True:
        i = buf.find(VIDEO_SYNC_MARKER, pos)
        if i < 0:
            return None
        start = i - 8
        if start > 0:
            plen = struct.unpack_from(">I", buf, start)[0]
            if 24 <= plen <= OWSP_MAX_PACKET:
                return start
        pos = i + 1


def build_login(user: str, password: str, channel: int, stream_mode: int,
                data_type: int, new_proto: bool,
                device_id: int = 0, flag: int = 0, seq: int = 0) -> bytes:
    """Логин-пакет. new_proto=True → версия 5.0 + LoginRequestEx,
    иначе версия 3.7 + старый LoginRequest (как в приложении).

    Поля LoginRequestEx выверены по референсному дампу работающего
    приложения (slinex.pcap): packet_seq=0, deviceId=0, flag=0,
    streamMode=1 (суб-поток). Наш прежний вариант (deviceId=1, flag=2,
    streamMode=0) прошивка STM83xx терпела лишь ~2 секунды, после
    чего рвала соединение.

    device_id/flag/seq переопределяются для логина-настройки
    (перезагрузка по TLV 465): упаковщик приложения шлёт там
    deviceId=1 (дефолт при UID без "|"), flag=2 и packet_seq=2,
    а сам reboot-пакет — с packet_seq=1 (команда собирается до
    логина и отправляется сразу после его подтверждения).
    """
    user_b = user.encode("utf-8", "replace")[:31] + b"\x00"
    pwd_field = encrypt_password(password.encode("utf-8", "replace"))
    if new_proto:
        ver = struct.pack("<HH", 5, 0)
        body = (
            b"\x00"                                   # encryptType
            + user_b.ljust(32, b"\x00")[:32]          # userName
            + pwd_field                               # password[16]
            + struct.pack("<I", device_id)            # deviceId (0!)
            + struct.pack("<I", flag)                 # flag (0!)
            + b"\x00" * 3                             # reserve3
            + struct.pack("<I", 1 << (channel - 1))   # channelMask
            + bytes([stream_mode & 0xFF, data_type & 0xFF, 0, 0])
        )
    else:
        ver = struct.pack("<HH", 3, 7)
        body = (
            user_b.ljust(32, b"\x00")[:32]
            + pwd_field
            + struct.pack("<I", 0)                    # deviceId
            + bytes([0, (channel - 1) & 0xFF])         # flag, channel (0-based)
            + b"\x00\x00"                             # reserve
        )
    return owsp_packet([(TLV_VERSION_REQ, ver), (TLV_LOGIN_REQ, body)], seq)


def build_lock_req(password: str, channel: int, action: int = 1,
                   delay: int = 1) -> bytes:
    """TLV 425 LockRequest — 40 байт по _TLV_V_Lock_Req из APK.

    Раскладка (createLockPacket → EyeProtocolPacker):
      deviceId  u32 = 0 (хардкод в приложении)
      lockPwd   [32] — XOR «lbtech»+25, шифруются ТОЛЬКО байты пароля
                     (Encrypt.EncrypKey: цикл for i < len), остаток поля
                     нули — как в логине (проверено по Encrypt.java)
      channel   u8 — 1-BASED для нового протокола (прошивка 5.0):
                     EyeSourceTransNet.remoteLock делает
                     «if (Version == 0 || Version == 1) channel++», где
                     newVersion=1, oldVersion=2, а chanIndex сессии
                     0-based → для канала 1 приложение шлёт байт 1.
                     НАБЛЮДЕНИЕ 31.10: с 0-based прошивка отвечает
                     TLV 426 result=2 при любом пароле (приложение при
                     этом успешно открывает тем же паролем логина).
      action    u8 — 1 = открыть замок, 0 = закрыть
      delayTime u8 — удержание реле, секунды
      reserve   u8 = 0
    """
    pwd = password.encode("utf-8", "replace")[:31]
    field = bytearray(32)
    for i in range(len(pwd)):
        field[i] = pwd[i] ^ ((ENC_KEY[i % len(ENC_KEY)] + 25) & 0xFF)
    return (struct.pack("<I", 0) + bytes(field)
            + bytes([channel & 0xFF, action & 0xFF,
                     delay & 0xFF, 0]))


def build_volume_req(action: int) -> bytes:
    """TLV 1054 VolumeConfigRequest — 8 байт по _GLNK_V_VolumeConfigRequest.

    Кнопки громкости в приложении (MainActivity btn_device_voice_add/des):
      action  u8 — 1 = громче, 0 = тише
      volume  u8 — шаг, приложение всегда шлёт 10
      reserve [6] — нули
    """
    return bytes([1 if action else 0, 10]) + b"\x00" * 6


def build_talk_req(channel: int, action: int) -> bytes:
    """TLV 331 TalkRequest — 8 байт по TLV_V_TalkRequest из APK.

    EyeSourceTransNet.setTalk → TalkRequestReqPack (остальные параметры
    упаковщика — samplesPerSecond и пр. — в пакет НЕ пишутся, только
    эти 8 байт):
      deviceId u32 = 0
      action   u8 — 1 = старт, 2 = стоп
      chn      u8 — 1-BASED (setTalk: chanIndex+1, как у замка)
      reserve [2] — нули
    """
    return (struct.pack("<I", 0)
            + bytes([action & 0xFF, channel & 0xFF, 0, 0]))


def build_talk_audio(channel: int, chunk: bytes):
    """TLV 97+98 — аудио «вверх» (AudioInfoRequestPack из APK).

    Один OWSP-пакет на чанк 320 Б µ-law (40 мс @ 8 кГц), как writeTalkData
    в приложении (блокирующее чтение 320 сэмплов задаёт темп):
      TLV 97 (8 Б): channelId u8 1-based, reserve=0, checksum u16=0,
                    time u32=200 (константа, не таймстамп!)
      TLV 98: сэмплы µ-law
    """
    info = (bytes([channel & 0xFF, 0])
            + struct.pack("<H", 0) + struct.pack("<I", 200))
    return [(TLV_AUDIO_INFO, info), (TLV_AUDIO_DATA, bytes(chunk))]


def parse_talk_rsp(value: bytes):
    """TLV 332 TalkResponse (24 байта) → (result, dict формата).

    Раскладка по ЖЕЛЕЗУ STM83xx (проверено 31.10 14:31 на панели:
    реальные 8000 Гц (0x1F40) и waveFormat 0x7A25 лежат со сдвигом +2 Б
    относительно TLV_V_TalkResponse.deserialize из APK — после result
    идёт reserve u16):
      result u16 @0, reserve u16 @2, samplesPerSecond u32 @4,
      audiobitrate u32 @8, waveFormat u16 @12, channelNumber u16 @14,
      blockAlign u16 @16, bitsPerSample u16 @18, frameInterval u16 @20.
    Поля после @14 — по APK-порядку, сверяются по «332 hex=…» в логе.
    """
    if len(value) < 6:
        return (struct.unpack_from("<H", value)[0]
                if len(value) >= 2 else None), None
    result = struct.unpack_from("<H", value, 0)[0]
    srate, abr = struct.unpack_from("<II", value, 4)
    fmt = {"sample_rate": srate, "audio_bitrate": abr,
           "hex": value[:24].hex()}
    if len(value) >= 14:
        fmt["wave_format"] = struct.unpack_from("<H", value, 12)[0]
    if len(value) >= 22:
        chn, balign, bps, finterval = struct.unpack_from(
            "<HHHH", value, 14)
        fmt.update({"channels": chn, "block_align": balign,
                    "bits_per_sample": bps, "frame_interval": finterval})
    return result, fmt


def build_time_sync_req(when=None) -> bytes:
    """TLV 1007 TimeSyncRequest — 32 байта, все u32 LE (_TLV_V_TIMESYNREQ_NEW).

    Как в приложении (DeviceRemoteSettingActivity.configTimeSync →
    createTimeSyncRequestPack): локальное время + зона в МИНУТАХ
    (UTC+3 → 180); m_microsecond на деле — миллисекунды.
    Для старых прошивок (< 5.0) есть другой формат (_TLV_V_TIMESYNREQ) —
    не реализуем, прошивка панели 5.0.
    """
    t = when or time.localtime()
    gmtoff = getattr(t, "tm_gmtoff", None)
    if gmtoff is None:  # платформы без tm_gmtoff
        gmtoff = -time.timezone
        if time.daylight and t.tm_isdst:
            gmtoff = -time.altzone
    zone_min = gmtoff // 60            # секунды → минуты (UTC+3 → 180)
    ms = int(time.time() * 1000) % 1000
    return struct.pack("<8I", zone_min & 0xFFFFFFFF, ms,
                       t.tm_year, t.tm_mon, t.tm_mday,
                       t.tm_hour, t.tm_min, t.tm_sec)


def parse_stream_format(data: bytes):
    """TLV 203/199/200 → dict с параметрами потока (поля little-endian)."""
    if len(data) < 40:
        return None
    vch, ach, dtype, _res, codec, vbr, width, height = \
        struct.unpack_from("<BBBBIIHH", data, 0)
    framerate = data[16]
    srate, abr, wfmt, chnum, _ba, _bps, _afi, _ar = \
        struct.unpack_from("<IIHHHHHH", data, 20)
    return {
        "video_channel": vch, "audio_channel": ach, "codec_id": codec,
        "width": width, "height": height, "framerate": framerate,
        "sample_rate": srate, "wave_format": wfmt, "channels": chnum,
        "video_bitrate": vbr, "audio_bitrate": abr, "data_type": dtype,
    }


def parse_device_info(data: bytes):
    """TLV 70 (DeviceInfo, 72 байта) → dict; интересует channleNumber.

    Раскладка (по TLV_V_DeviceInfo.deserialize): company[16], equipment[16],
    name[16], version[16], year u16, month u8, day u8, channleNumber u8,
    alarmType u8, deviceType u8, reserve u8.
    """
    if len(data) < 69:
        return None
    company = data[0:16].split(b"\x00")[0].decode("latin-1", "replace")
    equip_id = data[16:32].split(b"\x00")[0].decode("latin-1", "replace")
    name = data[32:48].split(b"\x00")[0].decode("latin-1", "replace")
    return {
        "company": company, "equipment_id": equip_id, "name": name,
        "channel_number": data[68],
        "device_type": data[70] if len(data) > 70 else 0,
    }


# ---------------------------------------------------------------------------
# H.264 утилиты
# ---------------------------------------------------------------------------

_START_CODE_RE = re.compile(rb"\x00\x00\x00\x01|\x00\x00\x01")


def iter_nals(frame: bytes):
    """Разбить Annex-B кадр на NAL-юниты (без start-кодов)."""
    return [n for n in _START_CODE_RE.split(frame) if n]


# ---------------------------------------------------------------------------
# OWSP-клиент: одно подключение к домофону, fan-out подписчикам
# ---------------------------------------------------------------------------

class Subscriber:
    """Очередь кадров для одной RTSP-сессии; до первого IDR видео не отдаётся."""

    def __init__(self, maxsize=600):
        self.q = queue.Queue(maxsize=maxsize)
        self.seen_idr = False

    def push_video(self, frame: bytes, is_idr: bool):
        if is_idr:
            self.seen_idr = True
        elif not self.seen_idr:
            return
        self._put(("video", frame))

    def push_audio(self, data: bytes):
        if self.seen_idr:  # аудио имеет смысл только вместе с видео
            self._put(("audio", data))

    def _put(self, item):
        try:
            self.q.put_nowait(item)
        except queue.Full:
            try:
                self.q.get_nowait()  # отбросить самый старый
                self.q.put_nowait(item)
            except (queue.Empty, queue.Full):
                pass

    def get(self, timeout=1.0):
        return self.q.get(timeout=timeout)

    def notify_disconnect(self):
        self.seen_idr = False
        self._put(("reset", None))


# ---------------------------------------------------------------------------
# Детектор звонка по аудио (частотно-агностичный)
# ---------------------------------------------------------------------------

def _build_ulaw_linear():
    """Таблица декодирования G.711 µ-law → linear (CCITT G.711, 256 входов).

    Референс (ulaw2linear): байт инвертируется (~), затем
    t = (mant << 3) + 0x84; value = (t << seg) - 0x84, где
    seg = (u & 0x70) >> 4 (0..7); знак — из бита 7 u.
    Оба «нулевых» кода 0x7F и 0xFF декодируются в 0, максимум ±32124.
    """
    table = []
    for i in range(256):
        u = (~i) & 0xFF
        seg = (u & 0x70) >> 4
        t = ((u & 0x0F) << 3) + 0x84
        v = (t << seg) - 0x84
        table.append(-v if (u & 0x80) else v)
    return tuple(table)


ULAW_LINEAR = _build_ulaw_linear()


def _build_ulaw_encode():
    """Обратная таблица linear → µ-law (65536 входов, точная инверсия
    декодера: каждому линейному — код с БЛИЖАЙШИМ декод-значением).

    Нужна только для --talk-gain-shift: декод чанка → сдвиг (как
    calc1 «>>2» в приложении — эхо-защита) → повторное кодирование.
    Отрицательная ветка зеркальна положительной: код(-x) = код(|x|)^0x80.
    """
    pos = sorted((ULAW_LINEAR[c], c) for c in range(0x80, 0x100))
    vals = [v for v, _ in pos]

    def best(m):
        i = bisect.bisect_left(vals, m)
        cand = []
        if i < len(vals):
            cand.append((abs(vals[i] - m), pos[i][1]))
        if i > 0:
            cand.append((abs(vals[i - 1] - m), pos[i - 1][1]))
        return min(cand)[1] if cand else pos[-1][1]

    tbl = bytearray(65536)
    for m in range(32768):
        c = best(m)
        tbl[32768 + m] = c            # x=+m
        tbl[32768 - m] = c ^ 0x80     # x=−m (m=0 — общий индекс нуля)
    return bytes(tbl)


ULAW_ENCODE = _build_ulaw_encode()


def ulaw_gain_shift(data: bytes, shift: int) -> bytes:
    """Сдвиг усиления µ-law-чанка: shift>0 — тише (app: >>2), <0 — громче."""
    if not shift:
        return bytes(data)
    out = bytearray(len(data))
    enc, dec = ULAW_ENCODE, ULAW_LINEAR
    for i, b in enumerate(data):
        out[i] = enc[((dec[b] >> shift) + 32768) & 0xFFFF]
    return bytes(out)


class RingDetector:
    """Детектор звонка по G.711-аудио панели (микрофон слышит рингтон).

    Валидирован на дампах tyk.pcap (звонок) и nop.pcap (фон):
    - протокольного события вызова в OWSP нет (только медиа-TLV),
      UDP-активности нет — единственный след звонка это гудок;
    - гудок: чистый синус ~500 Гц, +18..+55 дБ над фоном; фон без
      звонка плоский (±1 дБ) — но тихий шум после µ-law-квантования
      «тонален» (R до 17), поэтому главный дискриминатор — МОЩНОСТЬ,
      а тональность защищает от громких широкополосных всплесков.

    Алгоритм на каждое окно 100 мс (800 сэмплов @ 8 кГц):
    1. декод µ-law, вычет среднего (DC);
    2. мощность P; базлайн — EMA «тихих» окон (не активных);
    3. если P > базлайн × 10^(gain_db/10) — Goertzel по сетке
       freq_min..freq_max (шаг freq_step): f0 и тональность
       R = P(f0)/P_total; окно «тоновое», если R >= min_tonality
       (реальный гудок даёт R 39..52; громкий белый шум — максимум
       сетки ~4, речь ещё ниже — порог 8 по умолчанию);
    4. ring_start: start_windows тоновых окон подряд (300 мс при 3);
       ring_end: end_silence_s подряд нетоновых окон (паузы
       огибающей рингтона короче — не рвут активное состояние).

    Схема не привязана к частоте (любой чистый синус в сетке) и к
    последовательности звуков (только мощность/тональность/длительность).
    """

    SAMPLE_RATE = 8000
    WIN = 800                    # 100 мс

    def __init__(self, on_start, on_end, gain_db=10.0, min_tonality=8.0,
                 start_windows=3, end_silence_s=1.0,
                 freq_min=300, freq_max=2600, freq_step=50, warmup_s=0.0):
        self.on_start = on_start
        self.on_end = on_end
        self.gain_db = float(gain_db)
        self.min_tonality = float(min_tonality)
        self.start_windows = max(1, int(start_windows))
        self.end_silence_s = max(0.2, float(end_silence_s))
        self.warmup_s = max(0.0, float(warmup_s))
        self.win_s = self.WIN / float(self.SAMPLE_RATE)
        self._gate = 10.0 ** (self.gain_db / 10.0)
        grid = list(range(int(freq_min), int(freq_max) + 1, int(freq_step)))
        self._grid = grid or [int(freq_min)]
        self._coeffs = [2.0 * math.cos(2.0 * math.pi * f / self.SAMPLE_RATE)
                        for f in self._grid]
        self._alpha = 0.05        # EMA базлайна (постоянная ~2 с)
        self._buf = bytearray()
        # состояние
        self._baseline = None      # EMA мощности фона
        self._active = False
        self._run = 0             # подряд тоновых окон
        self._quiet = 0.0         # секунд тишины в активном состоянии
        self._f0 = None
        self._peak_db = 0.0
        self._active_wins = 0      # окон в активном состоянии (длительность
                                   # по сэмплам — верно и для оффлайн-прогона)
        self._warmup_left = self.warmup_s   # сек до готовности (rearm)

    # -- публичное ----------------------------------------------------------

    def feed(self, data: bytes):
        """Порция сырого µ-law из TLV 98 (любой кратности)."""
        self._buf += data
        n = self.WIN
        while len(self._buf) >= n:
            self._process(bytes(self._buf[:n]))
            del self._buf[:n]

    @property
    def active(self):
        return self._active

    def rearm(self):
        """Перезапустить прогрев (вызывается OwspClient на каждом старте
        сессии): первые warmup_s секунд аудио детектор учит базлайн, но
        НЕ стреляет — стартовая транзиентка аудиотракта давала ложные
        ring start (наблюдение 31.10: 450 Гц/+18.6 дБ на старте, end не
        пришёл — аудио замолчало; на следующем рестарте не повторилось —
        транзиентка интермиттящая)."""
        self._warmup_left = self.warmup_s
        self._run = 0

    # -- внутреннее ---------------------------------------------------------

    def _process(self, win: bytes):
        lin = [ULAW_LINEAR[b] for b in win]
        n = len(lin)
        mean = sum(lin) / n
        p = 0.0
        for x in lin:
            d = x - mean
            p += d * d
        p /= n
        if p <= 0.0:
            self._advance(False, None, 0.0)
            return
        if self._baseline is None:
            self._baseline = p
        elif p < self._baseline * 0.01:
            # мощность резко ниже базлайна — он устарел (например, шлюз
            # стартовал СЕРЕДИНА звонка и первый громкий окно попало в
            # базлайн): снап вниз, иначе EMA спускалась бы ~десятки секунд
            self._baseline = p
        if p <= self._baseline * self._gate:
            # тихое окно: обновляем базлайн, тон не ищем (экономия CPU —
            # сетка Goertzel считается только для громких окон)
            self._baseline += self._alpha * (p - self._baseline)
            self._advance(False, None, 0.0)
            return
        f0, pf, r = self._scan_tone(lin, mean, p)
        db = 10.0 * math.log10(p / self._baseline) if self._baseline else 0.0
        self._advance(r >= self.min_tonality, f0, db)

    def _scan_tone(self, lin, mean, p):
        """Goertzel по сетке: (f0, P(f0), R)."""
        s = [x - mean for x in lin]
        n = len(s)
        total = p * n
        best_p, best_f = 0.0, None
        for f, c in zip(self._grid, self._coeffs):
            s1 = s2 = 0.0
            for x in s:
                s0 = x + c * s1 - s2
                s2 = s1
                s1 = s0
            pw = s1 * s1 + s2 * s2 - c * s1 * s2
            if pw > best_p:
                best_p, best_f = pw, f
        if best_f is None or total <= 0:
            return None, 0.0, 0.0
        return best_f, best_p, best_p / total

    def _advance(self, tonal, f0, db):
        if self._warmup_left > 0:
            # прогрев: базлайн уже обновлён в _process (тихие окна),
            # события не стреляем и серию тоновых окон не копим
            self._warmup_left -= self.win_s
            self._run = 0
            return
        if self._active:
            self._active_wins += 1
            if tonal:
                self._quiet = 0.0
                if f0:
                    self._f0 = f0
                self._peak_db = max(self._peak_db, db)
            else:
                self._quiet += self.win_s
                if self._quiet >= self.end_silence_s:
                    self._active = False
                    info = {"freq": self._f0,
                            "gain_db": round(self._peak_db, 1),
                            "duration_s": round(self._active_wins * self.win_s, 1)}
                    self._peak_db = 0.0
                    try:
                        self.on_end(info)
                    except Exception:  # noqa: BLE001
                        pass
            return
        if tonal:
            self._run += 1
            if f0:
                self._f0 = f0
            self._peak_db = max(self._peak_db, db)
            if self._run >= self.start_windows:
                self._active = True
                self._quiet = 0.0
                self._active_wins = 0
                info = {"freq": self._f0, "gain_db": round(self._peak_db, 1)}
                try:
                    self.on_start(info)
                except Exception:  # noqa: BLE001
                    pass
        else:
            self._run = 0


class OwspClient(threading.Thread):
    """Поддерживает единственное TCP-подключение к домофону для ОДНОГО канала
    (как в оригинальном приложении: каждое окно 4-экранного обзора — своё
    соединение с маской своего канала) и раздаёт H.264-кадры / G.711a-аудио
    подписчикам (RTSP-сессиям)."""

    def __init__(self, host, port, user, password, channel=1, sub_stream=False,
                 data_type=2, reconnect_delay=3.0, on_log=None,
                 on_info=None, new_proto_first=True, keepalive_interval=0.0,
                 send_tlv44=False, send_tlv427=False, recycle_secs=0.0,
                 send_audio_ack=False, idle_timeout=15.0,
                 on_dump=None, on_event=None, ring_cfg=None,
                 mute_local_steps=0):
        super().__init__(name="owsp-ch%d" % channel, daemon=True)
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.channel = channel
        self.stream_mode = 1 if sub_stream else 0
        self.keepalive_interval = keepalive_interval
        self.send_tlv44 = send_tlv44      # TLV 44 StreamDataRequest после логина
        self.send_tlv427 = send_tlv427    # TLV 427 AudioRequest (вкл. аудиотракт)
        self.send_audio_ack = send_audio_ack  # ACK аудио-меток TLV 97 (не нужен!)
        self.recycle_secs = recycle_secs  # плановый перезапуск сессии, сек (0=выкл)
        self.idle_timeout = idle_timeout  # сторож простоя: нет данных N сек → реконнект
        self._dump_hook = on_dump        # отладочный дамп протокола
        self.data_type = data_type
        self.reconnect_delay = reconnect_delay
        self.on_info = on_info            # callback: dict от TLV 70
        self._log = on_log or (lambda msg: print(msg, flush=True))
        self.log = lambda msg: self._log("[канал %d] %s" % (channel, msg))

        self._lock = threading.Lock()
        self._subscribers = []          # list[Subscriber]
        self._stop = threading.Event()
        self._sock = None
        self._seq = 1
        self._use_new_proto = new_proto_first  # авто-переговоры версии прошивки

        # состояние потока
        self.format = None              # dict от TLV 203
        self.sps = None                 # bytes, последний SPS (без start-кода)
        self.pps = None                 # bytes, последний PPS
        self.frame_count = 0
        self.audio_bytes = 0
        self.connected = threading.Event()
        self.login_ok = threading.Event()
        self.login_error = None
        self.record_file = None         # опциональный дамп H.264
        self.last_used = time.monotonic()
        # статистика текущей сессии (для диагностики обрывов)
        self._t0 = None
        self._bytes_in = 0
        self._pkts_in = 0
        self.sess_frames = 0
        self._info_logged = False  # не спамить логом TLV 70 при реконнектах
        self._fmt_logged = False
        self._desync_skipped = 0   # байт мусора, пропущено парсером за сессию
        self._desync_events = 0    # событий мусора за сессию (для rate-limit лога)
        self._last_rx = 0.0        # время последнего чанка от устройства
        self._last_login_code = None  # код последнего отказа логина (TLV 42)
        self._fail_streak = 0      # подряд неудачных попыток (для backoff)
        self.sess_gen = 0           # поколение OWSP-сессии (+1 на каждый
        # реконнект): TalkSession отслеживает, чтобы после смерти сессии
        # НЕ лить 97/98 без свежего 331 (прошивка рвёт соединение —
        # инцидент 31.10: при 2way канал «не поднимался», пока активен
        # микрофон)
        # команды из других потоков (HTTP-контроль/CLI/MQTT): пакеты
        # кладутся в очередь и отправляются циклом сессии — единственный
        # писатель в сокет, никакой гонки с реконнектом
        self._send_q = queue.Queue()
        self._seq_lock = threading.Lock()
        self._lock_evt = threading.Event()
        self._lock_result = None
        self.on_event = on_event          # callback(kind, detail) шины событий
        # монитор небазовых TLV: тип → [время последней посылки события,
        # счётчик скоалесированных повторов]
        self._tlv_evt = {}
        # громкость локального динамика (TLV 1054/1055): как замок —
        # команда в очередь, ответ ждём в объём() пошагово
        self.mute_local_steps = max(0, int(mute_local_steps))
        self._vol_lock = threading.Lock()
        self._vol_evt = threading.Event()
        self._vol_results = []
        # громкая связь (TLV 331/332): как замок — команда в очередь,
        # ответ 332 (result + формат аудио) выставляет событие
        self._talk_evt = threading.Event()
        self._talk_result = None
        self.talk_format = None
        # детектор звонка по аудио (TLV 98 → RingDetector)
        self._ring = None
        if ring_cfg:
            self._ring = RingDetector(
                on_start=lambda info: self._emit_ring("start", info),
                on_end=lambda info: self._emit_ring("end", info),
                **dict(ring_cfg))

    def _dump(self, line):
        if self._dump_hook:
            try:
                self._dump_hook(line)
            except Exception:  # noqa: BLE001
                pass

    def _dump_packet(self, tlvs):
        if not self._dump_hook:
            return
        parts = []
        for t, v in tlvs:
            if t in (100, 101):
                parts.append("%d[%d] %s" % (t, len(v), v[:8].hex()))
            elif t == 98:
                parts.append("98[%d] %s.." % (len(v), v[:6].hex()))
            else:
                parts.append("%d[%d] %s" % (t, len(v), v[:32].hex()))
        self._dump("PKT tlvs=%s" % " ".join(parts))

    # -- публичное ----------------------------------------------------------

    def subscribe(self):
        sub = Subscriber()
        with self._lock:
            self._subscribers.append(sub)
        self.last_used = time.monotonic()
        return sub

    def unsubscribe(self, sub):
        with self._lock:
            if sub in self._subscribers:
                self._subscribers.remove(sub)
        self.last_used = time.monotonic()

    def subscriber_count(self):
        with self._lock:
            return len(self._subscribers)

    def wait_ready(self, timeout=15.0):
        """Дождаться логина и первого I-кадра (SPS/PPS)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self._stop.is_set():
            if self.login_error:
                return False
            if self.login_ok.is_set() and self.sps:
                return True
            time.sleep(0.1)
        return self.login_ok.is_set() and self.sps is not None

    def wait_login(self, timeout=8.0):
        """Дождаться подтверждения логина (без ожидания I-кадра)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self._stop.is_set():
            if self.login_error:
                return False
            if self.login_ok.is_set():
                return True
            time.sleep(0.05)
        return self.login_ok.is_set()

    def lock(self, lock_password, action=1, delay=1, timeout=5.0):
        """Команда замка (TLV 425) через активную сессию канала.

        Как в приложении (MainActivity → EyeVideoView.remoteLock →
        EyeSourceTransNet.remoteLock): команда идёт в РАБОТАЮЩУЮ
        стрим-сессию, а не в отдельное settings-соединение. Ответ
        TLV 426 (result u16, 1 = успех) ожидается в потоке этой же
        сессии. Возвращает (ok, сообщение).
        """
        if not self.login_ok.is_set():
            return False, "сессия канала %d не активна (нет логина)" \
                % self.channel
        self._lock_result = None
        self._lock_evt.clear()
        payload = build_lock_req(lock_password or self.password,
                                 self.channel, action, delay)
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._send_q.put(owsp_packet([(TLV_LOCK_REQ, payload)], seq))
        self._dump("SEND TLV425 lock action=%d delay=%d" % (action, delay))
        if not self._lock_evt.wait(timeout):
            return False, ("нет ответа TLV 426 за %.0f с — прошивка не "
                           "поддерживает замок или сессия умерла" % timeout)
        if self._lock_result == 1:
            return True, "замок: команда принята (TLV 426 result=1)"
        return False, "замок: отказ (TLV 426 result=%s)" % self._lock_result

    def volume(self, direction="down", steps=1, timeout=3.0):
        """Громкость ЛОКАЛЬНОГО динамика панели (TLV 1054/1055).

        Как кнопки громкости в приложении: команда в РАБОЧУЮ
        стрим-сессию. Шаги отправляются последовательно — каждый ждёт
        свой TLV 1055 (result u16, 1 = успех), как одиночное нажатие
        кнопки. Возвращает (ok, сообщение).
        """
        if not self.login_ok.is_set():
            return False, "сессия канала %d не активна (нет логина)" \
                % self.channel
        d = str(direction).strip().lower()
        action = 1 if d in ("up", "+", "1", "louder", "vol_up") else 0
        steps = max(1, min(int(steps), 30))
        results = []
        for i in range(steps):
            with self._vol_lock:
                self._vol_results = []
            self._vol_evt.clear()
            with self._seq_lock:
                self._seq += 1
                seq = self._seq
            self._send_q.put(owsp_packet(
                [(TLV_VOLUME_REQ, build_volume_req(action))], seq))
            self._dump("SEND TLV1054 volume %s (шаг %d/%d)"
                       % ("up" if action else "down", i + 1, steps))
            if not self._vol_evt.wait(timeout):
                return False, ("нет ответа TLV 1055 (шаг %d/%d) — прошивка "
                               "не поддерживает громкость или сессия умерла"
                               % (i + 1, steps))
            with self._vol_lock:
                results += self._vol_results
        ok = all(r == 1 for r in results) and bool(results)
        word = "громче" if action else "тише"
        return ok, "громкость %s ×%d: %s (TLV 1055 result=%s)" % (
            word, steps, "принято" if ok else "отказ", results)

    def talk_start(self, timeout=5.0):
        """Начать громкую связь (TLV 331 action=1) — как кнопка «говорить»
        в приложении (setTalk(true)). Ответ TLV 332: result=1 + формат
        аудио talk-канала (логируется). Возвращает (ok, msg)."""
        if not self.login_ok.is_set():
            return False, "сессия канала %d не активна (нет логина)" \
                % self.channel
        self._talk_result = None
        self._talk_evt.clear()
        self._talk_fmt_logged = False
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._send_q.put(owsp_packet(
            [(TLV_TALK_REQ, build_talk_req(self.channel, 1))], seq))
        self._dump("SEND TLV331 talk-start chn=%d" % self.channel)
        if not self._talk_evt.wait(timeout):
            return False, ("нет ответа TLV 332 за %.0f с — прошивка не "
                           "поддерживает talk или сессия умерла" % timeout)
        if self._talk_result == 1:
            return True, "talk: начат (TLV 332 result=1)"
        if self._talk_result == 23:
            # железо 31.10 21:35/22:08: слот talk у панели ОДИН на все
            # панели — соседний разговор заканчивается, ретрай подхватит
            return False, ("talk: отказ (TLV 332 result=23 — занято; "
                           "возможно, идёт разговор с другой панели)")
        return False, "talk: отказ (TLV 332 result=%s)" % self._talk_result

    def talk_stop(self, timeout=1.5):
        """Закончить громкую связь (TLV 331 action=2). Ответ 332 не
        обязателен (приложение его не ждёт) — таймаут не ошибка."""
        if not self.login_ok.is_set():
            return False, "сессия канала %d не активна" % self.channel
        self._talk_evt.clear()
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._send_q.put(owsp_packet(
            [(TLV_TALK_REQ, build_talk_req(self.channel, 2))], seq))
        self._dump("SEND TLV331 talk-stop chn=%d" % self.channel)
        self._talk_evt.wait(timeout)
        return True, "talk: остановлен (TLV 331 action=2 отправлен)"

    def talk_send_audio(self, chunk: bytes):
        """Чанк µ-law (320 Б = 40 мс) вверх в панель — через _send_q
        (цикл сессии — единственный писатель в сокет). Пейсер задаёт
        TalkSession; здесь только упаковка AudioInfoRequestPack."""
        if not self.login_ok.is_set() or not chunk:
            return False
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._send_q.put(owsp_packet(
            build_talk_audio(self.channel, chunk), seq))
        return True

    def _emit_ring(self, state, info):
        """Событие ring-детектора → шина событий Gateway (дедуп там)."""
        d = {"channel": self.channel, "state": state}
        d.update(info or {})
        if self.on_event:
            try:
                self.on_event("ring", d)
            except Exception:  # noqa: BLE001
                pass

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    # -- поток --------------------------------------------------------------

    def run(self):
        while not self._stop.is_set():
            try:
                self._session()
            except Exception as exc:  # noqa: BLE001
                if not self._stop.is_set():
                    if self._t0 is not None:
                        age = "%.1f с" % (time.monotonic() - self._t0)
                    else:
                        age = "— (логин не выполнен)"
                    self.log("ошибка: %r — сессия жила %s, кадров %d, "
                             "пакетов %d, байт %d, мусора %d"
                             % (exc, age, self.sess_frames, self._pkts_in,
                                self._bytes_in, self._desync_skipped))
            # backoff: если логин не удаётся подряд, не долбим устройство
            # каждые 3 с часами (код 2/5 после сбоя прошивки) — растим паузу.
            # Сессия БЕЗ единого кадра («тишина» после логина) тоже считается
            # неудачей: такие сессии копятся на устройстве и приводят к
            # коду 5 (лимит подключений) — им тоже нужен backoff.
            if self._t0 is not None and self.sess_frames > 0:
                self._fail_streak = 0
            else:
                self._fail_streak += 1
            self.connected.clear()
            self.login_ok.clear()
            for sub in list(self._subscribers):
                sub.notify_disconnect()
            if self._stop.is_set():
                break
            delay = self.reconnect_delay
            if self._fail_streak > 1:
                delay = min(60.0, self.reconnect_delay * (2 ** (self._fail_streak - 1)))
                self.log("попытка %d не удалась — следующая через %.0f с"
                         % (self._fail_streak, delay))
            time.sleep(delay)
        self.log("остановлен")

    def _session(self):
        # поколение сессии: TalkSession по нему понимает, что панель
        # потеряла talk-контекст (реконнект), и делает свежий 331
        self.sess_gen += 1
        # выкидываем остатки очереди мёртвой сессии: висящие talk-чанки
        # 97/98 иначе уйдут в НОВУЮ сессию раньше свежего 331 — прошивка
        # рвёт соединение (поймано фазой 6 itest11)
        while True:
            try:
                self._send_q.get_nowait()
            except queue.Empty:
                break
        # статистику сбрасываем ДО логина: неудачная попытка не должна
        # показывать цифры прошлой сессии
        self._t0 = None
        self._bytes_in = 0
        self._pkts_in = 0
        self.sess_frames = 0
        self._desync_skipped = 0
        self._desync_events = 0
        self._tlv_evt.clear()
        self.log("подключение к %s:%d ..." % (self.host, self.port))
        sock = socket.create_connection((self.host, self.port), timeout=10)
        self._sock = sock
        sock.settimeout(15)
        self.connected.set()

        # 1) логин (новый → при версии прошивки <5.0 повтор старым)
        ok, leftover = self._login(sock)
        if not ok:
            code = self._last_login_code
            self.login_error = ("логин отклонён (код=%s)" % code)
            if code == 2:
                self.login_error += (" — устройство считает пароль неверным. "
                                    "Если пароль не менялся, это сбой прошивки: "
                                    "перезагрузите домофон питанием "
                                    "(наблюдалось после ~10 ч uptime)")
            elif code == 5:
                self.login_error += (" — превышен лимит подключений "
                                     "(закройте мобильное приложение)")
            self.log(self.login_error)
            raise ConnectionError("login failed")
        # _login мог переподключиться при fallback на старую прошивку
        sock = self._sock

        # 2) пост-логинные пакеты: keep-alive (TLV 49), включение аудиотракта
        #    (TLV 427) и опционально явный запрос потока (TLV 44)
        try:
            self._post_login_sends(sock)
        except OSError:
            pass
        last_ka = time.monotonic()

        # статистика сессии
        self._t0 = time.monotonic()
        self._last_rx = self._t0
        self._dump("SESSION start ch=%d" % self.channel)

        self.log("стрим запущен")
        if self._ring is not None:
            self._ring.rearm()   # прогрев детектора на каждой сессии
        buf = leftover  # непарсированный остаток от этапа логина
        # короткий таймаут: цикл просыпается хотя бы раз в секунду и шлёт
        # keep-alive по расписанию (даже при непрерывном потоке кадров)
        sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                chunk = None
            if chunk == b"":
                raise ConnectionError("домофон закрыл соединение")
            if chunk:
                self._last_rx = time.monotonic()
                buf += chunk
                self._bytes_in += len(chunk)
                try:
                    packets, buf = parse_owsp_packets(buf)
                except ValueError as exc:
                    # Как приложение (ParserState.ParserStateErrDate): при
                    # мусоре в начале буфера данные отбрасываются и сессия
                    # ПРОДОЛЖАЕТСЯ. Но в отличие от приложения мы пытаемся
                    # выровняться на границу следующего пакета по маркеру
                    # TLV 99: без этого следующий recv начнётся с середины
                    # кадра и мусор станет бесконечным (каскад десинка).
                    start = resync_owsp(buf)
                    head = buf[:64].hex()
                    if start is not None:
                        skipped = start
                        buf = buf[start:]
                        self._dump("DESYNC %r; resync +%d B; next=%s"
                                   % (exc, skipped, buf[:64].hex()))
                    else:
                        skipped = len(buf)
                        buf = b""
                        self._dump("DESYNC %r; dropped %d B; head=%s"
                                   % (exc, skipped, head))
                    self._desync_skipped += skipped
                    self._desync_events += 1
                    if self._desync_events <= 3 or self._desync_events % 20 == 0:
                        self.log("мусор протокола: событие %d, пропущено %d байт"
                                 " (всего за сессию %d)"
                                 % (self._desync_events, skipped,
                                    self._desync_skipped))
                    packets = []
                for tlvs in packets:
                    self._pkts_in += 1
                    self._dump_packet(tlvs)
                    self._handle_tlvs(tlvs)
                    # ACK аудио-меток устройства — только по явному флагу
                    # (референсное приложение их НЕ отправляет, и они не нужны)
                    ack_t = self._audio_ack_time(tlvs)
                    if ack_t is not None and self.send_audio_ack:
                        self._send_audio_ack(sock, ack_t)
            # исходящие команды (замок TLV 425, talk-чанки 97/98) из
            # других потоков: отправляет цикл сессии — единственный
            # писатель в сокет. Таймаут отправки 10 с, а не 1 с чтения:
            # медленный приём панели во время 2way не должен рвать
            # сессию по socket.timeout (sendall наследует settimeout)
            try:
                sock.settimeout(10.0)
                while True:
                    pkt = self._send_q.get_nowait()
                    sock.sendall(pkt)
            except queue.Empty:
                pass
            finally:
                sock.settimeout(1.0)
            now = time.monotonic()
            # сторож простоя («зомби»-сессия): TCP жив, но прошивка молчит —
            # без FIN/RST обычный реконнект никогда не случится, поэтому
            # закрываем соединение сами (замечено на STM83xx: канал
            # подвисает, пока соседние каналы продолжают стримить)
            if (self.idle_timeout > 0
                    and now - self._last_rx > self.idle_timeout):
                raise ConnectionError(
                    "нет данных от устройства %.0f с (мёртвая сессия) — "
                    "переподключение" % (now - self._last_rx))
            if (self.keepalive_interval > 0
                    and now - last_ka >= self.keepalive_interval):
                self._seq += 1
                sock.sendall(owsp_packet([(TLV_KEEPALIVE, b"")], self._seq))
                last_ka = now
                self._dump("SEND TLV49 keepalive")

            if (self.recycle_secs > 0 and self._t0
                    and now - self._t0 >= self.recycle_secs):
                raise ConnectionError("запланированный перезапуск сессии")

    def _login(self, sock):
        """Отправить логин и дождаться ответа. При версии прошивки < 5.0
        автоматически переподключается старым логином (как в приложении).

        Возвращает (ok, leftover) — leftover это непарсированный остаток
        буфера (начало потока), который _session обязан подхватить, иначе
        парсинг начнётся с середины кадра → рассинхрон.

        ВАЖНО (баг 28.10): на одном соединении шлём РОВНО ОДИН логин.
        Прежний код при медленном устройстве (версия и код ответа приходят
        разными TCP-сегментами) успевал отправить второй логин в тот же
        сокет: прошивка поднимала сессию по первому логину, получала второй
        и сессия рождалась «битой» — либо тишина по данным (каналы
        отваливались по сторожу простоя), либо мусор в потоке (каскад
        десинка, картинка рассыпается). Второй вариант логина — только на
        СВЕЖЕМ сокете.
        """
        tried = set()
        while not self._stop.is_set():
            attempt_new = self._use_new_proto
            tried.add(attempt_new)
            version, result, leftover = self._login_attempt(sock, attempt_new)
            if version is not None:
                self.log("прошивка OWSP %d.%d" % (version // 10, version % 10))
                if version < 50 and attempt_new:
                    self._use_new_proto = False
                    self.log("прошивка < 5.0 — переключение на старый логин")
                    sock = self._reconnect_login_socket(sock)
                    continue
            if result == 1:
                self._use_new_proto = attempt_new
                self._last_login_code = None
                self.login_ok.set()
                self.login_error = None
                return True, leftover
            if result is not None:
                # запоминаем код отказа; пробуем ДРУГОЙ вариант логина —
                # после сбоя прошивка может начать парсить старый формат
                # (сдвиг поля password на 1 байт → код 2 «неверный пароль»)
                self._last_login_code = result
                self.log("логин отклонён, код=%d (вариант %s)"
                         % (result, "новый" if attempt_new else "старый"))
                other = not attempt_new
                if other in tried:
                    return False, b""
                self._use_new_proto = other
                sock = self._reconnect_login_socket(sock)
                continue
            # нет ответа за отведённое время — пусть reconnect-цикл повторит
            return False, b""
        return False, b""

    def _reconnect_login_socket(self, sock):
        """Закрыть сокет и открыть свежий для повторной попытки логина."""
        try:
            sock.close()
        except OSError:
            pass
        sock2 = socket.create_connection((self.host, self.port), timeout=10)
        self._sock = sock2
        sock2.settimeout(15)
        return sock2

    def _login_attempt(self, sock, attempt_new):
        """Одна попытка логина в СВОЁМ соединении. Возвращает
        (version, result, leftover). Дожидается именно ответа логина
        (result), а не только эха версии — иначе на медленном устройстве
        возможна гонка и двойной логин в один сокет."""
        pkt = build_login(self.user, self.password, self.channel,
                          self.stream_mode, self.data_type, attempt_new)
        sock.sendall(pkt)

        version = None
        result = None
        deadline = time.monotonic() + 6.0
        buf = b""
        while time.monotonic() < deadline and result is None:
            if version is not None and attempt_new and version < 50:
                # старая прошивка: нового ответа логина не будет,
                # переключаемся на старый формат немедленно
                break
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                raise ConnectionError("сокет закрыт при логине")
            buf += chunk
            packets, buf = parse_owsp_packets(buf)
            for tlvs in packets:
                for tlv_type, value in tlvs:
                    # STM83xx отвечает на версию ЭХОМ TLV 40 (не 39!)
                    if (tlv_type in (TLV_VERSION_RSP, TLV_VERSION_REQ)
                            and len(value) >= 4):
                        major, minor = struct.unpack_from("<HH", value)
                        version = major * 10 + minor
                    elif tlv_type == TLV_LOGIN_RSP and len(value) >= 2:
                        result = struct.unpack_from("<H", value)[0]
                    elif tlv_type == TLV_VIDEO_IFRAME:
                        # некоторые прошивки отвечают сразу потоком
                        result = 1
                # инфо об устройстве/канале и кадры, пришедшие до ответа на
                # логин, тоже обрабатываем (TLV 70, 203, 98, 99/100/101)
                self._handle_tlvs(tlvs)
                ack_t = self._audio_ack_time(tlvs)
                if ack_t is not None and self.send_audio_ack:
                    try:
                        self._send_audio_ack(sock, ack_t)
                    except OSError:
                        pass
        return version, result, buf

    def _post_login_sends(self, sock):
        """Пакеты сразу после успешного логина (используется и основным
        соединением, и ротацией). ВСЕ опциональны: референсное приложение
        после логина не отправляет НИЧЕГО — сессия живёт сама по себе.
        Флаги ниже — только для экспериментов с другими прошивками."""
        if self.keepalive_interval > 0:
            self._seq += 1
            sock.sendall(owsp_packet([(TLV_KEEPALIVE, b"")], self._seq))
        if self.send_tlv427:
            self._seq += 1
            sock.sendall(owsp_packet([(427, b"")], self._seq))
            self._dump("SEND TLV427 audio-request-on")
        if self.send_tlv44:
            self._seq += 1
            req = bytes([self.channel, self.channel]) + struct.pack("<H", 0)
            sock.sendall(owsp_packet([(44, req)], self._seq))
            self._dump("SEND TLV44 videoChannel=%d audioChannel=%d" %
                       (self.channel, self.channel))
        if self.mute_local_steps > 0:
            # глушение локального динамика: N × «громче/тише» (TLV 1054)
            # после КАЖДОГО логина — громкость может сбрасываться при
            # ежедневном ребуте устройства (~06:50); повторные «тише» от
            # нуля безвредны. Шаги с паузой — как одиночные нажатия.
            for _ in range(self.mute_local_steps):
                self._seq += 1
                sock.sendall(owsp_packet(
                    [(TLV_VOLUME_REQ, build_volume_req(0))], self._seq))
                time.sleep(0.15)
            self._dump("SEND TLV1054 volume-down ×%d (mute-local)"
                       % self.mute_local_steps)

    def _send_audio_ack(self, sock, time_ms):
        """ACK аудио-потока (TLV 97, аналог EyeProtocolPacker.AudioInfoPack).

        ВНИМАНИЕ: по референсному дампу рабочее приложение НЕ отправляет
        эти ACK — устройство 35+ секунд стримит аудио без единого пакета
        от клиента. Механизм оставлен только как экспериментальный флаг
        --audio-ack (например, для других прошивок платформы).
        """
        self._seq += 1
        ack = struct.pack("<BBHI", self.channel, 0, 0,
                          time_ms & 0xFFFFFFFF)
        sock.sendall(owsp_packet([(TLV_AUDIO_INFO, ack)], self._seq))

    @staticmethod
    def _audio_ack_time(tlvs, default=None):
        """Время для ACK: таймстамп TLV 97 + длина сопутствующего TLV 98."""
        ts = None
        chunk = 320
        for t, v in tlvs:
            if t == TLV_AUDIO_INFO and len(v) >= 8:
                ts = struct.unpack_from("<I", v, 4)[0]
            elif t == TLV_AUDIO_DATA and v:
                chunk = len(v)
        if ts is None:
            return default
        return ts + chunk

    # -- обработка потока ---------------------------------------------------

    def _handle_tlvs(self, tlvs):
        """Обработать TLV пакета.

        Базовые TLV стрима (хендшейк/медиа/формат) обрабатываются по
        назначению; ответы на наши команды (426/1055/1008) выставляют
        события. ВСЁ ОСТАЛЬНОЕ — монитор: событие «tlv» на каждое
        вхождение (лог + /events + MQTT), повторы в пределах секунды
        коалесируются в счётчик."""
        for tlv_type, value in tlvs:
            if tlv_type == TLV_DEVICE_INFO:
                info = parse_device_info(value)
                if info:
                    if not self._info_logged:
                        self._info_logged = True
                        self.log("устройство: %r (%r), каналов: %d"
                                 % (info["name"], info["company"],
                                    info["channel_number"]))
                    if self.on_info:
                        try:
                            self.on_info(info)
                        except Exception:  # noqa: BLE001
                            pass
            elif tlv_type in TLV_STREAM_FORMAT:
                fmt = parse_stream_format(value)
                if fmt:
                    self.format = fmt
                    if not self._fmt_logged:
                        self._fmt_logged = True
                        self.log("формат: %dx%d @%dfps, аудио %d Гц wave=0x%X"
                                 % (fmt["width"], fmt["height"], fmt["framerate"],
                                    fmt["sample_rate"], fmt["wave_format"]))
            elif tlv_type == TLV_LOCK_RSP and len(value) >= 2:
                # ответ замка (TLV 426): result u16 (1 = успех)
                self._lock_result = struct.unpack_from("<H", value)[0]
                self._lock_evt.set()
            elif tlv_type == TLV_VOLUME_RSP and len(value) >= 2:
                # ответ громкости (TLV 1055): result u16 (1 = успех)
                result = struct.unpack_from("<H", value)[0]
                with self._vol_lock:
                    self._vol_results.append(result)
                self._vol_evt.set()
                if result != 1:
                    self.log("TLV 1055 result=%d (отказ громкости)" % result)
            elif tlv_type == TLV_TALK_RSP and len(value) >= 2:
                # ответ talk (TLV 332, 24 Б): result u16 + формат аудио.
                # Приходит и на start, и на stop — формат логируем раз за
                # talk_start, сырой hex — для сверки раскладки на железе
                result, fmt = parse_talk_rsp(value)
                self._talk_result = result
                self.talk_format = fmt
                if (result == 1 and fmt
                        and not getattr(self, "_talk_fmt_logged", True)):
                    self._talk_fmt_logged = True
                    self.log("talk-формат: %d Гц, wave=0x%X, %d бит×%d, "
                             "кадр %d мс [332 hex=%s]"
                             % (fmt.get("sample_rate"),
                                fmt.get("wave_format", 0),
                                fmt.get("bits_per_sample", 0),
                                fmt.get("channels", 1),
                                fmt.get("frame_interval", 0),
                                fmt.get("hex", "")))
                self._talk_evt.set()
            elif tlv_type in (TLV_VIDEO_IFRAME, TLV_VIDEO_PFRAME):
                is_idr = tlv_type == TLV_VIDEO_IFRAME
                if is_idr:
                    self._extract_sps_pps(value)
                self.frame_count += 1
                self.sess_frames += 1
                if self.record_file is not None:
                    try:
                        self.record_file.write(value)
                    except OSError:
                        pass
                self._fanout_video(value, is_idr)
            elif tlv_type == TLV_AUDIO_DATA and value:
                self.audio_bytes += len(value)
                if self._ring is not None:
                    try:
                        self._ring.feed(value)
                    except Exception:  # noqa: BLE001
                        # детектор не должен ронять стрим-сессию
                        self._ring = None
                        self.log("ring-детектор отключён после ошибки")
                self._fanout_audio(value)
            elif tlv_type not in TLV_QUIET_TLVS:
                # всё, что не базовый стрим и не ответ на нашу команду:
                # потенциальное спонтанное событие прошивки (MD-аларм и
                # т.п.) — регистрируем КАЖДОЕ вхождение; повторы в пределах
                # секунды коалесируются (count)
                now = time.monotonic()
                ent = self._tlv_evt.get(tlv_type)
                if ent is None or now - ent[0] >= 1.0:
                    cnt = (ent[1] + 1) if ent else 1
                    self._tlv_evt[tlv_type] = [now, 0]
                    d = {"channel": self.channel, "type": tlv_type,
                         "len": len(value), "hex": value[:32].hex()}
                    if cnt > 1:
                        d["count"] = cnt
                    if self.on_event:
                        try:
                            self.on_event("tlv", d)
                        except Exception:  # noqa: BLE001
                            pass
                else:
                    ent[1] += 1

    def _extract_sps_pps(self, frame: bytes):
        for nal in iter_nals(frame):
            nal_type = nal[0] & 0x1F
            if nal_type == 7:
                self.sps = nal
            elif nal_type == 8:
                self.pps = nal

    def _fanout_video(self, frame: bytes, is_idr: bool):
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            sub.push_video(frame, is_idr)

    def _fanout_audio(self, data: bytes):
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            sub.push_audio(data)


# ---------------------------------------------------------------------------
# Gateway: по одному OwspClient на канал (как в оригинальном приложении)
# ---------------------------------------------------------------------------

class TalkSession:
    """Сессия громкой связи (talk): ингресс → динамик панели.

    Протокол (EyeSourceTransNet): TLV 331 action=1 → 332 result=1 →
    поток вверх каждые 40 мс: OWSP [TLV 97 (8 Б) + TLV 98 (320 Б µ-law)],
    стоп — TLV 331 action=2. Жизненный цикл как push-to-talk:

      - автостарт по ПЕРВОМУ аудио-пакету ингресса (не по факту
        подключения — пустое соединение не занимает talk-канал);
      - автостоп через silence_s тишины (ингресс пропал) — сессия
        перевзводится: новое аудио → новый 331/332;
      - stop() ингресса (HTTP-тело кончилось / RTSP-разрыв) — флаш
        остатка тем же пейсером, затем 331 action=2.

    Пейсер: один чанк 320 Б не чаще чем раз в 40 мс (как блокирующее
    чтение AudioRecord.read(320) в приложении); готовые OWSP-пакеты
    кладутся в _send_q клиента — цикл сессии единственный писатель.
    Эксклюзив на канал — второй ингресс получает «занято» (Gateway).
    """

    CHUNK = 320                  # сэмплов µ-law = 40 мс @ 8 кГц
    PERIOD = 0.04
    WATERMARK = 16384            # 2 с несент-аудио: выше — feed() ждёт

    def __init__(self, gateway, channel, silence_s=2.0, gain_shift=0,
                 autorelease=False):
        self.gateway = gateway
        self.channel = channel
        self.silence_s = max(0.5, float(silence_s))
        self.gain_shift = int(gain_shift)
        # RTSP-ингрессы (backchannel go2rtc, ffmpeg-микрофон): после
        # 2 с тишины слот панели ОСВОБОЖДАЕТСЯ (go2rtc держит backchannel
        # открытым всю сессию просмотра — eager-сессия блокировала канал
        # 409, инцидент 31.10); новый RTP ингресса откроет сессию заново.
        # HTTP /talk — False: время жизни = тело запроса (stop() в конце)
        self.autorelease = bool(autorelease)
        self._q = queue.Queue()         # ингресс → пейсер
        self._stop = threading.Event()
        self._thread = None
        self.finished = False           # ингресс закрыл сессию
        self.bytes_in = 0               # принято от ингресса
        self.bytes_sent = 0             # отправлено в панель
        self.error = None               # диагноз при провале старта
        # backpressure (наблюдение 31.10 14:31: файловый POST быстрее
        # реального времени, прежний «кап с выбросом старого» доиграл
        # только 16960 из 40000 Б): счётчик несент-байт + условная
        # переменная; feed() ждёт, пока пейсер не отправит
        self._cond = threading.Condition()
        self._pending = 0
        self.last_data = 0.0            # время последнего feed() — для
        # детектора тишины (НЕ приход в очередь: сам backpressure
        # приём-передачу ~1 чанк/2 с, и молчание очереди ≠ молчание
        # ингресса)

    # -- публичное (вызывают потоки ингресса: HTTP/RTSP) -------------------

    def start(self):
        self._thread = threading.Thread(target=self._pacer, daemon=True,
                                        name="talk-ch%d" % self.channel)
        self._thread.start()

    def feed(self, data: bytes):
        """Порция µ-law от ингресса (любой кратности).

        Backpressure: если несент-аудио больше WATERMARK (2 с) — ждём
        пейсер (файл играется ЦЕЛИКОМ, POST занимает время файла), а не
        выбрасываем старое. Живость пейсера проверяем — при его смерти
        не виснем, а теряем данные."""
        if self.finished or self._stop.is_set() or not data:
            return
        with self._cond:
            while (self._pending >= self.WATERMARK
                   and not self.finished and not self._stop.is_set()
                   and self._thread is not None
                   and self._thread.is_alive()):
                self._cond.wait(0.5)
            if self.finished or self._stop.is_set():
                return
            self._pending += len(data)
        self.bytes_in += len(data)
        self.last_data = time.monotonic()
        self._q.put(data)

    def _drained(self, n):
        """Пейсер отправил/выбросил n байт — будим ждущий ингресс."""
        with self._cond:
            self._pending = max(0, self._pending - n)
            self._cond.notify_all()

    def stop(self):
        """Ингресс закончил: флаш остатка + TLV 331 action=2."""
        self.finished = True
        self._q.put(b"")                 # разбудить пейсер
        with self._cond:
            self._cond.notify_all()       # разбудить feed(), если ждёт
        if self._thread is not None:
            self._thread.join(timeout=15.0)

    # -- пейсер ---------------------------------------------------------------

    def _pacer(self):
        client = self.gateway.get_client(self.channel)
        started = False                  # 331/332 выполнены
        gen = None                        # поколение OWSP-сессии старта
        buf = bytearray()
        t_start = 0.0
        next_send = 0.0
        next_try = 0.0                   # когда снова пробовать 331
        last_err = None                  # последняя ошибка (событие — раз)
        while not self._stop.is_set():
            # ожидание данных: если буфер полон и пейсинг уже готов —
            # спим до next_send (иначе таймаут очереди 50 мс растягивал
            # чанки до 50 мс вместо 40), иначе — до прихода данных
            now = time.monotonic()
            if started and len(buf) >= self.CHUNK and next_send > now:
                wait = min(0.05, next_send - now)
            else:
                wait = 0.05
            try:
                data = self._q.get(timeout=wait)
                if data:
                    buf += data
            except queue.Empty:
                pass
            # OWSP-сессия канала умерла и пересоздалась: talk-контекст
            # панели потерян, лить 97/98 без свежего 331 нельзя — прошивка
            # рвёт соединение (инцидент 31.10: при активном микрофоне канал
            # «не поднимался», пока не уйдёшь с карточки). Конец без 331/2:
            # останавливать на панели нечего (новая сессия), буфер жив
            if started and client.sess_gen != gen:
                if client.login_ok.is_set():
                    self.gateway._add_event("talk", {
                        "channel": self.channel, "state": "end",
                        "bytes": self.bytes_sent, "reason": "session"})
                    started = False
                    t_start = 0.0
                    gen = None
                    next_try = 0.0
                # иначе ждём реконнекта: отправка не идёт (login сброшен
                # → talk_send_audio мимо), переполнение исключено
                # (WATERMARK + backpressure ингресса)
            # старт по первому звуку; неудачи НЕ фатальны — ретраи раз в
            # 3 с, пока идёт звук (железо 31.10 21:24/22:08):
            #  - result=23 — talk занят: слот у панели один на все
            #    панели, соседний разговор кончится — ретрай подхватит
            #  - таймаут 332 — talk-движок прошивки застрял: панель сама
            #    рвёт OWSP-сессию канала (~30 с), ретрай попадёт в свежую
            if not started and buf and time.monotonic() >= next_try:
                ok, msg = client.talk_start()
                if ok:
                    started = True
                    gen = client.sess_gen
                    t_start = time.monotonic()
                    last_err = None
                    self.error = None
                    self.gateway._add_event("talk", {
                        "channel": self.channel, "state": "start",
                        "gain_shift": self.gain_shift or None})
                else:
                    if msg != last_err:   # событие раз на серию неудач
                        last_err = msg
                        self.error = msg
                        self.gateway._add_event("talk", {
                            "channel": self.channel, "state": "error",
                            "detail": msg})
                    if "нет ответа" in msg:
                        # подстраховка (железо 31.10 15:21): 331 мог быть
                        # принят панелью, а 332 — потеряться (мусор
                        # протокола) → панель держала talk занятым и
                        # отказывала соседям (result=23). Чистим 331
                        # action=2; при явном отказе чистить нечего
                        client.talk_stop()
                    next_try = time.monotonic() + 3.0
            if not started:
                if buf:
                    self._drained(len(buf))
                    buf.clear()      # не копим мусор неустановленной сессии
                if self.finished:
                    break            # не начался — чистить на панели нечего
                continue
            if started:
                # автостоп по тишине: ингресс не подавал данных 2 с И
                # нечего доигрывать (buf/queue пусты — backpressure сам
                # держит паузы ~2 с между чанками от медленного ингресса)
                if (self.last_data and not self.finished
                        and len(buf) < self.CHUNK and self._q.empty()
                        and time.monotonic() - self.last_data
                        > self.silence_s):
                    self._end_talk(client, t_start, "silence")
                    if self.autorelease:
                        # слот панели свободен; RTSP-ингресс откроет
                        # сессию заново по следующему RTP (лениво)
                        self.finished = True
                    started = False
                    t_start = 0.0
                    buf.clear()
                # пейсер: ≤1 чанк за тик 40 мс
                elif len(buf) >= self.CHUNK and time.monotonic() >= next_send:
                    chunk = ulaw_gain_shift(bytes(buf[:self.CHUNK]),
                                            self.gain_shift)
                    del buf[:self.CHUNK]
                    self._drained(self.CHUNK)
                    if client.talk_send_audio(chunk):
                        self.bytes_sent += len(chunk)
                    now = time.monotonic()
                    next_send = now if next_send + 4 * self.PERIOD < now \
                        else next_send + self.PERIOD
            # ингресс закрыл сессию и буфер дренирован — на флаш и выход
            if self.finished and len(buf) < self.CHUNK:
                break
        # останов сессии (ингресс закрыл / gateway гасится): флаш + 331/2
        if started:
            while len(buf) >= self.CHUNK:     # остаток тем же темпом
                chunk = ulaw_gain_shift(bytes(buf[:self.CHUNK]),
                                        self.gain_shift)
                del buf[:self.CHUNK]
                self._drained(self.CHUNK)
                client.talk_send_audio(chunk)
                self.bytes_sent += len(chunk)
                time.sleep(self.PERIOD)
            self._end_talk(client, t_start, "stop")

    def _end_talk(self, client, t_start, reason):
        client.talk_stop()
        evt = {"channel": self.channel, "state": "end",
               "bytes": self.bytes_sent, "reason": reason}
        if t_start:
            evt["duration_s"] = round(time.monotonic() - t_start, 1)
        self.gateway._add_event("talk", evt)


class Gateway:
    """Владеет OWSP-подключениями домофона: по одному на канал.

    Каналы из boot-списка открываются на старте; прочие (/camN) — лениво при
    первом RTSP-запросе. Простаивающие ленивые подключения закрываются через
    idle_timeout (у домофона ограничено число одновременных пользователей).
    """

    IDLE_TIMEOUT = 120.0
    REAP_INTERVAL = 15.0
    MAX_CHANNELS = 16

    def __init__(self, host, port, user, password, channels=(1,),
                 sub_stream=True, record_path=None, on_log=None,
                 keepalive_interval=0.0, data_type=2, send_tlv44=False,
                 send_tlv427=False, recycle_secs=0.0,
                 send_audio_ack=False, idle_timeout=15.0, dump_path=None,
                 lock_password=None, ring_cfg=None, mute_local_steps=0,
                 ring_max_s=180.0, talk_gain_shift=0):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.lock_password = lock_password or password
        self.sub_stream = sub_stream
        self.record_path = record_path
        self.keepalive_interval = keepalive_interval
        self.data_type = data_type
        self.send_tlv44 = send_tlv44
        self.send_tlv427 = send_tlv427
        self.send_audio_ack = send_audio_ack
        self.recycle_secs = recycle_secs
        self.idle_timeout = idle_timeout
        self.ring_cfg = ring_cfg
        self.ring_max_s = max(0.0, float(ring_max_s))
        self.mute_local_steps = max(0, int(mute_local_steps))
        self.talk_gain_shift = int(talk_gain_shift)
        self._talk = {}                # channel → TalkSession (эксклюзив)
        self._talk_lock = threading.Lock()
        self.mqtt = None            # MqttBridge (attach_mqtt)
        self.log = on_log or (lambda msg: print("[gw] %s" % msg, flush=True))
        self.boot_channels = [c for c in channels if 1 <= c <= self.MAX_CHANNELS]
        self.default_channel = self.boot_channels[0] if self.boot_channels else 1
        self._lock = threading.Lock()
        self._clients = {}             # channel -> OwspClient
        self._firmware_new = None       # кэш переговоров версии (True/False/None)
        self.chan_total = None          # из TLV 70
        self._stop = threading.Event()
        self._dump_file = None
        self._dump_lock = threading.Lock()
        self._events = collections.deque(maxlen=200)  # шина событий (/events)
        self._events_lock = threading.Lock()
        # дедупликация звонка по каналам (каналы 1 и 4 — один источник
        # аудио, оба детектора сработают; событие должно быть одно)
        self._ring_lock = threading.Lock()
        self._ring_active = False
        self._ring_channels = set()
        self._ring_f0 = None
        self._ring_gain = None
        self._ring_t0 = 0.0
        if dump_path:
            self._dump_file = open(dump_path, "a", buffering=1)
            self._dump_file.write("\n=== запуск %s ===\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        threading.Thread(target=self._reaper, daemon=True,
                         name="gw-reaper").start()

    def _make_dump_hook(self, channel):
        if self._dump_file is None:
            return None

        def hook(line):
            with self._dump_lock:
                self._dump_file.write("%s [ch%d] %s\n"
                                      % (time.strftime("%H:%M:%S"), channel, line))
        return hook

    # -- каналы ---------------------------------------------------------------

    def get_client(self, channel: int) -> OwspClient:
        """Клиент канала; при отсутствии — создаётся и запускается (лениво)."""
        channel = max(1, min(int(channel), self.MAX_CHANNELS))
        with self._lock:
            client = self._clients.get(channel)
            if client is not None and client.is_alive():
                client.last_used = time.monotonic()
                return client
            client = OwspClient(
                self.host, self.port, self.user, self.password,
                channel=channel, sub_stream=self.sub_stream,
                data_type=self.data_type,
                on_info=self._on_device_info,
                new_proto_first=(self._firmware_new is not False),
                keepalive_interval=self.keepalive_interval,
                send_tlv44=self.send_tlv44,
                send_tlv427=self.send_tlv427,
                send_audio_ack=self.send_audio_ack,
                recycle_secs=self.recycle_secs,
                idle_timeout=self.idle_timeout,
                on_dump=self._make_dump_hook(channel),
                on_event=self._on_client_event,
                ring_cfg=self.ring_cfg,
                mute_local_steps=self.mute_local_steps)
            if self.record_path:
                if "{ch}" in self.record_path:
                    client.record_file = open(
                        self.record_path.replace("{ch}", str(channel)), "wb")
                elif channel == self.default_channel:
                    client.record_file = open(self.record_path, "wb")
            self._clients[channel] = client
        client.start()
        return client

    def boot(self):
        """Открыть каналы стартового списка."""
        for ch in self.boot_channels:
            self.get_client(ch)

    def open_all(self, timeout=12.0):
        """Режим --channels all: узнать число каналов (TLV 70) и открыть все."""
        first = self.get_client(self.default_channel)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.chan_total is None:
            if first.login_error:
                break
            time.sleep(0.2)
        total = self.chan_total
        if not total:
            self.log("не удалось узнать число каналов — открыт только канал %d"
                     % self.default_channel)
            return
        self.log("домофон сообщил %d канал(ов)" % total)
        for ch in range(1, min(total, self.MAX_CHANNELS) + 1):
            if ch != self.default_channel:
                self.get_client(ch)

    def _on_device_info(self, info):
        self.chan_total = info.get("channel_number") or None

    # -- события и замок ------------------------------------------------------

    def _on_client_event(self, kind, detail):
        if kind == "ring":
            self._on_ring(detail)
        else:
            self._add_event(kind, detail)

    def _on_ring(self, d):
        """Дедуп звонка по каналам: первый start — событие, старты других
        каналов сливаются в список; первый end закрывает (каналы дублируют
        аудио, концы приходят почти одновременно)."""
        ch = d.get("channel")
        if d.get("state") == "start":
            with self._ring_lock:
                if self._ring_active:
                    self._ring_channels.add(ch)
                    if d.get("freq"):
                        self._ring_f0 = d["freq"]
                    return
                self._ring_active = True
                self._ring_channels = {ch}
                self._ring_f0 = d.get("freq")
                self._ring_gain = d.get("gain_db")
                self._ring_t0 = time.time()
            self._add_event("ring", {
                "state": "start", "channels": [ch],
                "freq": self._ring_f0, "gain_db": self._ring_gain})
        else:
            self._finish_ring()

    def _finish_ring(self, stuck=False):
        """Закрыть активный звонок (первый end от любого канала)."""
        with self._ring_lock:
            if not self._ring_active:
                return
            self._ring_active = False
            chans = sorted(self._ring_channels)
            dur = round(time.time() - self._ring_t0, 1)
            f0, gain = self._ring_f0, self._ring_gain
            self._ring_channels = set()
        evt = {"state": "end", "channels": chans,
               "freq": f0, "gain_db": gain, "duration_s": dur}
        if stuck:
            evt["stuck"] = True   # принудительное закрытие по таймауту
        self._add_event("ring", evt)

    def _add_event(self, kind, detail):
        evt = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind}
        evt.update(detail)
        with self._events_lock:
            self._events.append(evt)
        self.log("событие %s: %s" % (kind, " ".join(
            "%s=%s" % (k, v) for k, v in detail.items())))
        if self.mqtt is not None:
            try:
                self.mqtt.publish_event(kind, evt)
            except Exception:  # noqa: BLE001
                pass

    def attach_mqtt(self, bridge):
        """Подключить MQTT-мост: все события шины публикуются в брокер,
        мост шлёт команды (unlock/volume) обратно в шлюз."""
        self.mqtt = bridge

    def events(self):
        """Последние события (замок, неизвестные TLV) — для GET /events."""
        with self._events_lock:
            return list(self._events)

    def unlock(self, channel=1, action=1, delay=1, password=None,
               login_timeout=8.0, cmd_timeout=5.0):
        """Открыть замок канала (TLV 425 через активную OWSP-сессию).

        Канал подключается лениво при необходимости (как /camN), но в
        продакшене boot-каналы уже держат сессии — команда уходит без
        дополнительного соединения к устройству.
        """
        client = self.get_client(channel)
        if not client.wait_login(login_timeout):
            return False, ("канал %d: нет сессии (%s)"
                           % (channel, client.login_error or "таймаут логина"))
        ok, msg = client.lock(password or self.lock_password, action, delay,
                              cmd_timeout)
        self._add_event("unlock", {"channel": channel, "action": action,
                                  "delay": delay, "ok": ok, "detail": msg})
        return ok, msg

    def volume(self, channel=1, direction="down", steps=1,
               login_timeout=8.0, cmd_timeout=3.0):
        """Громкость локального динамика панели (TLV 1054 через активную
        OWSP-сессию канала — как кнопки в приложении)."""
        client = self.get_client(channel)
        if not client.wait_login(login_timeout):
            return False, ("канал %d: нет сессии (%s)"
                           % (channel, client.login_error or "таймаут логина"))
        ok, msg = client.volume(direction, steps, cmd_timeout)
        self._add_event("volume", {"channel": channel,
                                   "direction": direction, "steps": steps,
                                   "ok": ok, "detail": msg})
        return ok, msg

    def sync_time(self):
        """Синхронизировать время панели (TLV 1007/1008).

        Отдельное settings-соединение — как кнопка в приложении; стрим-
        сессии НЕ трогает (TLV 1007 в стрим-сессии прошивка рвёт
        соединение — наблюдение 31.10). Работает при 4 boot-каналах:
        код 5 (лимит) повтора́ется с паузой внутри sync_time_device.
        """
        code, msg = sync_time_device(self.host, self.port, self.user,
                                     self.password)
        ok = code == 0
        self._add_event("timesync", {"ok": ok, "detail": msg})
        return ok, msg

    def open_talk(self, channel, autorelease=False):
        """Ингресс громкой связи (RTSP RECORD / HTTP POST /talk).

        Эксклюзив на канал: живая сессия (не finished) → None («занято»).
        TalkSession стартует лениво — TLV 331 уйдёт только когда
        ингресс начнёт слать аудио. autorelease=True — RTSP-ингрессы:
        после 2 с тишины слот панели освобождается (закрытый go2rtc
        backchannel не должен держать канал, пока никто не говорит)."""
        channel = max(1, min(int(channel), self.MAX_CHANNELS))
        with self._talk_lock:
            s = self._talk.get(channel)
            if s is not None and not s.finished:
                return None
            s = TalkSession(self, channel,
                            gain_shift=self.talk_gain_shift,
                            autorelease=autorelease)
            self._talk[channel] = s
        s.start()
        return s

    def status(self):
        """Состояние каналов — для GET /status."""
        with self._lock:
            clients = list(self._clients.items())
        channels = []
        for ch, c in sorted(clients):
            fmt = c.format or {}
            channels.append({
                "channel": ch, "alive": c.is_alive(),
                "login_ok": c.login_ok.is_set(),
                "login_error": c.login_error,
                "frames": c.frame_count,
                "audio_bytes": c.audio_bytes,
                "subscribers": c.subscriber_count(),
                "width": fmt.get("width"), "height": fmt.get("height"),
                "fps": fmt.get("framerate"),
            })
        ring = {"active": self._ring_active}
        if self._ring_active:
            ring["channels"] = sorted(self._ring_channels)
            ring["seconds"] = round(time.time() - self._ring_t0, 1)
        with self._talk_lock:
            talks = {ch: {"finished": s.finished, "bytes_in": s.bytes_in,
                          "bytes_sent": s.bytes_sent, "error": s.error}
                     for ch, s in self._talk.items() if not s.finished}
        return {"channels": channels, "ring": ring, "talk": talks}

    def stop_all(self):
        self._stop.set()
        with self._talk_lock:
            talks = list(self._talk.values())
            self._talk.clear()
        for s in talks:
            try:
                s.stop()
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for c in clients:
            c.stop()
        if self.mqtt is not None:
            try:
                self.mqtt.stop()
            except Exception:  # noqa: BLE001
                pass
        if self._dump_file is not None:
            try:
                self._dump_file.close()
            except OSError:
                pass

    # -- уборка простаивающих ленивых подключений ------------------------------

    def _reaper(self):
        boot = set(self.boot_channels)
        while not self._stop.wait(self.REAP_INTERVAL):
            now = time.monotonic()
            # страховка «зависшего» звонка: если аудио канала замолчало
            # (TLV 98 прекратился), end никогда не придёт — закрываем
            # принудительно (наблюдение 31.10: ring start без end, аудио
            # на канале живо только на старте)
            if (self._ring_active and self.ring_max_s > 0
                    and time.time() - self._ring_t0 > self.ring_max_s):
                self.log("ring активен дольше %.0f с — принудительное "
                         "закрытие" % self.ring_max_s)
                self._finish_ring(stuck=True)
            with self._lock:
                stale = [(ch, c) for ch, c in self._clients.items()
                         if ch not in boot
                         and c.subscriber_count() == 0
                         and (c.login_error is not None
                              or now - c.last_used > self.IDLE_TIMEOUT)]
                for ch, _c in stale:
                    self._clients.pop(ch, None)
            for ch, c in stale:
                self.log("канал %d не используется — закрытие соединения" % ch)
                c.stop()


# ---------------------------------------------------------------------------
# RTP
# ---------------------------------------------------------------------------

class RtpPacketizer:
    def __init__(self, ssrc):
        self.ssrc = ssrc
        self.seq = random.randrange(0xFFFF)

    def packet(self, payload: bytes, pt: int, ts: int, marker: bool) -> bytes:
        self.seq = (self.seq + 1) & 0xFFFF
        b1 = (0x80 if marker else 0) | (pt & 0x7F)  # M-бит + payload type
        return (struct.pack(">BBH", 0x80, b1, self.seq)
                + struct.pack(">II", ts & 0xFFFFFFFF, self.ssrc & 0xFFFFFFFF)
                + payload)


def h264_rtp_packets(pktz: RtpPacketizer, frame: bytes, ts: int, mtu=1400):
    """Кадр Annex-B → список RTP-пакетов (RFC 6184, packetization-mode=1)."""
    nals = iter_nals(frame)
    if not nals:
        return []
    out = []
    for i, nal in enumerate(nals):
        last_nal = i == len(nals) - 1
        if len(nal) <= mtu - 12:
            # одиночный NAL-юнит
            out.append(pktz.packet(nal, 96, ts, last_nal))
        else:
            # фрагментация FU-A
            hdr0 = nal[0]
            indicator = (hdr0 & 0xE0) | 28
            ntype = hdr0 & 0x1F
            data = memoryview(nal)[1:]
            first = True
            while True:
                chunk = bytes(data[:mtu - 14])
                data = data[len(chunk):]
                last = len(data) == 0
                fu_header = (0x80 if first else 0) | (0x40 if last else 0) | ntype
                out.append(pktz.packet(bytes([indicator, fu_header]) + chunk,
                                       96, ts, last and last_nal))
                if last:
                    break
                first = False
    return out


# ---------------------------------------------------------------------------
# RTSP-сервер
# ---------------------------------------------------------------------------

SERVER_NAME = "SlinexOWSP"
SDP_SESSION_ID = str(random.randrange(1 << 30))


def audio_payload_type(client: OwspClient):
    """31257 (G.711 A-law) → PT 8 PCMA; 31269 (µ-law) → PT 0 PCMU; прочее → None."""
    wfmt = (client.format or {}).get("wave_format", WAVE_FORMAT_G711A)
    if wfmt == WAVE_FORMAT_G711A:
        return 8, "PCMA"
    if wfmt == WAVE_FORMAT_G711U:
        return 0, "PCMU"
    return None, None


def sdp_for(client: OwspClient, channel: int) -> str:
    title = "Slinex SL-10PT (OWSP gateway)"
    if channel > 1:
        title += ", channel %d" % channel
    lines = [
        "v=0",
        "o=- %s 1 IN IP4 0.0.0.0" % SDP_SESSION_ID,
        "s=%s" % title,
        "i=Live stream from IP doorphone",
        "c=IN IP4 0.0.0.0",
        "t=0 0",
        "a=tool:%s" % SERVER_NAME,
        "a=range:npt=now-",
        "a=control:*",
        "m=video 0 RTP/AVP 96",
        "a=rtpmap:96 H264/90000",
    ]
    fmtp = "a=fmtp:96 packetization-mode=1"
    if client.sps:
        sps = base64.b64encode(client.sps).decode()
        if client.pps:
            fmtp += ";sprop-parameter-sets=%s,%s" % (sps,
                                                     base64.b64encode(client.pps).decode())
        else:
            fmtp += ";sprop-parameter-sets=%s" % sps
    lines += [fmtp, "a=control:trackID=0", "a=recvonly"]

    pt, codec = audio_payload_type(client)
    if pt is not None:
        lines += [
            "m=audio 0 RTP/AVP %d" % pt,
            "a=rtpmap:%d %s/8000/1" % (pt, codec),
            "a=control:trackID=1",
            "a=recvonly",
        ]
    # talk-backchannel (ONVIF Profile T, как Dahua/Hikvision/go2rtc).
    # ВАЖНО (урок 31.10: probe go2rtc дал EOF, а канал словил 409):
    # направление в SDP источника — С ТОЧКИ ЗРЕНИЯ КЛИЕНТА, а не RFC-
    # буквальной «стороны сервера»: воспроизведение a=recvonly («клиент
    # принимает»), backchannel a=sendonly («клиент шлёт») — так пишут
    # реальные камеры (go2rtc TestBugSDP7; без атрибута go2rtc тоже
    # считает recvonly). go2rtc шлёт микрофон SETUP-ом sendonly-трека
    # БЕЗ mode=record и БЕЗ RECORD (в отличие от ffmpeg-пути ANNOUNCE)
    lines += [
        "m=audio 0 RTP/AVP 0",
        "a=rtpmap:0 PCMU/8000/1",
        "a=control:trackID=2",
        "a=sendonly",
    ]
    return "\r\n".join(lines) + "\r\n"


def channel_from_url(url: str, default: int) -> int:
    """Канал из RTSP-URL: /camera → default, /camera2|/cam2|/ch2|/2 → 2.
    Суффикс /talk (ингресс громкой связи) отбрасывается: /camera2/talk → 2."""
    path = url.split("?", 1)[0]
    path = re.sub(r"/trackID=\d+$", "", path)
    path = re.sub(r"/talk/?$", "", path, flags=re.IGNORECASE)
    m = re.search(r"/(?:cam(?:era)?|ch)?(\d{1,2})$", path, re.IGNORECASE)
    if m:
        return max(1, int(m.group(1)))
    return default


def is_talk_url(url: str) -> bool:
    """URL ингресса громкой связи: путь кончается на /talk."""
    path = url.split("?", 1)[0]
    path = re.sub(r"/trackID=\d+$", "", path)
    return path.rstrip("/").lower().endswith("/talk")


def rtp_payload(pkt: bytes):
    """RTP-пакет → (payload_type, payload) либо None (не RTP / RTCP)."""
    if len(pkt) < 12 or pkt[0] >> 6 != 2:
        return None
    cc = pkt[0] & 0x0F
    off = 12 + cc * 4
    if pkt[0] & 0x10:                     # header extension
        if len(pkt) < off + 4:
            return None
        off += 4 + struct.unpack_from(">H", pkt, off + 2)[0] * 4
    pt = pkt[1] & 0x7F
    if 200 <= pt <= 205 or len(pkt) <= off:  # RTCP или пустой
        return None
    return pt, pkt[off:]


def make_rtp_udp_socket():
    """UDP-сокет на чётном порту (RTCP-порт +1 резервируется)."""
    for _ in range(64):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
        if port % 2 == 0:
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s2.bind(("0.0.0.0", port + 1))
                s2.close()
                return s
            except OSError:
                pass
        s.close()
    raise OSError("не удалось выделить чётный UDP-порт")


class RtpTrack:
    """Один трек RTSP-сессии: UDP или TCP-interleaved."""

    def __init__(self, channel_pair):
        self.channel_pair = channel_pair  # (rtp_ch, rtcp_ch) для TCP
        self.udp_sock = None
        self.dst = None  # (ip, port) для UDP


class RtspConnection(threading.Thread):
    def __init__(self, conn, addr, gateway: Gateway, server):
        super().__init__(daemon=True, name="rtsp-%s:%d" % addr[:2])
        self.conn = conn
        self.addr = addr
        self.gateway = gateway
        self.server = server
        self.channel = gateway.default_channel
        self._chan_client = None         # OwspClient канала (после DESCRIBE)
        self.tracks = {}             # trackID -> RtpTrack
        self.subscriber = None
        self.playing = threading.Event()
        self.session_id = "%08x" % random.randrange(1 << 31)
        self.cseq = "0"
        self.request_url = "rtsp://dummy/"
        self.lock = threading.Lock()  # запись interleaved-кадров в conn
        self.video_pktz = None
        self.audio_pktz = None
        # ингресс громкой связи: ANNOUNCE (ffmpeg — eager в
        # handle_announce) или backchannel trackID=2 (go2rtc — лениво
        # по первому RTP, см. _talk_feed)
        self.talk = None              # TalkSession
        self.talk_ingress = False     # соединение объявило ANNOUNCE
        self.talk_rtp_ch = None       # interleaved-канал входящего RTP
        self.talk_channel = None      # канал панели (снапшот на SETUP)
        self.talk_udp_sock = None     # UDP-сокет talk-трека (RECORD без
        # interleaved): закрывается в cleanup → поток чтения завершается

    # ---- цикл приёма RTSP-запросов -----------------------------------------

    def run(self):
        try:
            self.conn.settimeout(120)
            rbuf = b""
            while True:
                data = self.conn.recv(65536)
                if not data:
                    break
                rbuf += data
                while True:
                    if rbuf[:1] == b"$":
                        # interleaved-данные от клиента: для talk-ингресса
                        # это входящий RTP (аудио в панель), иначе RTCP — мимо
                        if len(rbuf) < 4:
                            break
                        plen = struct.unpack_from(">H", rbuf, 2)[0]
                        if len(rbuf) < 4 + plen:
                            break
                        frame, rbuf = rbuf[:4 + plen], rbuf[4 + plen:]
                        if (self.talk_rtp_ch is not None
                                and frame[1] == self.talk_rtp_ch):
                            # входящий RTP talk-трека (микрофон клиента)
                            parsed = rtp_payload(frame[4:])
                            if parsed and parsed[0] == 0:   # PCMU
                                self._talk_feed(parsed[1])
                        continue
                    if b"\r\n\r\n" not in rbuf:
                        break
                    head, rbuf = rbuf.split(b"\r\n\r\n", 1)
                    lines = head.decode("latin-1", "replace").split("\r\n")
                    if not lines[0]:
                        continue
                    headers = {}
                    for ln in lines[1:]:
                        if ":" in ln:
                            k, v = ln.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    clen = int(headers.get("content-length", "0") or 0)
                    while len(rbuf) < clen:
                        more = self.conn.recv(65536)
                        if not more:
                            return
                        rbuf += more
                    body, rbuf = rbuf[:clen], rbuf[clen:]
                    if not self.handle(lines[0], headers, body):
                        return
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self.cleanup()

    # ---- ответы -------------------------------------------------------------

    def reply(self, code, text, headers=None, body=b""):
        out = "RTSP/1.0 %d %s\r\n" % (code, text)
        hdrs = {"CSeq": self.cseq, "Server": SERVER_NAME}
        if headers:
            hdrs.update(headers)
        for k, v in hdrs.items():
            out += "%s: %s\r\n" % (k, v)
        if body:
            out += "Content-Length: %d\r\nContent-Type: application/sdp\r\n" % len(body)
        out += "\r\n"
        self.conn.sendall(out.encode("latin-1") + body)

    # ---- методы RTSP ----------------------------------------------------------

    def handle(self, req_line, headers, body) -> bool:
        parts = req_line.split()
        if len(parts) < 2:
            self.reply(400, "Bad Request")
            return False
        method, self.request_url = parts[0], parts[1]
        self.cseq = headers.get("cseq", "0")
        self.channel = channel_from_url(self.request_url,
                                       self.gateway.default_channel)

        if method == "OPTIONS":
            self.reply(200, "OK", {"Public":
                        "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, "
                        "GET_PARAMETER, ANNOUNCE, RECORD"})
        elif method == "GET_PARAMETER":
            self.reply(200, "OK")
        elif method == "DESCRIBE":
            self.handle_describe()
        elif method == "SETUP":
            self.handle_setup(headers)
        elif method == "PLAY":
            self.handle_play()
        elif method == "PAUSE":
            self.playing.clear()
            self.reply(200, "OK", {"Session": self.session_id})
        elif method == "TEARDOWN":
            self.reply(200, "OK", {"Session": self.session_id})
            return False
        elif method == "ANNOUNCE":
            self.handle_announce(headers, body)
        elif method == "RECORD":
            self.handle_record()
        else:
            self.reply(501, "Not Implemented")
        return True

    def chan_client(self) -> OwspClient:
        """Клиент OWSP для канала данной RTSP-сессии (создаётся лениво)."""
        if self._chan_client is None or not self._chan_client.is_alive():
            self._chan_client = self.gateway.get_client(self.channel)
        return self._chan_client

    def handle_describe(self):
        client = self.chan_client()
        if not client.wait_ready(timeout=10.0):
            self.reply(503, "Service Unavailable: channel %d stream not ready"
                       % self.channel)
            return
        self.reply(200, "OK", {"Content-Base": self.base_url()},
                   sdp_for(client, self.channel).encode("utf-8"))

    def base_url(self):
        return self.request_url.split("?", 1)[0].rstrip("/") + "/"

    def handle_setup(self, headers):
        if self.talk_ingress:
            self.handle_setup_talk(headers)
            return
        track = self.track_from_url()
        if track == 2:
            # backchannel (go2rtc/ONVIF Profile T): talk-трек из DESCRIBE
            self.handle_setup_talk(headers)
            return
        if track not in (0, 1):
            self.reply(404, "Not Found")
            return
        if track == 1 and audio_payload_type(self.chan_client())[0] is None:
            self.reply(404, "Not Found: audio not available")
            return
        transport = headers.get("transport", "")
        default_pair = (0, 1) if track == 0 else (2, 3)
        rtp = RtpTrack(default_pair)

        m = re.search(r"interleaved=(\d+)-(\d+)", transport)
        if m:
            rtp.channel_pair = (int(m.group(1)), int(m.group(2)))
            reply_transport = "RTP/AVP/TCP;unicast;interleaved=%d-%d" % rtp.channel_pair
        else:
            m = re.search(r"client_port=(\d+)", transport)
            if not m:
                self.reply(461, "Unsupported Transport")
                return
            client_port = int(m.group(1))
            try:
                sock = make_rtp_udp_socket()
                sock.connect((self.addr[0], client_port))
            except OSError:
                self.reply(500, "Internal Server Error")
                return
            rtp.udp_sock = sock
            sport = sock.getsockname()[1]
            reply_transport = ("RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d"
                               % (client_port, client_port + 1, sport, sport + 1))
        self.tracks[track] = rtp
        self.reply(200, "OK", {
            "Session": self.session_id + ";timeout=60",
            "Transport": reply_transport,
        })

    def track_from_url(self):
        m = re.search(r"trackID=(\d+)", self.request_url)
        if m:
            return int(m.group(1))
        url = self.request_url.lower()
        if url.rstrip("/").endswith("/video"):
            return 0
        if url.rstrip("/").endswith("/audio"):
            return 1
        return 0

    def handle_play(self):
        if not self.tracks:
            self.reply(454, "Session Not Found")
            return
        client = self.chan_client()
        self.subscriber = client.subscribe()
        self.video_pktz = RtpPacketizer(random.randrange(1 << 31))
        self.audio_pktz = RtpPacketizer(random.randrange(1 << 31))
        rtp_info = "url=%strackID=0;seq=%d;rtptime=0" % (
            self.base_url(), (self.video_pktz.seq + 1) & 0xFFFF)
        if 1 in self.tracks:
            rtp_info += ",url=%strackID=1;seq=%d;rtptime=0" % (
                self.base_url(), (self.audio_pktz.seq + 1) & 0xFFFF)
        # ответ отправляем ДО старта стримера, чтобы interleaved-RTP не опережал ответ
        self.reply(200, "OK", {
            "Session": self.session_id + ";timeout=60",
            "RTP-Info": rtp_info,
        })
        self.playing.set()
        threading.Thread(target=self.stream_loop, daemon=True,
                         name="rtp-stream").start()

    # ---- ингресс громкой связи (ANNOUNCE + SETUP + RECORD, ffmpeg -f rtsp) ---

    def handle_announce(self, headers, body):
        """ANNOUNCE от публикующего клиента (ffmpeg -f rtsp ...): SDP с
        m=audio PCMU/8000. Канал — из URL (.../cameraN/talk). Эксклюзив
        на канал проверяется здесь же — второй ингресс получает 503."""
        sdp = body.decode("utf-8", "replace") if body else ""
        has_audio = re.search(r"^m=audio", sdp, re.MULTILINE) is not None
        has_pcmu = re.search(r"PCMU/8000", sdp) is not None
        if not (has_audio and has_pcmu):
            self.reply(415, "Unsupported Media Type: нужен m=audio PCMU/8000")
            return
        url = self.request_url.split("?", 1)[0]
        channel = channel_from_url(url, self.gateway.default_channel)
        session = self.gateway.open_talk(channel, autorelease=True)
        if session is None:
            self.reply(503, "Service Unavailable: talk на канале %d занят"
                       % channel)
            return
        self.talk = session
        self.talk_ingress = True
        self.talk_channel = channel
        self.reply(200, "OK", {"Session": self.session_id})

    def handle_setup_talk(self, headers):
        """SETUP talk-трека: после ANNOUNCE (ffmpeg -f rtsp, сессия уже
        создана в handle_announce) или trackID=2 backchannel из DESCRIBE
        (go2rtc/ONVIF Profile T — TalkSession НЕ создаётся здесь: go2rtc
        держит backchannel открытым всю сессию просмотра, а слот панели
        должен заниматься только реальным звуком — см. _talk_feed).
        Interleaved (ffmpeg -rtsp_transport tcp) или UDP — свой сокет +
        фоновый поток чтения RTP."""
        self.talk_channel = self.channel   # снапшот канала для ленивого
        transport = headers.get("transport", "")
        m = re.search(r"interleaved=(\d+)-(\d+)", transport)
        if m:
            self.talk_rtp_ch = int(m.group(1))
            reply_transport = ("RTP/AVP/TCP;unicast;interleaved=%s-%s;mode=record"
                               % (m.group(1), m.group(2)))
        else:
            m = re.search(r"client_port=(\d+)", transport)
            if not m:
                self.reply(461, "Unsupported Transport")
                return
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("0.0.0.0", 0))
            except OSError:
                self.reply(500, "Internal Server Error")
                return
            sport = sock.getsockname()[1]
            reply_transport = ("RTP/AVP;unicast;client_port=%s;server_port="
                               "%d-%d;mode=record" % (m.group(1), sport,
                                                      sport + 1))
            sock.connect((self.addr[0], int(m.group(1))))
            self.talk_udp_sock = sock
            threading.Thread(target=self._talk_udp_reader, args=(sock,),
                             daemon=True, name="talk-rtp-udp").start()
        self.reply(200, "OK", {
            "Session": self.session_id + ";timeout=60",
            "Transport": reply_transport,
        })

    def _talk_feed(self, payload: bytes):
        """PCMU-payload от клиента (interleaved или UDP): лениво открыть
        TalkSession канала talk_channel и накормить. Занято другим
        ингрессом — тихо мимо (в /status видно, кто держит канал)."""
        if self.talk is None or self.talk.finished:
            self.talk = self.gateway.open_talk(self.talk_channel,
                                               autorelease=True)
            if self.talk is None:
                return
        self.talk.feed(payload)

    def _talk_udp_reader(self, sock):
        """Чтение RTP из UDP-сокета talk-трека (SETUP без interleaved).
        Живёт, пока cleanup не закроет сокет (OSError → выход)."""
        sock.settimeout(0.5)
        while True:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            parsed = rtp_payload(data)
            if parsed and parsed[0] == 0:          # PCMU
                self._talk_feed(parsed[1])

    def handle_record(self):
        """RECORD (после ANNOUNCE или SETUP talk-трека): подтверждаем —
        аудио потечёт в TalkSession (ленивая — при backchannel её ещё
        нет; пейсер сам отправит TLV 331 по первому пакету)."""
        if (self.talk is None and self.talk_rtp_ch is None
                and self.talk_udp_sock is None):
            self.reply(454, "Session Not Found")
            return
        self.reply(200, "OK", {"Session": self.session_id + ";timeout=60"})

    # ---- отправка медиа -------------------------------------------------------

    def stream_loop(self):
        client = self._chan_client
        vts = random.randrange(1 << 20)
        ats = random.randrange(1 << 20)
        audio_buf = bytearray()
        have_video = 0 in self.tracks
        have_audio = 1 in self.tracks
        fps = 0

        while self.playing.is_set():
            # OwspClient канала мог завершиться (поток умер) — перепривязка
            if client is None or not client.is_alive():
                client = self.chan_client()
                self.subscriber = client.subscribe()
                audio_buf.clear()
            # параметры потока могли обновиться после перепривязки
            have_audio = have_audio and audio_payload_type(client)[0] is not None
            audio_pt = audio_payload_type(client)[0]
            fps = (client.format or {}).get("framerate") or fps or 30
            v_delta = max(1, 90000 // max(fps, 1))
            try:
                kind, payload = self.subscriber.get(timeout=1.0)
            except queue.Empty:
                continue
            if kind == "reset":
                audio_buf.clear()
                continue
            if kind == "video" and have_video:
                vts = (vts + v_delta) & 0xFFFFFFFF
                for pkt in h264_rtp_packets(self.video_pktz, payload, vts):
                    self.send_rtp(0, pkt)
            elif kind == "audio" and have_audio:
                audio_buf += payload
                # G.711: 1 байт = 1 сэмпл, 8000 Гц → 160 байт = 20 мс
                while len(audio_buf) >= 160:
                    chunk = bytes(audio_buf[:160])
                    del audio_buf[:160]
                    ats = (ats + 160) & 0xFFFFFFFF
                    self.send_rtp(1, self.audio_pktz.packet(chunk, audio_pt, ats, True))

    def send_rtp(self, track, pkt):
        rtp = self.tracks.get(track)
        if rtp is None:
            return
        try:
            if rtp.udp_sock is not None:
                rtp.udp_sock.send(pkt)
            else:
                # interleaved: '$' + channel(1 байт) + length(2 байта BE)
                frame = b"$" + struct.pack(">BH", rtp.channel_pair[0], len(pkt)) + pkt
                with self.lock:
                    self.conn.sendall(frame)
        except OSError:
            self.playing.clear()

    def cleanup(self):
        self.playing.clear()
        if self.talk is not None:
            try:
                self.talk.stop()      # флаш остатка + TLV 331 action=2
            except Exception:  # noqa: BLE001
                pass
            self.talk = None
        if self.talk_udp_sock is not None:
            try:
                self.talk_udp_sock.close()   # поток чтения завершится
            except OSError:
                pass
        if self.subscriber and self._chan_client is not None:
            self._chan_client.unsubscribe(self.subscriber)
        for rtp in self.tracks.values():
            if rtp.udp_sock is not None:
                try:
                    rtp.udp_sock.close()
                except OSError:
                    pass
        try:
            self.conn.close()
        except OSError:
            pass
        self.server.remove(self)


class RtspServer:
    def __init__(self, gateway: Gateway, port=8554):
        self.gateway = gateway
        self.port = port
        self._conns = set()
        self._lock = threading.Lock()

    def serve_forever(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(16)
        print("[rtsp] сервер запущен: rtsp://<этот-хост>:%d/ (RTP/UDP и TCP)"
              % self.port, flush=True)
        while True:
            conn, addr = srv.accept()
            handler = RtspConnection(conn, addr, self.gateway, self)
            with self._lock:
                self._conns.add(handler)
            handler.start()

    def remove(self, conn):
        with self._lock:
            self._conns.discard(conn)


# ---------------------------------------------------------------------------
# HTTP-контроль шлюза: /unlock, /status, /events
# ---------------------------------------------------------------------------

class ControlHandler(BaseHTTPRequestHandler):
    """Мини-интерфейс управления шлюзом.

      POST|GET /unlock?ch=1&action=1&delay=1[&pwd=...] — открыть замок
      POST|GET /volume?ch=1&dir=down&steps=3 — громкость локального
                                    динамика панели (TLV 1054)
      POST /talk?ch=1 — громкая связь: тело = сырой µ-law 8 кГц
                          (audio/basic; Content-Length или chunked)
      POST|GET /sync-time — синхронизировать время панели (TLV 1007,
                                    settings-соединение, стримы не трогает)
      GET /mute?ch=1 — «тише» ×12 (глушение локального динамика)
      GET /status — состояние каналов
      GET /events — последние события (замок, звонок, talk, TLV)
    """
    gateway = None  # подставляется в start_control_server()
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # стандартный лог замещаем своим
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._route()

    def do_POST(self):
        # /talk — стриминговое тело (НЕ читаем заранее): чанки µ-law
        # уходят в TalkSession по мере поступления
        path = urllib.parse.urlsplit(self.path).path
        if path == "/talk":
            self._handle_talk()
            return
        self._route()

    def _handle_talk(self):
        """POST /talk?ch=1 — ингресс громкой связи (Content-Type:
        audio/basic или любой; тело — сырой µ-law 8 кГц, Content-Length
        или chunked). Сессия стартует лениво (первый байт → TLV 331),
        конец тела → флаш + 331 action=2."""
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            ch = int(qs.get("ch", qs.get("channel", ["1"]))[0] or 1)
        except ValueError:
            ch = 1
        session = self.gateway.open_talk(ch)
        if session is None:
            self._json(409, {"ok": False,
                             "msg": "talk на канале %d уже идёт" % ch})
            return
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        t0 = time.monotonic()
        try:
            if "chunked" in te:
                while True:
                    line = self.rfile.readline(64)
                    if not line:
                        break
                    try:
                        size = int(line.split(b";")[0].strip(), 16)
                    except ValueError:
                        break
                    if size == 0:
                        while True:            # трейлеры до пустой строки
                            t = self.rfile.readline(1024)
                            if not t or t in (b"\r\n", b"\n"):
                                break
                        break
                    data = self.rfile.read(size)
                    self.rfile.read(2)        # CRLF за чанком
                    if data:
                        session.feed(data)
            else:
                try:
                    clen = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    clen = 0
                if clen <= 0:
                    self._json(411, {"ok": False, "msg":
                                     "нужен Content-Length или chunked"})
                    return
                left = clen
                while left > 0:
                    data = self.rfile.read(min(left, 16384))
                    if not data:
                        break
                    session.feed(data)
                    left -= len(data)
        finally:
            session.stop()
        self._json(200, {"ok": session.error is None, "channel": ch,
                         "bytes": session.bytes_in,
                         "sent": session.bytes_sent,
                         "duration_s": round(time.monotonic() - t0, 1),
                         "error": session.error})

    def _route(self):
        # HTTP/1.1 keep-alive: тело запроса обязано быть прочитано, иначе
        # оно будет воспринято как следующий запрос на этом соединении
        try:
            clen = int(self.headers.get("Content-Length", "0") or 0)
            if clen > 0:
                self.rfile.read(min(clen, 1 << 20))
        except (ValueError, OSError):
            pass
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path in ("/unlock", "/lock"):
                ch = int(qs.get("ch", qs.get("channel", ["1"]))[0] or 1)
                action = int(qs.get("action", ["1"])[0])
                delay = int(qs.get("delay", ["1"])[0])
                pwd = qs.get("pwd", [None])[0]
                ok, msg = self.gateway.unlock(ch, action, delay, pwd)
                self._json(200 if ok else 502,
                           {"ok": ok, "msg": msg, "channel": ch})
            elif parsed.path in ("/volume", "/mute"):
                ch = int(qs.get("ch", qs.get("channel", ["1"]))[0] or 1)
                if parsed.path == "/mute":
                    direction, steps = "down", 12
                else:
                    direction = (qs.get("dir",
                                qs.get("direction", ["down"]))[0]
                                 or "down").lower()
                    steps = int(qs.get("steps", ["1"])[0] or 1)
                ok, msg = self.gateway.volume(ch, direction, steps)
                self._json(200 if ok else 502,
                           {"ok": ok, "msg": msg, "channel": ch})
            elif parsed.path == "/sync-time":
                ok, msg = self.gateway.sync_time()
                self._json(200 if ok else 502, {"ok": ok, "msg": msg})
            elif parsed.path == "/status":
                self._json(200, self.gateway.status())
            elif parsed.path == "/events":
                self._json(200, {"events": self.gateway.events()})
            else:
                self._json(404, {"ok": False, "msg":
                                 "пути: /unlock?ch=N&action=1&delay=1, "
                                 "/volume?ch=1&dir=down&steps=3, /mute, "
                                 "/talk?ch=1 (POST, µ-law), /sync-time, "
                                 "/status, /events"})
        except Exception as exc:  # noqa: BLE001
            try:
                self._json(500, {"ok": False, "msg": repr(exc)})
            except OSError:
                pass


def start_control_server(gateway: Gateway, port: int):
    """Запустить HTTP-контроль в фоне; возвращает httpd (для shutdown)."""
    ControlHandler.gateway = gateway
    httpd = ThreadingHTTPServer(("0.0.0.0", port), ControlHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True,
                    name="http-ctl").start()
    return httpd


# ---------------------------------------------------------------------------
# MQTT: публикация событий / приём команд (paho-mqtt, конфиг в INI-файле)
# ---------------------------------------------------------------------------

def load_mqtt_config(path):
    """Прочитать [mqtt]-секцию конфиг-файла (INI).

    Возвращает dict или None (файла нет / секции нет). Параметры брокера
    и топики — только здесь; креды пустые по умолчанию (открытый брокер),
    при включении авторизации в mosquitto достаточно вписать их в файл.
    """
    if not path or not os.path.isfile(path):
        return None
    cp = configparser.ConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except (configparser.Error, OSError):
        return None
    if not cp.has_section("mqtt"):
        return None
    sec = cp["mqtt"]
    base = (sec.get("base_topic", fallback="slinex/door") or "").strip()
    base = "/".join(x for x in base.split("/") if x) or "slinex/door"
    return {
        "enabled": sec.getboolean("enabled", fallback=True),
        "host": (sec.get("host", fallback="127.0.0.1") or "").strip()
                or "127.0.0.1",
        "port": sec.getint("port", fallback=1883),
        "username": (sec.get("username", fallback="") or "").strip() or None,
        "password": (sec.get("password", fallback="") or "").strip() or None,
        "client_id": (sec.get("client_id", fallback="slinex-gw") or "").strip()
                     or "slinex-gw",
        "base_topic": base,
        "topic_events": (sec.get("topic_events", fallback="events")
                         or "events").strip().strip("/"),
        "topic_commands": (sec.get("topic_commands", fallback="cmd")
                           or "cmd").strip().strip("/"),
        "keepalive": sec.getint("keepalive", fallback=30),
    }


class MqttBridge:
    """MQTT-мост шлюза (paho-mqtt, совместим с API 1.x и 2.x).

    Публикация (QoS 0):
      {base}/{events}/ring    — {"state":"start|end", "channels":[..],
                                 "freq":Гц, "gain_db":дБ, "duration_s":с}
      {base}/{events}/unlock — результат команды замка
      {base}/{events}/volume — результат команды громкости
      {base}/status           — LWT: "offline" при обрыве, "online" онлайн
    Подписка (QoS 0), JSON-полезная нагрузка:
      {base}/{cmd}/unlock  {"channel":1, "action":1, "delay":1[, "pwd":..]}
      {base}/{cmd}/volume  {"channel":1, "direction":"down", "steps":3}
    Команды исполняются рабочим потоком (не сетевым потоком paho) —
    медленный unlock не блокирует keepalive.
    """

    def __init__(self, conf, gateway, on_log=None):
        self.conf = conf
        self.gateway = gateway
        self.log = on_log or (lambda msg: print("[mqtt] %s" % msg, flush=True))
        self.base = conf["base_topic"]
        self._ev = conf["topic_events"]
        self._cmd = conf["topic_commands"]
        self._client = None
        self._q = queue.Queue()
        self._stop = threading.Event()

    def start(self):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.log("paho-mqtt не установлен — MQTT отключён "
                     "(pip install paho-mqtt)")
            return False
        cid = self.conf.get("client_id") or "slinex-gw"
        try:  # paho 2.x: первым аргументом — версия callback-API
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                     client_id=cid)
        except (AttributeError, TypeError):  # paho 1.x
            client = mqtt.Client(client_id=cid)
        self._client = client
        if self.conf.get("username"):
            client.username_pw_set(self.conf["username"],
                                   self.conf.get("password") or "")
        client.will_set("%s/status" % self.base, "offline", qos=0, retain=True)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        host = self.conf.get("host") or "127.0.0.1"
        port = int(self.conf.get("port") or 1883)
        # connect_async: paho сам повторяет подключение, пока брокер
        # недоступен (старт шлюза раньше брокера и т.п.)
        client.connect_async(host, port, int(self.conf.get("keepalive") or 30))
        client.loop_start()
        threading.Thread(target=self._worker, daemon=True,
                         name="mqtt-cmd").start()
        self.log("запущен: %s:%d, base=%s" % (host, port, self.base))
        return True

    # -- колбэки paho (VERSION1-сигнатуры) -----------------------------------

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            t_unlock = "%s/%s/unlock" % (self.base, self._cmd)
            t_volume = "%s/%s/volume" % (self.base, self._cmd)
            client.subscribe([(t_unlock, 0), (t_volume, 0)])
            client.publish("%s/status" % self.base, "online",
                           qos=0, retain=True)
            self.log("подключён к брокеру; подписки: %s, %s"
                     % (t_unlock, t_volume))
        else:
            self.log("брокер отклонил подключение: rc=%s" % rc)

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8") or "{}")
            if not isinstance(payload, dict):
                raise ValueError("не объект")
        except (ValueError, UnicodeDecodeError):
            self.log("некорректный JSON в %s: %r"
                     % (msg.topic, msg.payload[:64]))
            payload = {}
        self._q.put((msg.topic, payload))

    # -- исполнитель команд ----------------------------------------------------

    def _worker(self):
        while not self._stop.is_set():
            try:
                topic, payload = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._dispatch(topic, payload)
            except Exception as exc:  # noqa: BLE001
                self.log("ошибка команды %s: %r" % (topic, exc))

    def _dispatch(self, topic, p):
        if topic.endswith("/unlock"):
            ch = int(p.get("channel") or p.get("ch") or 1)
            action = int(p.get("action") or 1)
            delay = int(p.get("delay") or 1)
            pwd = p.get("pwd")
            ok, msg = self.gateway.unlock(ch, action, delay, pwd)
            self.log("cmd unlock ch=%d: %s" % (ch, msg))
        elif topic.endswith("/volume"):
            ch = int(p.get("channel") or p.get("ch") or 1)
            direction = str(p.get("direction") or p.get("dir") or "down")
            steps = int(p.get("steps") or 1)
            ok, msg = self.gateway.volume(ch, direction, steps)
            self.log("cmd volume %s×%d ch=%d: %s"
                     % (direction, steps, ch, msg))
        else:
            self.log("команда без обработчика: %s" % topic)

    # -- публикация --------------------------------------------------------------

    def publish_event(self, kind, evt):
        """Событие шины → {base}/{events}/{kind} (вызывает Gateway)."""
        if self._client is None:
            return
        topic = "%s/%s/%s" % (self.base, self._ev, kind)
        try:
            self._client.publish(topic, json.dumps(evt, ensure_ascii=False),
                                 qos=0)
        except Exception:  # noqa: BLE001
            pass

    def stop(self):
        self._stop.set()
        if self._client is not None:
            try:
                self._client.publish("%s/status" % self.base, "offline",
                                     qos=0, retain=True)
                self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# LAN discovery — поиск домофона (как в приложении)
# ---------------------------------------------------------------------------

def discover(timeout=5):
    req = struct.pack("<HH", 40967, 32) + b"0".ljust(32, b"\x00")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for target in (("255.255.255.255", 1500), ("235.10.10.10", 1500)):
        try:
            s.sendto(req, target)
        except OSError:
            pass
    found = {}
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        s.settimeout(max(0.1, end - time.monotonic()))
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            break
        except OSError:
            break
        pos = 0
        while len(data) - pos >= 4:
            msg_type, msg_len = struct.unpack_from("<HH", data, pos)
            pos += 4
            body = data[pos: pos + msg_len]
            pos += msg_len
            if msg_type == 40968 and len(body) >= 68:
                dev_id = body[0:32].split(b"\x00")[0].decode("latin-1", "replace")
                bindport = struct.unpack_from("<H", body, 34)[0]
                if dev_id and dev_id not in found:
                    found[dev_id] = (addr[0], bindport)
                    print("найдено: UID=%s  ip=%s  owsp_port=%d"
                          % (dev_id, addr[0], bindport), flush=True)
    s.close()
    if not found:
        print("устройства не найдены (укажите IP/порт вручную: --host ... --port ...)",
              flush=True)
    return found


# ---------------------------------------------------------------------------
# удалённая перезагрузка (кнопка «Перезагрузить» в настройках приложения)
# ---------------------------------------------------------------------------

def reboot_device(host, port, user, password, timeout=10.0,
                  device_id=None, flag=None, pause=5.0, retries=2):
    """Перезагрузить домофон по сети и выйти (TLV 465).

    Повторяет путь приложения (DeviceRemoteSettingActivity →
    com.goolink.comm.DeviceConfig.configReboot): отдельное соединение
    в тот же OWSP-порт, логин-настройка (streamMode=3
    OWSP_MODE_SETTING, dataType=0, channelMask=1), и СРАЗУ после
    подтверждения логина — TLV 465 DeviceRestartRequest (4 нуля).
    Никакого keep-alive и пауз после логина: в DeviceConfig
    вызывается sendConfig(), пишущий команду немедленно.

    Варианты полей логина (deviceId, flag) перебираются на свежих
    соединениях: (0,2), (1,2), (0,0). Параметры device_id/flag
    сужают перебор: указан один — семейство из двух, указаны оба —
    ровно один вариант.

    Между вариантами делается пауза pause секунд, а код 5 (лимит
    подключений — слот только что закрытой settings-сессии ещё не
    освобождён прошивкой) дополнительно поворяется retries раз после
    той же паузы (наблюдение 28.10: без паузы второй вариант ловит
    код 5 и не проверяется вовсе).

    Возвращает (код_выхода, сообщение):
      0 — устройство подтвердило перезагрузку (TLV 466);
      2 — логин отклонён (код в сообщении);
      3 — прошивка игнорирует TLV 465 (не реализует);
      4 — сеть/протокол недоступны.
    """
    if device_id is not None and flag is not None:
        variants = ((device_id, flag),)
    elif device_id is not None:
        variants = ((device_id, 2), (device_id, 0))
    elif flag is not None:
        variants = ((0, flag), (1, flag))
    else:
        # по умолчанию: deviceId=0 + flag=2 (стрим-стиль deviceId +
        # признак сессии-настройки); как приложение (deviceId=1, flag=2);
        # чистый стрим-стиль (0, 0)
        variants = ((0, 2), (1, 2), (0, 0))
    last_code = None
    outcomes = []   # (deviceId, flag, исход) для итогового отчёта
    for vi, (dev_id, flg) in enumerate(variants):
        if vi > 0 and pause > 0:
            time.sleep(pause)  # даём прошивке освободить слот
        tries = 0
        while True:
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
            except OSError as exc:
                return 4, "не удалось подключиться к %s:%s: %r" % (host, port, exc)
            try:
                sock.settimeout(timeout)
                # как в приложении: packet_seq логина = 2, команда — seq=1
                # (configReboot() собирает пакет ДО логина, m_sequence=1)
                sock.sendall(build_login(user, password, 1, 3, 0, True,
                                         device_id=dev_id, flag=flg, seq=2))
                # ждём именно ответ логина (версия может прийти отдельным
                # сегментом — не гонимся, как когда-то в _login, за эхом)
                deadline = time.monotonic() + timeout
                result = None
                buf = b""
                while time.monotonic() < deadline and result is None:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        raise ConnectionError("соединение закрыто при логине")
                    buf += chunk
                    packets, buf = parse_owsp_packets(buf)
                    for tlvs in packets:
                        for tlv_type, value in tlvs:
                            if tlv_type == TLV_LOGIN_RSP and len(value) >= 2:
                                result = struct.unpack_from("<H", value)[0]
                if result == 5 and tries < retries:
                    # слот предыдущей сессии ещё занят — подождать и
                    # повторить ЭТОТ ЖЕ вариант на свежем соединении
                    tries += 1
                    print("[reboot] код=5 (лимит подключений) — пауза %.1f с, "
                          "повтор %d/%d варианта deviceId=%d, flag=%d"
                          % (pause, tries, retries, dev_id, flg), flush=True)
                    if pause > 0:
                        time.sleep(pause)
                    continue
                if result != 1:
                    if result is not None:
                        last_code = result
                        outcomes.append((dev_id, flg, "логин отклонён, "
                                         "код=%d" % result))
                        print("[reboot] логин-настройка отклонён, код=%d "
                              "(deviceId=%d, flag=%d — пробую другой вариант "
                              "полей)" % (result, dev_id, flg), flush=True)
                    else:
                        outcomes.append((dev_id, flg, "нет ответа логина"))
                    break
                # sendConfig(): команда — НЕМЕДЛЕННО после ответа логина
                sock.sendall(owsp_packet([(TLV_REBOOT_REQ, b"\x00" * 4)], 1))
                deadline = time.monotonic() + 10.0
                closed = False
                while time.monotonic() < deadline:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        closed = True
                        break
                    buf += chunk
                    packets, buf = parse_owsp_packets(buf)
                    for tlvs in packets:
                        for tlv_type, value in tlvs:
                            if tlv_type == TLV_REBOOT_RSP:
                                return 0, "устройство подтвердило " \
                                          "перезагрузку (TLV 466)"
                # обрыв БЕЗ TLV 466 — НЕ успех: прошивка STM83xx так рвёт
                # settings-сессию на неизвестной ей команде (наблюдение
                # 28.10: соединение закрыто, устройство не перезагрузилось)
                if closed:
                    outcomes.append((dev_id, flg,
                                     "465 отправлен, соединение закрыто без "
                                     "ответа (команда проигнорирована)"))
                    print("[reboot] deviceId=%d, flag=%d: соединение закрыто "
                          "без TLV 466 — команда проигнорирована"
                          % (dev_id, flg), flush=True)
                else:
                    outcomes.append((dev_id, flg, "нет ответа на 465"))
                    print("[reboot] deviceId=%d, flag=%d: нет ответа на TLV 465"
                          % (dev_id, flg), flush=True)
                break
            except (OSError, ValueError, ConnectionError) as exc:
                return 4, "ошибка протокола: %r" % exc
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
    if last_code is not None and not any("465" in o[2] or "закрыто" in o[2]
                                         for o in outcomes):
        return 2, "логин отклонён, код=%d" % last_code
    summary = "; ".join("deviceId=%d,flag=%d: %s" % o for o in outcomes)
    return 3, ("прошивка не выполняет TLV 465 ни в одном варианте полей "
               "[%s]. Удалённой перезагрузки в протоколе больше нет "
               "(весь список TLV проверен по APK); остальные способы — "
               "telnet/web/adb (см. scan_device.py), питание/PoE, либо "
               "штатный ежедневный ребут ~06:50" % summary)


# ---------------------------------------------------------------------------
# синхронизация времени (кнопка «Синхронизировать время» в настройках)
# ---------------------------------------------------------------------------

def sync_time_device(host, port, user, password, timeout=10.0,
                     pause=5.0, retries=2, when=None):
    """Синхронизировать время панели (TLV 1007/1008) и выйти.

    ДВА варианта из APK, оба — отдельное settings-соединение
    (streamMode=3 OWSP_MODE_SETTING, channelMask=1, deviceId=0, flag=2):

      A. DeviceConfig (кнопка «Синхронизировать время» в настройках):
         dataType=0, логин packet_seq=2 → ждать result=1 → TLV 1007 с
         packet_seq=1 (команда собирается до логина, m_sequence=1);
      B. GooLinkAdd.sendTimeAsyncCmd (тайм-синк при добавлении
         устройства): dataType=2 (OWSP_MIXED_DATA), логин packet_seq=1,
         и TLV 1007 с packet_seq=1 — СРАЗУ за логином, НЕ дожидаясь
         ответа логина (sendSettingUserAndPwd не инкрементит
         m_sequence — команда уходит с тем же seq).

    ВАЖНО: TLV 1007 в СТРИМ-сессии прошивка НЕ принимает — закрывает
    соединение без ответа (наблюдение 31.10: канал умер ровно на
    тайм-синке, сессия 33 с). На settings-соединении с dataType=0
    (вариант A) — та же картина (наблюдение 31.10, 11:22 и 11:38:
    «соединение закрыто без TLV 1008»).

    Диагностика: в КАЖДОМ варианте логируются все TLV после логина;
    TLV 1006 (NOTRECOGNIZE) — прямой ответ прошивки «команда не
    распознана». Код 5 (лимит подключений — 4 boot-канала шлюза)
    повтора́ется с паузой (как в reboot_device).

    Возвращает (код_выхода, сообщение):
      0 — время синхронизировано (TLV 1008 result=1);
      2 — логин-настройка отклонён в обоих вариантах;
      3 — 1007 не принят в обоих вариантах (1006/обрыв/тишина);
      4 — сеть/протокол недоступны.
    """
    variants = (
        ("A(DeviceConfig: dt=0, 1007 после ответа логина)", 0),
        ("B(GooLinkAdd: dt=2, 1007 сразу за логином)", 2),
    )
    outcomes = []
    login_codes = []   # коды TLV 42 по вариантам (None = ответа не было)
    for vi, (vname, dt) in enumerate(variants):
        if vi > 0 and pause > 0:
            time.sleep(pause)   # слот предыдущей settings-сессии
        tries = 0
        while True:
            try:
                sock = socket.create_connection((host, port),
                                                timeout=timeout)
            except OSError as exc:
                return 4, ("не удалось подключиться к %s:%s: %r"
                           % (host, port, exc))
            try:
                sock.settimeout(timeout)
                # вариант A: логин seq=2 (m_sequence инкрементится
                # сборкой команды ДО логина); B: seq=1 у обоих
                lseq = 2 if vi == 0 else 1
                sock.sendall(build_login(user, password, 1, 3, dt, True,
                                         device_id=0, flag=2, seq=lseq))
                if vi == 1:
                    # GooLinkAdd: команда — сразу, тем же seq
                    sock.sendall(owsp_packet(
                        [(TLV_TIMESYNC_REQ, build_time_sync_req(when))],
                        lseq))
                result = None    # TLV 42
                answer = None    # TLV 1008 (result,) | "1006" | None
                rbuf = b""
                deadline = time.monotonic() + timeout
                # читаем всё: ответ логина, 1008, 1006, обрыв
                while time.monotonic() < deadline and answer is None:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        answer = "closed"
                        break
                    rbuf += chunk
                    packets, rbuf = parse_owsp_packets(rbuf)
                    for tlvs in packets:
                        for tlv_type, value in tlvs:
                            if (tlv_type == TLV_LOGIN_RSP
                                    and len(value) >= 2):
                                result = struct.unpack_from("<H", value)[0]
                                if vi == 0 and result == 1:
                                    # sendConfig(): сразу после ответа
                                    sock.sendall(owsp_packet(
                                        [(TLV_TIMESYNC_REQ,
                                          build_time_sync_req(when))], 1))
                            elif (tlv_type == TLV_TIMESYNC_RSP
                                    and len(value) >= 2):
                                answer = ("1008",
                                          struct.unpack_from(
                                              "<H", value)[0])
                            elif tlv_type == TLV_NOT_RECOGNIZE:
                                answer = ("1006", None)
                if result == 5 and tries < retries and answer is None:
                    tries += 1
                    print("[sync-time] %s: код=5 (лимит подключений) — "
                          "пауза %.1f с, повтор %d/%d"
                          % (vname, pause, tries, retries), flush=True)
                    if pause > 0:
                        time.sleep(pause)
                    continue
                # финальный код TLV 42 варианта (после ретраев) — до
                # классификации исхода; break в try выходит из while
                # МИМО кода после finally, поэтому append только здесь
                login_codes.append(result)
                if answer is None:
                    outcomes.append("%s: нет ответа (логин=%s)"
                                    % (vname, result))
                    break
                if answer == "closed":
                    outcomes.append("%s: соединение закрыто без TLV 1008 "
                                    "(логин=%s)" % (vname, result))
                    print("[sync-time] %s: прошивка закрыла соединение "
                          "без ответа" % vname, flush=True)
                    break
                kind, r = answer
                if kind == "1006":
                    outcomes.append("%s: TLV 1006 — прошивка НЕ РАСПОЗНАЛА "
                                    "команду" % vname)
                    print("[sync-time] %s: TLV 1006 (NotRecognize) — "
                          "команда не поддерживается" % vname, flush=True)
                    break
                # TLV 1008
                if r == 1:
                    return 0, ("время панели синхронизировано "
                               "(TLV 1008 result=1, вариант %s)" % vname)
                outcomes.append("%s: 1008 result=%d (отказ)" % (vname, r))
                break
            except (OSError, ValueError, ConnectionError) as exc:
                return 4, "ошибка протокола: %r" % exc
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        # вариант исчерпан — следующий
    if login_codes and all(c is not None and c != 1 for c in login_codes):
        return 2, ("логин-настройка отклонён в обоих вариантах (коды %s): "
                   "%s" % (login_codes, "; ".join(outcomes)))
    return 3, ("прошивка не принимает TLV 1007: %s — сетевая синхронизация "
               "времени не поддерживается (как и TLV 465/1054)"
               % "; ".join(outcomes))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="RTSP-шлюз для Slinex SL-10PT (OWSP → RTSP, H.264 + G.711a)")
    ap.add_argument("--host", help="IP-адрес домофона")
    ap.add_argument("--port", type=int, default=100,
                    help="TCP-порт OWSP на домофоне (по умолчанию 100)")
    ap.add_argument("--user", default="admin",
                    help="имя пользователя (по умолчанию admin)")
    ap.add_argument("--password", default="", help="пароль (по умолчанию пустой)")
    ap.add_argument("--channel", type=int, default=1,
                    help="номер канала для пути /camera (с 1)")
    ap.add_argument("--channels", default=None,
                    help="каналы, открываемые на старте: '1,2,3,4' или 'all' "
                         "(все, по числу каналов из TLV 70); по умолчанию — только --channel")
    ap.add_argument("--sub", action="store_true",
                    help="(устарело: суб-поток теперь по умолчанию, как в "
                         "референсном приложении)")
    ap.add_argument("--main", action="store_true",
                    help="запрашивать основной поток (streamMode=0); "
                         "по умолчанию суб-поток (streamMode=1), как в приложении "
                         "(на STM83xx формат НЕ меняется — у панели один режим "
                         "энкодера 320x240@5fps; проверено 31.10)")
    ap.add_argument("--keepalive", type=float, default=0.0, metavar="SEC",
                    help="интервал keep-alive (TLV 49) в секундах; 0 — отключить "
                         "(по умолчанию 0 — референсное приложение не шлёт "
                         "keep-alive вовсе, сессия живёт без него)")
    ap.add_argument("--tlv44", action="store_true",
                    help="после логина отправить явный запрос потока (TLV 44)")
    ap.add_argument("--tlv427", action="store_true",
                    help="после логина отправить TLV 427 (включение аудиотракта); "
                         "референсное приложение его НЕ шлёт")
    ap.add_argument("--audio-ack", action="store_true",
                    help="подтверждать аудио-метки TLV 97 (эхо таймстампа); "
                         "референсное приложение их НЕ шлёт")
    ap.add_argument("--data-type", type=int, default=2, metavar="N",
                    choices=(0, 1, 2),
                    help="тип данных в логине: 0=видео, 1=аудио, 2=смешанный "
                         "(по умолчанию 2; попробуйте 0 для отладки)")
    ap.add_argument("--recycle", type=float, default=0.0, metavar="SEC",
                    help="принудительно переподключаться каждые N секунд "
                         "(обход жёсткого тайм-аута сессии прошивки)")
    ap.add_argument("--idle-timeout", type=float, default=15.0, metavar="SEC",
                    help="сторож простоя: если N секунд нет данных от "
                         "домофона (TCP жив, но прошивка молчит — «зомби»), "
                         "соединение пересоздаётся (по умолчанию 15; "
                         "0 = выключить)")
    ap.add_argument("--dump", metavar="FILE",
                    help="отладочный дамп протокола OWSP в файл (текст)")
    ap.add_argument("--rtsp-port", type=int, default=8554)
    ap.add_argument("--record", metavar="FILE",
                    help="писать H.264 в файл (шаблон может содержать {ch})")
    ap.add_argument("--discover", action="store_true",
                    help="поиск домофона в LAN и выход")
    ap.add_argument("--reboot", action="store_true",
                    help="удалённо перезагрузить домофон (логин-настройка "
                         "streamMode=3 + TLV 465, как кнопка в приложении) "
                         "и выйти")
    ap.add_argument("--reboot-device-id", type=int, default=None, metavar="ID",
                    help="с --reboot: только этот deviceId в логине-настройке "
                         "(по умолчанию перебор: (0,2), (1,2), (0,0); "
                         "указан только deviceId — семейство (ID,2), (ID,0))")
    ap.add_argument("--reboot-flag", type=int, default=None, metavar="F",
                    help="с --reboot: только этот flag в логине-настройке "
                         "(указан только flag — семейство (0,F), (1,F))")
    ap.add_argument("--reboot-pause", type=float, default=5.0, metavar="SEC",
                    help="с --reboot: пауза между вариантами и повторами "
                         "логина — прошивка освобождает слот подключения "
                         "не мгновенно, без паузы ловится код 5 "
                         "(по умолчанию 5 с)")
    ap.add_argument("--reboot-retries", type=int, default=2, metavar="N",
                    help="с --reboot: повторов логина при коде 5 (лимит "
                         "подключений), по умолчанию 2")
    ap.add_argument("--unlock", action="store_true",
                    help="открыть замок (TLV 425 в стрим-сессии, как кнопка "
                         "в приложении) и выйти")
    ap.add_argument("--lock-password", default=None, metavar="PWD",
                    help="пароль замка (по умолчанию — пароль логина)")
    ap.add_argument("--lock-delay", type=int, default=1, metavar="SEC",
                    help="время удержания реле замка, с (по умолчанию 1)")
    ap.add_argument("--lock-action", type=int, default=1, metavar="N",
                    help="действие замка: 1 = открыть (по умолчанию), "
                         "0 = закрыть")
    ap.add_argument("--http-port", type=int, default=8555, metavar="PORT",
                    help="HTTP-контроль шлюза: POST /unlock?ch=N, /volume, "
                         "/mute, GET /status, /events (по умолчанию 8555; "
                         "0 = выключить)")
    ap.add_argument("--no-ring", action="store_true",
                    help="отключить детектор звонка по аудио "
                         "(включён по умолчанию)")
    ap.add_argument("--ring-gain-db", type=float, default=10.0, metavar="DB",
                    help="ring-детектор: порог мощности над фоном, дБ "
                         "(по умолчанию 10; реальный гудок +18..+55 дБ, "
                         "фон без звонка ±1 дБ)")
    ap.add_argument("--ring-tonality", type=float, default=8.0, metavar="R",
                    help="ring-детектор: порог тональности окна "
                         "(P(f0)/P_total, по умолчанию 8; реальный гудок "
                         "39..52, максимум белого шума ~4)")
    ap.add_argument("--ring-start-windows", type=int, default=3, metavar="N",
                    help="ring-детектор: тоновых окон (100 мс) подряд для "
                         "старта (по умолчанию 3)")
    ap.add_argument("--ring-end-silence", type=float, default=1.0,
                    metavar="SEC",
                    help="ring-детектор: тишины до конца звонка, с "
                         "(по умолчанию 1.0)")
    ap.add_argument("--ring-warmup", type=float, default=5.0, metavar="SEC",
                    help="ring-детектор: прогрев после старта сессии — "
                         "учим базлайн, не стреляя (защита от стартовой "
                         "транзиентки аудиотракта; по умолчанию 5, 0 = выкл)")
    ap.add_argument("--ring-max", type=float, default=180.0, metavar="SEC",
                    help="ring-детектор: принудительный end, если звонок "
                         "активен дольше N секунд (страховка от замолчавшего "
                         "аудио; по умолчанию 180, 0 = выкл)")
    ap.add_argument("--mute-local", type=int, default=0, metavar="N",
                    help="после каждого логина N × «громкость вниз» "
                         "(TLV 1054) — глушение локального динамика панели")
    ap.add_argument("--talk-gain-shift", type=int, default=0, metavar="N",
                    help="громкая связь (talk): сдвиг усиления микрофона "
                         "на N бит (аналог calc1 «>>2» в приложении — "
                         "эхо-защита); >0 тише, <0 громче, 0 = без изменений")
    ap.add_argument("--sync-time", action="store_true",
                    help="one-shot: синхронизировать время панели (TLV 1007, "
                         "локальное время хоста) и выйти")
    ap.add_argument("--sync-time-every", type=float, default=0.0,
                    metavar="HOURS",
                    help="периодическая синхронизация времени панели каждые "
                         "N часов (в работающем шлюзе; 0 = выкл. Полезно на "
                         "случай сброса часов при ежедневном ребуте ~06:50)")
    ap.add_argument("--config", metavar="FILE",
                    help="путь к конфигу INI с секцией [mqtt] (по умолчанию "
                         "slinex_gateway.conf рядом со скриптом)")
    ap.add_argument("--no-mqtt", action="store_true",
                    help="отключить MQTT независимо от конфига")
    args = ap.parse_args()

    if args.discover:
        discover()
        return 0
    if not args.host:
        ap.error("укажите --host (или --discover для поиска в LAN)")
    if args.reboot:
        code, msg = reboot_device(args.host, args.port, args.user,
                                  args.password,
                                  device_id=args.reboot_device_id,
                                  flag=args.reboot_flag,
                                  pause=max(0.0, args.reboot_pause),
                                  retries=max(0, args.reboot_retries))
        print("[reboot] %s" % msg, flush=True)
        return code
    if args.unlock:
        # one-shot: поднимаем стрим-сессию (как окно приложения), ждём
        # I-кадр (приложение шлёт замок только при работающем стриме),
        # команда, ждём TLV 426, выходим
        gw = Gateway(args.host, args.port, args.user, args.password,
                     channels=[args.channel],
                     lock_password=args.lock_password)
        client = gw.get_client(args.channel)
        if not client.wait_ready(timeout=15):
            print("[unlock] не удалось подключиться: %s"
                  % (client.login_error or "нет ответа/нет кадров"), flush=True)
            gw.stop_all()
            return 1
        ok, msg = client.lock(args.lock_password or args.password,
                              args.lock_action, args.lock_delay)
        print("[unlock] %s" % msg, flush=True)
        gw.stop_all()
        return 0 if ok else 2
    if args.sync_time:
        # one-shot: settings-соединение как в приложении (DeviceConfig);
        # TLV 1007 в стрим-сессии прошивка НЕ принимает — рвёт соединение
        code, msg = sync_time_device(args.host, args.port, args.user,
                                     args.password)
        print("[sync-time] %s" % msg, flush=True)
        return code

    # список стартовых каналов
    open_all = False
    if args.channels:
        if args.channels.strip().lower() == "all":
            open_all = True
            boot = [args.channel]
        else:
            try:
                boot = sorted({int(x) for x in args.channels.split(",")
                               if x.strip()})
            except ValueError:
                ap.error("--channels: ожидается список вида 1,2,3,4 или all")
            if not boot or any(c < 1 or c > Gateway.MAX_CHANNELS for c in boot):
                ap.error("--channels: каналы от 1 до %d" % Gateway.MAX_CHANNELS)
            if args.channel not in boot:
                boot.insert(0, args.channel)
    else:
        boot = [args.channel]

    ring_cfg = None
    if not args.no_ring:
        ring_cfg = {"gain_db": args.ring_gain_db,
                    "min_tonality": args.ring_tonality,
                    "start_windows": args.ring_start_windows,
                    "end_silence_s": args.ring_end_silence,
                    "warmup_s": max(0.0, args.ring_warmup)}

    gateway = Gateway(args.host, args.port, args.user, args.password,
                      channels=boot, sub_stream=not args.main,
                      record_path=args.record,
                      keepalive_interval=max(0.0, args.keepalive),
                      data_type=args.data_type,
                      send_tlv44=args.tlv44,
                      send_tlv427=args.tlv427,
                      send_audio_ack=args.audio_ack,
                      recycle_secs=max(0.0, args.recycle),
                      idle_timeout=max(0.0, args.idle_timeout),
                      dump_path=args.dump,
                      lock_password=args.lock_password,
                      ring_cfg=ring_cfg,
                      mute_local_steps=max(0, args.mute_local),
                      ring_max_s=max(0.0, args.ring_max),
                      talk_gain_shift=args.talk_gain_shift)

    # MQTT: конфиг [mqtt] в INI-файле (брокер/креды/топики); --no-mqtt
    # выключает принудительно. Все события шины публикуются в брокер,
    # команды unlock/volume приходят обратно по подписке.
    if not args.no_mqtt:
        conf_path = args.config
        if conf_path is None:
            conf_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "slinex_gateway.conf")
        conf = load_mqtt_config(conf_path)
        if conf is None and args.config:
            print("[mqtt] конфиг %s не найден или без секции [mqtt] — "
                  "MQTT выключен" % args.config, flush=True)
        if conf and conf["enabled"]:
            bridge = MqttBridge(conf, gateway)
            if bridge.start():
                gateway.attach_mqtt(bridge)
        elif conf and not conf["enabled"]:
            print("[mqtt] отключён в конфиге (enabled=0)", flush=True)
    if args.http_port > 0:
        start_control_server(gateway, args.http_port)
        print("[http] контроль: http://<этот-хост>:%d/unlock?ch=1 "
              "(также /status, /events)" % args.http_port, flush=True)
    gateway.boot()
    if open_all:
        gateway.open_all()

    first = gateway.get_client(gateway.default_channel)
    if not first.wait_ready(timeout=20):
        print("[!] не удалось получить поток канала %d: %s"
              % (gateway.default_channel,
                 first.login_error or "нет ответа/нет кадров"), flush=True)
        print("    проверьте IP/порт/логин; порт OWSP по умолчанию 100", flush=True)
        gateway.stop_all()
        return 1

    fmt = first.format or {}
    audio_kind = {31257: "G.711a", 31269: "G.711u"}.get(fmt.get("wave_format"))
    print("[+] канал %d: поток получен (%sx%s @%dfps, аудио: %s)"
          % (gateway.default_channel, fmt.get("width", "?"),
             fmt.get("height", "?"), fmt.get("framerate", "?"),
             audio_kind or "нет"), flush=True)
    extra = [ch for ch in gateway._clients if ch != gateway.default_channel]
    if extra:
        print("[+] также открыты каналы: %s (rtsp://<host>:%d/cameraN)"
              % (", ".join(str(c) for c in sorted(extra)), args.rtsp_port), flush=True)
    else:
        print("[i] прочие каналы доступны лениво: rtsp://<host>:%d/cameraN"
              % args.rtsp_port, flush=True)

    # периодическая синхронизация времени панели (TLV 1007): первая —
    # через ~30 с после старта (когда каналы точно подняты), затем каждые
    # N часов; страховка на сброс часов при ежедневном ребуте ~06:50
    if args.sync_time_every > 0:
        interval = max(0.05, args.sync_time_every) * 3600.0

        def _timesync_loop():
            time.sleep(30.0)
            while True:
                try:
                    gateway.sync_time()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(interval)

        threading.Thread(target=_timesync_loop, daemon=True,
                         name="timesync").start()
        print("[time] синхронизация времени панели: каждые %.1f ч"
              % args.sync_time_every, flush=True)

    server = RtspServer(gateway, port=args.rtsp_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] остановка", flush=True)
    finally:
        gateway.stop_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
