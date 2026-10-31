# slinex_rtsp

RTSP-шлюз для IP-видеодомофонов **Slinex** (и других устройств на платформе
Gooclient/Goolink «Mobile Eye Door», железо STM83xx; проверен на Slinex SL-10PT).

Домофон отдаёт H.264 + G.711 по проприетарному бинарному протоколу **OWSP/TLV
поверх TCP** и не имеет ни RTSP, ни ONVIF. Шлюз разговаривает с ним на его
языке (логин, поток, команды) и превращает это в обычный RTSP + удобные
интерфейсы: HTTP API, MQTT, громкая связь (two-way audio) — включая
интеграцию с [go2rtc](https://github.com/AlexxIT/go2rtc).

Протокол реверс-инжинирен по официальному Android-приложению
(`com.gooclient.mobileeyedoor.plus`); полная документация — в
[PROTOCOL.md](PROTOCOL.md), история исследования и бэклог — в
[BACKLOG.md](BACKLOG.md).

## Возможности

- **RTSP-сервер** (RTP/UDP и RTP/TCP interleaved): каждый канал панели —
  свой URL (`rtsp://host:8554/camera1` … `/camera4`, а также `/camN`, `/chN`)
- **Многоканальность**: каналы STM83xx — вызывные панели (у каждой свой
  микрофон/динамик/замок); своё OWSP-соединение на канал, как в приложении
- **Детектор вызова (звонка) по аудио**: протокольного события звонка нет —
  единственный след это рингтон; частотно-агностичный детектор (мощность +
  Goertzel-тональность), события в HTTP/MQTT
- **Открытие замка** (TLV 425): one-shot CLI, HTTP, MQTT
- **Громкая связь (talk)** — три ингресса:
  - HTTP `POST /talk` (сырой µ-law 8 кГц),
  - RTSP `ANNOUNCE+SETUP+RECORD` (ffmpeg),
  - **RTSP backchannel** (ONVIF Profile T, как Dahua/Hikvision) —
    two-way audio в [go2rtc](https://github.com/AlexxIT/go2rtc)
    (кнопка микрофона в WebRTC-плеере)
- **MQTT-мост**: события (ring/unlock/talk/tlv) в брокер, команды обратно;
  LWT-статус; конфиг в INI
- **Отказоустойчивость**: авторесинк потока по маркеру кадра (мусор от
  прошивки не роняет сессию), backoff-реконнекты, сторож «зомби»-сессий,
  обход лимита подключений устройства
- Только стандартная библиотека Python 3.8+ (paho-mqtt — опционально)

## Быстрый старт

```bash
# найти домофон в LAN (UDP broadcast/multicast :1500)
./slinex_rtsp.py --discover

# запустить шлюз (порт OWSP сообщается при поиске; «классический» — 100)
./slinex_rtsp.py --host 192.168.1.50 --port 10510 \
    --user admin --password <пароль> --channels all

# смотреть (VLC/ffplay/любой RTSP-клиент)
ffplay -rtsp_transport tcp rtsp://127.0.0.1:8554/camera1
```

Формат от панели: 320×240 @5fps H.264 + G.711 µ-law 8 кГц моно
(на этом железе основной и суб-поток одинаковы — один режим энкодера).

## HTTP API (порт `--http-port`, по умолчанию 8555)

| Запрос | Действие |
|---|---|
| `POST /unlock?ch=1&action=1&delay=1[&pwd=…]` | открыть замок канала |
| `POST /talk?ch=1` | громкая связь: тело = сырой µ-law 8 кГц |
| `POST /volume?ch=1&dir=down&steps=3` | громкость локального динамика* |
| `GET /status` | состояние каналов/звонка/talk |
| `GET /events` | последние события |

\* на проверенной прошивке STM83xx не поддерживается — см. «Ограничения».

## Громкая связь

```bash
# файл в динамик панели (5 с синус 440 Гц)
python3 - <<'EOF'
import math, sys, urllib.request
sys.path.insert(0, ".")
from slinex_rtsp import ULAW_ENCODE
tone = bytes(ULAW_ENCODE[(int(8000 * math.sin(2 * math.pi * 440 * i / 8000.0))
                          + 32768) & 0xFFFF] for i in range(40000))
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8555/talk?ch=1", data=tone, method="POST",
    headers={"Content-Type": "audio/basic"})).read()
EOF

# живой микрофон через ffmpeg
ffmpeg -f avfoundation -i :0 -acodec pcm_mulaw -ar 8000 -ac 1 \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/camera1/talk
```

### go2rtc (two-way audio)

Добавьте шлюз как RTSP-источник — в DESCRIBE отдаётся talk-трек
`trackID=2 a=sendonly` (ONVIF Profile T backchannel), go2rtc сам определит
two-way audio и включит кнопку микрофона в плеере:

```yaml
streams:
  door1: rtsp://127.0.0.1:8554/camera1
```

Слот динамика занимается только реальным звуком: 2 секунды тишины —
и канал свободен (push-to-talk семантика).

## MQTT

Конфиг — INI-файл `slinex_gateway.conf` рядом со скриптом
(шаблон: `slinex_gateway.conf.example`):

```ini
[mqtt]
enabled = 1
host = 127.0.0.1
port = 1883
base_topic = slinex/door
```

- публикация: `{base}/events/ring|unlock|talk|volume|tlv`, `{base}/status`
  (LWT: offline/online)
- подписка: `{base}/cmd/unlock` `{"channel":1,"action":1,"delay":1}`,
  `{base}/cmd/volume` `{"channel":1,"direction":"down","steps":3}`

## Ограничения прошивки STM83xx (проверено на железе)

| Команда | Статус |
|---|---|
| TLV 425 замок | работает (канал 1-based) |
| TLV 331/332 громкая связь | работает |
| TLV 1007 синхронизация времени | рвёт соединение — не поддерживается |
| TLV 1054 громкость | рвёт соединение — не поддерживается |
| TLV 465 перезагрузка | рвёт соединение — не поддерживается |

Неизвестные прошивке клиентские TLV рвут соединение; весь класс
«настроек» на этой панели мёртв. Сетевой вызов (звонок) протокольно не
событийный — детектор работает по аудио.

## Тесты

Мок-домофон на localhost, без железа:

```bash
for t in itest.py itest2.py itest3.py itest4.py itest5.py itest6.py \
         itest7.py itest8.py itest9.py itest10.py itest11.py; do
    python3 "$t" || echo "FAIL: $t"
done
```

Покрытие: логин/ресинк/ротация, RTSP+RTP (UDP/TCP), многоканальность,
замок, ring-детектор, MQTT, тайм-синк/TLV-монитор, громкая связь
(таблицы µ-law, HTTP/RTSP/backchannel, эксклюзив, отказ старта).

## Структура

- `slinex_rtsp.py` — шлюз (OWSP-клиент, RTSP/RTP сервер, HTTP, MQTT)
- `PROTOCOL.md` — полная документация протокола OWSP/TLV
- `BACKLOG.md` — история исследования, вердикты по командам, планы
- `slinex_gateway.conf.example` — шаблон MQTT-конфига
- `scan_device.py` — сканер TCP-портов устройства
- `ring_check.py` — офлайн-прогон ring-детектора по pcap
- `udp_monitor.py` — монитор UDP-активности устройства
- `itest*.py` — интеграционные тесты с моком

## Дисклеймер

Проект — результат независимого реверс-инжиниринга для личной
совместимости со своим оборудованием; не связан с Slinex, Gooclient или
Goolink. Используйте на свой риск; всё, что вы шлёте своему домофону,
вы шлёте осознанно.
