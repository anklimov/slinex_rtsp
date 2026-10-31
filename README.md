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

Отдельный стрим на `/camera1/talk` не нужен: backchannel входит в каждый
DESCRIBE, микрофон доступен прямо на `door1`.

Слот динамика занимается только реальным звуком: 2 секунды тишины —
и канал свободен (push-to-talk семантика).

Устойчивость к капризам прошивки (проверено на железе):

- слот громкой связи у панели **один на все вызывные панели**
  (занято → `TLV 332 result=23`): шлюз держит ретраи раз в 3 с, пока
  идёт звук — соседний разговор закончился, микрофон подключится сам;
- если прошивка «застряла» (нет ответа на TLV 331), панель сама рвёт
  OWSP-сессию канала (~30 с): шлюз чистит слот `331 action=2`,
  переподключается и продолжает говорить без передёргивания клиента;
- обрыв OWSP-сессии посреди разговора не ломает канал: шлюз делает
  **свежий 331** на новой сессии (а не льёт аудио в никуда) — прошивка
  такого не прощает.

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

## Интеграция с Home Assistant

Типовая топология (адреса замените на свои):

```
[панели STM83xx 192.168.1.50] ⇄ OWSP ⇄ [шлюз 192.168.1.10]
                                            RTSP:8554 / HTTP:8555
[Frigate 192.168.1.30] ← RTSP ←──── шлюз (запись/детекция)
[HA 192.168.1.20 + go2rtc] ← RTSP ←── шлюз (live + микрофон)
```

Шлюз раздаёт RTSP нескольким клиентам одновременно (Frigate + go2rtc),
не занимая лишних подключений панели.

### 1. MQTT — один брокер на всех

Опубликуйте события шлюза в тот же брокер, что использует HA
(например, Mosquitto-аддон на хосте HA). Создайте пользователя HA
для шлюза (Настройки → Люди → Пользователи) и укажите его в
`slinex_gateway.conf`:

```ini
[mqtt]
enabled = 1
host = 192.168.1.20
username = slinex-gw
password = <пароль пользователя HA>
```

Проверка: HA → интеграция MQTT → «Прослушивать топик» `slinex/#` →
нажать кнопку звонка на панели.

### 2. `configuration.yaml`: замок и статус

```yaml
mqtt:
  button:
    - name: "Дверь 1 — открыть"
      unique_id: slinex_lock_1
      icon: mdi:door-open
      command_topic: "slinex/cmd/unlock"
      payload_press: '{"channel": 1, "action": 1, "delay": 1}'
    - name: "Дверь 2 — открыть"
      unique_id: slinex_lock_2
      icon: mdi:door-open
      command_topic: "slinex/cmd/unlock"
      payload_press: '{"channel": 2, "action": 1, "delay": 1}'

rest:
  - resource: http://192.168.1.10:8555/status
    scan_interval: 30
    sensor:
      - name: "Домофон: каналы онлайн"
        unique_id: slinex_channels
        value_template: >
          {{ value_json.channels | selectattr('login_ok', 'truthy')
             | list | count }}/{{ value_json.channels | count }}
```

### 3. Автоматизация звонка (push со снимком)

```yaml
- alias: "Домофон: звонок"
  id: slinex_ring
  trigger:
    - platform: mqtt
      topic: "slinex/events/ring"
  condition: >
    {{ trigger.payload_json.state == 'start' }}
  action:
    - service: camera.snapshot
      target: {entity_id: camera.door_1}     # из Frigate (шаг 4)
      data: {filename: "/config/www/door1_last.jpg"}
    - service: notify.mobile_app_телефон
      data:
        title: "Домофон"
        message: "Звонок ({{ trigger.payload_json.channels | join(', ') }})"
        data:
          image: "/local/door1_last.jpg"
```

### 4. Frigate — запись и детекция

Конфиг Frigate (там же, где его интеграция с HA — брокер общий):

```yaml
cameras:
  door1:
    ffmpeg:
      inputs:
        - path: rtsp://192.168.1.10:8554/camera1
          roles: [detect]          # + record, если нужна история
  door2:
    ffmpeg:
      inputs:
        - path: rtsp://192.168.1.10:8554/camera2
          roles: [detect]
```

Появятся `camera.door_1`/`camera.door_2` для снапшотов и карточек
Frigate. 320×240@5fps для детекции достаточно и почти бесплатно по CPU.

### 5. Lovelace: live и микрофон

- просмотр/клипы — карточка Frigate на `camera.door_1`;
- two-way audio — карточка [WebRTC Camera](https://github.com/AlexxIT/WebRTC)
  (связка того же автора, что и go2rtc-аддон):

```yaml
type: custom:webrtc-camera
entity: camera.door_1
ui: true        # кнопка микрофона
```

Сущности камеры достаточно `stream_source`, совпадающего со стримом
go2rtc. Для микрофона обязателен HTTPS (Nabu Casa / reverse proxy) —
иначе браузер не даст доступ к getUserMedia.

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
(таблицы µ-law, HTTP/RTSP/backchannel, эксклюзив, отказ и застревание
старта с ретраями, обрыв OWSP посреди разговора).

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
