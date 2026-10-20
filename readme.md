# lightweightbot

Облегчённая версия [mercurykd/vpnbot](https://github.com/mercurykd/vpnbot) (ветка `dev`). Оставлены только Vless (Xray), OpenConnect, AdGuard, Warp, PAC и DNSTT.

### Удалено

* Контейнеры WireGuard ×2 (`wg`, `wg1`), NaiveProxy (`np`), MTProto (`tg`), Shadowsocks (`ss` + `proxy`), Hysteria (`hy`). Вместе с ними их меню, кнопки, статусы, порты, бэкап, скрипты, dockerfile и конфиги.
* Связка nginx с удалёнными сервисами: upstream `np:443`, `location /v2ray`. certbot больше не запрашивает сертификат на naive-поддомен.
* Формат v2ray/xray-JSON: шаблон, кнопки, импорт в v2rayNG и Streisand. Ссылки hiddify и karing.
* Архив sing-box для Windows (служба winsw) и ссылка на него.
* HWID-лимит целиком.
* AWG-ссылка для Vless, Settings → Ports для удалённых сервисов.
* В меню маршрутов Vless — списки subnet, process, package.
* Мёртвый код: около 130 методов, около 20 маршрутов без кнопок, устаревший `offWarp` для старого клиента Cloudflare, недоделанные списки exclude/reverse/subzones, около 35 строк перевода.

### Изменено

* XHTTP: `xmux` у sing-box и mihomo выровнены (без `max_connections`), значения совпадают с `vless://`-ссылкой.
* Telegram API: таймауты cURL 5/15 с, бот больше не зависает намертво.
* sing-box 1.14: `http_client` и `http_clients` вместо `download_detour`.
* Шаблоны `origin` заменены новыми: sing-box 1.14 и mihomo для Android/Windows, `authentication` = `123:321`.
* Главное меню: Vless + OpenConnect, AdGuard + PAC, DNSTT + Warp.
* Образы собираются на сервере (`botlight/vpnbot-*:local`), а не скачиваются готовыми у автора. Версии ядер под контролем: Xray берётся последний стабильный релиз (или закреплённый в `.env`, `XRAY_VERSION`), в контейнере `php` sing-box 1.14.3 (сборка rule-set'ов) и mihomo 1.19.32. Убран неиспользуемый Qt (`py3-qt5`).
* Исправлен разбор вывода `xray x25519`: на новом сервере публичный ключ Reality получался пустым.
* Исправлено: клавиатура меню PAC (не открывалась бы после удаления кнопки), предупреждение в `addRuleSet()`, `ssh()` теперь требует имя контейнера.

### Переход с исходного vpnbot

Перед `make r` уберите из `docker-compose.override.yml` секции удалённых сервисов (`wg`, `wg1`, `np`, `tg`, `ss`, `proxy`, `hy`), если они там есть.

```shell
cd /root/vpnbot
git remote set-url origin https://github.com/umnya-is-a-god/botlight.git
git fetch origin && git checkout -f -B main origin/main
git fetch https://github.com/mercurykd/vpnbot.git --tags   # версии бота берутся из тегов автора
make r
```

---

## Установка с нуля

Для чистого сервера Debian/Ubuntu, выполняется от root. Бот ставится в `/root/vpnbot`. Первый запуск занимает несколько минут: образы контейнеров собираются на сервере.

```shell
wget -O- https://raw.githubusercontent.com/umnya-is-a-god/botlight/main/scripts/init.sh | sh -s YOUR_TELEGRAM_BOT_KEY
```

#### Версия Xray

По умолчанию (`XRAY_VERSION=latest` в `.env`) при каждом запуске (`make r`, перезагрузка, обновление через бота) берётся последний релиз Xray с отметкой Latest на GitHub, пре-релизы пропускаются. Если вышла новая версия, образ пересобирается. Чтобы закрепить конкретную версию, укажите её, например `XRAY_VERSION=v26.3.27`.

#### Обновление

Бот раз в час проверяет новые коммиты в этом репозитории и присылает их список с кнопкой «update bot». Вручную:

```shell
cd /root/vpnbot
git pull
make r
```

#### Restart:
```shell
cd /root/vpnbot
make r
```
#### autoload:
```shell
crontab -e
add `@reboot cd /root/vpnbot && make r` and save
```
