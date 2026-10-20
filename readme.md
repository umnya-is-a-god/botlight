# lightweightbot

Облегчённая версия [mercurykd/vpnbot](https://github.com/mercurykd/vpnbot) (ветка `dev`). Оставлены только Vless (Xray), OpenConnect, AdGuard, Warp, PAC и DNSTT.

Текущая версия указана в файле `VERSION` и показывается в главном меню бота.

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
* Безопасность: PHP-FPM принимает соединения только от nginx (`ng`); VPN-клиенты Xray и OpenConnect не могут обращаться к внутренним сетям сервера и хоста (кроме DNS AdGuard у OpenConnect); у контейнера `php` больше нет доступа к Docker (`docker.sock` остался только у `service`); убран открытый без пароля socks-вход `wg-in` в Xray.
* Безопасность веб-части: закрыто чтение любых файлов через ссылку PAC (`?t=`); редактор и сохранение шаблонов, вход в панель AdGuard доступны только по свежей подписи Telegram от админа; убран небезопасный `unserialize`; секрет в адресах удлинён до 32 символов, у cookie AdGuard отдельный секрет; ввод админа экранируется в shell-командах; удалён неиспользуемый вебхук `/tlgrm`.
* Базовый образ Alpine 3.18 → 3.24, PHP 8.1 → 8.3.
* Веб-часть бота (подписки, PAC, webapp) работает через PHP-FPM вместо NGINX Unit, который архивирован в октябре 2025 и не поддерживается. nginx в контейнере `ng` передаёт запросы в `php:9000` по FastCGI.
* OpenConnect: `ocserv` 1.6.0 собирается через Meson из релизного архива с проверкой контрольной суммы (сборка из master через autotools больше не работала).
* Warp: из образа убраны AmneziaWG, Go, tun2socks и xtables-addons, которые ему не нужны.
* Убраны остатки списков subnet/process/package, обратный PAC и связанные теги шаблонов.

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
