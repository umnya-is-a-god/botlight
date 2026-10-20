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
* Исправлено: клавиатура меню PAC (не открывалась бы после удаления кнопки), предупреждение в `addRuleSet()`, `ssh()` теперь требует имя контейнера.

### Обновление сервера с исходного vpnbot

Репозиторий приватный: серверу нужен deploy key с доступом на чтение (Settings → Deploy keys).

```shell
ssh-keygen -t ed25519 -f /root/.ssh/botlight -N ''
cat /root/.ssh/botlight.pub   # добавить в Deploy keys, без write access
cat >> /root/.ssh/config <<'CFG'
Host github-botlight
    HostName github.com
    IdentityFile /root/.ssh/botlight
CFG
```

Перед `make r` уберите из `docker-compose.override.yml` секции удалённых сервисов (`wg`, `wg1`, `np`, `tg`, `ss`, `proxy`, `hy`), если они там есть.

```shell
cd /root/vpnbot
git remote set-url origin git@github-botlight:umnya-is-a-god/botlight.git
git fetch origin && git checkout -f -B main origin/main
git fetch https://github.com/mercurykd/vpnbot.git --tags   # версии бота берутся из тегов автора
make r
```

---

## Установка с нуля

Подходит для чистого сервера Debian/Ubuntu, всё выполняется от root.

1. Создайте ключ для доступа к приватному репозиторию:

```shell
ssh-keygen -t ed25519 -f /root/.ssh/botlight -N ''
cat /root/.ssh/botlight.pub
cat >> /root/.ssh/config <<'CFG'
Host github-botlight
    HostName github.com
    IdentityFile /root/.ssh/botlight
CFG
ssh -o StrictHostKeyChecking=accept-new -T git@github-botlight
```

2. Добавьте выведенный ключ в репозиторий: Settings → Deploy keys → Add deploy key, без «Allow write access». Последняя команда должна ответить «successfully authenticated».

3. Установите бота (скрипт берётся из репозитория, ссылка raw для приватного репозитория не работает):

```shell
apt update && apt install -y git
git clone git@github-botlight:umnya-is-a-god/botlight.git /tmp/botlight-init
sh /tmp/botlight-init/scripts/init.sh YOUR_TELEGRAM_BOT_KEY
rm -rf /tmp/botlight-init
```

Бот ставится в `/root/vpnbot`.

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
