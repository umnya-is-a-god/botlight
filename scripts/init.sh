#!/bin/sh
# Fresh install of lightweightbot from umnya-is-a-god/botlight:
#   wget -O- .../scripts/init.sh | sh             (branch main)
#   wget -O- .../scripts/init.sh | sh -s dev      (another branch)
# The bot token is asked for and not shown: on the command line every
# process on the host could read it. Without a terminal it comes from the
# BOT_TOKEN environment variable.
set -e

DIR=/root/vpnbot
# a Telegram bot token: id, colon, secret; it goes into data/config.php
token_ok() { printf '%s' "$1" | grep -Eq '^[0-9]{5,20}:[A-Za-z0-9_-]{30,100}$'; }

KEY="${BOT_TOKEN:-}"
BRANCH=main
if [ -n "$1" ] && token_ok "$1"; then
    # the earlier form: sh init.sh TOKEN [branch]
    KEY="$1"
    BRANCH="${2:-main}"
    echo "note: a token on the command line is visible to other processes; leave it out next time, it is asked for"
elif [ -n "$1" ]; then
    BRANCH="$1"
fi
case "$BRANCH" in
    *[!A-Za-z0-9._/-]*|-*) echo "wrong branch name: $BRANCH"; exit 1 ;;
esac
if [ -z "$KEY" ] && (: < /dev/tty) 2> /dev/null; then
    stty -echo < /dev/tty 2> /dev/null || true
    printf 'Telegram bot token (from @BotFather, not shown): ' > /dev/tty
    read -r KEY < /dev/tty || true
    stty echo < /dev/tty 2> /dev/null || true
    printf '\n' > /dev/tty
fi
if ! token_ok "$KEY"; then
    echo "no valid bot token: run this in a terminal, or with BOT_TOKEN=... set"
    exit 1
fi

apt update
apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    cron \
    git \
    iptables \
    iproute2 \
    xtables-addons-common \
    xtables-addons-dkms
if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
fi

git clone -b "$BRANCH" https://github.com/umnya-is-a-god/botlight.git "$DIR"
cd "$DIR"
mkdir -p ./data
# the token was checked above: only digits, letters, ":", "_" and "-"
(umask 077 && printf "<?php\n\n\$c = ['key' => '%s'];\n" "$KEY" > ./data/config.php)
make u
# start the bot again after a reboot (make uncron turns it off)
systemctl enable --now cron >/dev/null 2>&1 || true
make cron
