#!/bin/sh
# Fresh install of lightweightbot from umnya-is-a-god/botlight.
# Usage: sh init.sh YOUR_TELEGRAM_BOT_KEY [branch]
set -e

KEY="$1"
BRANCH="${2:-main}"
DIR=/root/vpnbot

if [ -z "$KEY" ]; then
    echo "usage: sh init.sh YOUR_TELEGRAM_BOT_KEY [branch]"
    exit 1
fi

apt update
apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
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
echo "<?php

\$c = ['key' => '$KEY'];" > ./app/config.php
make u
