#!/bin/sh
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
# the config the bot writes (./data/up)
nginx -c /etc/nginx/bot/upstream.conf -g "daemon off;"
