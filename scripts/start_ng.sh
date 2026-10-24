#!/bin/sh
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
# the config the bot writes (./data/ng)
nginx -c /etc/nginx/bot/nginx.conf -g "daemon off;"
