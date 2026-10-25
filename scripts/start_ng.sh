#!/bin/sh
ssh-keygen -A
# sshd: the bot's commands; started again if it stops
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
# the config the bot writes (./data/ng)
nginx -c /etc/nginx/bot/nginx.conf -g "daemon off;"
