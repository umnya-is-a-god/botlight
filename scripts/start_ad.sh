#!/bin/sh
route add -net 10.0.2.0 netmask 255.255.255.0 gw oc
ssh-keygen -A
# sshd: the bot's commands; started again if it stops
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work
tail -f /dev/null
