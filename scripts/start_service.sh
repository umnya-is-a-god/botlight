#!/bin/sh
ssh-keygen -A
exec /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
php service.php
php iplimit.php &
php cron.php