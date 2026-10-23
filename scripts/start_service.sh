#!/bin/sh
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
php service.php
php iplimit.php &
php cron.php