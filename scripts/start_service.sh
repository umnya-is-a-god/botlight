#!/bin/sh
ssh-keygen -A
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e &
php service.php
# started again when they stop or their loop hangs (scripts/supervise.sh)
sh /scripts/supervise.sh iplimit /tmp/iplimit_heartbeat 300 php iplimit.php &
exec sh /scripts/supervise.sh cron /tmp/cron_heartbeat 900 php cron.php
