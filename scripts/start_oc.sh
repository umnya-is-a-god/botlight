#!/bin/sh
INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
ssh-keygen -A
exec /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT
iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
# VPN clients (vpns*) must not reach internal networks or this container,
# except AdGuard DNS
iptables -A FORWARD -i vpns+ -d 10.10.0.5 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i vpns+ -d 10.10.0.5 -p tcp --dport 53 -j ACCEPT
for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A FORWARD -i vpns+ -d $net -j DROP
done
iptables -A INPUT -i vpns+ -p tcp --dport 22 -j DROP
ocserv -c /etc/ocserv/ocserv.conf
tail -f /dev/null
