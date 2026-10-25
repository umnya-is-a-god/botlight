#!/bin/sh
INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
ssh-keygen -A
# sshd: the bot's commands; started again if it stops
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
# The nat rules are only added if missing: POSTROUTING also holds Docker's
# own rules (its DNS), so it is not flushed. The filter chains are the
# container's own: flushed, the rules are not added twice on a restart in
# the same network namespace.
add_nat() {
    iptables -t nat -C POSTROUTING "$@" 2> /dev/null || iptables -t nat -A POSTROUTING "$@"
}
add_nat --destination 10.10.0.5 -j ACCEPT
add_nat -o "$INTERFACE" -j MASQUERADE
iptables -F FORWARD
iptables -F INPUT
# VPN clients (vpns*) must not reach internal networks or this container,
# except AdGuard DNS
iptables -A FORWARD -i vpns+ -d 10.10.0.5 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i vpns+ -d 10.10.0.5 -p tcp --dport 53 -j ACCEPT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 \
    192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A FORWARD -i vpns+ -d $net -j DROP
done
iptables -A INPUT -i vpns+ -p tcp --dport 22 -j DROP
# no IPv6 for the clients (ocserv.conf gives them none): nothing of theirs
# is forwarded over IPv6 if the network gets it
if command -v ip6tables > /dev/null 2>&1; then
    ip6tables -F FORWARD 2> /dev/null
    ip6tables -A FORWARD -i vpns+ -j DROP 2> /dev/null
    ip6tables -F INPUT 2> /dev/null
    ip6tables -A INPUT -i vpns+ -p tcp --dport 22 -j DROP 2> /dev/null
fi
ocserv -c /etc/ocserv/ocserv.conf
tail -f /dev/null
