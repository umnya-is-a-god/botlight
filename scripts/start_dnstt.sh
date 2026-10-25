#!/bin/sh
ssh-keygen -A

# Tunnel users (vpnbot) reach the internet only: no internal networks,
# no other containers, no host. Docker DNS (127.0.0.11) stays reachable.
# If the rules cannot be set, tunnel logins are refused rather than
# left unrestricted.
uid=$(id -u vpnbot)
fw=ok
iptables -F OUTPUT && iptables -A OUTPUT -o lo -j ACCEPT || fw=fail
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 \
    192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A OUTPUT -m owner --uid-owner "$uid" -d $net -j REJECT || fw=fail
done
# IPv6 only matters when the container has it
if ip6tables -F OUTPUT 2>/dev/null; then
    ip6tables -A OUTPUT -o lo -j ACCEPT || fw=fail
    for net in fc00::/7 fe80::/10 ff00::/8; do
        ip6tables -A OUTPUT -m owner --uid-owner "$uid" -d $net -j REJECT || fw=fail
    done
fi

if [ "$fw" = ok ]; then
    /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &
else
    echo "dnstt: firewall rules failed, tunnel logins disabled" >&2
    /usr/sbin/sshd -f /system/sshd_config -D -e -o DenyUsers=vpnbot "$@" &
fi
tail -f /dev/null
