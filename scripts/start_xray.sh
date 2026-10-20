#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
/usr/sbin/sshd -D -e "$@" &

# Egress filter: Xray clients must not reach the server's internal networks
# or the host. Xray's routing already blocks private destination IPs; this
# also covers domains that resolve to private addresses (DNS rebinding,
# docker service names). Allowed: replies, loopback (Docker DNS, stats API),
# the WARP socks proxy and nginx as the Reality "self" destination.
# If the filter cannot be set, Xray is not started (/tmp/fw_failed).
fw() {
    iptables -F OUTPUT \
    && iptables -A OUTPUT -o lo -j ACCEPT \
    && iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
    && iptables -A OUTPUT -d 10.10.0.13 -p tcp --dport 1080 -j ACCEPT \
    && iptables -A OUTPUT -d 10.10.1.2 -p tcp --dport 443 -j ACCEPT \
    || return 1
    for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 \
        192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
        iptables -A OUTPUT -d $net -j REJECT || return 1
    done
    if ip6tables -F OUTPUT 2>/dev/null; then
        ip6tables -A OUTPUT -o lo -j ACCEPT \
        && ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
        || return 1
        for net in fc00::/7 fe80::/10 ff00::/8; do
            ip6tables -A OUTPUT -d $net -j REJECT || return 1
        done
    fi
}
if fw; then
    rm -f /tmp/fw_failed
else
    touch /tmp/fw_failed
    echo "xray: firewall rules failed, xray is not started" >&2
fi

uuid=$(jq -r '.inbounds[0].settings.clients[0].id // empty' /xray.json)
if [ -n "$uuid" ] && [ ! -e /tmp/fw_failed ]; then
    xray run -config /xray.json > /dev/null 2>&1 &
fi
tail -f /dev/null
