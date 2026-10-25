#!/bin/sh
set -e

ssh-keygen -A
# sshd: the bot's commands; started again if it stops
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &

WGCF_DIR="/etc/warp"
WGCF_CONF="$WGCF_DIR/wgcf-profile.conf"
WGCF_TOML="$WGCF_DIR/wgcf-account.toml"
SOCKS_PORT="${SOCKS_PORT:-1080}"

# written by the bot into the warp volume (Bot::writeWarpKey)
WARP_LICENSE_KEY=$(head -n 1 "$WGCF_DIR/license_key" 2>/dev/null | tr -d '\r\n')
# goes into a sed expression below: key characters only
case "$WARP_LICENSE_KEY" in
    *[!A-Za-z0-9-]*) WARP_LICENSE_KEY= ;;
esac

# The socks proxy carries Xray client traffic: it must not reach the
# server's internal networks or the host, even for a domain that resolves
# to a private address. Replies and loopback (Docker DNS) stay allowed.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 \
    192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A OUTPUT -d $net -j REJECT
done

mkdir -p "$WGCF_DIR"
cd "$WGCF_DIR"

if [ ! -f "$WGCF_CONF" ]; then
    echo "[warp] Registering WARP account..."
    wgcf register --accept-tos
    if [ -n "$WARP_LICENSE_KEY" ]; then
        echo "[warp] Applying license key..."
        # Заменяем license_key в wgcf-account.toml на WARP_LICENSE_KEY
        if grep -q '^license_key' "$WGCF_TOML"; then
            sed -i "s/^license_key.*/license_key = \"$WARP_LICENSE_KEY\"/" "$WGCF_TOML"
        fi
        wgcf update
    fi
    echo "[warp] Generating WireGuard profile..."
    wgcf generate
    echo "[warp] Stripping IPv6 from profile..."
    sed -i '/^Address.*:/d' "$WGCF_CONF"
    sed -i '/^AllowedIPs.*::/d' "$WGCF_CONF"
fi

# no DNS line: wg-quick would call resolvconf, which refuses to touch the
# resolv.conf Docker manages (Alpine 3.24) and the interface is torn down.
# Names are resolved by Docker DNS anyway.
sed -i '/^DNS *=/d' "$WGCF_CONF"

echo "[warp] Starting WireGuard (WARP)..."
wg-quick up "$WGCF_CONF"

echo "[warp] Starting microsocks on port $SOCKS_PORT..."
# -b 0.0.0.0: outgoing connections over IPv4, the address family WARP has
# here (the profile is stripped of IPv6); without it microsocks takes the
# first address of a name, which can be IPv6 and fail
exec microsocks -p "$SOCKS_PORT" -b 0.0.0.0
