#!/bin/sh
# No "set -e": a failed registration or a WireGuard that does not come up
# is retried here; the container keeps running (sshd for the bot) instead
# of restarting in a loop.

ssh-keygen -A
# sshd: the bot's commands; started again if it stops
sh /scripts/supervise.sh sshd "" 0 /usr/sbin/sshd -f /system/sshd_config -D -e "$@" &

WGCF_DIR="/etc/warp"
WGCF_CONF="$WGCF_DIR/wgcf-profile.conf"
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
# Flushed first: the rules are not added twice if this runs again in the
# same network namespace.
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 \
    192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A OUTPUT -d $net -j REJECT
done

mkdir -p "$WGCF_DIR"
cd "$WGCF_DIR" || exit 1

# A new account and profile, made in boot/ and moved into place only when
# complete (the bot uses new/ for its own re-registration)
register() (
    rm -rf boot && mkdir boot && cd boot || exit 1
    wgcf register --accept-tos > /dev/null || exit 1
    if [ -n "$WARP_LICENSE_KEY" ]; then
        sed -i "s/^license_key.*/license_key = \"$WARP_LICENSE_KEY\"/" wgcf-account.toml
        # a key that cannot be applied (used up, revoked) leaves free WARP
        wgcf update > /dev/null || echo "[warp] the license key is not applied, free WARP"
    fi
    wgcf generate > /dev/null || exit 1
    # IPv4 only, no DNS line
    sh /scripts/warp_profile.sh wgcf-profile.conf || exit 1
    cd .. || exit 1
    # the bot may have made a profile meanwhile
    [ -f "$WGCF_CONF" ] || mv boot/wgcf-account.toml boot/wgcf-profile.conf .
    rm -rf boot
)

# a switch by the bot that was cut short: the previous profile is in old/
if [ ! -f "$WGCF_CONF" ] && [ -f old/wgcf-profile.conf ]; then
    echo "[warp] restoring the previous profile"
    cp -p old/wgcf-account.toml old/wgcf-profile.conf .
fi
rm -rf boot new

# a profile without its IPv4 address or route (an earlier version cut them
# out of wgcf 2.3's one-line format): made again from the same account
if [ -f "$WGCF_CONF" ] && [ -f wgcf-account.toml ] \
    && { ! grep -q '^Address' "$WGCF_CONF" || ! grep -q '^AllowedIPs' "$WGCF_CONF"; }; then
    echo "[warp] the profile has no address or route, generating it again"
    wgcf generate > /dev/null && sh /scripts/warp_profile.sh "$WGCF_CONF"
fi

until [ -f "$WGCF_CONF" ]; do
    echo "[warp] Registering WARP account..."
    register && break
    echo "[warp] registration failed, again in a minute"
    sleep 60
done

# left from an earlier start in this network namespace
ip link show wgcf-profile > /dev/null 2>&1 && wg-quick down "$WGCF_CONF"

# No socks proxy until WARP is up: Xray traffic meant for WARP must not
# leave from the server's own address.
echo "[warp] Starting WireGuard (WARP)..."
# the bot may bring the interface up itself (re-registration) meanwhile
until ip link show wgcf-profile > /dev/null 2>&1; do
    # no DNS line: wg-quick would call resolvconf, which refuses to touch
    # the resolv.conf Docker manages (Alpine 3.24) and the interface is
    # torn down. Names are resolved by Docker DNS anyway.
    sed -i '/^DNS *=/d' "$WGCF_CONF"
    wg-quick up "$WGCF_CONF" && break
    if [ -f old/wgcf-profile.conf ]; then
        echo "[warp] the profile does not come up, back to the previous one"
        cp -p old/wgcf-account.toml old/wgcf-profile.conf . && rm -rf old
    fi
    echo "[warp] WireGuard is not up, again in 30 seconds"
    sleep 30
done

echo "[warp] Starting microsocks on port $SOCKS_PORT..."
# -b 0.0.0.0: outgoing connections over IPv4, the address family WARP has
# here (the profile is stripped of IPv6); without it microsocks takes the
# first address of a name, which can be IPv6 and fail
exec microsocks -p "$SOCKS_PORT" -b 0.0.0.0
