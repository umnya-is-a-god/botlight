#!/bin/bash
# scripts/warp_profile.sh on profiles as wgcf writes them: the one-line
# addresses of wgcf 2.3+ and the one-per-line ones of earlier versions keep
# their IPv4 entries; a profile with no IPv4 left is refused unchanged.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
check() {
    if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1"; printf 'got:\n%s\nexpected:\n%s\n' "$2" "$3"; failed=$((failed + 1)); fi
}
# fit NAME PROFILE: the file after the script, or "refused"
fit() {
    printf '%s\n' "$2" > "$tmp/$1"
    sh scripts/warp_profile.sh "$tmp/$1" 2> /dev/null && cat "$tmp/$1" || echo refused
}
expected='[Interface]
PrivateKey = key
Address = 172.16.0.2/32
MTU = 1280
[Peer]
PublicKey = peer
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:2408'

check 'wgcf 2.3: one line per setting' "$(fit new '[Interface]
PrivateKey = key
Address = 172.16.0.2/32, 2606:4700:110:8a36::1/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
[Peer]
PublicKey = peer
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408')" "$expected"

check 'wgcf 2.2: one line per address' "$(fit old '[Interface]
PrivateKey = key
Address = 172.16.0.2/32
Address = 2606:4700:110:8a36::1/128
DNS = 1.1.1.1
MTU = 1280
[Peer]
PublicKey = peer
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = engage.cloudflareclient.com:2408')" "$expected"

check 'keepalive kept' "$(fit keep '[Interface]
Address = 172.16.0.2/32, 2606::1/128
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25' | tail -n 1)" 'PersistentKeepalive = 25'

profile='[Interface]
Address = 2606::1/128
[Peer]
AllowedIPs = ::/0'
check 'no IPv4 left: refused' "$(fit v6 "$profile")" refused
check 'refused: the file as it was' "$(cat "$tmp/v6")" "$profile"
check 'no address at all: refused' "$(fit none '[Interface]
[Peer]
AllowedIPs = 0.0.0.0/0')" refused
fit mode "$expected" > /dev/null
check 'the private key stays private (600)' "$(stat -c %a "$tmp/mode")" 600

[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
