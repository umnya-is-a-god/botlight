#!/bin/sh
# Fits a WARP WireGuard profile (wgcf generate) to the wp container: IPv4
# only (the container has no IPv6) and no DNS line (wg-quick would call
# resolvconf, which refuses the resolv.conf Docker manages). wgcf 2.3+
# writes both addresses on one line ("Address = 172.16.0.2/32,
# 2606:.../128"), earlier versions one per line: the IPv6 entries go, the
# IPv4 ones stay. Fails, leaving the file as it was, when no IPv4 address
# or route is left.
#   warp_profile.sh FILE
umask 077
f=$1
if awk '
    /^(Address|AllowedIPs)[ \t]*=/ {
        key = $0; sub(/[ \t]*=.*/, "", key)
        val = $0; sub(/^[^=]*=[ \t]*/, "", val)
        n = split(val, a, /[ \t]*,[ \t]*/)
        out = ""
        for (i = 1; i <= n; i++) {
            if (a[i] != "" && a[i] !~ /:/) {
                out = out (out == "" ? "" : ", ") a[i]
            }
        }
        if (out != "") {
            print key " = " out
            seen[key] = 1
        }
        next
    }
    /^DNS[ \t]*=/ { next }
    { print }
    END { exit !(seen["Address"] && seen["AllowedIPs"]) }
' "$f" > "$f.tmp"; then
    mv "$f.tmp" "$f"
else
    rm -f "$f.tmp"
    echo "warp_profile.sh: no IPv4 address or route left in $f" >&2
    exit 1
fi
