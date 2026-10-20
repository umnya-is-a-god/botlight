#!/bin/sh
# Prints the Xray release tag to build.
# XRAY_VERSION (environment or .env): an exact tag like v26.3.27, or
# "latest" for the newest release GitHub marks as Latest (pre-releases
# are skipped). The last resolved tag is remembered, so a failed lookup
# keeps the current build instead of breaking the start.
cd "$(dirname "$0")/.." || exit 1

v="$XRAY_VERSION"
[ -z "$v" ] && v=$(sed -n 's/^XRAY_VERSION=//p' .env 2>/dev/null | tr -d '\r')
[ -z "$v" ] && v=latest

if [ "$v" = latest ]; then
    cache=./update/xray_version
    t=$(curl -s -m 10 -o /dev/null -w '%{redirect_url}' \
        https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
        | sed -n 's#.*/releases/download/\([^/]*\)/.*#\1#p')
    if [ -n "$t" ]; then
        echo "$t" > "$cache"
        v="$t"
    elif [ -s "$cache" ]; then
        v=$(cat "$cache")
    fi
fi
echo "$v"
