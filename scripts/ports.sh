#!/bin/sh
# Builds docker-compose.ports.yml from the bot's port switches.
# The bot (inside a container) only writes "ad=1" / "dnstt=1" lines to
# update/ports; the compose file itself is written here, on the host,
# so a container cannot inject compose settings.
cd "$(dirname "$0")/.." || exit 1
switches=./update/ports
out=./docker-compose.ports.yml
on() { grep -qx "$1=1" "$switches" 2>/dev/null; }
{
    if on ad || on dnstt; then
        echo "services:"
        if on ad; then printf '  ad:\n    ports:\n      - "853:853"\n'; fi
        if on dnstt; then printf '  dnstt:\n    ports:\n      - "53:53/udp"\n'; fi
    fi
} > "$out"
