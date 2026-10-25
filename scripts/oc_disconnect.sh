#!/bin/sh
# ocserv disconnect-script (ocserv.conf): the traffic of the session that
# ended, a file of its own in ./data/octraffic. The bot adds it to the
# user's totals and removes it (Bot::ocTraffic). STATS_BYTES_IN: from the
# client, STATS_BYTES_OUT: to the client.
d=/octraffic
[ -d "$d" ] || exit 0
f="$d/$(date +%s)-${ID:-0}"
printf '%s\n%s\n%s\n' "$USERNAME" "${STATS_BYTES_IN:-0}" "${STATS_BYTES_OUT:-0}" > "$f.tmp" && mv "$f.tmp" "$f"
exit 0
