#!/bin/sh
# Moves the bot's working state out of the git tree into ./data (ignored by
# git, so an update cannot reset it): the runtime files in config/,
# app/config.php and app/webapp/override.html. Run by "make start" before
# the containers start, on every start.
# Safe to run again: a file already in ./data is never overwritten, the
# originals are archived first (data/backup/), and a git-tracked original
# is only reset to its template after its copy is verified.
cd "$(dirname "$0")/.." || exit 1
umask 077

D=./data
for d in "$D" "$D/xray" "$D/adguard" "$D/ocserv" "$D/up" "$D/ng" "$D/www" "$D/dnstt" "$D/backup" "$D/letsencrypt" "$D/acme"; do
    mkdir -p "$d" || exit 1
done
# read by the containers that mount them (as root) and by nginx workers
chmod 755 "$D/www" "$D/acme"

# original:copy in ./data
pairs="app/config.php:config.php
config/pac.json:pac.json
config/xray.stats:xray.stats
config/xray.json:xray/xray.json
config/AdGuardHome.yaml:adguard/AdGuardHome.yaml
config/ocserv.conf:ocserv/ocserv.conf
config/ocserv.passwd:ocserv/ocserv.passwd
config/upstream.conf:up/upstream.conf
config/deny:up/deny
config/nginx.conf:ng/nginx.conf
config/dnstt/server.key:dnstt/server.key
config/dnstt/server.pub:dnstt/server.pub
app/webapp/override.html:www/override.html"

tracked() { git ls-files --error-unmatch -- "$1" > /dev/null 2>&1; }

# the originals still holding state go into one archive before anything moves
todo=""
for p in $pairs; do
    src=${p%%:*}
    dst=$D/${p#*:}
    if [ -f "$src" ] && [ ! -e "$dst" ]; then
        todo="$todo $src"
    fi
done
if [ -n "$todo" ]; then
    archive="$D/backup/pre-data-$(date +%Y%m%d-%H%M%S).tar.gz"
    # shellcheck disable=SC2086 # a list of plain repository paths
    if ! tar -czf "$archive" $todo; then
        echo "migrate_data: cannot archive the originals, nothing moved" >&2
        rm -f "$archive"
        exit 1
    fi
    echo "migrate_data: originals archived in $archive"
fi

failed=0
for p in $pairs; do
    src=${p%%:*}
    dst=$D/${p#*:}
    [ -e "$dst" ] && continue
    [ -f "$src" ] || continue
    tmp="$dst.migrate.$$"
    if cp -p "$src" "$tmp" && mv "$tmp" "$dst" && cmp -s "$src" "$dst"; then
        echo "migrate_data: $src -> $dst"
        if tracked "$src"; then
            # the template again: the state lives in ./data now
            git checkout -q -- "$src" 2> /dev/null || true
        else
            rm -f "$src"
        fi
    else
        rm -f "$tmp"
        echo "migrate_data: copy of $src failed, the original is kept" >&2
        failed=1
    fi
done

# a fresh install: the templates for whatever is still missing
for p in $pairs; do
    src=${p%%:*}
    dst=$D/${p#*:}
    case "$src" in
        config/*) ;;
        *) continue ;;
    esac
    if [ ! -e "$dst" ] && tracked "$src"; then
        git show "HEAD:$src" > "$dst.migrate.$$" 2> /dev/null && mv "$dst.migrate.$$" "$dst"
        rm -f "$dst.migrate.$$"
    fi
done
rmdir config/dnstt 2> /dev/null || true

# the built-in sing-box/mihomo template, if it was edited (Mini App): it
# was kept in config/ and lives in data/templates now
mkdir -p "$D/templates"
for t in sing clash; do
    if [ ! -e "$D/templates/$t.origin.json" ] && ! git diff --quiet -- "config/$t.json" 2> /dev/null; then
        tar -czf "$D/backup/pre-data-$t-$(date +%Y%m%d-%H%M%S).tar.gz" "config/$t.json" \
            && cp "config/$t.json" "$D/templates/$t.origin.json" \
            && git checkout -q -- "config/$t.json" \
            && echo "migrate_data: config/$t.json -> $D/templates/$t.origin.json"
    fi
done
# the bot token: root only
[ -f "$D/config.php" ] && chmod 600 "$D/config.php"

if [ ! -s "$D/config.php" ]; then
    echo "migrate_data: no bot key: $D/config.php is missing (install with scripts/init.sh)" >&2
fi
exit $failed
