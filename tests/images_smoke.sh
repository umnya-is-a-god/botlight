#!/bin/bash
# Checks of a freshly built image before it is published
# (.github/workflows/images.yml): the programs start, the configs the bot
# starts from are accepted, sshd takes system/sshd_config.
#   tests/images_smoke.sh ng|php|ad|xr|oc|wg|dnstt IMAGE
# the commands in single quotes run inside the image, not here
# shellcheck disable=SC2016
set -u
cd "$(dirname "$0")/.." || exit 1
kind="$1"
image="$2"
failed=0
# a throwaway certificate (ocserv loads one): made here, the oc image has no openssl
certs=$(mktemp -d)
trap 'rm -rf "$certs"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=t \
    -keyout "$certs/cert_private" -out "$certs/cert_public" 2> /dev/null
chmod 644 "$certs"/*

# in IMAGE, with the repository's config/ and system/ mounted read-only
run() {
    docker run --rm --entrypoint /bin/sh \
        -v "$PWD/config:/c:ro" -v "$PWD/system:/system:ro" -v "$certs:/certs:ro" \
        "$image" -c "$1"
}
check() {
    local what="$1" out
    if out=$(run "$2" 2>&1); then
        echo "ok   $kind: $what"
    else
        echo "FAIL $kind: $what"
        printf '%s\n' "$out" | tail -n 20
        failed=$((failed + 1))
    fi
}

# every container runs sshd for the bot's commands
check 'sshd accepts system/sshd_config' \
    'ssh-keygen -A > /dev/null && mkdir -p /etc/ssh/pinned && ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/pinned/ssh_host_ed25519_key && /usr/sbin/sshd -t -f /system/sshd_config'

case "$kind" in
    ng)
        check 'nginx and its stream module' 'nginx -V 2>&1 | head -n 1 && test -f /usr/lib/nginx/modules/ngx_stream_module.so'
        ;;
    php)
        check 'PHP extensions the bot needs' 'for e in curl json sodium ssh2 yaml; do php -m | grep -qix "$e" || { echo "no $e"; exit 1; }; done'
        check 'php-fpm accepts system/php-fpm.conf' 'mkdir -p /logs && php-fpm83 -t -y /system/php-fpm.conf -c /system/php.ini'
        check 'users of the web pools' 'id botweb && id botadmin && id -nG botadmin | grep -qw botsecret'
        check 'sing-box, dnslookup, certbot, logrotate' 'sing-box version && dnslookup --version && certbot --version && logrotate --version'
        ;;
    ad)
        check 'AdGuard Home accepts the template' 'mkdir -p /tmp/w && /opt/adguardhome/AdGuardHome --check-config --no-permcheck --no-check-update -c /c/AdGuardHome.yaml -w /tmp/w'
        ;;
    xr)
        check 'Xray accepts the template' 'xray version | head -n 1 && xray run -test -config /c/xray.json'
        # the Reality transport the bot switches to (Bot::changeTransport)
        check 'Xray accepts a Reality config' \
            'k=$(xray x25519 | sed -n "s/^Private\s\?[Kk]ey: *//p") && [ -n "$k" ] && jq --arg k "$k" ".inbounds[0].streamSettings = {network: \"tcp\", security: \"reality\", realitySettings: {dest: \"www.example.com:443\", serverNames: [\"www.example.com\"], privateKey: \$k, shortIds: [\"a1b2c3d4\"]}}" /c/xray.json > /tmp/r.json && xray run -test -config /tmp/r.json'
        ;;
    oc)
        check 'ocserv accepts the template, workers isolated' \
            'mkdir -p /etc/ocserv && cp /c/ocserv.passwd /etc/ocserv/ && sed "s/^isolate-workers.*/isolate-workers = true/" /c/ocserv.conf > /tmp/oc.conf && ocserv -t -c /tmp/oc.conf'
        ;;
    wg)
        check 'wgcf, WireGuard, microsocks' 'wgcf --help > /dev/null && command -v wg-quick && wg --version && command -v microsocks'
        ;;
    dnstt)
        check 'dnstt-server makes its keys' 'dnstt-server -gen-key -privkey-file /tmp/k -pubkey-file /tmp/p && test -s /tmp/p'
        ;;
    *)
        echo "unknown image kind: $kind"
        exit 1
        ;;
esac

[ "$failed" -eq 0 ] && echo "$kind: all passed" || echo "$kind: $failed failed"
exit "$failed"
