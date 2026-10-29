#!/bin/bash
# scripts/release.sh with curl replaced by a stub that serves a list of
# releases and their files: the newest stable release at least 3 days old
# with the prefix, an exact tag whatever its age, and a file whose SHA-256
# does not match or is not listed is refused.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
failed=0
ago() { date -u -d "@$(($(date +%s) - $1 * 86400))" +%Y-%m-%dT%H:%M:%SZ; }
echo good > "$tmp/file"
good=$(sha256sum "$tmp/file" | cut -d' ' -f1)
bad=$(printf '%064d' 0)
# release TAG AGE_DAYS PRERELEASE DIGEST [URL]
release() {
    printf '{"tag_name":"%s","draft":false,"prerelease":%s,"published_at":"%s","assets":[{"name":"p-%s.tgz","digest":%s,"browser_download_url":"%s"}]}' \
        "$1" "$3" "$(ago "$2")" "${1#v}" "$4" "${5:-https://github.com/o/p/releases/download/$1/p-${1#v}.tgz}"
}
{
    echo '['
    release v1.15.0 1 false "\"sha256:$good\""; echo ','
    release v1.14.9 1 false "\"sha256:$good\""; echo ','
    release v1.14.8 4 true "\"sha256:$good\""; echo ','
    release v1.14.7 5 false "\"sha256:$good\""; echo ','
    release v1.14.6 8 false "\"sha256:$bad\""; echo ','
    release v1.14.5 9 false null; echo ','
    release v1.14.4 10 false "\"sha256:$good\"" "https://example.com/p.tgz"; echo ','
    release v1.13.0 30 false "\"sha256:$good\""
    echo ']'
} > "$tmp/releases.json"
# the stub: the list for the API, the good file for a download (-o OUT)
cat > "$tmp/bin/curl" << EOF
#!/bin/sh
out=""
while [ \$# -gt 1 ]; do [ "\$1" = -o ] && out=\$2; shift; done
case "\$1" in
    https://api.github.com/*) cat "$tmp/releases.json" ;;
    *) cp "$tmp/file" "\$out" ;;
esac
EOF
chmod +x "$tmp/bin/curl"

# run DESCRIPTION EXPECTED SELECT: EXPECTED is the tag printed, or "fail"
run() {
    local got
    got=$(PATH="$tmp/bin:$PATH" sh scripts/release.sh o/p "$3" 'p-{v}.tgz' "$tmp/out" 2> /dev/null) || got=fail
    if [ "$got" = "$2" ]; then echo "ok   $1"; else echo "FAIL $1: got $got, expected $2"; failed=$((failed + 1)); fi
}
run 'latest 1.14: newest stable older than 3 days' v1.14.7 latest:v1.14.
run 'latest: a newer series too new, a pre-release skipped' v1.14.7 latest:v
run 'exact tag: taken whatever its age' v1.14.9 tag:v1.14.9
run 'SHA-256 does not match: refused' fail tag:v1.14.6
run 'no SHA-256 listed: refused' fail tag:v1.14.5
run 'a download outside the project: refused' fail tag:v1.14.4
run 'no such release: refused' fail latest:v2.
run 'a tag with other characters: refused' fail 'tag:v1/../x'
if [ "$(cat "$tmp/out" 2> /dev/null)" = good ]; then echo "ok   the file is saved"; else echo "FAIL the file is saved"; failed=$((failed + 1)); fi

[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
