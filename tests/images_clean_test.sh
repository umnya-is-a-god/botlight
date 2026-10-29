#!/bin/bash
# scripts/images.sh with docker replaced by a stub that logs its calls:
# prune keeps this branch's images and their -prev, removes the bot's
# images of other branches and leaves others' images alone; a build here
# is followed by the removal of the build cache and the base images, a
# download is not.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts" "$tmp/bin"
cp scripts/images.sh "$tmp/scripts/"
printf 'IMAGE=alpine:3.24\n' > "$tmp/.env"
r=ghcr.io/umnya-is-a-god/botlight
# the stub: "docker images" lists these; image inspect fails and pull
# fails (missing, not downloadable) when $tmp/missing exists
cat > "$tmp/bin/docker" << EOF
#!/bin/sh
echo "docker \$*" >> "$tmp/calls"
case "\$1 \$2" in
    "images --format")
        printf '%s\n' "$r-php dev" "$r-php dev-prev" "$r-php main" "$r-xr main-prev" \\
            "$r-xr dev-20261029" "nginx latest" "ghcr.io/other/app main" "<none> <none>"
        ;;
    "image inspect"|"pull -q") [ -e "$tmp/missing" ] && exit 1 ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/docker"
failed=0
check() {
    local what="$1"
    shift
    if "$@"; then echo "ok   $what"; else echo "FAIL $what"; failed=$((failed + 1)); fi
}
# shellcheck disable=SC2317 # called through check
called() { grep -qx -- "docker $1" "$tmp/calls"; }
# shellcheck disable=SC2317
not_called() { ! called "$1"; }
images() { : > "$tmp/calls"; (cd "$tmp" && PATH="$tmp/bin:$PATH" IMAGE_TAG=dev bash scripts/images.sh "$@" > /dev/null 2>&1); }

images prune
check 'prune: another branch removed' called "rmi $r-php:main"
check 'prune: its -prev too' called "rmi $r-xr:main-prev"
check 'prune: a dated tag too' called "rmi $r-xr:dev-20261029"
check 'prune: this branch kept' not_called "rmi $r-php:dev"
check 'prune: its -prev kept' not_called "rmi $r-php:dev-prev"
check 'prune: other images left alone' not_called 'rmi nginx:latest'
check 'prune: another project left alone' not_called 'rmi ghcr.io/other/app:main'

images ensure
check 'downloaded: no cleanup' not_called 'builder prune -af'

touch "$tmp/missing"
images ensure
check 'built here: the images built' grep -q 'compose .* build --pull --no-cache' "$tmp/calls"
check 'built here: the build cache removed' called 'builder prune -af'
check 'built here: the base images removed' called 'rmi alpine:3.24'
check 'built here: golang too' called 'rmi golang:alpine'
check 'built here: cleaned once' test "$(grep -c 'builder prune' "$tmp/calls")" -eq 1

images update
check 'update, built here: cleaned' called 'builder prune -af'

[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
