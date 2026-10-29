#!/bin/bash
# scripts/update.sh with docker, make, git and curl replaced by stubs that
# log their calls: a command it does not know must not stop the containers,
# a restart (2) must; an update (1) or images (3) with nothing new must not.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d)
trap 'pkill -f "$tmp/scripts/update.sh" 2> /dev/null; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts" "$tmp/update" "$tmp/bin"
cp scripts/update.sh scripts/images.sh "$tmp/scripts/"
for c in docker make git curl; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$c" "$tmp" > "$tmp/bin/$c"
    chmod +x "$tmp/bin/$c"
done
# HEAD and the branch upstream are the same commit: nothing new to install
# shellcheck disable=SC2016 # $1 is the stub's argument
printf '[ "$1" = rev-parse ] && echo 0123abcd\n' >> "$tmp/bin/git"
: > "$tmp/calls"
failed=0
# check DESCRIPTION COMMAND...: ok when the command succeeds
check() {
    local what="$1"
    shift
    if "$@"; then echo "ok   $what"; else echo "FAIL $what"; failed=$((failed + 1)); fi
}
# shellcheck disable=SC2317 # called through check
called() { grep -q "$1" "$tmp/calls"; }
# shellcheck disable=SC2317
not_called() { ! called "$1"; }

PATH="$tmp/bin:$PATH" bash "$tmp/scripts/update.sh" > /dev/null 2>&1 &
sleep 2
printf 'rm -rf /' > "$tmp/update/pipe"
sleep 3
check 'unknown command: containers not stopped' not_called 'docker compose down'
check 'unknown command: dropped from the pipe' test ! -s "$tmp/update/pipe"

printf '2' > "$tmp/update/pipe"
sleep 3
check 'restart (2): containers stopped' called 'docker compose down'
check 'restart (2): started again' called 'make start'

# new images (3) when the registry has nothing new: nothing is stopped
: > "$tmp/calls"
sleep 2
printf '3' > "$tmp/update/pipe"
sleep 4
check 'images (3), nothing new: images asked for' called 'docker pull'
check 'images (3), nothing new: containers not stopped' not_called 'docker compose down'
check 'images (3), nothing new: menu back' grep -qx '0:config' "$tmp/update/menu"

# an update (1) with no new commits: nothing is stopped, the menu comes back
: > "$tmp/calls"
: > "$tmp/update/menu"
printf '1' > "$tmp/update/pipe"
sleep 3
check 'update (1), nothing new: fetched' called 'git fetch'
check 'update (1), nothing new: containers not stopped' not_called 'docker compose down'
check 'update (1), nothing new: menu back' grep -qx '0:update' "$tmp/update/menu"

[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
