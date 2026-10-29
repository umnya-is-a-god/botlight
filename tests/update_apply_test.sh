#!/bin/bash
# apply_update and changes_since from scripts/update.sh on real git
# repositories: an update of the branch, a change of branch and an update
# with nothing new report the version, the new commits and the ones the
# new branch does not have.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed -n '/^changes_since() {/,/^}/p; /^apply_update() {/,/^}/p' scripts/update.sh > "$tmp/functions.sh"
# shellcheck source=/dev/null
. "$tmp/functions.sh"
failed=0
# has DESCRIPTION TEXT: the last report contains TEXT
has() {
    if grep -qF -- "$2" <<< "$out"; then echo "ok   $1"; else echo "FAIL $1"; printf '%s\n' "$out"; failed=$((failed + 1)); fi
}
lacks() {
    if ! grep -qF -- "$2" <<< "$out"; then echo "ok   $1"; else echo "FAIL $1"; printf '%s\n' "$out"; failed=$((failed + 1)); fi
}
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
commit() { echo "$1" >> file && git add -A && git commit -qm "$1"; }

# the repository on GitHub: dev with one commit more than the server has
git init -q -b dev "$tmp/src" && cd "$tmp/src" || exit 1
echo 1.1 > VERSION
commit "first"
git clone -q "$tmp/src" "$tmp/server"
commit "dev change"
echo 1.2 > VERSION
commit "Version 1.2"
git branch -q main HEAD~2
git checkout -q main
commit "main only"
git checkout -q dev

cd "$tmp/server" || exit 1
git fetch -q origin
out=$(apply_update '@{u}')
has 'update: version' 'v1.1 → v1.2'
has 'update: new commits' '- dev change'
has 'update: newest first' "$(printf -- '- Version 1.2\n- dev change')"
lacks 'update: nothing left behind' 'not in this branch'

out=$(apply_update '@{u}')
has 'nothing new: said so' 'no new commits'
lacks 'nothing new: no version' '→ v'

out=$(apply_update 'branch:main')
has 'branch: named' 'branch: dev → main'
has 'branch: version back' 'v1.2 → v1.1'
has 'branch: its commits' '- main only'
has 'branch: dev commits it lacks' 'not in this branch (2):'
has 'branch: they are listed' '- Version 1.2'
out=$(git rev-parse --abbrev-ref HEAD)
has 'branch: switched' main

[ "$failed" -eq 0 ] && echo "all passed" || echo "$failed failed"
exit "$failed"
