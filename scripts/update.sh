#!/bin/bash
# Runs on the host (make preup), one copy at a time. The bot (in a
# container) asks for an update (1), restart (2) or image rebuild (3)
# through ./update/pipe; whatever the containers write into ./update is
# checked before use. The working state lives in ./data, outside git: an
# update only moves the code forward (fast-forward), it never resets or
# cleans the folder.
cd "$(dirname "$0")/.." || exit 1
pwd=$(pwd)
TELEGRAM_API=$(grep -m1 '^TELEGRAM_API=' "$pwd/.env" 2>/dev/null | cut -d'=' -f2- | tr -d '\r')
case "$TELEGRAM_API" in
    ''|*[!A-Za-z0-9.:-]*) TELEGRAM_API=api.telegram.org ;;
esac
process_name="$pwd/scripts/update.sh"
current_pid=$$
for pid in $(pgrep -f "$process_name"); do
    if [ "$pid" -ne "$current_pid" ]; then
        kill -9 "$pid"
    fi
done

: > "$pwd/update/pipe"
# pid lives outside ./update: that folder is writable from the containers
echo "$$" > "$pwd/.update_pid"
last_fetch=0

# The bot token goes to curl in a config file (mode 600), not on the
# command line, where every process on the host could read it.
tg() {
    local method="$1" json="$2" cfg
    [ -n "$_key" ] || return
    cfg=$(mktemp) || return
    chmod 600 "$cfg"
    printf 'url = "https://%s/bot%s/%s"\n' "$TELEGRAM_API" "$_key" "$method" > "$cfg"
    printf '%s' "$json" | curl -s -K "$cfg" -H "Content-Type: application/json" -X POST --data-binary @- > /dev/null
    rm -f "$cfg"
}

json_str() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/}
    s=${s//$'\t'/ }
    printf '"%s"' "$s"
}

tg_draft() {
    tg sendMessageDraft "{\"chat_id\":$_chat_id,\"draft_id\":1,\"text\":$(json_str "$1")}"
}

# git verify-tag with the key in ./data/update-signing-key: a GPG public
# key (armored) or SSH allowed signers lines ("* ssh-ed25519 AAAA...")
verify_tag() {
    local key="$pwd/data/update-signing-key" tmp rc
    [ -s "$key" ] || return 1
    if grep -q 'BEGIN PGP PUBLIC KEY' "$key"; then
        tmp=$(mktemp -d) || return 1
        GNUPGHOME="$tmp" gpg --batch --quiet --import "$key" > /dev/null 2>&1 \
            && GNUPGHOME="$tmp" git -C "$pwd" -c gpg.program=gpg verify-tag "$1" > /dev/null 2>&1
        rc=$?
        rm -rf "$tmp"
        return $rc
    fi
    git -C "$pwd" -c gpg.ssh.program=ssh-keygen -c gpg.ssh.allowedSignersFile="$key" verify-tag "$1" > /dev/null 2>&1
}

# Before anything stops: fetch, check the signature of a tag and that the
# code can move forward. Prints the ref to merge, or why not (non-zero).
check_update() {
    local branch="$1" target="$2" ref out
    if ! out=$(git fetch -q --tags origin 2>&1); then
        echo "fetch failed: $out"
        return 1
    fi
    case "$target" in
        tag:*)
            ref=${target#tag:}
            if ! git rev-parse -q --verify "refs/tags/$ref" > /dev/null; then
                echo "no tag $ref"
                return 1
            fi
            if ! verify_tag "$ref"; then
                echo "tag $ref: the signature does not match data/update-signing-key, not installed"
                return 1
            fi
            ref="refs/tags/$ref^{commit}"
            ;;
        *)
            if [ -n "$branch" ] && [ "$branch" != "$(git rev-parse --abbrev-ref HEAD)" ]; then
                if ! git rev-parse -q --verify "origin/$branch" > /dev/null; then
                    echo "no branch origin/$branch"
                    return 1
                fi
                echo "branch:$branch"
                return 0
            fi
            ref='@{u}'
            ;;
    esac
    if ! git merge-base --is-ancestor HEAD "$ref" 2> /dev/null; then
        echo "not updated: the local branch differs from origin (no fast-forward); to replace it on the host: git reset --hard origin/<branch> (the settings in ./data stay)"
        return 1
    fi
    echo "$ref"
}

# moves the code to what check_update printed; prints what happened
apply_update() {
    local ref="$1" stash out
    # local edits of tracked files would stop the merge: kept in git stash
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        stash="botlight update $(date '+%Y-%m-%d %H:%M')"
        if git stash push -q -m "$stash"; then
            echo "local changes saved: git stash list ($stash)"
        else
            echo "local changes could not be saved, update stopped"
            return 1
        fi
    fi
    case "$ref" in
        branch:*)
            ref=${ref#branch:}
            if ! out=$( (git checkout -q -t "origin/$ref" || git checkout -q "$ref") 2>&1 ); then
                echo "branch $ref: $out"
                return 1
            fi
            echo "branch: $ref"
            ref='@{u}'
            ;;
    esac
    if ! out=$(git merge --ff-only "$ref" 2>&1); then
        echo "not updated: $out"
        return 1
    fi
    echo "$out"
}

while true
do
    # fetch the bot repository (origin) hourly on the host; the bot reads
    # the fetched refs to report new commits and signed tags
    now=$(date +%s)
    if (( now - last_fetch >= 3600 )); then
        last_fetch=$now
        git -C "$pwd" fetch -q --tags origin >/dev/null 2>&1 &
    fi
    cmd=$(tr -d '\r\n' 2>/dev/null < "$pwd/update/pipe")
    # the bot writes 1 (update), 2 (restart) or 3 (images); anything else
    # is dropped before the containers are touched
    case "$cmd" in
        ''|1|2|3) ;;
        *)
            echo "update.sh: unknown command in update/pipe ignored" >&2
            : > "$pwd/update/pipe"
            cmd=""
            ;;
    esac
    if [[ -n "$cmd" ]]
    then
        # written by the bot (container): a plain branch name only
        branch=$(tr -d '\r\n' 2>/dev/null < "$pwd/update/branch")
        case "$branch" in
            *[!A-Za-z0-9._/-]*|-*) branch="" ;;
        esac
        # tag:<name> of a signed release, or empty: the branch's latest commit
        target=$(tr -d '\r\n' 2>/dev/null < "$pwd/update/target")
        case "$target" in
            tag:[A-Za-z0-9]*) case "${target#tag:}" in *[!A-Za-z0-9._-]*) target="" ;; esac ;;
            *) target="" ;;
        esac
        _key=$(cat "$pwd/update/key" 2>/dev/null)
        # a bot token has only these characters
        case "$_key" in
            *[!A-Za-z0-9:_-]*) _key="" ;;
        esac
        _curl_data=$(cat "$pwd/update/curl" 2>/dev/null)
        _chat_id=$(echo "$_curl_data" | grep -o '"chat_id":[0-9-]*' | head -1 | cut -d: -f2)
        _chat_id=${_chat_id:-0}
        : > "$pwd/update/pipe"
        : > "$pwd/update/target"

        if [[ "$cmd" == "1" ]]
        then
            tg_draft "downloading the update"
            if ! ref=$(check_update "$branch" "$target" 2>&1); then
                # nothing was stopped: the bot keeps running as it was
                tg sendMessage "{\"chat_id\":$_chat_id,\"text\":$(json_str "update not installed: $ref")}"
                : > "$pwd/update/key"
                : > "$pwd/update/curl"
                _key=""
                continue
            fi
        fi

        tg_draft "stopping the bot"
        docker compose down --remove-orphans

        report=""
        if [[ "$cmd" == "1" ]]
        then
            if result=$(apply_update "$ref" 2>&1); then
                report="\n\nupdated"
            else
                report="\n\nUPDATE FAILED, the bot runs the previous version"
            fi
            printf '%s\n' "$result" > ./update/message
        fi

        if [[ "$cmd" == "3" ]]
        then
            # every image built anew, one at a time (low memory, the
            # containers are stopped): fresh base images and packages. A
            # failed build keeps the image it had. The log is kept outside
            # ./update, which the containers can write to.
            : > "$pwd/.rebuild.log"
            services=(ng php ad xr oc wp dnstt)
            i=0
            for s in "${services[@]}"; do
                i=$((i + 1))
                tg_draft "building $s ($i/${#services[@]})"
                if make -s rebuild S="$s" >> "$pwd/.rebuild.log" 2>&1; then
                    report="$report\n$s ok"
                else
                    report="$report\n$s FAILED"
                fi
            done
            report="\n\nimages:$report"
            case "$report" in
                *FAILED*) report="$report\nlog: .rebuild.log in the bot folder" ;;
            esac
        fi

        tg_draft "launching the bot"
        make start

        : > "$pwd/update/key"
        : > "$pwd/update/curl"

        tg sendMessage "{\"chat_id\":$_chat_id,\"text\":$(json_str "$(printf '%b' "bot started$report")")}"
        _key=""

        bash "$pwd/scripts/update.sh" &
        exit 0
    fi
    sleep 1
done
