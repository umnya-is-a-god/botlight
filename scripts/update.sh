#!/bin/bash
# Runs on the host (make preup), one copy at a time. The bot (in a
# container) asks for an update (1), restart (2) or new images (3)
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
: > "$pwd/update/backup"
# pid lives outside ./update: that folder is writable from the containers
echo "$$" > "$pwd/.update_pid"
last_fetch=0
last_images=0

# the containers after a change of images: all running, none unhealthy,
# within 5 minutes; else prints the ones that are not
healthy() {
    local i bad=""
    for i in $(seq 1 60); do
        bad=$(docker compose ps -a --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null \
            | awk '$2 != "running" || $3 == "unhealthy" || $3 == "starting"')
        [ -z "$bad" ] && return 0
        [ "$i" -lt 60 ] && sleep 5
    done
    printf '%s\n' "$bad"
    return 1
}

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

# a backup from the bot before anything stops, only when there is
# something to install: the bot's cron (service container, every 10 s)
# sends it to the main admin and answers in ./update/backup (Bot::hostBackup);
# no answer in 2 minutes: the update goes on, the report says so
request_backup() {
    local i answer=""
    tg_draft "sending a backup"
    printf 'request' > "$pwd/update/backup"
    for i in $(seq 1 120); do
        answer=$(tr -d '\r\n' < "$pwd/update/backup" 2> /dev/null)
        case "$answer" in
            sent|'no password'|failed) break ;;
        esac
        answer=""
        sleep 1
    done
    : > "$pwd/update/backup"
    case "$answer" in
        sent) backup_note="\nbackup: sent" ;;
        'no password') backup_note="\nbackup: not sent, no backup password" ;;
        failed) backup_note="\nbackup: FAILED to send" ;;
        *) backup_note="\nbackup: no answer from the bot" ;;
    esac
}

# done: the token forgotten, and the bot asked to show the admin the menu
# the command came from again (Bot::menuAfterHost reads ./update/menu)
back_to_menu() {
    local menu=config
    [ "$cmd" = 1 ] && menu=update
    : > "$pwd/update/key"
    : > "$pwd/update/curl"
    _key=""
    printf '%s:%s' "$_chat_id" "$menu" > "$pwd/update/menu"
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
# code can move forward. Prints the ref to merge, or why not: 1 not
# possible, 2 nothing new (the bot is not stopped for it).
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
    if [ "$(git rev-parse -q --verify HEAD)" = "$(git rev-parse -q --verify "$ref^{commit}")" ]; then
        echo "no new commits, nothing was restarted"
        return 2
    fi
    if ! git merge-base --is-ancestor HEAD "$ref" 2> /dev/null; then
        echo "not updated: the local branch differs from origin (no fast-forward); to replace it on the host: git reset --hard origin/<branch> (the settings in ./data stay)"
        return 1
    fi
    echo "$ref"
}

# what an update brought since commit $1: the version if it changed, the
# new commits (subjects, newest first) and, after a change of branch, the
# ones the new branch does not have; the bot shows it after the restart
changes_since() {
    local before="$1" old new n gone
    old=$(git show "$before:VERSION" 2> /dev/null | tr -d '\r\n')
    new=$(tr -d '\r\n' < VERSION 2> /dev/null)
    [ -n "$old" ] && [ "$old" != "$new" ] && echo "v$old → v$new"
    n=$(git rev-list --no-merges --count "$before..HEAD" 2> /dev/null)
    if [ "${n:-0}" -eq 0 ]; then
        echo "no new commits"
    else
        git log --no-merges --format='- %s' -n 30 "$before..HEAD"
        [ "$n" -gt 30 ] && echo "... and $((n - 30)) more"
    fi
    gone=$(git rev-list --no-merges --count "HEAD..$before" 2> /dev/null)
    if [ "${gone:-0}" -gt 0 ]; then
        echo "not in this branch ($gone):"
        git log --no-merges --format='- %s' -n 10 "HEAD..$before"
        [ "$gone" -gt 10 ] && echo "... and $((gone - 10)) more"
    fi
    true
}

# moves the code to what check_update printed; prints what happened
apply_update() {
    local ref="$1" stash out before from
    before=$(git rev-parse -q --verify HEAD)
    from=$(git rev-parse --abbrev-ref HEAD)
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
            echo "branch: $from → $ref"
            ref='@{u}'
            ;;
    esac
    if ! out=$(git merge --ff-only "$ref" 2>&1); then
        echo "not updated: $out"
        return 1
    fi
    changes_since "$before"
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
    # daily: which images GitHub's registry has newer versions of; the bot
    # reads ./update/images and tells the admin (nothing is downloaded)
    if (( now - last_images >= 86400 )); then
        last_images=$now
        ( bash "$pwd/scripts/images.sh" check > "$pwd/update/images.tmp" 2> /dev/null \
            && mv "$pwd/update/images.tmp" "$pwd/update/images" ) &
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
        backup_note=""

        if [[ "$cmd" == "1" ]]
        then
            tg_draft "downloading the update"
            ref=$(check_update "$branch" "$target" 2>&1)
            rc=$?
            if [ "$rc" -ne 0 ]; then
                # nothing was stopped: the bot keeps running as it was
                [ "$rc" -eq 2 ] || ref="update not installed: $ref"
                tg sendMessage "{\"chat_id\":$_chat_id,\"text\":$(json_str "$ref")}"
                back_to_menu
                continue
            fi
            request_backup
        fi

        report=""
        if [[ "$cmd" == "3" ]]
        then
            # new images downloaded while everything still runs; the
            # current ones are kept as <tag>-prev
            tg_draft "downloading the images"
            images=$(bash "$pwd/scripts/images.sh" update 2>&1)
            report="\n\nimages: $images"
            if [[ "$images" == "new: none" ]]
            then
                # nothing new: no restart
                : > "$pwd/update/images"
                tg sendMessage "{\"chat_id\":$_chat_id,\"text\":$(json_str "the images are up to date, nothing was restarted")}"
                back_to_menu
                continue
            fi
            request_backup
        fi

        tg_draft "stopping the bot"
        docker compose down --remove-orphans

        if [[ "$cmd" == "1" ]]
        then
            if result=$(apply_update "$ref" 2>&1); then
                report="\n\nupdated"
            else
                report="\n\nUPDATE FAILED, the bot runs the previous version"
            fi
            printf '%s\n' "$result" > ./update/message
        fi

        tg_draft "launching the bot"
        make start

        if [[ "$cmd" == "3" ]]
        then
            tg_draft "checking the containers"
            if ! bad=$(healthy); then
                # the new images do not run here: the previous ones back
                bash "$pwd/scripts/images.sh" rollback
                make start
                report="$report\nnot healthy with the new images:\n$bad\nthe previous images are back"
            fi
            bash "$pwd/scripts/images.sh" prune
        fi

        tg sendMessage "{\"chat_id\":$_chat_id,\"text\":$(json_str "$(printf '%b' "bot started$report$backup_note")")}"
        back_to_menu

        bash "$pwd/scripts/update.sh" &
        exit 0
    fi
    sleep 1
done
