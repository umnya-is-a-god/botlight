#!/bin/bash
pwd=`pwd`
TELEGRAM_API=$(grep -m1 '^TELEGRAM_API=' "$pwd/.env" 2>/dev/null | cut -d'=' -f2-)
TELEGRAM_API=${TELEGRAM_API:-api.telegram.org}
process_name="$pwd/scripts/update.sh"
current_pid=$$
pids=$(pgrep -f $process_name)
for pid in $pids; do
    if [ $pid -ne $current_pid ]; then
        kill -9 $pid
    fi
done

> $pwd/update/pipe
# pid lives outside ./update: that folder is writable from the containers
echo "$$" > $pwd/.update_pid
last_fetch=0

tg_draft() {
    local text="$1"
    local escaped="${text//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    curl -s -H "Content-Type: application/json" \
        -X POST "https://$TELEGRAM_API/bot$_key/sendMessageDraft" \
        -d "{\"chat_id\":$_chat_id,\"draft_id\":1,\"text\":\"$escaped\"}" > /dev/null
}

while true
do
    # fetch the bot repository (origin) hourly on the host; the bot reads
    # the fetched refs to report new commits
    now=$(date +%s)
    if (( now - last_fetch >= 3600 )); then
        last_fetch=$now
        git -C "$pwd" fetch -q origin >/dev/null 2>&1 &
    fi
    cmd=$(cat $pwd/update/pipe)
    # written by the bot (container): accept a plain branch name only
    branch=$(cat $pwd/update/branch 2>/dev/null | tr -d '\r\n')
    case "$branch" in
        *[!A-Za-z0-9._/-]*|-*) branch="" ;;
    esac
    if [[ -n "$cmd" ]]
    then
        _key=$(cat $pwd/update/key)
        _curl_data=$(cat $pwd/update/curl)
        _chat_id=$(echo "$_curl_data" | grep -o '"chat_id":[0-9-]*' | head -1 | cut -d: -f2)
        _message_id=$(echo "$_curl_data" | grep -o '"message_id":[0-9]*' | head -1 | cut -d: -f2)

        tg_draft "stopping the bot"
        docker compose down --remove-orphans

        if [[ "$cmd" == "1" ]]
        then
            tg_draft "clearing the directory"
            git reset --hard && git clean -fd
            tg_draft "downloading the update"
            git fetch
            if [[ -n "$branch" ]]
            then
                tg_draft "changing branch"
                git checkout -t "origin/$branch" || git checkout "$branch"
            fi
            tg_draft "applying updates"
            git pull > ./update/message
        fi

        tg_draft "launching the bot"
        make start

        > $pwd/update/key
        > $pwd/update/curl

        curl -s -H "Content-Type: application/json" \
            -X POST "https://$TELEGRAM_API/bot$_key/sendMessage" \
            -d "{\"chat_id\":$_chat_id,\"text\":\"bot started\"}" > /dev/null

        bash $pwd/scripts/update.sh &
        exit 0
    fi
    sleep 1
done
