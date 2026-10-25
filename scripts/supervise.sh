#!/bin/sh
# Keeps a process of the container running.
#   supervise.sh NAME HEARTBEAT MAX_AGE COMMAND [ARGS...]
# The command is started again when it exits. With a HEARTBEAT file (the
# process touches it on every loop) it is also stopped and started again
# when the file is older than MAX_AGE seconds: the loop hangs.
name=$1
hb=$2
max=$3
shift 3
while true; do
    "$@" &
    pid=$!
    started=$(date +%s)
    while kill -0 "$pid" 2> /dev/null; do
        sleep 10
        if [ -n "$hb" ]; then
            now=$(date +%s)
            last=$(stat -c %Y "$hb" 2> /dev/null || echo "$started")
            [ "$last" -lt "$started" ] && last=$started
            if [ $((now - last)) -gt "$max" ]; then
                echo "supervise: $name: no heartbeat for $((now - last))s, restarting it" >&2
                kill "$pid" 2> /dev/null
                sleep 5
                kill -9 "$pid" 2> /dev/null
            fi
        fi
    done
    wait "$pid"
    echo "supervise: $name exited ($?), starting it again in 5 s" >&2
    sleep 5
done
