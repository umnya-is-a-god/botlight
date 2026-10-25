#!/bin/sh
# Health of a container: each heartbeat file given was touched by its loop
# within the last MAX_AGE seconds.
#   check_file.sh MAX_AGE FILE [FILE...]
max=${1:-120}
shift
[ $# -gt 0 ] || set -- /tmp/heartbeat
now=$(date +%s)
for f in "$@"; do
    last=$(stat -c %Y "$f" 2> /dev/null) || exit 1
    [ $((now - last)) -le "$max" ] || exit 1
done
# php: the bot's key the other containers log in with
if [ -e /sshpub ] && [ ! -s /ssh/key.pub ]; then
    exit 1
fi
exit 0
