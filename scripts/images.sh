#!/bin/bash
# The bot's images on the server. They are built on GitHub
# (.github/workflows/images.yml) and published as
# ghcr.io/<owner>/botlight-<image>:<branch>; whatever cannot be downloaded
# is built here from dockerfile/ as before.
#   images.sh tag       the tag for this checkout (the branch name)
#   images.sh ensure    every image present (make start): kept as it is,
#                       a missing one downloaded or built
#   images.sh check     the images the registry has a newer version of
#                       (scripts/update.sh, daily; nothing is downloaded)
#   images.sh update    the newer images downloaded (built here if the
#                       registry cannot be reached), the current ones kept
#                       as <tag>-prev; prints what changed
#   images.sh rollback  the <tag>-prev images back in place
#   images.sh prune     images no longer used: earlier builds of the bot,
#                       its images under the names of earlier versions and
#                       those of other branches (this branch's and its
#                       -prev stay)
#   images.sh buildclean  after a build here: the build cache and the base
#                       images the build pulled
cd "$(dirname "$0")/.." || exit 1
[ -f override.env ] || touch override.env

# IMAGES (override.env or .env) replaces the registry and owner
IMAGES=${IMAGES:-$(sed -n 's/^IMAGES=//p' .env override.env 2> /dev/null | tr -d '\r' | tail -n 1)}
IMAGES=${IMAGES:-ghcr.io/umnya-is-a-god/botlight}
if [ -z "$IMAGE_TAG" ]; then
    IMAGE_TAG=$(git rev-parse --abbrev-ref HEAD 2> /dev/null | tr -c 'A-Za-z0-9_.\n-' '-')
fi
IMAGE_TAG=${IMAGE_TAG:-main}
# docker-compose.yml takes the same names from these
export IMAGES IMAGE_TAG

# service in docker-compose.yml:image ("up" and "service" share ng and php)
SERVICES="ng:ng php:php ad:ad xr:xr oc:oc wp:wg dnstt:dnstt"

name() { echo "$IMAGES-$1:$IMAGE_TAG"; }

compose() { docker compose --env-file ./.env --env-file ./override.env "$@"; }

# built here from dockerfile/, under the same name: anew, so the newest
# packages and programs are taken, not the ones of an earlier build
built=""
build() {
    built=1
    compose build --pull --no-cache "$1"
}

# After a build here: its cache and the base images it pulled are not
# needed, the images come from GitHub's registry (gigabytes otherwise).
# Docker keeps one build cache for the whole server: all of it goes. A base
# image a container still uses stays (docker rmi refuses).
buildclean() {
    local base
    docker builder prune -af > /dev/null 2>&1
    base=$(sed -n 's/^IMAGE=//p' .env override.env 2> /dev/null | tr -d '\r' | tail -n 1)
    for b in "${base:-alpine:3.24}" golang:alpine adguard/adguardhome; do
        docker rmi "$b" > /dev/null 2>&1
    done
    true
}

# the digest the registry has for an image (ghcr.io only), '' if unknown
remote_digest() {
    local repo="${IMAGES#ghcr.io/}-$1" token
    case "$IMAGES" in ghcr.io/*) ;; *) return 0 ;; esac
    token=$(curl -fsS -m 20 "https://ghcr.io/token?scope=repository:$repo:pull" 2> /dev/null \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    [ -n "$token" ] || return 0
    curl -fsSI -m 20 -H "Authorization: Bearer $token" \
        -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
        "https://ghcr.io/v2/$repo/manifests/$IMAGE_TAG" 2> /dev/null \
        | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p'
}

# the digest the local image was downloaded with, '' if it was built here
local_digest() {
    docker image inspect --format '{{join .RepoDigests "\n"}}' "$(name "$1")" 2> /dev/null \
        | sed -n "s#^$IMAGES-$1@##p" | head -n 1
}

case "$1" in
    tag)
        echo "$IMAGE_TAG"
        ;;

    ensure)
        for s in $SERVICES; do
            svc=${s%%:*}
            img=$(name "${s#*:}")
            docker image inspect "$img" > /dev/null 2>&1 && continue
            echo "images: $img"
            docker pull -q "$img" > /dev/null 2>&1 || build "$svc" || { buildclean; exit 1; }
        done
        [ -n "$built" ] && buildclean
        true
        ;;

    check)
        new=""
        for s in $SERVICES; do
            n=${s#*:}
            remote=$(remote_digest "$n")
            [ -n "$remote" ] && [ "$remote" != "$(local_digest "$n")" ] && new="$new $n"
        done
        echo "${new# }"
        ;;

    update)
        changed=""
        for s in $SERVICES; do
            svc=${s%%:*}
            n=${s#*:}
            img=$(name "$n")
            before=$(docker image inspect --format '{{.Id}}' "$img" 2> /dev/null)
            [ -n "$before" ] && docker tag "$img" "$IMAGES-$n:$IMAGE_TAG-prev"
            if ! docker pull -q "$img" > /dev/null 2>&1; then
                echo "$n: not downloaded, built here"
                build "$svc" > /dev/null 2>&1 || echo "$n: build failed, the image stays as it was"
            fi
            after=$(docker image inspect --format '{{.Id}}' "$img" 2> /dev/null)
            [ "$before" != "$after" ] && changed="$changed $n"
        done
        [ -n "$built" ] && buildclean
        echo "new:${changed:- none}"
        ;;

    rollback)
        for s in $SERVICES; do
            n=${s#*:}
            prev="$IMAGES-$n:$IMAGE_TAG-prev"
            docker image inspect "$prev" > /dev/null 2>&1 && docker tag "$prev" "$(name "$n")"
        done
        ;;

    prune)
        docker image prune -f --filter label=org.botlight.project=vpnbot > /dev/null
        # names of earlier versions, built on the server: removed once unused
        docker images --format '{{.Repository}}:{{.Tag}}' \
            | grep -E '^botlight/vpnbot-[a-z]+:local$' \
            | xargs -r docker rmi > /dev/null 2>&1
        # the bot's images of other branches (after a change of branch);
        # one a container still uses stays (docker rmi refuses)
        docker images --format '{{.Repository}} {{.Tag}}' | while read -r repo tag; do
            case "$repo" in "$IMAGES"-*) ;; *) continue ;; esac
            case "$tag" in "$IMAGE_TAG" | "$IMAGE_TAG-prev") continue ;; esac
            docker rmi "$repo:$tag" > /dev/null 2>&1
        done
        true
        ;;

    buildclean)
        buildclean
        ;;

    *)
        echo "usage: images.sh tag|ensure|check|update|rollback|prune|buildclean" >&2
        exit 1
        ;;
esac
