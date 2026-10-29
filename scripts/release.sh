#!/bin/sh
# Downloads a program's release file from GitHub for the image builds
# (dockerfile/) and checks it against the SHA-256 GitHub lists for the file.
#   release.sh OWNER/REPO latest:PREFIX|tag:TAG ASSET OUT
# latest:PREFIX  the newest release (not a draft or pre-release) whose tag
#                starts with PREFIX and that is at least 3 days old: one
#                pulled or replaced soon after it came out is not taken
# tag:TAG        exactly that release, whatever its age
# ASSET is the file name: {tag} stands for the tag, {v} for it without the
# leading v. Prints the tag. Needs curl and jq. A GitHub token in
# /run/secrets/github_token (a build secret, never kept in the image) or
# in GITHUB_TOKEN raises the API's rate limit.
set -eu
repo=$1 pick=$2 asset=$3 out=$4
min_age_days=3

token=${GITHUB_TOKEN:-}
[ -s /run/secrets/github_token ] && token=$(cat /run/secrets/github_token)
set -- curl -fsSL -m 60 --retry 2
api() {
    if [ -n "$token" ]; then
        "$@" -H "Authorization: Bearer $token" -H 'Accept: application/vnd.github+json' "$url"
    else
        "$@" -H 'Accept: application/vnd.github+json' "$url"
    fi
}
case "$pick" in
    tag:*)
        # a tag goes into the address: its characters are checked
        case "${pick#tag:}" in ''|*[!A-Za-z0-9._-]*) echo "release.sh: bad tag: $pick" >&2; exit 1 ;; esac
        url="https://api.github.com/repos/$repo/releases/tags/${pick#tag:}"
        ;;
    *) url="https://api.github.com/repos/$repo/releases?per_page=50" ;;
esac
# "<tag> <sha256> <url>" of the chosen release's file
found=$(api "$@" | jq -er \
    --arg pick "$pick" --arg asset "$asset" \
    --argjson before "$(($(date +%s) - min_age_days * 86400))" '
    [if type == "object" then . else .[] end | select((.draft or .prerelease) | not)
        | if ($pick | startswith("tag:")) then select(.tag_name == ($pick | ltrimstr("tag:")))
          else select((.tag_name | startswith($pick | ltrimstr("latest:")))
              and ((.published_at | fromdateiso8601) <= $before)) end]
    | max_by(.published_at) // error("no release for " + $pick)
    | .tag_name as $tag
    | ($asset | gsub("\\{tag\\}"; $tag) | gsub("\\{v\\}"; $tag | ltrimstr("v"))) as $name
    | [.assets[] | select(.name == $name)] | first // error("no file " + $name + " in " + $tag)
    | (.digest // "" | ltrimstr("sha256:")) as $sum
    | if ($sum | test("^[0-9a-f]{64}$")) then "\($tag) \($sum) \(.browser_download_url)"
      else error("no SHA-256 listed for " + $name + " in " + $tag) end')
tag=${found%% *}
rest=${found#* }
sum=${rest%% *}
file=${rest#* }
case "$file" in
    "https://github.com/$repo/releases/download/"*) ;;
    *) echo "release.sh: unexpected download address: $file" >&2; exit 1 ;;
esac
"$@" -o "$out" "$file"
echo "$sum  $out" | sha256sum -c - > /dev/null
echo "$tag"
