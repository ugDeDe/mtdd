#!/usr/bin/env bash
# Release version and tag for a CI build.
#
#   main: a new immutable release vMAJOR.MINOR.PATCH per build. The version
#         always grows: it is the VERSION file when that is above the highest
#         released vX.Y.Z (a manual minor or major bump), otherwise the
#         highest release with PATCH + 1.
#   dev:  the single moving prerelease channel-dev, re-uploaded on every
#         build; the binary reports dev-<7-char commit sha>.
#
# Usage:
#   tools/release-version.sh main|dev   # inspects git tags of the checkout
#   tools/release-version.sh next BASE  # pure: tags on stdin, prints version
#
# The main/dev forms print key=value lines for $GITHUB_OUTPUT:
#   version   string embedded in the binary (1.4.2 or dev-1a2b3c4)
#   tag       release tag (v1.4.2 or channel-dev)
#   existing  main: 1 when HEAD already has its release tag (re-run: publish
#             nothing); always 0 for dev
#   previous  main: the previous vX.Y.Z, empty for the first one; dev: empty
set -euo pipefail

die() {
    printf 'release-version: %s\n' "$*" >&2
    exit 2
}

semver='^[0-9]+\.[0-9]+\.[0-9]+$'

# Highest vX.Y.Z among the tags on stdin, without the "v"; empty if none.
highest_release() {
    local tag best=
    while IFS= read -r tag; do
        tag=${tag#v}
        [[ $tag =~ $semver ]] || continue
        if [[ -z $best ]] || [[ $(printf '%s\n%s\n' "$best" "$tag" | sort -V | tail -n 1) == "$tag" ]]; then
            best=$tag
        fi
    done
    printf '%s' "$best"
}

next_version() {
    local base=$1 latest=$2
    [[ $base =~ $semver ]] || die "VERSION must be MAJOR.MINOR.PATCH, got '$base'"
    if [[ -z $latest ]]; then
        printf '%s\n' "$base"
        return
    fi
    if [[ $base != "$latest" &&
          $(printf '%s\n%s\n' "$latest" "$base" | sort -V | tail -n 1) == "$base" ]]; then
        printf '%s\n' "$base"
        return
    fi
    local major minor patch
    IFS=. read -r major minor patch <<<"$latest"
    printf '%s.%s.%s\n' "$major" "$minor" "$((10#$patch + 1))"
}

base_version() {
    local root
    root=$(git rev-parse --show-toplevel)
    [[ -f $root/VERSION ]] || die "missing $root/VERSION"
    local base
    base=$(head -n 1 "$root/VERSION" | tr -d '[:space:]')
    printf '%s' "$base"
}

case ${1:-} in
    next)
        (($# == 2)) || die "usage: $0 next BASE < tags"
        next_version "$2" "$(highest_release)"
        ;;
    main)
        existing=$(git tag --list 'v*' --points-at HEAD | highest_release)
        latest=$(git tag --list 'v*' | highest_release)
        if [[ -n $existing ]]; then
            version=$existing
            previous=$(git tag --list 'v*' --no-contains HEAD | highest_release)
            printf 'version=%s\ntag=v%s\nexisting=1\nprevious=%s\n' \
                "$version" "$version" "${previous:+v$previous}"
        else
            version=$(next_version "$(base_version)" "$latest")
            printf 'version=%s\ntag=v%s\nexisting=0\nprevious=%s\n' \
                "$version" "$version" "${latest:+v$latest}"
        fi
        ;;
    dev)
        printf 'version=dev-%s\ntag=channel-dev\nexisting=0\nprevious=\n' \
            "$(git rev-parse --short=7 HEAD)"
        ;;
    *)
        die "usage: $0 main|dev | next BASE < tags"
        ;;
esac
