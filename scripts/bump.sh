#!/usr/bin/env bash
# Bump the [package] version in Cargo.toml, regenerate the lockfile,
# then run the tests against it. Restores the original files if anything fails.
#
# Always operates on the Cargo.toml at the git repository root, so it can be
# run from any directory inside the repo.
#
# Usage: ./bump.sh [patch|minor|major]
#   patch  1.2.3 -> 1.2.4   (default)
#   minor  1.2.3 -> 1.3.0
#   major  1.2.3 -> 2.0.0
set -euo pipefail

BUMP="${1:-patch}"
MANIFEST="Cargo.toml"

case "$BUMP" in
    patch|minor|major) ;;
    *)
        echo "error: bump type must be patch, minor or major (got '$BUMP')" >&2
        echo "usage: $0 [patch|minor|major]" >&2
        exit 1
        ;;
esac

if ! repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
    echo "error: not inside a git repository" >&2
    exit 1
fi

cd "$repo_root"

if [[ ! -f "$MANIFEST" ]]; then
    echo "error: no Cargo.toml at git root ($repo_root)" >&2
    exit 1
fi

# Read the version from the [package] section only, so dependency
# versions are never touched.
current=$(awk '
    /^\[/ { in_pkg = ($0 ~ /^\[package\][[:space:]]*$/) }
    in_pkg && /^version[[:space:]]*=/ {
        match($0, /"[^"]+"/)
        print substr($0, RSTART + 1, RLENGTH - 2)
        exit
    }
' "$MANIFEST")

if [[ -z "$current" ]]; then
    echo "error: no literal version found in [package] (workspace-inherited versions are not supported)" >&2
    exit 1
fi

if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "error: version '$current' is not plain MAJOR.MINOR.PATCH" >&2
    exit 1
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
case "$BUMP" in
    major) new="$((major + 1)).0.0" ;;
    minor) new="${major}.$((minor + 1)).0" ;;
    patch) new="${major}.${minor}.$((patch + 1))" ;;
esac

# Back up so a failed build or test run leaves nothing half-bumped.
backup_dir="$(mktemp -d)"
cp "$MANIFEST" "$backup_dir/Cargo.toml"
[[ -f Cargo.lock ]] && cp Cargo.lock "$backup_dir/Cargo.lock"

restore() {
    echo "Failed: restoring original Cargo.toml and Cargo.lock" >&2
    cp "$backup_dir/Cargo.toml" "$MANIFEST"
    if [[ -f "$backup_dir/Cargo.lock" ]]; then
        cp "$backup_dir/Cargo.lock" Cargo.lock
    else
        rm -f Cargo.lock
    fi
}
trap 'restore' ERR
trap 'rm -rf "$backup_dir"' EXIT

# Rewrite only the first version line inside [package].
awk -v new="$new" '
    /^\[/ { in_pkg = ($0 ~ /^\[package\][[:space:]]*$/) }
    in_pkg && !done && /^version[[:space:]]*=/ {
        sub(/"[^"]+"/, "\"" new "\"")
        done = 1
    }
    { print }
' "$MANIFEST" > "$MANIFEST.tmp"
mv "$MANIFEST.tmp" "$MANIFEST"

echo "Version ($BUMP): $current -> $new"

cargo generate-lockfile
cargo test --locked

echo "Done: now at version $new"
