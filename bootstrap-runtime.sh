#!/bin/sh
# Explicit setup only. No system Python, package manager, administrator, or build.
# Contract: bootstrap-runtime.sh ABS_DATA --prepare -> {ok,python,runtime_ready}.
#           bootstrap-runtime.sh ABS_DATA --exec SCRIPT [ARGS...] never downloads.
#           bootstrap-runtime.sh ABS_DATA reports an already prepared runtime.
# Pins: immutable publisher release https://github.com/astral-sh/python-build-standalone/releases/tag/20251014
# API digests: https://api.github.com/repos/astral-sh/python-build-standalone/releases/assets/304305223
#              https://api.github.com/repos/astral-sh/python-build-standalone/releases/assets/304305321
# Layout: https://gregoryszorc.com/docs/python-build-standalone/main/distributions.html
set -u
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset CDPATH ENV BASH_ENV
exec 2>/dev/null

fail() {
    printf '{"ok":false,"error":"%s"}\n' "$1"
    exit 1
}

[ "$#" -ge 1 ] || fail 'A private plugin-data directory is required'
data=$1
shift
mode=${1:-report}
case "$mode" in
    --prepare) [ "$#" -eq 1 ] || fail 'Prepare does not accept extra arguments' ;;
    --exec) shift; [ "$#" -ge 1 ] || fail 'Exec requires a script argument' ;;
    report) [ "$#" -eq 0 ] || fail 'Unknown runtime launcher arguments' ;;
    *) fail 'Unknown runtime launcher action' ;;
esac
case "$data" in
    /*) ;;
    *) fail 'Plugin-data must be an absolute directory' ;;
esac
case "$data" in
    /|*/|*//*|*/./*|*/../*|*/.|*/..) fail 'Plugin-data must be a canonical absolute directory' ;;
esac
clean=$(printf '%s' "$data" | /usr/bin/tr -d '\000-\037\177')
[ "$clean" = "$data" ] || fail 'Plugin-data contains unsupported control characters'
check=$data
while [ "$check" != / ]; do
    [ ! -L "$check" ] || fail 'Plugin-data must not contain symbolic links'
    check=${check%/*}
    [ -n "$check" ] || check=/
done
[ "$(/usr/bin/uname -s)" = Darwin ] || fail 'Managed Python supports macOS only'
release=20251014
version=3.13.9
case "$(/usr/bin/uname -m)" in
    arm64)
        architecture=aarch64
        sha256=931db8f735e18700d4eab9ee39dbbd0b4c114d7d039dd2707b2d932ded039698
        archive_bytes=16526691
        ;;
    x86_64)
        architecture=x86_64
        sha256=9f6bc3c15e2f9e2c9c90db2c8b3ee94598e777789f8aea6e36b69ae55d007d01
        archive_bytes=16376501
        ;;
    *) fail 'Managed Python supports macOS arm64 and x86_64 only' ;;
esac
uid=$(/usr/bin/id -u)
if [ ! -e "$data" ]; then
    [ "$mode" = --prepare ] || fail 'Managed Python is not prepared; run explicit setup'
    /bin/mkdir -p -m 700 "$data" || fail 'Cannot create private plugin-data directory'
fi
[ ! -L "$data" ] && [ -d "$data" ] && [ "$(/usr/bin/stat -f '%u' "$data")" = "$uid" ] ||
    fail 'Plugin-data must be a non-symlink directory owned by this user'
if [ "$(/usr/bin/stat -f '%Lp' "$data")" != 700 ]; then
    [ "$mode" = --prepare ] || fail 'Plugin-data must have mode 0700; run explicit setup'
    /bin/chmod 700 "$data" || fail 'Cannot secure the owned plugin-data directory'
fi
package=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" && pwd) || fail 'Cannot locate runtime helper'
python=$data/managed-python/python/bin/python3
expected=$(printf '%s\n%s\n%s\n' "$release" "$architecture" "$sha256")

existing_runtime() {
    for directory in "$data/managed-python" "$data/managed-python/python" "$data/managed-python/python/bin"; do
        [ ! -L "$directory" ] && [ -d "$directory" ] &&
            [ "$(/usr/bin/stat -f '%u:%Lp' "$directory")" = "$uid:700" ] || return 1
    done
    receipt=$data/managed-python/bootstrap.receipt
    [ ! -L "$receipt" ] && [ -f "$receipt" ] &&
        [ "$(/usr/bin/stat -f '%u:%Lp:%l' "$receipt")" = "$uid:600:1" ] || return 1
    [ "$(/usr/bin/stat -f '%z' "$receipt")" -le 128 ] || return 1
    [ "$(/bin/cat "$receipt")" = "$expected" ] || return 1
    executable=$python
    hops=0
    while [ -L "$executable" ]; do
        hops=$((hops + 1))
        [ "$hops" -le 4 ] || return 1
        target=$(/usr/bin/readlink "$executable") || return 1
        case "$target" in python|python3|python3.13) ;; *) return 1 ;; esac
        executable=$data/managed-python/python/bin/$target
    done
    [ -f "$executable" ] && [ -x "$executable" ] &&
        [ "$(/usr/bin/stat -f '%u:%Lp:%l' "$executable")" = "$uid:700:1" ]
}

if [ -e "$data/managed-python" ] || [ -L "$data/managed-python" ]; then
    existing_runtime || fail 'Existing managed Python is incompatible or unsafe; it was preserved'
    if [ "$mode" = --exec ]; then
        exec "$python" -E -s -B "$@"
    fi
    exec "$python" -I -B "$package/managed_runtime.py" report "$data"
fi
[ "$mode" = --prepare ] || fail 'Managed Python is not prepared; run explicit setup'

lock=$data/.managed-python.lock
/bin/mkdir -m 700 "$lock" || fail 'Runtime preparation is already active or its lock needs manual review'
stage=
worker=
watchdog=
cleanup() {
    if [ -n "$worker" ]; then
        /bin/kill -KILL "$worker" 2>/dev/null || :
        wait "$worker" 2>/dev/null || :
    fi
    if [ -n "$watchdog" ]; then /bin/kill -TERM "$watchdog" 2>/dev/null || :; fi
    # Only this invocation's mktemp directory is removed; never runtime/config,
    # dependencies, an existing managed-python directory, or another setup lock.
    if [ -n "$stage" ] && [ ! -L "$stage" ] && [ -d "$stage" ]; then
        case "$stage" in "$data"/.managed-python-*) /bin/rm -rf "$stage" ;; esac
    fi
    /bin/rmdir "$lock" 2>/dev/null || :
}
trap cleanup EXIT
trap 'fail "Runtime preparation was interrupted; existing data was preserved"' HUP INT TERM
bounded() {
    deadline=$1
    file_blocks=$2
    shift 2
    (ulimit -f "$file_blocks" || exit 1; exec "$@") >/dev/null 2>&1 &
    worker=$!
    (
        /bin/sleep "$deadline"
        /bin/kill -TERM "$worker" 2>/dev/null || exit 0
        /bin/sleep 2
        /bin/kill -KILL "$worker" 2>/dev/null || :
    ) &
    watchdog=$!
    wait "$worker"
    result=$?
    worker=
    /bin/kill -TERM "$watchdog" 2>/dev/null || :
    wait "$watchdog" 2>/dev/null || :
    watchdog=
    return "$result"
}
available=$(/bin/df -Pk "$data" | { read -r header; read -r filesystem blocks used free rest; printf '%s' "$free"; })
case "$available" in ''|*[!0-9]*) fail 'Cannot determine available runtime storage' ;; esac
[ "$available" -ge 1048576 ] || fail 'Managed Python preparation requires 1 GiB of free storage'
stage=$(/usr/bin/mktemp -d "$data/.managed-python-XXXXXXXX") || fail 'Cannot create runtime staging directory'
/bin/mkdir -m 700 "$stage/runtime" || fail 'Cannot create runtime staging directory'
archive=$stage/python.tar.gz
url=https://github.com/astral-sh/python-build-standalone/releases/download/$release/cpython-$version%2B$release-$architecture-apple-darwin-install_only.tar.gz
# curl is additionally capped by a per-file OS limit and an outer wall clock.
# -q ignores ~/.curlrc; HTTPS-only redirects cannot downgrade transport security.
bounded 200 65536 /usr/bin/curl -q --fail --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 90 --retry 1 --retry-max-time 150 \
    --max-filesize "$archive_bytes" --output "$archive" "$url" ||
    fail 'Pinned Python download failed or timed out; retry explicit setup'
[ "$(/usr/bin/stat -f '%z' "$archive")" -eq "$archive_bytes" ] || fail 'Pinned Python archive size did not match the publisher'
actual=$(/usr/bin/shasum -a 256 "$archive") || fail 'Cannot verify pinned Python archive'
actual=${actual%% *}
[ "$actual" = "$sha256" ] || fail 'Pinned Python archive SHA-256 did not match; nothing was installed'
# Only the exact publisher-pinned archive reaches tar. Never extract an unchecked
# response. The trusted artifact is finite; cap extraction time and each file,
# then audit total bytes, entries, ownership, links and special files in Python.
bounded 45 262144 /usr/bin/tar -xzf "$archive" -C "$stage/runtime" --no-same-owner --no-same-permissions ||
    fail 'Pinned Python extraction failed or timed out'
bounded 45 262144 "$stage/runtime/python/bin/python3" -I -B "$package/managed_runtime.py" finalize "$data" \
    --stage "$stage/runtime" --release "$release" --architecture "$architecture" --sha256 "$sha256" ||
    fail 'Pinned Python runtime could not be finalized; existing data was preserved'
existing_runtime || fail 'Prepared Python did not satisfy its ownership contract'
cleanup
trap - EXIT HUP INT TERM
exec "$python" -I -B "$package/managed_runtime.py" report "$data"
