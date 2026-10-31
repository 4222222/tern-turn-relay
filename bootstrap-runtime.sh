#!/bin/sh
# Explicit native setup. No interpreter installation, package manager or local build.
# --prepare downloads only pinned release assets; report/--exec never download.
set -u
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset CDPATH ENV BASH_ENV
exec 2>/dev/null
fail() { printf '{"ok":false,"error":"%s"}\n' "$1"; exit 1; }
[ "$#" -ge 1 ] || fail 'A private plugin-data directory is required'
data=$1; shift
mode=${1:-report}
case "$mode" in
    --prepare) [ "$#" -eq 1 ] || fail 'Prepare does not accept extra arguments' ;;
    --exec) shift; [ "$#" -ge 1 ] || fail 'Exec requires a native command' ;;
    report) [ "$#" -eq 0 ] || fail 'Unknown runtime arguments' ;;
    *) fail 'Unknown runtime action' ;;
esac
case "$data" in /*) ;; *) fail 'Plugin-data must be absolute' ;; esac
case "$data" in /|*/|*//*|*/./*|*/../*|*/.|*/..) fail 'Plugin-data must be canonical' ;; esac
clean=$(printf '%s' "$data" | /usr/bin/tr -d '\000-\037\177')
[ "$clean" = "$data" ] || fail 'Plugin-data contains control characters'
uid=$(/usr/bin/id -u)
check=$data
while [ "$check" != / ]; do
    [ ! -L "$check" ] || fail 'Plugin-data must not contain symbolic links'
    if [ -e "$check" ]; then
        [ -d "$check" ] || fail 'Plugin-data ancestors must be directories'
        owner=$(/usr/bin/stat -f '%u' "$check") || fail 'Cannot verify ancestor ownership'
        permissions=$(/usr/bin/stat -f '%Lp' "$check") || fail 'Cannot verify ancestor permissions'
        case "$permissions" in ''|*[!0-7]*) fail 'Invalid ancestor permissions' ;; esac
        [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail 'Plugin-data ancestor belongs to another user'
        bits=$((0$permissions))
        if [ $((bits & 0022)) -ne 0 ]; then
            [ "$owner" = 0 ] && [ $((bits & 01000)) -ne 0 ] || fail 'Plugin-data ancestor is writable by another user'
        fi
    fi
    check=${check%/*}; [ -n "$check" ] || check=/
done
[ "$(/usr/bin/uname -s)" = Darwin ] || fail 'Native window setup supports macOS only'
case "$(/usr/bin/uname -m)" in arm64) arch=arm64 ;; x86_64) arch=x86_64 ;; *) fail 'Unsupported macOS architecture' ;; esac
if [ ! -e "$data" ]; then
    [ "$mode" = --prepare ] || fail 'Native runtime is not prepared; open TURN Settings'
    /bin/mkdir -p -m 700 "$data" || fail 'Cannot create private plugin data'
fi
[ ! -L "$data" ] && [ -d "$data" ] && [ "$(/usr/bin/stat -f '%u' "$data")" = "$uid" ] || fail 'Plugin data ownership is invalid'
if [ "$(/usr/bin/stat -f '%Lp' "$data")" != 700 ]; then
    [ "$mode" = --prepare ] || fail 'Open TURN Settings to secure the private data directory'
    /bin/chmod 700 "$data" || fail 'Cannot secure private data'
fi
package=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" && pwd) || fail 'Cannot locate plugin package'
manifest=$package/release.json
[ ! -L "$manifest" ] && [ -f "$manifest" ] && [ "$(/usr/bin/stat -f '%u:%l' "$manifest")" = "$uid:1" ] || fail 'Native release manifest ownership is invalid'
permissions=$(/usr/bin/stat -f '%Lp' "$manifest")
case "$permissions" in 400|600|444|644) ;; *) fail 'Native release manifest is writable by another user' ;; esac
[ "$(/usr/bin/stat -f '%z' "$manifest")" -le 65536 ] || fail 'Native release manifest exceeds its limit'
version=$(/usr/bin/plutil -extract version raw -o - "$manifest") || fail 'Invalid native release manifest'
[ "$version" = 0.4.0 ] || fail 'Native release version does not match the plugin'
[ "$(/usr/bin/plutil -extract schema raw -o - "$manifest")" = 1 ] || fail 'Unsupported native release manifest'
asset=tern-turn-relay-darwin-$arch
sha256=$(/usr/bin/plutil -extract "assets.$asset.sha256" raw -o - "$manifest") || fail 'Native asset checksum is missing'
bytes=$(/usr/bin/plutil -extract "assets.$asset.size" raw -o - "$manifest") || fail 'Native asset size is missing'
case "$sha256" in *[!0-9a-f]*|'') fail 'Invalid native asset checksum' ;; esac
[ "${#sha256}" -eq 64 ] || fail 'Invalid native asset checksum length'
case "$bytes" in *[!0-9]*|'') fail 'Invalid native asset size' ;; esac
[ "$bytes" -gt 0 ] && [ "$bytes" -le 67108864 ] || fail 'Native asset exceeds its limit'
root=$data/native-runtime
runtime=$root/$version
binary=$runtime/tern-turn-relay
verify_binary() {
    [ ! -L "$binary" ] && [ -f "$binary" ] && [ -x "$binary" ] && [ "$(/usr/bin/stat -f '%u:%Lp:%l:%z' "$binary")" = "$uid:500:1:$bytes" ] || return 1
    actual=$(/usr/bin/shasum -a 256 "$binary") || return 1
    [ "${actual%% *}" = "$sha256" ] || return 1
    [ ! -L "$runtime/release.json" ] && [ -f "$runtime/release.json" ] && [ "$(/usr/bin/stat -f '%u:%Lp:%l' "$runtime/release.json")" = "$uid:600:1" ] || return 1
    /usr/bin/cmp -s "$manifest" "$runtime/release.json"
}
if [ -e "$root" ] || [ -L "$root" ]; then
    [ ! -L "$root" ] && [ -d "$root" ] && [ "$(/usr/bin/stat -f '%u:%Lp' "$root")" = "$uid:700" ] || fail 'Native runtime root is unsafe; existing data was preserved'
fi
if [ -e "$runtime" ] || [ -L "$runtime" ]; then
    [ ! -L "$runtime" ] && [ -d "$runtime" ] && [ "$(/usr/bin/stat -f '%u:%Lp' "$runtime")" = "$uid:700" ] || fail 'Native runtime directory is unsafe'
    verify_binary || fail 'Existing native runtime failed verification; it was preserved'
    if [ "$mode" = --exec ]; then exec "$binary" "$@"; fi
    exec "$binary" runtime
fi
[ "$mode" = --prepare ] || fail 'Native runtime is not prepared; open TURN Settings'
lock=$data/.native-runtime.lock
/bin/mkdir -m 700 "$lock" || fail 'Native preparation is active or its lock needs review'
stage=
worker=
cleanup() {
    if [ -n "$worker" ]; then /bin/kill -KILL "$worker" 2>/dev/null || :; wait "$worker" 2>/dev/null || :; worker=; fi
    if [ -n "$stage" ] && [ ! -L "$stage" ] && [ -d "$stage" ]; then
        case "$stage" in "$data"/.native-runtime-*) /bin/rm -rf "$stage" ;; esac
    fi
    /bin/rmdir "$lock" 2>/dev/null || :
}
trap cleanup EXIT
trap 'fail "Native preparation interrupted; existing data was preserved"' HUP INT TERM
available=$(/bin/df -Pk "$data" | { read -r header; read -r filesystem blocks used free rest; printf '%s' "$free"; })
case "$available" in ''|*[!0-9]*) fail 'Cannot determine available storage' ;; esac
[ "$available" -ge 262144 ] || fail 'Native preparation requires 256 MiB free storage'
stage=$(/usr/bin/mktemp -d "$data/.native-runtime-XXXXXXXX") || fail 'Cannot create native staging directory'
url=https://github.com/jiwangyihao/tern-turn-relay/releases/download/v$version/$asset
(ulimit -f 131072; exec /usr/bin/curl -q --fail --silent --location --noproxy '*' --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --max-filesize "$bytes" --output "$stage/tern-turn-relay" "$url") &
worker=$!
wait "$worker"
download_status=$?
worker=
[ "$download_status" -eq 0 ] || fail 'Pinned native download failed; retry explicit setup'
[ "$(/usr/bin/stat -f '%z' "$stage/tern-turn-relay")" -eq "$bytes" ] || fail 'Native asset size did not match'
actual=$(/usr/bin/shasum -a 256 "$stage/tern-turn-relay") || fail 'Cannot verify native asset'
[ "${actual%% *}" = "$sha256" ] || fail 'Native asset SHA-256 did not match; nothing was installed'
/bin/chmod 500 "$stage/tern-turn-relay" || fail 'Cannot secure native executable'
/bin/cp "$manifest" "$stage/release.json" && /bin/chmod 600 "$stage/release.json" || fail 'Cannot preserve release manifest'
[ -d "$root" ] || /bin/mkdir -m 700 "$root" || fail 'Cannot create native runtime root'
[ ! -e "$runtime" ] && [ ! -L "$runtime" ] || fail 'Native runtime appeared during preparation; it was preserved'
/bin/mv "$stage" "$runtime" || fail 'Cannot publish verified native runtime'
stage=
verify_binary || fail 'Published native runtime failed verification'
cleanup
trap - EXIT HUP INT TERM
exec "$binary" runtime
