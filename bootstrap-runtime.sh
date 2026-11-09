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
# meta PATH prints "uid gid mode links bytes" with an octal mode. Platform
# tools at fixed paths only, never PATH lookups.
case "$(/usr/bin/uname -s)" in
    Darwin)
        platform=darwin
        case "$(/usr/bin/uname -m)" in arm64) arch=arm64 ;; x86_64) arch=x86_64 ;; *) fail 'Unsupported macOS architecture' ;; esac
        meta() { /usr/bin/stat -f '%u %g %p %l %z' "$1"; }
        sha256() { /usr/bin/shasum -a 256 "$1"; }
        field() { /usr/bin/plutil -extract "$1" raw -o - "$manifest"; }
        ;;
    Linux)
        platform=linux
        case "$(/usr/bin/uname -m)" in aarch64|arm64) arch=arm64 ;; x86_64) arch=x86_64 ;; *) fail 'Unsupported Linux architecture' ;; esac
        meta() { /usr/bin/stat -c '%u %g %a %h %s' "$1"; }
        sha256() { /usr/bin/sha256sum "$1"; }
        # Parse the complete release.py manifest before exposing any field. Only
        # its string/integer/object vocabulary is accepted, with exact key sets.
        field() {
            LC_ALL=C /usr/bin/awk -v want="$1" '
                function reject() { exit 1 }
                function space() {
                    while (substr(text, pos, 1) ~ /^[ \t\r\n]$/) pos++
                }
                function take(token) {
                    space()
                    if (substr(text, pos, 1) != token) reject()
                    pos++
                }
                function string(    value) {
                    space()
                    # Generated names, versions and hashes never need escapes.
                    if (!match(substr(text, pos), /^"[A-Za-z0-9_.-]*"/)) reject()
                    value = substr(text, pos + 1, RLENGTH - 2)
                    pos += RLENGTH
                    return value
                }
                function integer(    value) {
                    space()
                    if (!match(substr(text, pos), /^[0-9]+/)) reject()
                    value = substr(text, pos, RLENGTH)
                    pos += RLENGTH
                    if (length(value) > 8 || (length(value) > 1 && substr(value, 1, 1) == "0")) reject()
                    return value
                }
                function object(path, kind,    key, name, value, count, token) {
                    take("{")
                    do {
                        key = string()
                        name = path == "" ? key : path "." key
                        if (seen[name]++) reject()
                        take(":")
                        if (kind == "root" && key == "assets") object(name, "assets")
                        else if (kind == "assets" && (key in assets)) object(name, "entry")
                        else {
                            if (kind == "root" && key == "schema") {
                                value = integer()
                                if (value != "1") reject()
                            } else if (kind == "root" && key == "version") {
                                value = string()
                                if (value !~ /^[0-9]+\.[0-9]+\.[0-9]+$/) reject()
                            } else if (kind == "entry" && key == "sha256") {
                                value = string()
                                if (length(value) != 64 || value ~ /[^0-9a-f]/) reject()
                            } else if (kind == "entry" && key == "size") {
                                value = integer()
                                if (value + 0 < 1 || value + 0 > 67108864) reject()
                            } else reject()
                            if (name == want) { found++; result = value }
                        }
                        count++
                        space()
                        token = substr(text, pos++, 1)
                        if (token != "," && token != "}") reject()
                    } while (token == ",")
                    if (count != (kind == "root" ? 3 : kind == "assets" ? 5 : 2)) reject()
                }
                {
                    bytes += length($0) + 1
                    if (bytes > 65536) { bad = 1; exit 1 }
                    text = text $0 "\n"
                }
                END {
                    if (bad) reject()
                    assets["tern-turn-relay-darwin-arm64"] = 1
                    assets["tern-turn-relay-darwin-x86_64"] = 1
                    assets["tern-turn-relay-linux-arm64"] = 1
                    assets["tern-turn-relay-linux-x86_64"] = 1
                    assets["tern-turn-relay-windows-x86_64.exe"] = 1
                    pos = 1
                    object("", "root")
                    space()
                    if (pos <= length(text) || found != 1) reject()
                    print result
                }' "$manifest"
        }
        ;;
    *) fail 'Native window setup supports macOS and Linux only' ;;
esac
# read_meta PATH sets m_uid m_gid m_perm m_links m_size; m_perm keeps the
# setuid/setgid/sticky bits and drops the file type. Function-local `set --`
# leaves the caller's native arguments intact.
read_meta() {
    m=$(meta "$1") || return 1
    set -f; set -- $m; set +f
    [ "$#" -eq 5 ] || return 1
    case "$1$2$3$4$5" in *[!0-9]*) return 1 ;; esac
    m_uid=$1 m_gid=$2 m_perm=$(printf '%o' $((0$3 & 07777))) m_links=$4 m_size=$5
}
# Recheck local account authority whenever group write needs an exception. dd
# bounds each read before awk allocates a record; no account/NSS snapshot survives
# this call. Unknown NSS sources and incomplete or duplicate records fail closed.
private_group() (
    [ "$platform" = linux ] || exit 1
    primary_gid=$(/usr/bin/id -g) || exit 1
    [ "$1" = "$primary_gid" ] || exit 1
    for account in /etc/nsswitch.conf /etc/passwd /etc/group; do
        [ ! -L "$account" ] && [ -f "$account" ] && read_meta "$account" || exit 1
        [ "$m_uid:$m_links" = 0:1 ] && [ $((0$m_perm & 0022)) -eq 0 ] || exit 1
    done
    LC_ALL=C /usr/bin/awk -v uid="$uid" -v gid="$primary_gid" '
        function valid_id(value) {
            return value ~ /^[0-9]+$/ && length(value) <= 10 && value + 0 <= 4294967294
        }
        function valid_name(value) {
            return value != "" && value !~ /^[+-]/ && value !~ /[[:space:]:,]/
        }
        function record(line, kind,    fields, count, key, value, rest, group_name) {
            if (kind == "nss") {
                sub(/#.*/, "", line)
                gsub(/^[ \t]+|[ \t]+$/, "", line)
                if (line == "") return
                rest = line
                gsub(/\t/, "", rest)
                if (rest ~ /[[:cntrl:]\\]/) exit 1
                count = split(line, fields, ":")
                key = fields[1]
                sub(/[ \t]+$/, "", key)
                if (key != "passwd" && key != "group") return
                value = fields[2]
                gsub(/^[ \t]+|[ \t]+$/, "", value)
                if (count != 2 || nss[key]++ || value != "files") exit 1
                return
            }
            if (line ~ /[[:cntrl:]]/) exit 1
            if (line == "" || line ~ /^#/) return
            count = split(line, fields, ":")
            if (count != (kind == "passwd" ? 7 : 4) || !valid_name(fields[1]) || !valid_id(fields[3])) exit 1
            if (kind == "passwd") {
                if (!valid_id(fields[4]) || users[fields[1]]++ || uids[fields[3] + 0]++) exit 1
                if (fields[3] + 0 == uid + 0) {
                    if (fields[4] + 0 != gid + 0) exit 1
                    name = fields[1]
                }
                if (fields[4] + 0 == gid + 0 && fields[3] + 0 != uid + 0) exit 1
            } else {
                if (groups[fields[1]]++ || gids[fields[3] + 0]++) exit 1
                group_name = fields[1]
                rest = fields[4]
                if (rest != "") {
                    count = split(rest, fields, ",")
                    for (key = 1; key <= count; key++) {
                        if (!valid_name(fields[key])) exit 1
                        if (members[group_name SUBSEP fields[key]]++) exit 1
                    }
                }
                split(line, fields, ":")
                if (fields[3] + 0 == gid + 0) {
                    if (rest != "" && rest != name) exit 1
                    defined = 1
                }
            }
        }
        function load(path, limit, kind,    command, line, status, bytes) {
            command = "/usr/bin/dd if=" path " bs=" (limit + 1) " count=1 iflag=fullblock,nofollow,nonblock status=none"
            while ((status = (command | getline line)) > 0) {
                bytes += length(line) + 1
                if (bytes > limit) exit 1
                record(line, kind)
            }
            if (status < 0 || close(command) != 0) exit 1
        }
        BEGIN {
            if (!valid_id(uid) || !valid_id(gid)) exit 1
            load("/etc/nsswitch.conf", 65536, "nss")
            if (nss["passwd"] != 1 || nss["group"] != 1) exit 1
            load("/etc/passwd", 4194304, "passwd")
            if (name == "") exit 1
            load("/etc/group", 4194304, "group")
            if (!defined) exit 1
        }'
)
# foreign_writable PERMISSIONS GID: another account can modify the object.
foreign_writable() {
    bits=$((0$1))
    [ $((bits & 0002)) -eq 0 ] || return 0
    [ $((bits & 0020)) -ne 0 ] || return 1
    private_group "$2" && return 1
    return 0
}
check=$data
while [ "$check" != / ]; do
    [ ! -L "$check" ] || fail 'Plugin-data must not contain symbolic links'
    if [ -e "$check" ]; then
        [ -d "$check" ] || fail 'Plugin-data ancestors must be directories'
        read_meta "$check" || fail 'Cannot verify ancestor ownership'
        [ "$m_uid" = 0 ] || [ "$m_uid" = "$uid" ] || fail 'Plugin-data ancestor belongs to another user'
        if foreign_writable "$m_perm" "$m_gid"; then
            [ "$m_uid" = 0 ] && [ $((0$m_perm & 01000)) -ne 0 ] || fail 'Plugin-data ancestor is writable by another user'
        fi
    fi
    check=${check%/*}; [ -n "$check" ] || check=/
done
# owner_mode PATH prints "uid:permissions" without special bits.
owner_mode() { read_meta "$1" && printf '%s:%o' "$m_uid" $((0$m_perm & 0777)); }
if [ ! -e "$data" ]; then
    [ "$mode" = --prepare ] || fail 'Native runtime is not prepared; open TURN Settings'
    /bin/mkdir -p -m 700 "$data" || fail 'Cannot create private plugin data'
fi
[ ! -L "$data" ] && [ -d "$data" ] && read_meta "$data" && [ "$m_uid" = "$uid" ] || fail 'Plugin data ownership is invalid'
if [ "$(owner_mode "$data")" != "$uid:700" ]; then
    [ "$mode" = --prepare ] || fail 'Open TURN Settings to secure the private data directory'
    /bin/chmod 700 "$data" || fail 'Cannot secure private data'
fi
package=$(CDPATH= cd -P "$(/usr/bin/dirname "$0")" && pwd) || fail 'Cannot locate plugin package'
manifest=$package/release.json
[ ! -L "$manifest" ] && [ -f "$manifest" ] || fail 'Native release manifest ownership is invalid'
read_meta "$manifest" && [ "$m_uid" = "$uid" ] && [ "$m_links" = 1 ] || fail 'Native release manifest ownership is invalid'
# 664 is accepted only for a Linux user private group.
case "$m_perm" in 400|600|444|644|664) ;; *) fail 'Native release manifest is writable by another user' ;; esac
! foreign_writable "$m_perm" "$m_gid" || fail 'Native release manifest is writable by another user'
[ "$m_size" -le 65536 ] || fail 'Native release manifest exceeds its limit'
version=$(field version) || fail 'Invalid native release manifest'
[ "$version" = 0.5.10 ] || fail 'Native release version does not match the plugin'
[ "$(field schema)" = 1 ] || fail 'Unsupported native release manifest'
asset=tern-turn-relay-$platform-$arch
sha256=$(field "assets.$asset.sha256") || fail 'Native asset checksum is missing'
bytes=$(field "assets.$asset.size") || fail 'Native asset size is missing'
case "$sha256" in *[!0-9a-f]*|'') fail 'Invalid native asset checksum' ;; esac
[ "${#sha256}" -eq 64 ] || fail 'Invalid native asset checksum length'
case "$bytes" in *[!0-9]*|'') fail 'Invalid native asset size' ;; esac
[ "$bytes" -gt 0 ] && [ "$bytes" -le 67108864 ] || fail 'Native asset exceeds its limit'
root=$data/native-runtime
runtime=$root/$version
binary=$runtime/tern-turn-relay
verify_binary() {
    [ ! -L "$binary" ] && [ -f "$binary" ] && [ -x "$binary" ] || return 1
    read_meta "$binary" && [ "$m_uid:$m_perm:$m_links:$m_size" = "$uid:500:1:$bytes" ] || return 1
    actual=$(sha256 "$binary") || return 1
    [ "${actual%% *}" = "$sha256" ] || return 1
    [ ! -L "$runtime/release.json" ] && [ -f "$runtime/release.json" ] || return 1
    read_meta "$runtime/release.json" && [ "$m_uid:$m_perm:$m_links" = "$uid:600:1" ] || return 1
    /usr/bin/cmp -s "$manifest" "$runtime/release.json"
}
if [ -e "$root" ] || [ -L "$root" ]; then
    [ ! -L "$root" ] && [ -d "$root" ] && [ "$(owner_mode "$root")" = "$uid:700" ] || fail 'Native runtime root is unsafe; existing data was preserved'
fi
if [ -e "$runtime" ] || [ -L "$runtime" ]; then
    [ ! -L "$runtime" ] && [ -d "$runtime" ] && [ "$(owner_mode "$runtime")" = "$uid:700" ] || fail 'Native runtime directory is unsafe'
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
read_meta "$stage/tern-turn-relay" && [ "$m_size" -eq "$bytes" ] || fail 'Native asset size did not match'
actual=$(sha256 "$stage/tern-turn-relay") || fail 'Cannot verify native asset'
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
