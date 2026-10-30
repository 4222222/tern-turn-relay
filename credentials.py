#!/usr/bin/env python3
"""Private Cloudflare TURN-key onboarding (Python standard library only).

This stores an existing TURN key's API token, NOT an account-management API
token, in a mode-0600 JSON file; it does not provide Keychain encryption,
OAuth, Cloudflare account creation, or key creation/revocation. Obtain the TURN
key ID and its API token in Cloudflare Realtime TURN first. Never put either
secret in command arguments, environment variables, chat, or captured output.

CLI: configure [--stdin | --input-file PRIVATE_JSON] [--replace], check,
status, remove-local [--yes]. Every command accepts --file PATH. Interactive
configure uses hidden input and fails closed if terminal echo cannot be disabled.
For automation, a human/secret manager pipes the legacy JSON document to
configure --stdin, or supplies an existing private file with --input-file;
the agent need not see its contents. --replace authorizes noninteractive
replacement; --yes authorizes noninteractive local removal. TTY mutation of
an existing file always requires confirmation. Removal does NOT revoke the
Cloudflare key or erase already-issued TURN credentials.

Public integration APIs:
  default_credential_path() -> Path (macOS Tern default plugin-data directory).
  validate_management_key(value) -> normalized legacy dict, no network/storage.
  load_management_key(path) -> validated dict from an owned private regular file.
  issue_turn_credentials(key, ttl=86400) -> (ice_servers, expires_unix).
  probe_credentials(key) -> redacted validation summary; issues a 60-second
    credential via the official endpoint and never returns its secret fields.
CredentialError messages are safe to publish; exit_code is 2 usage, 3 absent,
4 invalid/unsafe input, 5 remote validation failure, 6 confirmation required/
cancelled, or 7 local I/O failure. CLI exit 0 is success, 130 interruption.
status validates local configuration only; it never issues TURN credentials.
"""
import argparse
from contextlib import contextmanager
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
import warnings

MAX_KEY_BYTES = 65536
MAX_RESPONSE_BYTES = 131072
API_TIMEOUT = 12


class CredentialError(Exception):
    """A deliberately redacted error safe for CLI and daemon status."""

    def __init__(self, message, exit_code=4):
        super().__init__(message)
        self.exit_code = exit_code


def default_credential_path():
    return (Path.home() / 'Library' / 'Application Support' / 'Tern' /
            'plugin-data' / 'tern-turn-relay' / 'credentials' / 'cloudflare.json')


def validate_management_key(value):
    """Accept legacy JSON; return only the three supported fields."""
    if not isinstance(value, dict) or value.get('provider') != 'cloudflare':
        raise CredentialError('Management key provider must be cloudflare.')
    key_id, token = value.get('turn_key_id'), value.get('api_token')
    if not isinstance(key_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key_id):
        raise CredentialError('Management key requires a valid TURN key ID.')
    if (not isinstance(token, str) or not token or len(token) > 8192
            or any(ord(char) < 33 or ord(char) > 126 for char in token)):
        raise CredentialError('Management key requires a valid TURN-key API token (not an account API token).')
    return {'provider': 'cloudflare', 'turn_key_id': key_id, 'api_token': token}


def _parse_key(raw):
    if len(raw) > MAX_KEY_BYTES:
        raise CredentialError('Management key exceeds the 64 KiB limit.')
    try:
        return validate_management_key(json.loads(raw))
    except (ValueError, UnicodeError, RecursionError):
        raise CredentialError('Management key must be a valid bounded JSON object.') from None


def _path(value):
    path = Path(value).expanduser().absolute()
    if '..' in path.parts or not path.name or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise CredentialError('Credential path must not contain parent traversal or control characters.')
    return path


@contextmanager
def _parent(path, create=False, private=False):
    """Walk directories by descriptor: never follow a symlink in any component."""
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            trusted_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, os.getuid())
                    or (info.st_mode & 0o022 and not trusted_sticky)):
                raise CredentialError('Credential directory ancestry must be owned and not writable by others.')
        info = os.fstat(fd)
        if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise CredentialError('Credential parent directory must be owned by you with mode 0700.')
        yield fd
    finally:
        os.close(fd)


def _check_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > MAX_KEY_BYTES):
        raise CredentialError('Credential file must be owned, regular, non-linked, mode 0600, and at most 64 KiB.')


def _snapshot(directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _check_file(info)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load_management_key(path):
    """Read bounded legacy JSON without following symlinks or accepting hardlinks."""
    try:
        path = _path(path)
        with _parent(path) as directory:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                _check_file(os.fstat(stream.fileno()))
                return _parse_key(stream.read(MAX_KEY_BYTES + 1))
    except FileNotFoundError:
        raise CredentialError('No local management key is configured.', 3) from None
    except OSError:
        raise CredentialError('Cannot securely read the management key file.', 7) from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise CredentialError('Cloudflare credential API redirect rejected.', 5)


def _usable_turn(entries):
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if (not isinstance(entry.get('username'), str) or not entry['username']
                or not isinstance(entry.get('credential'), str) or not entry['credential']
                or entry.get('credentialType', 'password') != 'password'):
            continue
        urls = entry.get('urls', [])
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list):
            continue
        for url in urls:
            if not isinstance(url, str):
                continue
            try:
                scheme, rest = url.split(':', 1)
                if scheme not in ('turn', 'turns') or rest.startswith('//'):
                    continue
                parsed = urlsplit(scheme + '://' + rest)
                query = parse_qs(parsed.query, strict_parsing=True)
                transport = query.get('transport', ['tcp' if scheme == 'turns' else 'udp'])
                if (parsed.hostname and not parsed.username and not parsed.password
                        and not parsed.path and not parsed.fragment
                        and not set(query) - {'transport'}
                        and transport in (['udp'], ['tcp'])
                        and (scheme != 'turns' or transport == ['tcp'])
                        and 1 <= (parsed.port if parsed.port is not None else 3478) <= 65535):
                    return True
            except (ValueError, TypeError):
                pass
    return False


def issue_turn_credentials(key, ttl=86400):
    """Use only Cloudflare's fixed HTTPS endpoint, system trust, no proxy/redirect.

    Returns secret ICE entries for daemon use, never for CLI printing. Authorization
    validity is checked by actual issuance, not by shape or account-token APIs.
    """
    key = validate_management_key(key)
    if type(ttl) is not int or not 1 <= ttl <= 86400:
        raise CredentialError('TURN credential TTL must be an integer from 1 to 86400.')
    request = Request(
        'https://rtc.live.cloudflare.com/v1/turn/keys/' + key['turn_key_id'] +
        '/credentials/generate-ice-servers',
        data=json.dumps({'ttl': ttl}).encode('ascii'), method='POST',
        headers={'Authorization': 'Bearer ' + key['api_token'],
                 'Content-Type': 'application/json', 'Accept': 'application/json',
                 'User-Agent': 'tern-turn-relay/1.0'})
    issued = time.time()
    try:
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
        with opener.open(request, timeout=API_TIMEOUT) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise CredentialError('Cloudflare credential API response exceeds size limit.', 5)
        document = json.loads(raw)
    except HTTPError as exc:
        code = exc.code
        exc.close()
        raise CredentialError('Cloudflare credential API rejected authorization/request (HTTP %d); use the TURN key token, not an account API token.' % code, 5) from None
    except CredentialError:
        raise
    except Exception:
        raise CredentialError('Cloudflare credential API request failed; check connectivity and TLS trust.', 5) from None
    entries = document.get('iceServers') if isinstance(document, dict) else None
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not _usable_turn(entries):
        raise CredentialError('Cloudflare credential API returned no usable TURN credentials.', 5)
    return entries, int(issued + ttl)


def probe_credentials(key):
    """Perform remote validation; intentionally discard all issued credential data."""
    issue_turn_credentials(key, ttl=60)
    return {'provider': 'cloudflare', 'validated': True, 'probe_ttl_seconds': 60}


def _confirm(action, authorized):
    if sys.stdin.isatty():
        print(action + ' Type yes to continue: ', end='', file=sys.stderr, flush=True)
        if sys.stdin.readline(16).strip() == 'yes':
            return
        raise CredentialError('Local credential change cancelled.', 6)
    if not authorized:
        raise CredentialError('Noninteractive replacement requires --replace; removal requires --yes.', 6)


def _read_input(args):
    if args.input_file is not None:
        return load_management_key(args.input_file)
    if args.stdin:
        if sys.stdin.isatty():
            raise CredentialError('--stdin requires a bounded JSON pipe or file, not an interactive terminal.', 2)
        stream = getattr(sys.stdin, 'buffer', sys.stdin)
        return _parse_key(stream.read(MAX_KEY_BYTES + 1))
    if not sys.stdin.isatty():
        raise CredentialError('Use --stdin or --input-file for noninteractive configuration.', 2)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            key_id = getpass.getpass('Cloudflare TURN key ID (hidden): ')
            token = getpass.getpass('Cloudflare TURN-key API token, not account token (hidden): ')
    except (getpass.GetPassWarning, EOFError, OSError):
        raise CredentialError('Secure terminal input unavailable; use a private file or stdin pipe.', 4) from None
    return validate_management_key({'provider': 'cloudflare', 'turn_key_id': key_id, 'api_token': token})


def _atomic_store(directory, name, key, before):
    temporary = '.cloudflare-' + secrets.token_hex(16) + '.tmp'
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, 'wb')
        fd = None
        with stream:
            stream.write((json.dumps(key, separators=(',', ':')) + '\n').encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        if _snapshot(directory, name) != before:
            raise CredentialError('Credential file changed during validation; refusing to overwrite.', 6)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's original message echoes arbitrary argv (possibly pasted secrets).
        raise CredentialError('Invalid arguments; use --help. Secrets are accepted only through hidden input, stdin, or a private file.', 2)


def _parser():
    parser = _Parser(description='Configure an existing Cloudflare TURN key; no OAuth or account-token login. Outputs redacted JSON.')
    parser.add_argument('--file', default=argparse.SUPPRESS, help='private credential destination (default: Tern plugin-data/tern-turn-relay/credentials/cloudflare.json)')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('configure', 'check', 'status', 'remove-local'):
        command = commands.add_parser(name)
        command.add_argument('--file', default=argparse.SUPPRESS, help='private credential file; parent must be mode 0700 for writes')
        if name == 'configure':
            source = command.add_mutually_exclusive_group()
            source.add_argument('--stdin', action='store_true', help='read at most 64 KiB legacy JSON from stdin; never echo it')
            source.add_argument('--input-file', help='read an existing owned mode-0600 JSON file, without displaying it')
            command.add_argument('--replace', action='store_true', help='explicitly authorize noninteractive replacement after successful validation')
        elif name == 'remove-local':
            command.add_argument('--yes', action='store_true', help='explicitly authorize noninteractive LOCAL deletion; does not revoke the Cloudflare key')
    return parser


def _execute(args):
    path = _path(getattr(args, 'file', default_credential_path()))
    result = {'ok': True, 'command': args.command, 'credential_file': str(path), 'provider': 'cloudflare'}
    if args.command in ('status', 'check'):
        key = load_management_key(path)
        result.update(configured=True, storage='private-file', network_checked=False)
        if args.command == 'check':
            result.update(probe_credentials(key), network_checked=True)
        return result
    if args.command == 'configure':
        with _parent(path, create=True, private=True) as directory:
            before = _snapshot(directory, path.name)
            if before is not None:
                _confirm('Replace the existing local TURN key after validation?', args.replace)
            key = _read_input(args)
            probe_credentials(key)
            _atomic_store(directory, path.name, key, before)
        result.update(configured=True, validated=True, storage='private-file', replaced=before is not None)
        return result
    with _parent(path, private=True) as directory:
        before = _snapshot(directory, path.name)
        if before is None:
            raise CredentialError('No local management key is configured.', 3)
        _confirm('Remove only this local TURN key file (no Cloudflare revocation)?', args.yes)
        if _snapshot(directory, path.name) != before:
            raise CredentialError('Credential file changed before removal; refusing to remove.', 6)
        os.unlink(path.name, dir_fd=directory)
    result.update(configured=False, removed=True, remote_revoked=False)
    return result


def main(argv=None):
    """Print one redacted JSON result and return a stable exit code; never traceback."""
    try:
        result = _execute(_parser().parse_args(argv))
        code = 0
    except CredentialError as exc:
        result, code = {'ok': False, 'error': str(exc)}, exc.exit_code
        if code == 3:
            result['configured'] = False
    except FileNotFoundError:
        result, code = {'ok': False, 'error': 'Credential path does not exist.', 'configured': False}, 3
    except KeyboardInterrupt:
        result, code = {'ok': False, 'error': 'Credential operation interrupted.'}, 130
    except Exception:
        result, code = {'ok': False, 'error': 'Credential operation failed; inspect private path ownership and permissions.'}, 7
    result['exit_code'] = code
    print(json.dumps(result, separators=(',', ':')))
    return code


if __name__ == '__main__':
    sys.exit(main())
