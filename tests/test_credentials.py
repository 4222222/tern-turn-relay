"""Offline credential CLI/storage/API security behavior; no real cloud requests."""
import contextlib
import getpass
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler

import credentials


KEY = {'provider': 'cloudflare', 'turn_key_id': 'synthetic-turn-id',
       'api_token': 'synthetic-token-never-real'}
ICE = {'iceServers': [{'urls': ['turns:turn.cloudflare.com:443?transport=tcp'],
                       'username': 'synthetic-issued-user',
                       'credential': 'synthetic-issued-secret'}]}


class InteractiveInput(io.StringIO):
    def isatty(self):
        return True


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # macOS's /var is a symlink; explicitly choose the real private test tree.
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'key.json'

    def tearDown(self):
        self.temporary.cleanup()

    def store(self, value=KEY, path=None):
        path = path or self.path
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def cli(self, arguments, stdin=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch('sys.stdin', stdin if stdin is not None else io.StringIO()), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = credentials.main(arguments)
        output = stdout.getvalue()
        for secret in (KEY['api_token'], KEY['turn_key_id'],
                       'synthetic-issued-user', 'synthetic-issued-secret'):
            self.assertNotIn(secret, output + stderr.getvalue())
        return code, json.loads(output), stderr.getvalue()

    def remote(self, document=ICE):
        response = Mock()
        response.read.return_value = json.dumps(document).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        return opener, response

    def test_default_is_private_plugin_data_path(self):
        with patch.object(Path, 'home', return_value=Path('/Users/example')):
            self.assertEqual(credentials.default_credential_path(), Path(
                '/Users/example/Library/Application Support/Tern/plugin-data/'
                'tern-turn-relay/credentials/cloudflare.json'))

    def test_legacy_document_is_read_and_normalized(self):
        self.store(dict(KEY, unused='ignored legacy metadata'))
        self.assertEqual(credentials.load_management_key(self.path), KEY)

    def test_invalid_document_does_not_echo_input(self):
        for value in ([], None, dict(KEY, provider='other'), dict(KEY, turn_key_id='../escape'),
                      dict(KEY, api_token='bad\nheader'), dict(KEY, api_token=''),
                      dict(KEY, api_token='x' * 8193)):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(credentials.CredentialError) as raised:
                    credentials.validate_management_key(value)
                self.assertNotIn(KEY['api_token'], str(raised.exception))

    def test_private_file_rejects_mode_symlink_hardlink_and_large_file(self):
        self.store()
        self.path.chmod(0o644)
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(self.path)
        self.path.chmod(0o600)
        link = self.root / 'link.json'
        link.symlink_to(self.path)
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(link)
        link.unlink()
        os.link(self.path, link)
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(self.path)
        link.unlink()
        self.path.write_bytes(b' ' * (credentials.MAX_KEY_BYTES + 1))
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(self.path)

    def test_private_file_rejects_wrong_owner_and_fifo(self):
        self.store()
        with patch('credentials.os.getuid', return_value=os.getuid() + 1):
            with self.assertRaises(credentials.CredentialError):
                credentials.load_management_key(self.path)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(self.path)

    def test_file_and_stdin_json_errors_are_redacted(self):
        self.path.write_text('{"api_token":"' + KEY['api_token'])
        self.path.chmod(0o600)
        code, _, _ = self.cli(['status', '--file', str(self.path)])
        self.assertEqual(code, 4)
        code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                              io.StringIO('{"api_token":"' + KEY['api_token']))
        self.assertEqual(code, 4)

    def test_directory_symlinks_and_shared_write_permissions_are_rejected(self):
        actual = self.root / 'actual'
        actual.mkdir(mode=0o700)
        alias = self.root / 'alias'
        alias.symlink_to(actual, target_is_directory=True)
        self.store(path=actual / 'key.json')
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(alias / 'key.json')
        actual.chmod(0o777)
        with self.assertRaises(credentials.CredentialError):
            credentials.load_management_key(actual / 'key.json')

    def test_status_is_redacted_and_does_not_issue_credentials(self):
        self.store()
        with patch('credentials.build_opener') as network:
            code, result, _ = self.cli(['status', '--file', str(self.path)])
        network.assert_not_called()
        self.assertEqual(code, 0)
        self.assertTrue(result['configured'])
        self.assertFalse(result['network_checked'])
        self.assertNotIn('validated', result)
        self.assertEqual(result['storage'], 'private-file')

    def test_status_missing_and_check_missing_have_stable_exit_code(self):
        for command in ('status', 'check', 'remove-local'):
            code, result, _ = self.cli([command, '--file', str(self.path)])
            self.assertEqual(code, 3)
            self.assertFalse(result['configured'])

    def test_configure_stdin_creates_private_atomic_file_after_probe(self):
        target = self.root / 'new' / 'private' / 'key.json'
        opener, _ = self.remote()
        with patch('credentials.build_opener', return_value=opener):
            code, result, _ = self.cli(['configure', '--file', str(target), '--stdin'],
                                      io.StringIO(json.dumps(KEY)))
        self.assertEqual(code, 0)
        self.assertTrue(result['validated'])
        self.assertFalse(result['replaced'])
        self.assertEqual(credentials.load_management_key(target), KEY)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
        self.assertEqual(list(target.parent.iterdir()), [target])

    def test_failed_remote_validation_preserves_working_file_and_inode(self):
        self.store()
        before, inode = self.path.read_bytes(), self.path.stat().st_ino
        opener = Mock()
        opener.open.side_effect = HTTPError('https://example.invalid/' + KEY['api_token'], 401,
                                           KEY['api_token'], {}, io.BytesIO(KEY['api_token'].encode()))
        with patch('credentials.build_opener', return_value=opener):
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                  io.StringIO(json.dumps(dict(KEY, api_token='synthetic-new-token'))))
        self.assertEqual(code, 5)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_noninteractive_overwrite_requires_explicit_replace_before_network(self):
        self.store()
        with patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin'],
                                  io.StringIO(json.dumps(KEY)))
        self.assertEqual(code, 6)
        network.assert_not_called()

    def test_interactive_overwrite_still_confirms_with_replace_flag(self):
        self.store()
        with patch('credentials.build_opener') as network, patch('credentials.getpass.getpass') as hidden:
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--replace'],
                                  InteractiveInput('no\n'))
        self.assertEqual(code, 6)
        network.assert_not_called()
        hidden.assert_not_called()

    def test_hidden_interactive_input_success(self):
        opener, _ = self.remote()
        with patch('credentials.build_opener', return_value=opener), \
                patch('credentials.getpass.getpass', side_effect=[KEY['turn_key_id'], KEY['api_token']]) as hidden:
            code, _, _ = self.cli(['configure', '--file', str(self.path)], InteractiveInput())
        self.assertEqual(code, 0)
        self.assertEqual(hidden.call_count, 2)
        self.assertEqual(credentials.load_management_key(self.path), KEY)

    def test_hidden_input_fails_closed_if_echo_cannot_be_disabled(self):
        with patch('credentials.getpass.getpass', side_effect=getpass.GetPassWarning('unsafe echo')), \
                patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['configure', '--file', str(self.path)], InteractiveInput())
        self.assertEqual(code, 4)
        self.assertFalse(self.path.exists())
        network.assert_not_called()

    def test_noninteractive_input_must_be_explicit_and_bounded(self):
        with patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['configure', '--file', str(self.path)])
            self.assertEqual(code, 2)
            stream = io.StringIO('x' * (credentials.MAX_KEY_BYTES + 100))
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin'], stream)
            self.assertEqual(code, 4)
            self.assertEqual(stream.tell(), credentials.MAX_KEY_BYTES + 1)
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin'], InteractiveInput())
            self.assertEqual(code, 2)
        network.assert_not_called()

    def test_source_file_workflow_never_prints_source_secrets(self):
        source = self.store(path=self.root / 'source.json')
        opener, _ = self.remote()
        with patch('credentials.build_opener', return_value=opener):
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--input-file', str(source)])
        self.assertEqual(code, 0)
        self.assertEqual(credentials.load_management_key(self.path), KEY)
        self.assertTrue(source.exists())

    def test_existing_nonprivate_directory_is_not_chmodded(self):
        self.root.chmod(0o755)
        with patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin'],
                                  io.StringIO(json.dumps(KEY)))
        self.assertEqual(code, 4)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        network.assert_not_called()

    def test_overwrite_rejects_symlink_or_hardlink_before_network(self):
        actual = self.store(path=self.root / 'actual.json')
        self.path.symlink_to(actual)
        with patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                  io.StringIO(json.dumps(KEY)))
            self.assertEqual(code, 4)
            self.path.unlink()
            os.link(actual, self.path)
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                  io.StringIO(json.dumps(KEY)))
            self.assertEqual(code, 4)
        network.assert_not_called()
        self.assertEqual(actual.read_text(), json.dumps(KEY))

    def test_concurrent_file_change_is_not_overwritten(self):
        self.store()
        changed = dict(KEY, api_token='synthetic-concurrent-token')
        with patch('credentials.probe_credentials', side_effect=lambda key: self.store(changed)):
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                  io.StringIO(json.dumps(KEY)))
        self.assertEqual(code, 6)
        self.assertEqual(credentials.load_management_key(self.path), changed)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_atomic_store_failure_preserves_original_and_cleans_temporary(self):
        self.store()
        before = self.path.read_bytes()
        with patch('credentials.probe_credentials'), \
                patch('credentials.os.replace', side_effect=OSError(KEY['api_token'])):
            code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                  io.StringIO(json.dumps(KEY)))
        self.assertEqual(code, 7)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_remove_requires_confirmation_and_only_removes_local_file(self):
        self.store()
        with patch('credentials.build_opener') as network:
            code, _, _ = self.cli(['remove-local', '--file', str(self.path)])
            self.assertEqual(code, 6)
            self.assertTrue(self.path.exists())
            code, _, _ = self.cli(['remove-local', '--file', str(self.path), '--yes'], InteractiveInput('no\n'))
            self.assertEqual(code, 6)
            code, result, _ = self.cli(['remove-local', '--file', str(self.path), '--yes'])
        self.assertEqual(code, 0)
        self.assertFalse(result['remote_revoked'])
        self.assertFalse(self.path.exists())
        network.assert_not_called()

    def test_unknown_secret_arguments_are_not_echoed(self):
        code, _, stderr = self.cli(['configure', '--token', KEY['api_token']])
        self.assertEqual(code, 2)
        self.assertEqual(stderr, '')

    def test_global_file_flag_is_supported(self):
        self.store()
        code, result, _ = self.cli(['--file', str(self.path), 'status'])
        self.assertEqual(code, 0)
        self.assertEqual(result['credential_file'], str(self.path))

    def test_api_uses_fixed_https_endpoint_no_proxy_or_redirect_and_bounded_body(self):
        opener, response = self.remote()
        with patch('credentials.build_opener', return_value=opener) as factory, \
                patch('credentials.time.time', return_value=1000):
            entries, expires = credentials.issue_turn_credentials(KEY, ttl=120)
        self.assertEqual(entries, ICE['iceServers'])
        self.assertEqual(expires, 1120)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://rtc.live.cloudflare.com/v1/turn/keys/'
                         'synthetic-turn-id/credentials/generate-ice-servers')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(json.loads(request.data), {'ttl': 120})
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + KEY['api_token'])
        self.assertEqual(opener.open.call_args.kwargs['timeout'], credentials.API_TIMEOUT)
        response.read.assert_called_once_with(credentials.MAX_RESPONSE_BYTES + 1)
        handlers = factory.call_args.args
        self.assertTrue(any(isinstance(handler, HTTPSHandler) for handler in handlers))
        proxy = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        redirect = next(handler for handler in handlers if isinstance(handler, credentials._NoRedirect))
        with self.assertRaises(credentials.CredentialError) as raised:
            redirect.redirect_request(request, Mock(), 302, '', {}, 'https://attacker.invalid')
        self.assertEqual(raised.exception.exit_code, 5)

    def test_probe_discards_issued_secrets_and_check_is_redacted(self):
        self.store()
        opener, _ = self.remote()
        with patch('credentials.build_opener', return_value=opener):
            code, result, _ = self.cli(['check', '--file', str(self.path)])
        self.assertEqual(code, 0)
        self.assertTrue(result['validated'])
        self.assertTrue(result['network_checked'])
        self.assertEqual(result['probe_ttl_seconds'], 60)
        self.assertEqual(json.loads(opener.open.call_args.args[0].data), {'ttl': 60})

    def test_invalid_api_responses_never_validate_or_replace(self):
        self.store()
        before = self.path.read_bytes()
        documents = ({}, {'iceServers': []}, {'iceServers': [{'urls': 'stun:example.com:3478'}]},
                     {'iceServers': [{'urls': 'turns:example.com:443?transport=tcp', 'username': 'x'}]},
                     {'iceServers': [{'urls': 'turns:example.com:0?transport=tcp', 'username': 'x', 'credential': 'y'}]})
        for document in documents:
            opener, _ = self.remote(document)
            with patch('credentials.build_opener', return_value=opener):
                code, _, _ = self.cli(['configure', '--file', str(self.path), '--stdin', '--replace'],
                                      io.StringIO(json.dumps(KEY)))
            self.assertEqual(code, 5)
            self.assertEqual(self.path.read_bytes(), before)

    def test_large_or_unparseable_remote_response_is_redacted(self):
        for body in (b'x' * (credentials.MAX_RESPONSE_BYTES + 1), KEY['api_token'].encode()):
            opener, response = self.remote()
            response.read.return_value = body
            with patch('credentials.build_opener', return_value=opener):
                with self.assertRaises(credentials.CredentialError) as raised:
                    credentials.issue_turn_credentials(KEY)
            self.assertEqual(raised.exception.exit_code, 5)
            self.assertNotIn(KEY['api_token'], str(raised.exception))

    def test_network_exception_and_interrupt_are_redacted(self):
        self.store()
        opener = Mock()
        opener.open.side_effect = RuntimeError(KEY['api_token'])
        with patch('credentials.build_opener', return_value=opener):
            code, _, _ = self.cli(['check', '--file', str(self.path)])
        self.assertEqual(code, 5)
        with patch('credentials.probe_credentials', side_effect=KeyboardInterrupt):
            code, _, _ = self.cli(['check', '--file', str(self.path)])
        self.assertEqual(code, 130)


if __name__ == '__main__':
    unittest.main()
