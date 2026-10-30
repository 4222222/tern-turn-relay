#!/usr/bin/env python3
"""Unlink this plugin and remove its marked SSH rule, preserving all remote state and secrets."""
import argparse
import fcntl
import json
import os
from pathlib import Path

from install import PLUGIN_ID, plugin_link, require_stopped, run, ssh_block_digest, tern_environment
from relay_config import lock_file, private_file, state_directory
from ssh_compat import update, without_block


def owned_installation(data, plugins):
    manifest = data / 'installation.json'
    private_file(manifest)
    record = json.loads(manifest.read_text(encoding='utf-8'))
    if (not isinstance(record, dict) or record.get('schema') != 1 or record.get('plugin') != PLUGIN_ID
            or record.get('plugins') != str(plugins)):
        raise ValueError('Installation ownership record does not match this Tern profile')
    package = Path(record['package'])
    if (not package.is_absolute() or package.parent != data / 'packages'
            or package.is_symlink() or not package.is_dir()):
        raise ValueError('Installed package is not owned by this plugin')
    helper = package / 'relay.py'
    private_file(helper)
    link, source = plugin_link(plugins)
    if source is not None and source != package.resolve():
        raise ValueError('Current plugin link points elsewhere; it was not removed')
    ssh = Path(record['ssh_config'])
    if not ssh.is_absolute():
        raise ValueError('SSH ownership record must contain an absolute path')
    expected = record.get('ssh_block_sha256')
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError('Installation does not record ownership of the marked SSH rule')
    return package, link, ssh, expected


def uninstall(args):
    tern, env, plugins, data = tern_environment(args.tern, args.config_dir)
    package, link, ssh, expected_rule = owned_installation(data, plugins)
    if args.ssh_config and args.ssh_config.expanduser().absolute() != ssh:
        raise ValueError('Requested SSH config does not match the installation ownership record')
    runtime = state_directory(data / 'runtime')
    # The relay verifies its live control-socket identity and never kills from a
    # stale PID file. Do not hold command.lock while invoking its stop command.
    import sys
    status = json.loads(run([sys.executable, str(package / 'relay.py'), 'stop',
                             '--config', str(data / 'config.json'), '--state-dir', str(runtime)], env))
    if status.get('ok') is not True or status.get('state') != 'stopped':
        raise ValueError('Owned backend did not stop; plugin and SSH configuration were preserved')
    command_lock = lock_file(runtime / 'command.lock')
    try:
        try:
            fcntl.flock(command_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another relay lifecycle operation is in progress; retry after it finishes') from None
        require_stopped(runtime)
        # Check markers before unlinking. Unrecognized/edited content is never
        # removed, and unrelated SSH rules are preserved byte-for-byte.
        if ssh.exists() or ssh.is_symlink():
            if ssh.is_symlink():
                raise ValueError('SSH configuration is a symlink; it was preserved')
            found = ssh_block_digest(ssh.read_text(encoding='utf-8'))
            if found is not None and found != expected_rule:
                raise ValueError('Marked SSH rule changed or belongs to another installation; it was preserved')
        current_link, source = plugin_link(plugins)
        if source is not None and source != package.resolve():
            raise ValueError('Plugin registration changed during uninstall; it was preserved')
        if current_link is not None:
            run([str(tern), 'plugin', 'unlink', PLUGIN_ID], env)
            if plugin_link(plugins)[0] is not None:
                raise ValueError('Tern did not remove the plugin registration; SSH configuration was preserved')
        if ssh.exists():
            def remove_owned(text):
                found = ssh_block_digest(text)
                if found is not None and found != expected_rule:
                    raise ValueError('Marked SSH rule changed during uninstall; it was preserved')
                return without_block(text)
            update(ssh, remove_owned)
        return {'ok': True, 'plugin_unlinked': True, 'owned_backend_stopped': True,
                'marked_ssh_rule_removed': True, 'remote_daemon_preserved': True,
                'remote_gateway_state_preserved': True, 'configuration_preserved': True,
                'credentials_preserved': True, 'installed_package_preserved': True,
                'secret_removal': 'Use credentials.py remove-local separately with explicit authorization'}
    finally:
        os.close(command_lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tern', type=Path)
    parser.add_argument('--config-dir', type=Path, help='same isolated profile used during installation')
    parser.add_argument('--ssh-config', type=Path, help='optional assertion; must match installed ownership record')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(uninstall(args), indent=2))
        return 0
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else 'Uninstall failed safely; private diagnostic output was withheld'
        print(json.dumps({'ok': False, 'error': message}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
