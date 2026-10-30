"""Exact-address OpenSSH compatibility for the plugin's raw TCP listener.

Only public SSH options are copied; private keys stay with the original client.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

BEGIN = '# BEGIN tern-turn-relay SSH compatibility\n'
END = '# END tern-turn-relay SSH compatibility\n'


def resolved(destination):
    result = subprocess.run(['/usr/bin/ssh', '-G', destination], capture_output=True, text=True, timeout=10, check=True)
    options = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(' ')
        options.setdefault(key, []).append(value)
    return options


def without_block(text):
    if BEGIN not in text and END not in text:
        return text
    if not text.startswith(BEGIN) or text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError('SSH compatibility markers were edited; preserve the file and resolve manually')
    return text.split(END, 1)[1]


def quoted(value):
    if any(ch in value for ch in '\r\n\x00'):
        raise ValueError('Invalid SSH option text')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

def rule(config):
    destination = config['ssh_destination']
    options = resolved(destination)
    host, user, port = (options[key][0] for key in ('hostname', 'user', 'port'))
    if host != config['target']['host'] or user != config['target']['user']:
        raise ValueError('SSH destination does not match the independently verified TURN target')
    pin = options.get('hostkeyalias', [host if port == '22' else '[%s]:%s' % (host, port)])[0]
    if pin == 'none':
        pin = host if port == '22' else '[%s]:%s' % (host, port)
    lines = [BEGIN.rstrip('\n'),
             'Match originalhost 127.0.0.1 user %s exec "test %%p = %d"' % (user, config['listen_port']),
             '    HostKeyAlias ' + quoted(pin),
             '    StrictHostKeyChecking yes', '    CheckHostIP no',
             '    PasswordAuthentication no', '    KbdInteractiveAuthentication no',
             '    PreferredAuthentications publickey', '    PubkeyAuthentication yes',
             '    ForwardAgent no', '    ProxyCommand none', '    ProxyJump none',
             '    CanonicalizeHostname no']
    # Resolve endpoint-dependent tokens for the original host, not the loopback alias.
    tokens = {'h': host, 'n': destination, 'p': port, 'r': user, 'd': str(Path.home()), '%': '%'}
    def expand(value):
        import re
        return re.sub(r'%([hnprd%])', lambda match: tokens[match[1]], value)
    for name in ('identityfile', 'certificatefile', 'identityagent', 'identitiesonly', 'hostkeyalgorithms'):
        for value in options.get(name, []):
            lines.append('    ' + name + ' ' + quoted(expand(value)))
    # Keep original trust databases, including custom paths; ssh -G emits these as a list.
    for name in ('userknownhostsfile', 'globalknownhostsfile'):
        if name in options:
            lines.append('    ' + name + ' ' + expand(options[name][0]))
    lines.extend(['Match all', END.rstrip('\n')])
    return '\n'.join(lines) + '\n', pin


def update(path, transform, validate=None):
    import stat
    path = Path(path).expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('SSH config must be an owned, non-symlink file not writable by others')
        original = path.read_bytes()
    else:
        original = b''
    replacement = transform(original.decode('utf-8')).encode('utf-8')
    if replacement == original:
        return
    fd, staged = tempfile.mkstemp(prefix='.tern-ssh-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(replacement)
        if validate:
            validate(staged)
        if (path.read_bytes() if path.exists() else b'') != original or path.is_symlink():
            raise ValueError('SSH config changed during installation; no changes applied')
        if original:
            backup_fd, backup = tempfile.mkstemp(prefix='config.tern-turn-relay-backup-', dir=str(path.parent))
            with os.fdopen(backup_fd, 'wb') as stream:
                stream.write(original)
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def install_compat(config, path):
    block, pin = rule(config)
    def validate(staged):
        result = subprocess.run(['/usr/bin/ssh', '-G', '-F', staged, '-p', str(config['listen_port']),
                                 config['target']['user'] + '@127.0.0.1'],
                                capture_output=True, text=True, timeout=10, check=True)
        values = dict(line.split(' ', 1) for line in result.stdout.splitlines() if ' ' in line)
        if values.get('hostkeyalias') != pin or values.get('hostname') != '127.0.0.1':
            raise ValueError('Existing SSH configuration overrides the scoped compatibility rule')
    update(path, lambda text: block + without_block(text), validate)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'remove'])
    parser.add_argument('--ssh-config', type=Path, default=Path.home() / '.ssh/config')
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    if args.action == 'remove':
        update(args.ssh_config, without_block)
    else:
        if not args.config:
            parser.error('--config is required for install')
        from relay_config import load_config
        install_compat(load_config(args.config, check_key=False), args.ssh_config)
    print(json.dumps({'ok': True, 'action': args.action, 'ssh_config': str(args.ssh_config)}))
