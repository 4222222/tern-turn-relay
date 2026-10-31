#!/usr/bin/env python3
"""Create a local, allowlisted source release; never publish or grant a license."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
# No recursive repository copy: these are the complete distributable inputs.
FILES = (
    'plugin.toml', 'window.luau', 'work-queue.luau', 'requirements.txt',
    'onboarding.luau', 'onboarding.py', 'bootstrap-runtime.sh', 'managed_runtime.py',
    'relay.py', 'relay_config.py', 'relay_transport.py', 'relay_ssh.py',
    'relay_intent.py', 'gateway_client.py', 'gateway_protocol.py',
    'remote_gateway.py', 'ssh_compat.py', 'credentials.py', 'install.py',
    'setup.py', 'uninstall.py', 'package_release.py', 'config.example.json', 'README.md',
    'LICENSE', 'CHANGELOG.md', 'docs/agent-setup.md',
)
TESTS = (
    'tests/test_gateway_client.py', 'tests/test_gateway_protocol.py',
    'tests/test_runtime.py', 'tests/test_ready_publication.py',
    'tests/test_gateway_transport.py', 'tests/test_congestion.py',
    'tests/test_intent.py', 'tests/work_queue_spec.luau',
    'tests/test_distribution.py', 'tests/test_setup.py', 'tests/test_credentials.py',
    'tests/test_allocation_recovery.py',
    'tests/test_renewal.py', 'tests/test_flow_recovery.py',
    'tests/test_gateway_errors.py', 'tests/test_gateway_recovery.py',
    'tests/test_onboarding.py', 'tests/test_native_runtime.py',
)


def release_version(root=ROOT):
    text = (root / 'plugin.toml').read_text(encoding='utf-8')
    match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', text, re.M)
    if not match:
        raise ValueError('plugin.toml must declare a numeric release version')
    return match.group(1)


def release_files(root=ROOT, include_tests=True):
    result = {}
    for name in FILES + (TESTS if include_tests else ()):
        path = root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
            raise ValueError('Release input must be a bounded, non-symlink regular file: ' + name)
        result[name] = path.read_bytes()
    example = json.loads(result['config.example.json'])
    if example.get('documentation_only') is not True or 'schema' in example:
        raise ValueError('Release example must be non-runnable documentation, not personal configuration')
    return result


def content_digest(files):
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        digest.update(name.encode('utf-8') + b'\0' + content + b'\0')
    return digest.hexdigest()


def create_release(root, output):
    files = release_files(root)
    version = release_version(root)
    prefix = 'tern-turn-relay-' + version
    output.mkdir(parents=True, exist_ok=True)
    destination = output / (prefix + '.tar.gz')
    checksum = output / (destination.name + '.sha256')
    if destination.exists() or checksum.exists() or destination.is_symlink() or checksum.is_symlink():
        raise ValueError('Release output already exists; use a fresh output directory')
    fd, staged = tempfile.mkstemp(prefix='.release-', dir=str(output))
    try:
        with os.fdopen(fd, 'wb') as stream:
            with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    for name, content in sorted(files.items()):
                        entry = tarfile.TarInfo(prefix + '/' + name)
                        entry.size = len(content)
                        entry.mode = 0o644
                        entry.mtime = 0
                        archive.addfile(entry, io.BytesIO(content))
        sha256 = hashlib.sha256(Path(staged).read_bytes()).hexdigest()
        # Exclusive links avoid silently overwriting another packaging process.
        os.link(staged, destination)
        with checksum.open('x', encoding='ascii') as stream:
            stream.write(sha256 + '  ' + destination.name + '\n')
    finally:
        os.unlink(staged)
    return {'ok': True, 'version': version, 'archive': str(destination),
            'checksum': str(checksum), 'sha256': sha256, 'published': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create_release(ROOT, args.output_dir.expanduser().absolute()), indent=2))
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
