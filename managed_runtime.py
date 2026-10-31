"""Private standalone-runtime finalization; invoked only after publisher SHA-256 verification.

bootstrap-runtime.sh owns the immutable release pins and download boundary. This
module never downloads, accepts credentials, or touches relay runtime/configuration.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 20000


def runtime_python(data):
    return Path(data) / 'managed-python' / 'python' / 'bin' / 'python3'


def audit_runtime(root):
    """Reject unexpected ownership, special files, escaping links and oversized trees."""
    root = Path(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('Runtime staging directory is not privately owned')
    root = root.resolve()
    total = 0
    for count, path in enumerate(root.rglob('*'), 1):
        if count > MAX_ENTRIES:
            raise ValueError('Runtime archive exceeds its file-count limit')
        info = path.lstat()
        if info.st_uid != os.getuid():
            raise ValueError('Runtime archive has unexpected file ownership')
        if stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            if root not in target.parents:
                raise ValueError('Runtime archive contains an escaping symbolic link')
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise ValueError('Runtime archive contains an unexpected hard link')
            total += info.st_size
            if total > MAX_BYTES:
                raise ValueError('Runtime archive exceeds its unpacked size limit')
            path.chmod(0o700 if info.st_mode & 0o111 else 0o600)
        elif stat.S_ISDIR(info.st_mode):
            path.chmod(0o700)
        else:
            raise ValueError('Runtime archive contains a special file')
    root.chmod(0o700)
    executable = root / 'python' / 'bin' / 'python3'
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('Runtime archive is missing the Python executable')
    return total


def finalize(stage, data, release, architecture, digest):
    stage, data = Path(stage), Path(data)
    if (not re.fullmatch(r'[0-9]{8}', release)
            or architecture not in ('aarch64', 'x86_64')
            or not re.fullmatch(r'[0-9a-f]{64}', digest)):
        raise ValueError('Invalid runtime publisher receipt')
    if stage.parent.parent != data or not stage.parent.name.startswith('.managed-python-'):
        raise ValueError('Runtime staging location is outside its private data directory')
    for component in (data, stage.parent, stage):
        info = component.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Runtime staging location is not private')
    audit_runtime(stage)
    receipt = stage / 'bootstrap.receipt'
    with receipt.open('x', encoding='ascii') as stream:
        stream.write(release + '\n' + architecture + '\n' + digest + '\n')
    receipt.chmod(0o600)
    destination = data / 'managed-python'
    if destination.exists() or destination.is_symlink():
        raise ValueError('Runtime destination appeared during preparation; it was preserved')
    os.rename(stage, destination)
    return runtime_python(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('finalize', 'report'))
    parser.add_argument('data', type=Path)
    parser.add_argument('--stage', type=Path)
    parser.add_argument('--release')
    parser.add_argument('--architecture')
    parser.add_argument('--sha256')
    args = parser.parse_args(argv)
    try:
        if args.action == 'finalize':
            finalize(args.stage, args.data, args.release, args.architecture, args.sha256)
        print(json.dumps({'ok': True, 'runtime_ready': True, 'python': str(runtime_python(args.data))}))
        return 0
    except Exception:
        print(json.dumps({'ok': False, 'error': 'Managed Python preparation failed safely; existing data was preserved'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
