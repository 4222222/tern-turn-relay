import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('release', Path(__file__).resolve().parents[1] / 'tools/release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def collected_fixtures(directory, current='0.5.9'):
    for index,(name,(target,system,arch)) in enumerate(release.ASSET_TARGETS.items()):
        data=(name.encode()+bytes(range(128)))*(index+1)
        (directory/name).write_bytes(data)
        # These are isolated metadata fixtures, not claims of executing foreign binaries.
        record={'schema':1,'asset':name,'version':current,'runtime':'rust','target':target,'os':system,'arch':arch,
                'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        (directory/(name+'.receipt.json')).write_text(json.dumps(record),encoding='utf-8')

class ReleaseTests(unittest.TestCase):
    def test_manifest_requires_all_five_matching_collection_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            collected_fixtures(root)
            destination = root / 'manifest.json'
            release.manifest(root, destination)
            assets = json.loads(destination.read_text())['assets']
            self.assertEqual(len(assets), 5)
            self.assertIn('tern-turn-relay-windows-x86_64.exe', assets)
            for name, entry in assets.items():
                data = (root / name).read_bytes()
                self.assertEqual(entry, {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            (root / 'tern-turn-relay-windows-x86_64.exe').unlink()
            with self.assertRaises(FileNotFoundError):
                release.manifest(root, destination)

    def test_package_contains_windows_runtime_and_licenses(self):
        with tempfile.TemporaryDirectory(prefix='release 中文 ') as temporary:
            root = Path(temporary)
            package = root / 'source'
            for name in release.RUNTIME_FILES:
                target = package / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((release.ROOT / name).read_bytes())
            (package / 'native/src').mkdir(parents=True)
            (package / 'native/Cargo.toml').write_text('version = "0.5.9"\n')
            (package / 'native/Cargo.lock').write_text('version = 4\n')
            (package / 'native/src/main.rs').write_text('fn main() {}\n')
            (package / 'tools').mkdir()
            (package / 'tools/release.py').write_bytes(Path(release.__file__).read_bytes())
            (package / '.github/workflows').mkdir(parents=True)
            (package / '.github/workflows/verify.yml').write_bytes((release.ROOT / '.github/workflows/verify.yml').read_bytes())
            # 测试资产仅位于隔离目录；发行工具仍计算真实输入大小/散列。
            binaries = root / 'binaries'
            binaries.mkdir()
            collected_fixtures(binaries)
            with patch.object(release, 'ROOT', package):
                release.manifest(binaries, package / 'release.json')
                with contextlib.redirect_stdout(io.StringIO()):
                    release.package(root / 'out',binaries)
                with tarfile.open(root / 'out/tern-turn-relay-0.5.9.tar.gz') as archive:
                    names = {Path(name).relative_to('tern-turn-relay-0.5.9').as_posix() for name in archive.getnames()}
                    self.assertTrue(set(release.RUNTIME_FILES).issubset(names))
                    manifest = json.load(archive.extractfile('tern-turn-relay-0.5.9/release.json'))
                    self.assertIn('tern-turn-relay-windows-x86_64.exe', manifest['assets'])
                value = json.loads((package / 'release.json').read_text())
                del value['assets']['tern-turn-relay-windows-x86_64.exe']
                (package / 'release.json').write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'Incomplete'):
                    release.package(root / 'incomplete',binaries)

    def test_manifest_rejects_old_receipts_and_post_collection_changes(self):
        for mutation in ('version','target','digest','binary','missing-receipt'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                collected_fixtures(root)
                name='tern-turn-relay-windows-x86_64.exe'
                record_path=root/(name+'.receipt.json')
                record=json.loads(record_path.read_text())
                if mutation=='version':record['version']='0.4.0'
                elif mutation=='target':record['target']='x86_64-unknown-linux-musl'
                elif mutation=='digest':record['sha256']='0'*64
                elif mutation=='binary':
                    with (root/name).open('ab') as output:output.write(b'changed after collection')
                elif mutation=='missing-receipt':record_path.unlink()
                if mutation!='missing-receipt':record_path.write_text(json.dumps(record))
                with self.assertRaises((ValueError,FileNotFoundError)):
                    release.manifest(root,root/'manifest.json')
                self.assertFalse((root/'manifest.json').exists())

    def test_package_rejects_well_formed_but_unbound_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            binaries=root/'binaries';binaries.mkdir()
            collected_fixtures(binaries)
            original=(release.ROOT/'release.json').read_bytes()
            current={'schema':1,'version':release.version(),'assets':release.verified_assets(binaries)}
            current['assets']['tern-turn-relay-windows-x86_64.exe']['sha256']='0'*64
            # Override only reads of the manifest; all other package inputs remain actual source files.
            real_read=Path.read_bytes
            def read_manifest(path):
                if path==release.ROOT/'release.json':return json.dumps(current).encode()
                return real_read(path)
            with patch.object(Path,'read_bytes',read_manifest):
                with self.assertRaisesRegex(ValueError,'verified final binaries'):
                    release.package(root/'out',binaries)
            self.assertEqual((release.ROOT/'release.json').read_bytes(),original)
            self.assertFalse((root/'out').exists())


if __name__ == '__main__':
    unittest.main()
