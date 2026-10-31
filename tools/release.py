#!/usr/bin/env python3
"""Build/release tooling only; never shipped as a runtime interpreter dependency."""
import argparse,gzip,hashlib,io,json,os,re,shutil,stat,subprocess,tarfile,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RUNTIME_FILES=('plugin.toml','window.luau','onboarding.luau','work-queue.luau','platform.luau','bootstrap-runtime.sh','bootstrap-runtime.ps1','release.json','LICENSE','THIRD_PARTY_NOTICES.txt','README.md','CHANGELOG.md','docs/agent-setup.md')
ASSET_TARGETS={
    'tern-turn-relay-darwin-arm64':('aarch64-apple-darwin','macos','aarch64'),
    'tern-turn-relay-darwin-x86_64':('x86_64-apple-darwin','macos','x86_64'),
    'tern-turn-relay-linux-arm64':('aarch64-unknown-linux-musl','linux','aarch64'),
    'tern-turn-relay-linux-x86_64':('x86_64-unknown-linux-musl','linux','x86_64'),
    'tern-turn-relay-windows-x86_64.exe':('x86_64-pc-windows-msvc','windows','x86_64'),
}
ASSETS=tuple(ASSET_TARGETS)

def version():
    match=re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', (ROOT/'native/Cargo.toml').read_text(),re.M)
    if not match:raise ValueError('Invalid release version')
    return match.group(1)

def notices(destination,target=None):
    if target is None:
        target=next(line.split(': ',1)[1] for line in subprocess.check_output(['rustc','-vV'],text=True).splitlines() if line.startswith('host: '))
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--filter-platform',target,'--manifest-path',str(ROOT/'native/Cargo.toml')]))
    nodes={node['id']:node for node in metadata['resolve']['nodes']}
    pending=[metadata['resolve']['root']];included=set()
    while pending:
        package_id=pending.pop()
        if package_id in included:continue
        included.add(package_id)
        pending.extend(dep['pkg'] for dep in nodes[package_id]['deps'])
    sections=['Third-party notices for Tern TURN Relay '+version()+'\nDependency licenses remain owned by their respective authors.\nProject source: https://github.com/jiwangyihao/tern-turn-relay\n']
    for package in sorted(metadata['packages'],key=lambda p:(p['name'],p['version'])):
        if package['name']=='tern-turn-relay' or package['id'] not in included:continue
        directory=Path(package['manifest_path']).parent
        texts=[]
        names=set()
        for path in directory.iterdir():
            if path.is_file() and path.name.upper().startswith(('LICENSE','LICENCE','COPYING','NOTICE','COPYRIGHT')):names.add(path)
        if package.get('license_file'):names.add(directory/package['license_file'])
        license_dir=directory/'LICENSES'
        if license_dir.is_dir():names.update(p for p in license_dir.iterdir() if p.is_file())
        for path in sorted(names):
            if not path.is_file() or path.stat().st_size>1024*1024:raise ValueError('Invalid dependency notice file')
            texts.append(path.name+'\n'+path.read_text(encoding='utf-8',errors='replace'))
        if not texts:raise ValueError('Dependency license text missing: '+package['name'])
        sections.append('\n'+'='*72+'\n'+package['name']+' '+package['version']+'\nLicense: '+str(package.get('license'))+'\nRepository: '+str(package.get('repository'))+'\n\n'+'\n\n'.join(texts))
    destination.write_text('\n'.join(sections),encoding='utf-8')

def document(raw):
    if len(raw)>65536:raise ValueError('Release metadata exceeds its limit')
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('Duplicate release metadata key')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique)

def measurement(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=64*1024*1024:raise ValueError('Invalid binary asset')
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'sha256':digest,'size':info.st_size}

def receipt(asset,measured):
    target,system,arch=ASSET_TARGETS[asset]
    return {'schema':1,'asset':asset,'version':version(),'runtime':'rust','target':target,'os':system,'arch':arch,**measured}

def verified_assets(directory):
    assets={}
    for name in ASSETS:
        measured=measurement(directory/name)
        record_path=directory/(name+'.receipt.json')
        if not stat.S_ISREG(record_path.lstat().st_mode):raise ValueError('Invalid collection receipt')
        record=document(record_path.read_bytes())
        if not isinstance(record,dict) or type(record.get('schema')) is not int or type(record.get('size')) is not int or record!=receipt(name,measured):
            raise ValueError('Collection receipt does not match the current version, target or binary')
        assets[name]=measured
    return assets

def manifest(directory,destination):
    assets=verified_assets(directory)
    destination.write_text(json.dumps({'schema':1,'version':version(),'assets':assets},indent=2)+'\n',encoding='utf-8',newline='\n')

def package(destination,assets_directory):
    files=list(RUNTIME_FILES)+['native/Cargo.toml','native/Cargo.lock','tools/release.py','.github/workflows/verify.yml']
    files.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT/'native/src').rglob('*.rs')))
    files.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT/'tests').rglob('*')) if path.is_file() and path.suffix in ('.py','.luau','.ps1'))
    contents={}
    for name in files:
        path=ROOT/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size>8*1024*1024:raise ValueError('Invalid source release input')
        contents[name]=path.read_bytes()
    current=version()
    release=document(contents['release.json'])
    if release.get('schema')!=1 or release.get('version')!=current:raise ValueError('Asset manifest version mismatch')
    if set(release.get('assets',{}))!=set(ASSETS):raise ValueError('Incomplete native asset manifest')
    for entry in release['assets'].values():
        if not re.fullmatch('[0-9a-f]{64}',entry.get('sha256','')) or type(entry.get('size')) is not int or not 0<entry['size']<=64*1024*1024:raise ValueError('Invalid native asset manifest')
    if release['assets']!=verified_assets(assets_directory):raise ValueError('Asset manifest does not match the verified final binaries')
    if 'version = "'+current+'"' not in contents['plugin.toml'].decode():raise ValueError('Plugin version mismatch')
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/('tern-turn-relay-'+current+'.tar.gz')
    with archive.open('xb') as raw:
        with gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as output:
                for name,data in sorted(contents.items()):
                    entry=tarfile.TarInfo('tern-turn-relay-'+current+'/'+name);entry.mode=0o644;entry.size=len(data);entry.mtime=0
                    output.addfile(entry,io.BytesIO(data))
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name+'.sha256').write_text(digest+'  '+archive.name+'\n')
    print(json.dumps({'archive':str(archive),'sha256':digest,'files':len(contents),'published':False}))

def smoke(binary):
    binary=binary.resolve(strict=True)
    environment=None
    def invoke(args,data=None):
        result=subprocess.run([str(binary),*args],input=None if data is None else json.dumps(data).encode(),env=environment,capture_output=True,timeout=20)
        if result.stderr:raise AssertionError('Unexpected native stderr')
        return result.returncode,json.loads(result.stdout)
    code,value=invoke(['--version']);assert code==0 and value['runtime']=='rust' and value['version']==version()
    code,value=invoke(['--help']);assert code==0 and value.get('ok') is True and isinstance(value.get('usage'),str)
    code,value=invoke(['credentials','not-a-command','DO_NOT_ECHO_PRIVATE_ARGUMENT']);assert code!=0 and 'DO_NOT_ECHO_PRIVATE_ARGUMENT' not in json.dumps(value)
    with tempfile.TemporaryDirectory(prefix='native-release-smoke-') as temporary:
        root=Path(temporary).resolve();root.chmod(0o700)
        home=root/'home';home.mkdir(mode=0o700)
        package_dir=root/'plugins/tern-turn-relay';package_dir.mkdir(parents=True,mode=0o700)
        for name in RUNTIME_FILES:
            source=ROOT/name
            if not source.exists():continue
            destination=package_dir/name;destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            destination.write_bytes(source.read_bytes());destination.chmod(0o600)
        # Windows Known Folders 属于真实登录用户；显式 profile 隔离不能靠伪造 USERPROFILE。
        environment=None if os.name=='nt' else dict(os.environ,HOME=str(home))
        profile=['--config-dir',str(root),'--data-dir',str(root/'plugin-data/tern-turn-relay'),'--package-dir',str(package_dir)]
        code,value=invoke(['onboarding','inspect',*profile],{})
        assert code==0 and value.get('configured') is False and value.get('running') is False, {key:value.get(key) for key in ('code','error','exit_code','configured','running')}
        assert not (root/'plugin-data/tern-turn-relay/config.json').exists()
        code,value=invoke(['onboarding','apply',*profile],{'review':{}})
        assert code!=0 and not (root/'plugin-data/tern-turn-relay/config.json').exists()
    print(json.dumps({'native_cli_smoke':'passed','invalid_review_left_unconfigured':True,'private_argument_redacted':True}))

def collect(binary,destination,asset,target):
    if asset not in ASSET_TARGETS or target!=ASSET_TARGETS[asset][0]:raise ValueError('Unknown or mismatched release target')
    before=measurement(binary)
    checked=subprocess.run([str(binary.resolve(strict=True)),'--version'],capture_output=True,timeout=20)
    if checked.returncode or checked.stderr:raise ValueError('Native asset version query failed')
    identity=document(checked.stdout)
    expected=receipt(asset,before)
    if not isinstance(identity,dict) or identity.get('ok') is not True or any(identity.get(key)!=expected[key] for key in ('version','runtime','os','arch')):
        raise ValueError('Native asset reports the wrong version or platform')
    if measurement(binary)!=before:raise ValueError('Native asset changed during version verification')
    destination.mkdir(parents=True,exist_ok=True)
    output=destination/asset
    shutil.copyfile(binary,output)
    if measurement(output)!=before:raise ValueError('Collected native asset changed')
    notices(destination/'THIRD_PARTY_NOTICES.txt',target)
    (destination/(asset+'.receipt.json')).write_text(json.dumps(expected,indent=2)+'\n',encoding='utf-8',newline='\n')
    (destination/'SHA256SUMS').write_text(before['sha256']+'  '+asset+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(expected))

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('notices');p.add_argument('destination',type=Path);p.add_argument('--target')
    p=sub.add_parser('manifest');p.add_argument('directory',type=Path);p.add_argument('destination',type=Path)
    p=sub.add_parser('package');p.add_argument('destination',type=Path);p.add_argument('--assets',type=Path,required=True)
    p=sub.add_parser('smoke');p.add_argument('binary',type=Path)
    p=sub.add_parser('collect');p.add_argument('binary',type=Path);p.add_argument('destination',type=Path);p.add_argument('--asset',required=True);p.add_argument('--target',required=True)
    args=parser.parse_args()
    if args.command=='manifest':manifest(args.directory,args.destination)
    elif args.command=='smoke':smoke(args.binary)
    elif args.command=='notices':notices(args.destination,args.target)
    elif args.command=='collect':collect(args.binary,args.destination,args.asset,args.target)
    else:package(args.destination,args.assets)
if __name__=='__main__':main()
