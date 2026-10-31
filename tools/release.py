#!/usr/bin/env python3
"""Build/release tooling only; never shipped as a runtime interpreter dependency."""
import argparse,gzip,hashlib,io,json,os,re,stat,subprocess,tarfile,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RUNTIME_FILES=('plugin.toml','window.luau','onboarding.luau','work-queue.luau','bootstrap-runtime.sh','release.json','LICENSE','THIRD_PARTY_NOTICES.txt','README.md','CHANGELOG.md','docs/agent-setup.md')
ASSETS=tuple('tern-turn-relay-'+platform+'-'+arch for platform in ('darwin','linux') for arch in ('arm64','x86_64'))

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
            texts.append(path.name+'\n'+path.read_text(errors='replace'))
        if not texts:raise ValueError('Dependency license text missing: '+package['name'])
        sections.append('\n'+'='*72+'\n'+package['name']+' '+package['version']+'\nLicense: '+str(package.get('license'))+'\nRepository: '+str(package.get('repository'))+'\n\n'+'\n\n'.join(texts))
    destination.write_text('\n'.join(sections))

def manifest(directory,destination):
    assets={}
    for name in ASSETS:
        path=directory/name
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=64*1024*1024:raise ValueError('Invalid binary asset')
        assets[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':info.st_size}
    destination.write_text(json.dumps({'schema':1,'version':version(),'assets':assets},indent=2)+'\n')

def package(destination):
    files=list(RUNTIME_FILES)+['native/Cargo.toml','native/Cargo.lock','tools/release.py','tests/work_queue_spec.luau']
    files.extend(str(path.relative_to(ROOT)) for path in sorted((ROOT/'native/src').rglob('*.rs')))
    contents={}
    for name in files:
        path=ROOT/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size>8*1024*1024:raise ValueError('Invalid source release input')
        contents[name]=path.read_bytes()
    current=version()
    if json.loads(contents['release.json'])['version']!=current:raise ValueError('Asset manifest version mismatch')
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
    def invoke(args,data=None):
        result=subprocess.run([str(binary),*args],input=None if data is None else json.dumps(data).encode(),capture_output=True,timeout=20)
        if result.stderr:raise AssertionError('Unexpected native stderr')
        return result.returncode,json.loads(result.stdout)
    code,value=invoke(['--version']);assert code==0 and value['runtime']=='rust' and value['version']==version()
    code,value=invoke(['credentials','not-a-command','DO_NOT_ECHO_PRIVATE_ARGUMENT']);assert code!=0 and 'DO_NOT_ECHO_PRIVATE_ARGUMENT' not in json.dumps(value)
    with tempfile.TemporaryDirectory(prefix='native-release-smoke-') as temporary:
        root=Path(temporary).resolve();root.chmod(0o700)
        profile=['--config-dir',str(root),'--data-dir',str(root/'plugin-data/tern-turn-relay'),'--package-dir',str(ROOT)]
        code,value=invoke(['onboarding','inspect',*profile],{})
        assert code==0 and value['configured'] is False and value['running'] is False
        assert not (root/'plugin-data/tern-turn-relay/config.json').exists()
        code,value=invoke(['onboarding','apply',*profile],{'review':{}})
        assert code!=0 and not (root/'plugin-data/tern-turn-relay/config.json').exists()
    print(json.dumps({'native_cli_smoke':'passed','invalid_review_left_unconfigured':True,'private_argument_redacted':True}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('notices');p.add_argument('destination',type=Path);p.add_argument('--target')
    p=sub.add_parser('manifest');p.add_argument('directory',type=Path);p.add_argument('destination',type=Path)
    p=sub.add_parser('package');p.add_argument('destination',type=Path)
    p=sub.add_parser('smoke');p.add_argument('binary',type=Path)
    args=parser.parse_args()
    if args.command=='manifest':manifest(args.directory,args.destination)
    elif args.command=='smoke':smoke(args.binary)
    elif args.command=='notices':notices(args.destination,args.target)
    else:package(args.destination)
if __name__=='__main__':main()
