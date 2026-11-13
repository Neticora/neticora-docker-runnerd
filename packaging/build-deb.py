#!/usr/bin/env python3
"""Build an unsigned local-engineering Ubuntu 26.04 amd64 package from Git.

The source checkout is cloned at the recorded commit, excluding all ignored and
untracked files. SOURCE_DATE_EPOCH defaults to that commit's timestamp.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=ROOT, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def maintainer_script(source, name):
    content = (source / 'packaging/debian' / name).read_text()
    if name in ('preinst', 'prerm'):
        marker = '# RUNNERD_SERVICE_GUARD\n'
        if content.count(marker) != 1:
            raise ValueError('Expected one package service guard marker')
        content = content.replace(marker, (source / 'packaging/debian/service-state.sh').read_text() + '\n')
    return content


def build():
    # Never inherit an operator's permissive umask into root-owned package files.
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', help='Debian version; defaults to commit version')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/ubuntu-amd64')
    args = parser.parse_args()
    if run('git', 'status', '--porcelain', '--untracked-files=all'):
        raise SystemExit('Commit all source changes before building a candidate.')
    commit = run('git', 'rev-parse', 'HEAD')
    tree = run('git', 'rev-parse', 'HEAD^{tree}')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', run('git', 'show', '-s', '--format=%ct', 'HEAD')))
    timestamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    version = args.version or '0.0.0~local.' + timestamp.strftime('%Y%m%d%H%M%S') + '.' + commit[:12]
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+~:-]{0,100}', version):
        raise SystemExit('Invalid Debian package version')
    expected = re.search(r'^toolchain (go\S+)$', (ROOT / 'go.mod').read_text(), re.M).group(1)
    # User workspaces/modfiles and GOFLAGS must not substitute source or embed
    # local linker data while provenance claims a clean, tracked Git checkout.
    env = dict(os.environ, GOTOOLCHAIN='local', GOENV='off', GOWORK='off', GOFLAGS='', GOEXPERIMENT='', GOPROXY='off', GOSUMDB='off', GOOS='linux', GOARCH='amd64', GOAMD64='v1', CGO_ENABLED='0', SOURCE_DATE_EPOCH=str(epoch))
    toolchain = run('go', 'version', env=env).split()[2]
    if toolchain != expected:
        raise SystemExit(f'Required toolchain {expected}; found {toolchain}')
    output = args.output.resolve() / version
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='runnerd-deb-') as work:
        work = Path(work)
        source = work / 'source'
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(ROOT), str(source)], check=True)
        subprocess.run(['git', 'checkout', '--quiet', '--detach', commit], cwd=source, check=True)
        stage = work / 'package'
        bins = stage / 'usr/bin'
        bins.mkdir(parents=True)
        subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=true', '-o', str(bins) + '/', './cmd/...'], cwd=source, env=env, check=True)
        for binary in bins.iterdir():
            binary.chmod(0o755)
        os.symlink('runnerd', bins / 'neticora-runnerd')
        binary_hashes = {p.name: sha(p) for p in sorted(bins.iterdir()) if not p.is_symlink()}
        contents = {
            'packaging/linux/neticora-runnerd.service': 'usr/lib/systemd/system/neticora-runnerd.service',
            'packaging/linux/neticora-runnerd.sysusers.conf': 'usr/lib/sysusers.d/neticora-runnerd.conf',
            'packaging/linux/neticora-runnerd.tmpfiles.conf': 'usr/lib/tmpfiles.d/neticora-runnerd.conf',
            'packaging/linux/config.example.json': 'usr/share/neticora-runnerd/config.example.json',
            'docs/UBUNTU-INSTALLATION.md': 'usr/share/doc/neticora-runnerd/UBUNTU-INSTALLATION.md',
        }
        for origin, target in contents.items():
            destination = stage / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / origin, destination)
            destination.chmod(0o644)
        provenance = dict(product='neticora-runnerd', version=version, distribution='ubuntu', ubuntuRelease='26.04', architecture='amd64', sourceCommit=commit, sourceTree=tree, runnerd08Baseline='2a8c68145e5d', goVersion=toolchain, buildTimestamp=timestamp.isoformat(), buildMode='local-engineering', productionApproved=False, sourceDirty=False, executableSha256=binary_hashes)
        share = stage / 'usr/share/neticora-runnerd'
        write_json(share / 'build-provenance.json', provenance)
        module_stream = run('go', 'list', '-m', '-json', 'all', cwd=source, env=env)
        decoder = json.JSONDecoder()
        modules = []
        while module_stream.strip():
            module, end = decoder.raw_decode(module_stream.lstrip())
            modules.append(module)
            module_stream = module_stream.lstrip()[end:]
        packages = []
        for i, module in enumerate(modules):
            packages.append({'SPDXID': f'SPDXRef-module-{i}', 'name': module['Path'], 'versionInfo': module.get('Version', commit if module.get('Main') or module.get('Replace', {}).get('Dir') else 'NOASSERTION'), 'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION', 'sourceInfo': 'Go module; go.sum verifies downloaded module content'})
        sbom = {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT', 'name': 'neticora-runnerd-' + version, 'documentNamespace': 'https://neticora.com/spdx/runnerd/' + commit + '/' + version, 'creationInfo': {'created': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'), 'creators': ['Tool: neticora-local-deb-builder']}, 'documentDescribes': ['SPDXRef-module-0'], 'packages': packages, 'relationships': [{'spdxElementId': 'SPDXRef-module-0', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': p['SPDXID']} for p in packages[1:]]}
        write_json(output / 'sbom.spdx.json', sbom)
        shutil.copyfile(output / 'sbom.spdx.json', share / 'sbom.spdx.json')
        metadata = stage / 'DEBIAN'
        metadata.mkdir()
        (metadata / 'control').write_text(f'Package: neticora-runnerd\nVersion: {version}\nArchitecture: amd64\nMaintainer: Neticora Engineering <engineering@neticora.com>\nDepends: systemd (>= 255), passwd\nSection: admin\nPriority: optional\nDescription: Neticora Linux Standard runner (local engineering)\n Customer-provisioned Docker required. No production signing or admission.\n')
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            (metadata / name).write_text(maintainer_script(source, name))
            (metadata / name).chmod(0o755)
        hashes = []
        for path in sorted(stage.rglob('*')):
            if path.is_file() and not path.is_symlink() and 'DEBIAN' not in path.relative_to(stage).parts:
                hashes.append(hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest() + '  ' + str(path.relative_to(stage)))
        (metadata / 'md5sums').write_text('\n'.join(hashes) + '\n')
        for path in stage.rglob('*'):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        package = output / f'neticora-runnerd_{version}_amd64.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z6', '--build', str(stage), str(package)], env=env, check=True)
        assert run('dpkg-deb', '-f', str(package), 'Architecture') == 'amd64'
        assert run('dpkg-deb', '-f', str(package), 'Version') == version
        extract = work / 'verify'
        subprocess.run(['dpkg-deb', '-x', str(package), str(extract)], check=True)
        for name, digest in binary_hashes.items():
            assert sha(extract / 'usr/bin' / name) == digest
            assert (extract / 'usr/bin' / name).stat().st_mode & 0o7777 == 0o755
        provenance.update(packageSha256=sha(package), runnerdBinarySha256=binary_hashes['runnerd'])
        write_json(output / 'build-manifest.json', provenance)
        (output / 'verification.txt').write_text('Local engineering package; unsigned; productionApproved=false.\nAuthenticate the manifest/checksums through an independent trusted channel.\nA checksum verifies equality, not producer identity.\nRun: sha256sum -c SHA256SUMS\nRun: dpkg-deb --info *.deb; dpkg-deb --contents *.deb\nTarget: Ubuntu 26.04 amd64; customer-provisioned Docker; no Go on target.\n')
        (output / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(output.iterdir()) if p.name != 'SHA256SUMS'))
    print(output)


if __name__ == '__main__':
    build()
