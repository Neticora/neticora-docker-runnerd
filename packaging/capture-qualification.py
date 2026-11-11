#!/usr/bin/env python3
"""Bind a lab build to unchanged source inputs; never claim release approval."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def source():
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split(b'\0')
    hashes = {}
    for raw in names:
        if not raw:
            continue
        file = Path(os.fsdecode(raw))
        if file.parts[0] in ['cmd', 'internal', 'agent', 'api', 'journal', 'transport', 'identity'] or str(file) in ['go.mod', 'go.sum', 'packaging/build-qualification.sh', 'packaging/capture-qualification.py']:
            if file.is_symlink():
                raise SystemExit('Symlink source input refused')
            if file.is_file() and not file.is_symlink():
                hashes[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()
    return {'sourceCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'])),
            'goVersion': subprocess.check_output(['go', 'version'], text=True).strip(),
            'sourceFiles': dict(sorted(hashes.items()))}


output = Path(sys.argv[2])
for directory in [output, *output.parents]:
    info = directory.lstat()
    if not directory.is_dir() or directory.is_symlink() or info.st_uid not in [0, os.getuid()] or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & 0o1000)):
        raise SystemExit('Protected build ancestors required')
if sys.argv[1] == 'before':
    value = source()
    destination = output / 'source-inputs.json'
elif sys.argv[1] == 'after':
    value = json.loads((output / 'source-inputs.json').read_text())
    if value != source():
        raise SystemExit('Source changed during build; retain candidate for diagnosis and rebuild from stable inputs')
    value.update({'version': 'runnerd09-build-provenance-v1', 'buildTag': 'runnerd_qualification',
                  'productionQualified': False,
                  'binaries': {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                               for name in ['runnerd-qualification', 'runnerd-config']}})
    destination = output / 'provenance.json'
else:
    raise SystemExit('before or after required')
with destination.open('x') as stream:
    json.dump(value, stream, sort_keys=True, indent=2)
    stream.write('\n')
    stream.flush()
    os.fsync(stream.fileno())
for directory in [output, output.parent]:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
