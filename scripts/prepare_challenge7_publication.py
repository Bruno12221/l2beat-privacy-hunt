#!/usr/bin/env python3
"""Validate/export a curated publication overlay; never stage, commit or push.

Only explicitly listed text files are copied. Caches, credentials, binaries,
logs and working diaries remain local. Tests run on the exported source with
outbound connections disabled, without accessing the private evidence caches.
"""
import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

ALLOWLIST = 'docs/challenge7/PUBLISH-FILES.txt'
SECRET_PATTERNS = (
    r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'gh[pousr]_[A-Za-z0-9]{30,}', r'github_pat_[A-Za-z0-9_]{40,}',
)


def valid_relative(value):
    path = PurePosixPath(value)
    if not value or str(path) != value or path.is_absolute() or any(p in ('..', '.') for p in value.split('/')) or '\\' in value:
        raise ValueError('publication paths must be canonical repository-relative paths')
    if (path.suffix in ('.json', '.jsonl', '.bin', '.log', '.sqlite3', '.pyc') or
            any(p in ('.git', 'target', '__pycache__', 'publication-build') for p in path.parts) or
            any(p.startswith('.env') or p.endswith('-data') for p in path.parts)):
        raise ValueError('raw/generated/credential path cannot enter publication')
    return path


def check_text(value):
    if any(re.search(pattern, value) for pattern in SECRET_PATTERNS):
        raise ValueError('credential-like material detected; value intentionally not printed')
    if re.search(r'/(?:Users|home)/[^/\s]+/', value):
        raise ValueError('machine-specific personal path detected')


def imports(value):
    result = set()
    for node in ast.walk(ast.parse(value)):
        if isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split('.')[0])
        elif isinstance(node, ast.Import):
            result.update(n.name.split('.')[0] for n in node.names)
    return result


def validate(repo):
    manifest = repo / ALLOWLIST
    rows = [line.strip() for line in manifest.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]
    if len(set(rows)) != len(rows) or ALLOWLIST not in rows:
        raise ValueError('duplicate allowlist path or missing allowlist itself')
    tracked = set(subprocess.run(['git', 'ls-files'], cwd=repo, check=True,
                                capture_output=True, text=True).stdout.splitlines())
    all_modules = {p.stem for p in (repo / 'scripts').glob('*.py')}
    available_modules = {PurePosixPath(p).stem for p in set(rows) | tracked
                         if p.startswith('scripts/') and p.endswith('.py')}
    entries, texts = [], {}
    for name in rows:
        relative = valid_relative(name)
        path = repo / relative
        if any((repo.joinpath(*relative.parts[:n])).is_symlink() for n in range(1, len(relative.parts) + 1)):
            raise ValueError('publication source symlink rejected: ' + name)
        if not path.is_file() or repo not in path.resolve().parents:
            raise ValueError('missing or escaped publication source: ' + name)
        raw = path.read_bytes()
        if len(raw) > 1500000 or b'\0' in raw:
            raise ValueError('oversize or binary publication source: ' + name)
        value = raw.decode('utf-8')
        check_text(value)
        if path.suffix == '.py':
            missing = (imports(value) & all_modules) - available_modules
            if missing:
                raise ValueError('missing local import dependencies: ' + name + ': ' + ', '.join(sorted(missing)))
        texts[name] = value
        entries.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    if sum(e['bytes'] for e in entries) > 5000000:
        raise ValueError('publication exceeds curated size bound')
    published = set(rows) | tracked
    for name, value in texts.items():
        if not name.endswith('.md'):
            continue
        for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', value):
            target = target.strip().strip('<>').split('#', 1)[0]
            if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                continue
            dest = (repo / name).parent / target
            try:
                relative = dest.resolve().relative_to(repo).as_posix()
            except ValueError:
                raise ValueError('documentation link leaves repository: ' + name)
            if relative not in published and not any(p.startswith(relative.rstrip('/') + '/') for p in published):
                raise ValueError('documentation links to excluded or missing evidence: ' + name + ': ' + target)
    return entries


def export(repo, entries):
    parent = repo / 'publication-build'
    if parent.is_symlink():
        raise ValueError('export parent symlink rejected')
    parent.mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='challenge7-ready-', dir=parent))
    for item in entries:
        src, dest = repo / item['path'], out / item['path']
        if hashlib.sha256(src.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('publication source changed during export')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    (out / 'PACKAGE-SHA256SUMS.txt').write_text(''.join(e['sha256'] + '  ' + e['path'] + '\n' for e in entries))
    return out


def run_tests(out, entries):
    modules = [PurePosixPath(e['path']).stem for e in entries
               if e['path'].startswith('scripts/test_challenge7_') and e['path'].endswith('.py')]
    code = '''import socket, urllib.request, sys, unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
def deny(*args, **kwargs): raise RuntimeError('outbound network disabled for publication tests')
with patch.object(socket.socket, 'connect', deny), patch.object(socket.socket, 'connect_ex', deny), patch.object(urllib.request, 'urlopen', deny):
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:]))
sys.exit(0 if result.wasSuccessful() else 1)
'''
    import sys
    subprocess.run([sys.executable, '-B', '-c', code, *modules], cwd=out, check=True)
    for item in entries:
        if hashlib.sha256((out / item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('exported publication file changed during test run')
    return len(modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', action='store_true')
    parser.add_argument('--test', action='store_true', help='Export a fresh overlay and test its selected source offline')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    entries = validate(repo)
    result = {'selectedFiles': len(entries), 'bytes': sum(e['bytes'] for e in entries),
              'credentialPatternScan': 'pass (not a universal secret-detection guarantee)',
              'localImportClosure': 'pass', 'localDocumentationLinks': 'pass',
              'gitIndexChanged': False, 'commitCreated': False, 'pushed': False, 'pullRequestCreated': False}
    if args.export or args.test:
        out = export(repo, entries)
        result['exportDirectory'] = str(out)
        if args.test:
            result['testModules'] = run_tests(out, entries)
            result['offlineExportTests'] = 'pass'
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
