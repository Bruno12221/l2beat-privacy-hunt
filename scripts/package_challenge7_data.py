#!/usr/bin/env python3
"""Build checked data release assets without changing original evidence or Git.

The fixed selection excludes duplicate live snapshots, obsolete baseline runs,
logs, databases and binaries. No network access or upload is performed here.
Original and published hashes are recorded separately if local paths are removed.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import re
import tarfile
import tempfile
from pathlib import Path

GROUPS = {
    'notes-and-constraints': (
        'challenge7-decoded-baseline-v5-data',
        'challenge7-decoded-baseline-v4-data',
        'challenge7-note-budget-data', 'challenge7-output-ledger-data',
    ),
    'outgoing-swaps': (
        'challenge7-outgoing-nonpending-collection',
        'challenge7-outgoing-nonpending-analysis-v5',
        'challenge7-explorer-positive-control-data',
        'challenge7-receiver-chronology-data',
        'challenge7-final-rescued-roles-data',
        'challenge7-refund-receiver-data', 'challenge7-quote-receiver-data',
        'challenge7-outgoing-quote-data',
    ),
    'zcash-transactions': (
        'challenge7-migration-data', 'challenge7-orchard-trace-data',
        'challenge7-batch-note-data', 'challenge7-pending-raw-data',
        'challenge7-pending-enriched-data',
        'challenge7-missing-tree-raw-data',
        'challenge7-missing-tree-enriched-data',
    ),
    'connector-evidence': (
        'challenge7-withdrawal-ledger-data',
        'challenge7-payout-universe-data', 'challenge7-complete-routes',
        'challenge7-free-trace-data', 'challenge7-free-raw-rescue-data',
        'challenge7-connector-id-audit-v2-data',
        'challenge7-pending-coverage-probe-data',
        'challenge7-missing-tree-rescue-data',
        'challenge7-failed-request-audit-data',
    ),
    'candidate-public-traces': (
        'challenge7-account-link-data', 'challenge7-public-branch-data',
        'challenge7-user-origin-data', 'challenge7-verified-origin-data',
        'challenge7-account-flow-data', 'challenge7-origin-ancestry-data',
        'challenge7-account-exit-data', 'challenge7-legacy-forwarding-data',
        'challenge7-ordinary-wallet-data', 'challenge7-staging-data',
        'challenge7-remaining-branches-v3-data',
        'challenge7-delegated-payout-data',
        'challenge7-new-receiver-pairs-data',
        'challenge7-new-exact-origins-data',
        'challenge7-new-exact-funding-data',
        'challenge7-shared-allocation-data', 'challenge7-solana-origin-data',
        'challenge7-candidate-history-data',
        'challenge7-candidate-affiliation-data',
    ),
}
ALLOWED_SUFFIXES = {'.json', '.jsonl', '.csv'}
JWT = re.compile(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
GH_TOKEN = re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})')
CREDENTIAL_FIELD = re.compile(
    rb'"(?:authorization|x-api-key|api_key|apikey|access_token|refresh_token|jwt|password|private_key|privatekey|secret_key)"\s*:\s*"(?!\s*"|\[redacted)[^"\s][^"]*"', re.I)
CREDENTIAL_QUERY = re.compile(rb'[?&](?:api[_-]?key|access_token|jwt|token)=([^&\s"\\]+)', re.I)
PERSONAL_PATH = re.compile(rb'/(?:Users|home)/[^\s"\\<>]+')


def sanitize_line(line, repo):
    """Fail on credential-like data; remove machine paths only, not chain data."""
    if ((b'eyJ' in line and JWT.search(line)) or
            ((b'gh' in line or b'github_pat_' in line) and GH_TOKEN.search(line)) or
            b'PRIVATE KEY-----' in line or CREDENTIAL_FIELD.search(line) or
            CREDENTIAL_QUERY.search(line)):
        raise ValueError('credential-like material detected (value not printed)')
    # Keep repository-relative evidence names usable in sanitized manifests.
    clean = line.replace(str(repo).encode() + b'/', b'')
    clean = clean.replace(str(repo).encode(), b'.')
    return PERSONAL_PATH.sub(b'<local-path>', clean)


def selected_files(repo, roots):
    included, excluded = [], []
    for root in roots:
        base = repo / root
        if not base.is_dir() or base.is_symlink():
            raise ValueError('missing or symlinked dataset root: ' + root)
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                raise ValueError('dataset symlink rejected: ' + path.relative_to(repo).as_posix())
            if not path.is_file():
                continue
            name = path.relative_to(repo).as_posix()
            if (path.suffix not in ALLOWED_SUFFIXES or
                    any(p in ('previous-runs', '__pycache__', 'target') for p in path.parts)):
                excluded.append(name)
            else:
                included.append(path)
    return included, excluded


def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build_group(repo, out, group, roots):
    files, excluded = selected_files(repo, roots)
    archive = out / ('challenge7-' + group + '.tar.gz')
    inventory = out / ('.' + group + '-inventory.jsonl')
    originals = published = changed = 0
    with archive.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=1) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar, inventory.open('x') as index:
            for number, source in enumerate(files, 1):
                name = source.relative_to(repo).as_posix()
                before_stat = source.stat()
                original_hash, clean_hash = hashlib.sha256(), hashlib.sha256()
                # Spill large files to a task-local temporary file, not memory.
                with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, dir=out) as spool:
                    original_bytes = clean_bytes = 0
                    try:
                        with source.open('rb') as handle:
                            for line in handle:
                                original_hash.update(line)
                                original_bytes += len(line)
                                if b'\0' in line:
                                    raise ValueError('unexpected binary data')
                                line.decode('utf-8')
                                clean = sanitize_line(line, repo)
                                clean_hash.update(clean)
                                clean_bytes += len(clean)
                                spool.write(clean)
                    except (ValueError, UnicodeError) as exc:
                        raise ValueError('unsafe dataset file: ' + name + ': ' + str(exc)) from None
                    after_stat = source.stat()
                    if (before_stat.st_size, before_stat.st_mtime_ns) != (after_stat.st_size, after_stat.st_mtime_ns):
                        raise ValueError('evidence changed during packaging: ' + name)
                    spool.seek(0)
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = clean_bytes, 0o644, 0
                    tar.addfile(info, spool)
                modified = original_hash.hexdigest() != clean_hash.hexdigest()
                changed += int(modified)
                originals += original_bytes
                published += clean_bytes
                index.write(json.dumps({'path': name, 'archive': archive.name,
                    'originalBytes': original_bytes, 'publishedBytes': clean_bytes,
                    'originalSha256': original_hash.hexdigest(),
                    'publishedSha256': clean_hash.hexdigest(),
                    'localPathsSanitized': modified}, sort_keys=True) + '\n')
                if number % 10000 == 0:
                    print(group + ': checked=' + str(number) + '/' + str(len(files)), flush=True)
    if archive.stat().st_size >= 2 * 1024**3:
        raise ValueError('release asset exceeds 2 GiB: ' + archive.name)
    result = {'asset': archive.name, 'sha256': hash_file(archive),
        'archiveBytes': archive.stat().st_size, 'files': len(files),
        'originalBytes': originals, 'publishedBytes': published,
        'localPathSanitizedFiles': changed, 'excludedFiles': excluded,
        'roots': list(roots)}
    print(group + ': complete files=' + str(len(files)) + ' compressedBytes=' + str(result['archiveBytes']), flush=True)
    return result


def verify_archive(path, rows):
    expected = {row['path']: row for row in rows}
    seen = set()
    with tarfile.open(path, mode='r|gz') as tar:
        for member in tar:
            if member.name not in expected or member.name in seen or not member.isfile():
                raise ValueError('unexpected archive member: ' + member.name)
            h, length = hashlib.sha256(), 0
            with tar.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    h.update(chunk)
                    length += len(chunk)
            row = expected[member.name]
            if h.hexdigest() != row['publishedSha256'] or length != row['publishedBytes']:
                raise ValueError('archive content mismatch: ' + member.name)
            seen.add(member.name)
    if seen != set(expected):
        raise ValueError('archive inventory incomplete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='Scan and build all fixed release groups locally')
    parser.add_argument('--verify', type=Path, help='Read back an existing generated bundle; no extraction')
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if args.verify:
        out = args.verify.resolve()
        if not out.is_relative_to(repo / 'publication-build'):
            raise ValueError('verification is limited to repository publication-build')
        with gzip.open(out / 'challenge7-dataset-inventory.jsonl.gz', 'rt') as handle:
            rows = [json.loads(line) for line in handle]
        manifest = json.loads((out / 'challenge7-dataset-manifest.json').read_text())
        for item in manifest['archives']:
            path = out / item['asset']
            if hash_file(path) != item['sha256']:
                raise ValueError('asset checksum mismatch')
            verify_archive(path, [row for row in rows if row['archive'] == item['asset']])
            print('verified ' + item['asset'], flush=True)
        print('done: full archive readback passed', flush=True)
        return
    if not args.build:
        print(json.dumps({k: list(v) for k, v in GROUPS.items()}, indent=2))
        return
    if args.workers < 1 or args.workers > 3:
        raise ValueError('workers must be between 1 and 3')
    parent = repo / 'publication-build'
    if parent.is_symlink():
        raise ValueError('output directory symlink rejected')
    parent.mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='challenge7-data-', dir=parent))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {k: pool.submit(build_group, repo, out, k, v) for k, v in GROUPS.items()}
        groups = [f.result() for f in futures.values()]
    combined = out / 'challenge7-dataset-inventory.jsonl.gz'
    with combined.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=1) as gz:
        for name in GROUPS:
            with (out / ('.' + name + '-inventory.jsonl')).open('rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    gz.write(chunk)
    manifest = {'schemaVersion': 1, 'challengeSolved': False,
        'scope': 'Current Challenge 7 evidence and supporting public traces; not all local runs or all chain activity.',
        'credentialScan': 'Common token/key patterns rejected; not a universal secret-detection guarantee.',
        'sanitization': 'Local machine paths removed in copies only. Original/published hashes distinguished in inventory.',
        'excluded': ['duplicate checkpoint snapshots', 'obsolete baseline v2/v3 and superseded branch runs',
            'logs', 'SQLite database (exported tables included)', 'binary files', 'environment files', 'previous-runs'],
        'archives': groups, 'inventory': {'asset': combined.name, 'bytes': combined.stat().st_size,
            'sha256': hash_file(combined)}}
    (out / 'challenge7-dataset-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    assets = [out / g['asset'] for g in groups] + [combined, out / 'challenge7-dataset-manifest.json']
    (out / 'SHA256SUMS.txt').write_text(''.join(hash_file(p) + '  ' + p.name + '\n' for p in assets))
    print('done: dataset=' + str(out), flush=True)


if __name__ == '__main__':
    main()
