#!/usr/bin/env python3
"""Offline, hash-pinned quote-UA receiver reuse check. Never performs HTTP.

Normalized quote metadata is not recovered plaintext, ownership, or a
note-to-nullifier link. Duplicate caches are not independent corroboration.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from check_challenge7_refund_receiver import STATUS_URL, quote_refund, receiver_hex
from trace_challenge7_free_near import digest

PINS = {
    'challenge7-complete-routes/all_routes.jsonl':
        ('496a0a49f5d59285d62d125d9a84ba77ecc5791079013f976a943699f5da7c01', 103456),
    'challenge7-exact-link-data/all_routes.jsonl':
        ('03107f23d2113a42670ceebccd528fe75bd83bc05ea6b4e6f604992ac98f4dd2', 27585),
    'challenge7-data/all_routes.jsonl':
        ('fceaaab80cc739740dc6f29e2a50527ee8f4fabe8abec042514e79f900852f69', 7500),
    'challenge7-orchard-trace-data/orchard-payouts.jsonl':
        ('651f1fd649160c732d20fc7998eff4671e3bf732ae1a1d50c55ed9472bfa8d37', 7297),
}
SOURCE_MANIFEST_ANALYSIS_SHA = '448076dab2d1f1514b7e3b125489be4414babf0c8d68c7e8c1ccd9d6ac52288e'
STATUS_ENVELOPE_SHA = 'f0d7703b66f61e2db8ec658789beb1fff64c1ca8edee4c24c4ebe61fc6da8822'
STATUS_BODY_SHA = '53cd3a5a813904109c7dff6bf87a9a519b68c6171b6372d28732ffb7f61945e4'
FIELDS = ('recipient', 'refundTo', 'refundAddress', 'depositAddress',
          'virtualChainRecipient', 'virtualChainRefundRecipient')


def pinned_rows(path, sha, expected_count):
    """Hash the very same raw bytes parsed, not a separate earlier file read."""
    hasher = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        for count, raw in enumerate(stream, 1):
            hasher.update(raw)
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError('non-object input row')
            yield count, hashlib.sha256(raw).hexdigest(), row
    if hasher.hexdigest() != sha or count != expected_count:
        raise ValueError('frozen input digest/row count mismatch: ' + str(path))


def typed_receivers(decoded):
    """Match exact receiver bytes *and* receiver type; never prefixes/pkd only."""
    if decoded.get('ok') is not True or decoded.get('network') != 'Main':
        return {}
    result = {}
    for receiver in decoded.get('receivers', []):
        kind = receiver.get('kind')
        if kind not in ('orchard', 'sapling'):
            continue
        expected = {'orchard': 3, 'sapling': 2}[kind]
        raw = receiver['rawHex'].lower()
        if (receiver.get('typecode') != expected or receiver.get('bytes') != 43
                or len(raw) != 86 or len(bytes.fromhex(raw)) != 43 or kind in result):
            raise ValueError('invalid/duplicate typed receiver in decoder result')
        result[kind] = raw
    return result


def matching_types(decoded, target):
    return sorted(kind for kind, raw in typed_receivers(decoded).items()
                  if target.get(kind) == raw)


def decode_batch(addresses, decoder):
    run = subprocess.run([str(decoder.resolve())],
                         input=''.join(json.dumps({'address':a})+'\n' for a in addresses),
                         text=True, capture_output=True, check=True, timeout=60)
    results = [json.loads(s) for s in run.stdout.splitlines()]
    if len(results) != len(addresses):
        raise ValueError('incomplete address decoder output; cannot claim zero matches')
    for address, result in zip(addresses, results):
        if not isinstance(result.get('ok'), bool):
            raise ValueError('invalid address decoder result')
        if result['ok'] and result.get('address') != address:
            raise ValueError('address decoder order/identity mismatch')
        typed_receivers(result)
    # Failed helper packets omit input identity: map strictly by position.
    return [{'address':a, 'decode':r} for a, r in zip(addresses, results)]


def target_evidence(repo, decoder):
    source = repo/'challenge7-refund-receiver-data'
    manifest_path, analysis_path = source/'manifest.json', source/'analysis.json'
    manifest = json.loads(manifest_path.read_text())
    if (digest(analysis_path) != SOURCE_MANIFEST_ANALYSIS_SHA
            or manifest['analysisSha256'] != SOURCE_MANIFEST_ANALYSIS_SHA):
        raise ValueError('refund-check analysis has changed; review scope explicitly')
    analysis = json.loads(analysis_path.read_text())
    if (analysis.get('completeComparison') is not True or analysis.get('stopped') is not None
            or manifest.get('stopped') is not None
            or digest(decoder) != analysis['decoderSha256']):
        raise ValueError('refund check/decoder not the completed pinned source')
    used = manifest['responsesUsed']
    if len(used) != 1 or used[0]['url'] != STATUS_URL or used[0]['sha256'] != STATUS_ENVELOPE_SHA:
        raise ValueError('unexpected target response identity')
    path = Path(used[0]['path'])
    if digest(path) != STATUS_ENVELOPE_SHA:
        raise ValueError('target response envelope hash mismatch')
    envelope = json.loads(path.read_text())
    raw = envelope['rawUtf8'].encode()
    if (envelope['url'] != STATUS_URL or envelope['request'] is not None
            or envelope['httpStatus'] != 200
            or hashlib.sha256(raw).hexdigest() != STATUS_BODY_SHA
            or envelope['responseBytesSha256'] != STATUS_BODY_SHA
            or manifest['statusResponseBodySha256'] != STATUS_BODY_SHA
            or json.loads(raw) != envelope['response']):
        raise ValueError('target original response bytes/identity mismatch')
    address = quote_refund(envelope['response'])
    decoded = decode_batch([address], decoder)[0]['decode']
    if (address != analysis['refundAddress'] or decoded != analysis['decodedAddress']
            or receiver_hex(decoded, address) != analysis['refundReceiverRaw']):
        raise ValueError('target re-decoding differs from completed refund check')
    return {'address':address, 'decodedAddress':decoded,
            'receivers':typed_receivers(decoded), 'quoteTimestamp':analysis['quoteTimestamp'],
            'statusEnvelopeSha256':STATUS_ENVELOPE_SHA, 'statusBodySha256':STATUS_BODY_SHA,
            'priorAnalysisSha256':SOURCE_MANIFEST_ANALYSIS_SHA,
            'priorManifestSha256':digest(manifest_path), 'decoderSha256':digest(decoder)}


def time_class(timestamp, target_timestamp):
    if not timestamp:
        return 'unknown'
    try:
        left = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        right = datetime.fromisoformat(target_timestamp.replace('Z', '+00:00'))
        if left.tzinfo is None:
            return 'unknown'
        return 'before' if left < right else 'after' if left > right else 'same'
    except (ValueError, TypeError, AttributeError):
        return 'unknown'


def scan(repo):
    addresses, sources = set(), []
    for relative, (sha, expected) in PINS.items():
        fields, prefixes, assets, statuses = Counter(), Counter(), Counter(), Counter()
        oldest, newest = None, None
        for line, row_sha, row in pinned_rows(repo/relative, sha, expected):
            assets[str(row.get('destinationAsset', '<not-stored>'))] += 1
            statuses[str(row.get('status', '<not-stored>'))] += 1
            stamp = row.get('createdAt')
            if isinstance(stamp, str):
                oldest = min(oldest, stamp) if oldest else stamp
                newest = max(newest, stamp) if newest else stamp
            for field in FIELDS:
                address = row.get(field)
                if isinstance(address, str):
                    prefixes[field+':'+address[:3].lower()] += 1
                    if address.lower().startswith('u1'):
                        addresses.add(address)
                        fields[field] += 1
        sources.append({'path':relative, 'sha256':sha, 'rows':expected,
                        'unifiedAddressOccurrencesByField':dict(fields),
                        'addressPrefixes':dict(prefixes), 'destinationAssets':dict(assets),
                        'statuses':dict(statuses), 'oldestCreatedAt':oldest, 'newestCreatedAt':newest})
        print('scanned '+relative+' rows='+str(expected), flush=True)
    return sorted(addresses), sources


def matching_occurrences(repo, matches_by_address, target):
    """Second complete pinned pass; keep line/raw-row hash and role provenance."""
    result = []
    for relative, (sha, expected) in PINS.items():
        for line, row_sha, row in pinned_rows(repo/relative, sha, expected):
            for field in FIELDS:
                address = row.get(field)
                if address not in matches_by_address:
                    continue
                result.append({'source':relative, 'line':line, 'rawRowSha256':row_sha,
                    'field':field, 'address':address, **matches_by_address[address],
                    'timing':time_class(row.get('createdAt'), target['quoteTimestamp']),
                    'metadata':row, 'evidenceClass':'normalized-API-address-metadata-only',
                    'ownershipProven':False, 'targetPrivateSpendLink':False})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output-dir', type=Path, default=Path('challenge7-quote-receiver-data'))
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.output_dir if args.output_dir.is_absolute() else repo/args.output_dir
    decoder = repo/'decoder/target/release/unified_receivers'
    # Mark an attempted run incomplete before processing; failures never leave
    # an old success manifest falsely representing this invocation.
    dump(out/'manifest.json', {'completeComparison':False, 'challengeSolved':False,
                             'newHttpCalls':0, 'stopped':'run in progress'})
    try:
        target = target_evidence(repo, decoder)
        addresses, sources = scan(repo)
        decoded = []
        for offset in range(0, len(addresses), 500):
            decoded.extend(decode_batch(addresses[offset:offset+500], decoder))
            if offset % 5000 == 0:
                print('decoded='+str(len(decoded))+'/'+str(len(addresses)), flush=True)
        matches_by_address = {}
        invalid, non_mainnet = [], []
        for row in decoded:
            d = row['decode']
            if not d['ok']:
                invalid.append(row)
                continue
            if d.get('network') != 'Main':
                non_mainnet.append(row)
                continue
            kinds = matching_types(d, target['receivers'])
            whole = d['canonicalAddress'] == target['decodedAddress']['canonicalAddress']
            if kinds or whole:
                matches_by_address[row['address']] = {'receiverTypesMatched':kinds,
                                                     'canonicalUnifiedAddressMatch':whole}
        occurrences = matching_occurrences(repo, matches_by_address, target)
        distinct = {(r['metadata'].get('depositAddress'), r['metadata'].get('depositMemo'),
                     r['field'], r['address']) for r in occurrences}
        analysis = {'completedAt':datetime.now(timezone.utc).isoformat(),
            'completeComparison':True, 'allCandidateAddressesProcessed':True,
            'newHttpCalls':0, 'challengeSolved':False, 'target':target, 'sources':sources,
            'rowsScanned':sum(s['rows'] for s in sources), 'uniqueUnifiedStrings':len(decoded),
            'validMainnetUnifiedAddresses':len(decoded)-len(invalid)-len(non_mainnet),
            'invalidUnifiedStrings':len(invalid), 'nonMainnetDecodedStrings':len(non_mainnet),
            'matchedUniqueUnifiedStrings':len(matches_by_address),
            'matchedMetadataOccurrences':len(occurrences), 'distinctDepositRoleAddressKeys':len(distinct),
            'receiverTypeMatchOccurrences':dict(Counter(k for r in occurrences for k in r['receiverTypesMatched'])),
            'matchedTiming':dict(Counter(r['timing'] for r in occurrences)),
            'excludedWallets':False, 'targetPrivateSpendLink':False,
            'scopeWarning':'Overlapping inbound-ZEC quote caches, not all outgoing quotes or all wallet activity. '
                'Only mainnet unified-address strings in explicitly named fields decoded. '
                'Other address formats and malformed UAs are not receiver-comparable. '
                'Orchard payout summaries are pool aggregates, not recovered notes. '
                'Address metadata reuse is not ownership or target note consumption proof.'}
        write_rows(out/'decoded-addresses.jsonl', decoded)
        write_rows(out/'invalid-addresses.jsonl', invalid)
        write_rows(out/'non-mainnet-addresses.jsonl', non_mainnet)
        write_rows(out/'matches.jsonl', occurrences)
        dump(out/'analysis.json', analysis)
        manifest = {'completeComparison':True, 'stopped':None, 'challengeSolved':False,
            'newHttpCalls':0, 'scriptSha256':digest(Path(__file__)),
            'analysisSha256':digest(out/'analysis.json'),
            'artifactHashes':{name:digest(out/name) for name in
                ('decoded-addresses.jsonl','invalid-addresses.jsonl','non-mainnet-addresses.jsonl','matches.jsonl')},
            'targetEvidence':target, 'inputHashes':{s['path']:s['sha256'] for s in sources}}
        dump(out/'manifest.json', manifest)
        print(json.dumps({k:analysis[k] for k in ('rowsScanned','uniqueUnifiedStrings',
            'validMainnetUnifiedAddresses','invalidUnifiedStrings','matchedUniqueUnifiedStrings',
            'matchedMetadataOccurrences','receiverTypeMatchOccurrences','matchedTiming')}, indent=2))
    except Exception as exc:
        dump(out/'manifest.json', {'completeComparison':False, 'challengeSolved':False,
                                 'newHttpCalls':0, 'stopped':str(exc)})
        raise


if __name__ == '__main__':
    main()
