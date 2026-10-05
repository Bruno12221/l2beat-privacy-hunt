#!/usr/bin/env python3
"""Repo-local offline outgoing-ZEC quote audit. No network or credentials.

Only source snapshots in challenge7-*/{pages,cache,responses,http-responses}
are inspected. No parent/home traversal, symlink traversal, or derived report
search. Target self-matches are never reported as new leads.
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
from check_challenge7_quote_receiver_reuse import target_evidence, decode_batch, matching_types, time_class
from check_challenge7_refund_receiver import DEPOSIT, TARGET_TX, STATUS_URL, quote_refund
from trace_challenge7_free_near import digest

ZEC_ASSETS = {'nep141:zec.omft.near', 'nep141:nzec.bridge.near'}
ADDRESS_FIELDS = ('refundTo', 'refundAddress', 'recipient', 'depositAddress',
                  'virtualChainRecipient', 'virtualChainRefundRecipient')
SOURCE_CATEGORIES = {'http-responses', 'responses', 'pages', 'cache'}


def source_paths(repo):
    # One explicit repo root; rg lists local filenames, never their parents.
    process = subprocess.run(['rg','--files','--hidden','--no-ignore','-g','*.json',
                              '-g','!decoder/target/**','-g','!node_modules/**','.'],
                             cwd=str(repo), capture_output=True, text=True,
                             check=True, timeout=45)
    paths = []
    for name in process.stdout.splitlines():
        relative = Path(name)
        parts = relative.parts
        if (len(parts) < 3 or not parts[0].startswith('challenge7-')
                or parts[1] not in SOURCE_CATEGORIES):
            continue
        # Only NEAR source caches can contain quote metadata; cipherscan raw
        # transaction caches are explicitly outside this quote-field audit.
        if parts[1] == 'cache' and (len(parts) < 4 or not parts[2].startswith('near')):
            continue
        path = repo/relative
        if path.is_symlink() or repo not in path.resolve().parents:
            raise ValueError('source escapes explicit repository: '+name)
        paths.append(relative)
    return sorted(paths)


def payload(value):
    """Validate original response bytes where an evidence envelope has them."""
    if isinstance(value, dict) and 'rawUtf8' in value:
        raw = value['rawUtf8'].encode()
        if hashlib.sha256(raw).hexdigest() != value['responseBytesSha256']:
            raise ValueError('cached original response hash mismatch')
        transport = {'url':value.get('url'),
                     'responseBodySha256':value['responseBytesSha256'],
                     'httpStatus':value.get('httpStatus'),
                     'originalResponseBytesValidated':True,
                     'storedParsedResponsePresent':'response' in value}
        if value.get('httpStatus') is not None and value['httpStatus'] != 200:
            # Preserve failed response coverage without interpreting an error
            # body as quote data. Some legacy caches store only raw bodies.
            return None, transport
        parsed = json.loads(raw)
        if 'response' in value and parsed != value['response']:
            raise ValueError('cached response bytes/parsed payload disagree')
        return parsed, transport
    return value, {'originalResponseBytesValidated':False}


def route_nodes(value, pointer='$'):
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from route_nodes(item, pointer+'/'+str(index))
    elif isinstance(value, dict):
        qr = value.get('quoteResponse')
        if isinstance(qr, dict) and isinstance(qr.get('quoteRequest'), dict):
            request, quote = qr['quoteRequest'], qr.get('quote') or {}
            details = value.get('swapDetails') or {}
            row = {**quote, **request, 'status':value.get('status'),
                   'createdAt':qr.get('timestamp'),
                   'originChainTxHashes':details.get('originChainTxHashes'),
                   'destinationChainTxHashes':details.get('destinationChainTxHashes')}
            yield pointer, row, 'full-status-quote', value
            return  # Never count the nested quoteRequest again.
        if 'originAsset' in value and 'destinationAsset' in value:
            yield pointer, value, 'route-or-request-metadata', None
            return
        for key, item in value.items():
            if isinstance(item, (dict,list)):
                yield from route_nodes(item, pointer+'/'+key.replace('~','~0').replace('/','~1'))


def classify(row):
    if row.get('originAsset') not in ZEC_ASSETS:
        return 'non-zec-origin'
    if row.get('destinationAsset') in ZEC_ASSETS:
        return 'zec-to-zec'
    if not row.get('destinationAsset'):
        return 'zec-origin-unknown-destination'
    return 'zec-to-other-asset'


def route_key(row):
    # For metadata deduplication only, not wallet identity. No amount matching.
    fields = ('originAsset','destinationAsset','depositAddress','depositMemo',
              'recipient','refundTo','refundAddress','createdAt','amountIn','amountOut')
    return hashlib.sha256(json.dumps({k:row.get(k) for k in fields},
                                     sort_keys=True,separators=(',',':')).encode()).hexdigest()


def self_status(row, full_status):
    is_target_deposit = row.get('depositAddress') == DEPOSIT
    origins = row.get('originChainTxHashes') or []
    is_target_tx = any((isinstance(item,dict) and item.get('hash')==TARGET_TX)
                       or item==TARGET_TX for item in origins)
    if full_status is not None and is_target_deposit:
        quote_refund(full_status)  # Require the exact #7 route binding.
        return True
    # Partial/normalized copies of the known route cannot become new leads.
    return is_target_deposit or is_target_tx


def audit(repo, out):
    decoder = repo/'decoder/target/release/unified_receivers'
    target = target_evidence(repo,decoder)
    paths = source_paths(repo)
    inventory, zec_rows, counts, groups = [], [], Counter(), Counter()
    for index, relative in enumerate(paths,1):
        path = repo/relative
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        value, transport = payload(json.loads(raw))
        local = Counter()
        for pointer, row, kind, full_status in route_nodes(value):
            classification = classify(row)
            local[classification] += 1
            if classification == 'non-zec-origin':
                continue
            zec_rows.append({'source':str(relative),'pointer':pointer,'sourceSha256':sha,
                'metadataKind':kind,'classification':classification,
                'isTargetSelf':self_status(row, full_status),'metadata':row,
                'routeFingerprint':route_key(row), **transport})
        counts.update(local)
        parts = relative.parts
        group = '/'.join(parts[:3] if parts[1]=='cache' else parts[:2])
        groups[group] += 1
        inventory.append({'path':str(relative),'sha256':sha,'bytes':len(raw),
                          'routeOccurrencesByClass':dict(local), **transport})
        if index % 2500 == 0:
            print('source files='+str(index)+'/'+str(len(paths)),flush=True)
    addresses = sorted({r['metadata'][field] for r in zec_rows for field in ADDRESS_FIELDS
                        if isinstance(r['metadata'].get(field),str)
                        and r['metadata'][field].lower().startswith('u1')})
    decoded = []
    for offset in range(0,len(addresses),500):
        decoded.extend(decode_batch(addresses[offset:offset+500],decoder))
    by_address = {r['address']:r['decode'] for r in decoded}
    matches, invalid = [], [r for r in decoded if not r['decode']['ok']]
    for row in zec_rows:
        for field in ADDRESS_FIELDS:
            address = row['metadata'].get(field)
            if not isinstance(address,str) or address not in by_address:
                continue
            d = by_address[address]
            kinds = matching_types(d,target['receivers'])
            whole = d.get('ok') is True and d.get('network')=='Main' and (
                d['canonicalAddress']==target['decodedAddress']['canonicalAddress'])
            if kinds or whole:
                matches.append({**row,'field':field,'address':address,'receiverTypesMatched':kinds,
                    'canonicalUnifiedAddressMatch':whole,
                    'timing':time_class(row['metadata'].get('createdAt'),target['quoteTimestamp']),
                    'evidenceClass':'API-quote-metadata-only','ownershipProven':False,
                    'targetPrivateSpendLink':False})
    new_matches = [r for r in matches if not r['isTargetSelf']]
    crossing = [r for r in zec_rows if r['classification']=='zec-to-other-asset']
    distinct_cross = {r['routeFingerprint'] for r in crossing if not r['isTargetSelf']}
    full_statuses = [r for r in zec_rows if r['metadataKind']=='full-status-quote']
    analysis = {'completedAt':datetime.now(timezone.utc).isoformat(),'cacheAuditComplete':True,
        'historicalOutgoingCoverageComplete':False,'newHttpCalls':0,'challengeSolved':False,
        'targetPrivateSpendLink':False,'target':target,'sourceFilesAudited':len(paths),
        'sourceGroups':dict(groups),'routeOccurrencesByClass':dict(counts),
        'sourceHttpStatusCounts':dict(Counter(str(r.get('httpStatus','not-stored')) for r in inventory)),
        'failedQuoteStatusResponseFiles':[r['path'] for r in inventory if
            str(r.get('url','')).startswith('https://1click.chaindefuser.com/v0/status?')
            and r.get('httpStatus') not in (None,200)],
        'zecOriginMetadataOccurrences':len(zec_rows),'fullZecOriginStatusQuoteOccurrences':len(full_statuses),
        'nonTargetFullZecOriginStatusQuotes':sum(not r['isTargetSelf'] for r in full_statuses),
        'crossAssetZecOriginOccurrences':len(crossing),
        'distinctNonTargetCrossAssetRouteFingerprints':len(distinct_cross),
        'uniqueUnifiedStrings':len(decoded),
        'validMainnetUnifiedStrings':sum(r['decode']['ok'] and r['decode'].get('network')=='Main' for r in decoded),
        'invalidUnifiedStrings':len(invalid),'allMatchOccurrencesIncludingSelf':len(matches),
        'targetSelfMatchOccurrences':sum(r['isTargetSelf'] for r in matches),
        'nonTargetReceiverMatchOccurrences':len(new_matches),
        'warning':'This is a cache inventory and exact receiver comparison, not a full outgoing-ZEC scan. '
                  'Repeated source/page copies are not independent swaps. Same-asset ZEC routes are '
                  'separate from ZEC-to-other-asset routes. The target quote matching itself is no new evidence.'}
    write_rows(out/'source-inventory.jsonl',inventory)
    write_rows(out/'zec-origin-metadata.jsonl',zec_rows)
    write_rows(out/'decoded-addresses.jsonl',decoded)
    write_rows(out/'invalid-addresses.jsonl',invalid)
    write_rows(out/'all-matches-including-self.jsonl',matches)
    write_rows(out/'new-matches.jsonl',new_matches)
    dump(out/'analysis.json',analysis)
    # Confirm the enumerated input set and every source are still the same.
    if source_paths(repo)!=paths or any(digest(repo/r['path'])!=r['sha256'] for r in inventory):
        raise ValueError('source snapshots changed during offline audit')
    names = ('source-inventory.jsonl','zec-origin-metadata.jsonl','decoded-addresses.jsonl',
             'invalid-addresses.jsonl','all-matches-including-self.jsonl','new-matches.jsonl','analysis.json')
    dump(out/'manifest.json',{'cacheAuditComplete':True,'historicalOutgoingCoverageComplete':False,
        'stopped':None,'newHttpCalls':0,'challengeSolved':False,'scriptSha256':digest(Path(__file__)),
        'targetEvidence':target,'artifactHashes':{name:digest(out/name) for name in names}})
    print(json.dumps({k:analysis[k] for k in ('sourceFilesAudited','routeOccurrencesByClass',
        'fullZecOriginStatusQuoteOccurrences','nonTargetFullZecOriginStatusQuotes',
        'distinctNonTargetCrossAssetRouteFingerprints','uniqueUnifiedStrings','invalidUnifiedStrings',
        'targetSelfMatchOccurrences','nonTargetReceiverMatchOccurrences')},indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,default=Path('challenge7-outgoing-quote-data'))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    out = (repo/args.output_dir).resolve()
    if repo not in out.parents or out==repo:
        raise ValueError('output must remain strictly inside repository')
    # Source directory names must not collide with these audit artifacts.
    if out.name!='challenge7-outgoing-quote-data':
        raise ValueError('use the dedicated outgoing-quote audit output directory')
    dump(out/'manifest.json',{'cacheAuditComplete':False,'stopped':'run in progress','newHttpCalls':0})
    try:
        audit(repo,out)
    except Exception as exc:
        dump(out/'manifest.json',{'cacheAuditComplete':False,'historicalOutgoingCoverageComplete':False,
                                 'stopped':str(exc),'newHttpCalls':0,'challengeSolved':False})
        raise


if __name__=='__main__': main()
