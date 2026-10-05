#!/usr/bin/env python3
"""Offline role/chronology audit of V5's 47 newly recovered actual notes.

Requires a completed V5 outgoing comparison, not a terminal collector run.
Quote-linked output/refund metadata is not private consumption or ownership.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from analyze_challenge7_baseline import ANCHOR, dump, write_rows
from analyze_challenge7_outgoing_collection import BASELINE_V5_SHA, KEEP, note_baseline, page_source
from audit_challenge7_receiver_chronology import classify, local, pinned_rows
from check_challenge7_quote_receiver_reuse import typed_receivers
from trace_challenge7_free_near import digest


def bind_match(row, match, receivers):
    canonical = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if (canonical != match['rowCanonicalSha256'] or
            {k: row.get(k) for k in KEEP} != match['metadata'] or
            row.get(match['field']) != match['address'] or
            receivers.get(match['receiverKind']) != match['receiverRaw']):
        raise ValueError('match does not bind original quote and exact typed receiver')


def main(args):
    repo = Path(__file__).resolve().parents[1]
    source = local(repo, args.analysis_dir.resolve())
    out = local(repo, args.output_dir.resolve() if args.output_dir else source.parent / 'rescued-quote-roles')
    if out == source or source in out.parents:
        raise ValueError('role audit output must be separate from comparison inputs')
    baseline = note_baseline(repo, True)
    baseline_manifest = json.loads((baseline.parent / 'manifest.json').read_text())
    manifest = json.loads((source / 'manifest.json').read_text())
    if not manifest.get('offlineAuditComplete') or manifest['baselineSha256'] != BASELINE_V5_SHA:
        raise ValueError('completed V5 comparison required')
    used = {str(source / 'manifest.json'): digest(source / 'manifest.json'),
            str(baseline): BASELINE_V5_SHA,
            str(baseline.parent / 'manifest.json'): digest(baseline.parent / 'manifest.json')}
    new_path = baseline.parent / 'new-decoded-notes.jsonl'
    new_rows = pinned_rows(new_path, baseline_manifest['artifactHashes'][new_path.name])
    notes = {row['id']: row for row in new_rows}
    if len(notes) != len(new_rows):
        raise ValueError('duplicate actual-note identity')
    used[str(new_path)] = digest(new_path)
    loaded = {}
    for name in ('analysis.json', 'decoded-addresses.jsonl', 'note-receiver-matches.jsonl'):
        path = source / name
        loaded[name] = (json.loads(path.read_text()) if name == 'analysis.json'
                        else pinned_rows(path, manifest['artifactHashes'][name]))
        if digest(path) != manifest['artifactHashes'][name]:
            raise ValueError('comparison artifact hash changed')
        used[str(path)] = manifest['artifactHashes'][name]
    analysis = loaded['analysis.json']
    addresses = {r['address']: typed_receivers(r['decode']) for r in loaded['decoded-addresses.jsonl']}
    pages, edges = {}, []
    for match in loaded['note-receiver-matches.jsonl']:
        ids = set(match['matchedBaselineNoteIds']) & set(notes)
        if not ids:
            continue
        path = local(repo, match['source'])
        if str(path) not in pages:
            if digest(path) != match['sourceSha256']:
                raise ValueError('original quote page hash mismatch')
            pages[str(path)] = page_source(path, analysis['scope']['statuses'])[0]
            used[str(path)] = match['sourceSha256']
        row = pages[str(path)][match['rowIndex']]
        bind_match(row, match, addresses[match['address']])
        for ident in sorted(ids):
            note = notes[ident]
            if (note['pool'] != 'ironwood' or note['blockHeight'] > ANCHOR or
                    note['valueZat'] <= 0 or match['receiverKind'] != 'orchard' or
                    match['receiverRaw'] not in note['receiverBytes']):
                raise ValueError('actual note/anchor/receiver mismatch')
            edges.append(classify(note, match))
    result = {'supplementNotes': len(notes), 'quoteLinkedNotes': len({e['noteId'] for e in edges}),
              'noteQuoteEdges': len(edges),
              'edgeClasses': dict(Counter('|'.join((e['field'], e['quoteStatus'], e['hashListRelation'], e['chronologyClass'])) for e in edges)),
              'createdBeforeQuoteEdges': sum(e['createdBeforeQuote'] for e in edges),
              'targetSelfEdges': sum(e['isTargetSelf'] for e in edges),
              'outgoingSourcePages': analysis['sourcePages'], 'outgoingRows': analysis['rowOccurrences'],
              'newHttpCalls': 0, 'independentStatusControlsFetched': 0,
              'challengeSolved': False, 'targetPrivateSpendLink': False,
              'warning': 'Post-quote refund-receiver/hash-list links are recorded roles, '
                         'not independently verified refunds or spends. No wallet exclusion or whole-chain completeness.'}
    for path, sha in used.items():
        if digest(local(repo, path)) != sha:
            raise ValueError('input changed during offline role audit')
    out.mkdir(exist_ok=True)
    write_rows(out / 'edges.jsonl', edges)
    dump(out / 'analysis.json', result)
    dump(out / 'manifest.json', {'offlineRoleAuditComplete': True, 'newHttpCalls': 0,
                                'scriptSha256': digest(Path(__file__)), 'frozenInputHashes': used,
                                'artifactHashes': {n: digest(out / n) for n in ('analysis.json', 'edges.jsonl')}})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis-dir', required=True, type=Path)
    parser.add_argument('--output-dir', type=Path)
    main(parser.parse_args())
