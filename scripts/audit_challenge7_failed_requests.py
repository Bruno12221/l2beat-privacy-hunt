#!/usr/bin/env python3
"""Offline classification of the frozen requests lacking a pending payout ID.

A failed connector descendant explains this execution branch, not a wallet's
whole history, a later retry, settlement/refund or a private target spend.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows
from audit_challenge7_connector_ids import full_tree_rpc_result, rpc_pending_ids
from rescue_challenge7_missing_connector_trees import inside
from trace_challenge7_free_near import digest


def classify(result, root, receipt):
    if result.get('transaction', {}).get('hash') != root:
        raise ValueError('execution root does not match request')
    pending, error = rpc_pending_ids(result, receipt)
    if pending or error != 'successful-listed-receipt-without-descendant-pending-ID':
        raise ValueError('request is not the declared no-pending-ID evidence class')
    by_id = {r['id']: r['outcome'] for r in result['receipts_outcome']}
    todo, seen, failures = [receipt], set(), []
    while todo:
        rid = todo.pop()
        if rid in seen:
            continue
        seen.add(rid)
        outcome = by_id[rid]
        todo.extend(outcome.get('receipt_ids') or [])
        if outcome.get('executor_id') != 'zcash-connector.bridge.near':
            continue
        failure = (outcome.get('status') or {}).get('Failure')
        if failure is None:
            continue
        message = (failure.get('ActionError', {}).get('kind', {})
                   .get('FunctionCallError', {}).get('ExecutionError'))
        if message is None:
            reason = 'other-connector-failure'
        elif 'Invalid expiry height:' in message:
            reason = 'invalid-expiry-height'
        elif message.startswith('Smart contract panicked: UTXO ') and message.endswith(' not exist'):
            reason = 'utxo-not-exist'
        elif 'ERR_INVALID_ORCHARD_BUNDLE' in message:
            reason = 'invalid-orchard-bundle'
        elif 'Too many pending sign transactions' in message:
            reason = 'pending-sign-queue-capacity'
        elif 'No receiver found in address' in message:
            reason = 'no-address-receiver'
        elif 'Invalid gas fee' in message:
            reason = 'invalid-gas-fee'
        else:
            reason = 'other-connector-failure'
        failures.append({'receiptId': rid, 'reason': reason,
                         'failure': failure, 'executionError': message})
    return {'classification': 'failed-connector-descendant-no-pending-ID' if failures
            else 'no-pending-ID-without-observed-connector-failure',
            'descendantReceiptsChecked': len(seen), 'connectorFailures': failures,
            'explicitPendingIdentifierObserved': False, 'settlementProven': False,
            'refundProven': False, 'walletExcluded': False, 'targetPrivateSpendLink': False}


def checked_payload(repo, reference, used):
    path = inside(repo, reference['path'])
    if digest(path) != reference['sha256']:
        raise ValueError('execution source hash mismatch')
    used[str(path)] = reference['sha256']
    payload = json.loads(path.read_text())
    if 'rawUtf8' in payload:
        if hashlib.sha256(payload['rawUtf8'].encode()).hexdigest() != payload['responseBytesSha256']:
            raise ValueError('original response body hash mismatch')
        if json.loads(payload['rawUtf8']) != payload['response']:
            raise ValueError('parsed response differs from original bytes')
        return payload['response']
    return payload


def main():
    repo = Path(__file__).resolve().parents[1]
    old = repo / 'challenge7-connector-id-audit-v2-data'
    rescue = repo / 'challenge7-missing-tree-rescue-data'
    out = repo / 'challenge7-failed-request-audit-data'
    used = {}
    old_manifest = json.loads((old / 'manifest.json').read_text())
    rescued_manifest = json.loads((rescue / 'manifest.json').read_text())
    for p in (old / 'manifest.json', rescue / 'manifest.json'):
        used[str(p)] = digest(p)
    original_path = old / 'unresolved-requests.jsonl'
    original = [json.loads(line) for line in original_path.read_text().splitlines()]
    used[str(original_path)] = digest(original_path)
    if len(original) != old_manifest['unresolvedRequests'] or dict(Counter(r['error'] for r in original)) != old_manifest['unresolvedReasons']:
        raise ValueError('original request scope/manifest mismatch')
    if rescued_manifest['frozenInputHashes'][str(original_path)] != used[str(original_path)]:
        raise ValueError('rescued scope differs from frozen original scope')
    rescue_path = rescue / 'unresolved-requests.jsonl'
    used[str(rescue_path)] = digest(rescue_path)
    if used[str(rescue_path)] != rescued_manifest['artifactHashes']['unresolved-requests.jsonl']:
        raise ValueError('rescued unresolved artifact changed')
    selected = [r for r in original if r['error'] != 'RPC-root-cache-missing']
    selected.extend(json.loads(line) for line in rescue_path.read_text().splitlines())
    identities = {(r['nearRoot'], r['listedReceiptId']) for r in selected}
    if len(identities) != len(selected):
        raise ValueError('duplicate request identity')
    original_identities = {(r['nearRoot'], r['listedReceiptId']) for r in original}
    if not identities <= original_identities:
        raise ValueError('request was not in original unresolved inventory')
    results = []
    for request in selected:
        if 'source' in request:
            reference = request['source']
            value = checked_payload(repo, reference, used)
            matching = [entry for entry in value['transactions']
                        if entry['transaction']['hash'] == request['nearRoot']]
            if len(matching) != 1:
                raise ValueError('missing/duplicate exact full-tree root')
            result = full_tree_rpc_result(matching[0])
        else:
            reference = {'path': request['sourceCacheFile'], 'sha256': request['sourceCacheSha256']}
            value = checked_payload(repo, reference, used)
            if request['sourceKind'] == 'cached-near-rpc':
                result = value.get('result') or value
            else:
                matching = [entry for entry in value['transactions']
                            if entry['transaction']['hash'] == request['nearRoot']]
                if len(matching) != 1:
                    raise ValueError('missing/duplicate exact cached full-tree root')
                result = full_tree_rpc_result(matching[0])
        results.append({'nearRoot': request['nearRoot'], 'listedReceiptId': request['listedReceiptId'],
                        'source': reference, **classify(result, request['nearRoot'], request['listedReceiptId'])})
    analysis = {'declaredRequests': len(selected), 'requestsChecked': len(results),
                'classifications': dict(Counter(r['classification'] for r in results)),
                'failureReasons': dict(Counter(f['reason'] for r in results for f in r['connectorFailures'])),
                'newHttpCalls': 0, 'challengeSolved': False, 'targetPrivateSpendLink': False,
                'warning': 'Failed descendants in the selected complete execution graphs, not '
                           'proof of refunds, no later retries, wallet exclusion, whole-chain completeness or target attribution.'}
    for path, sha in used.items():
        if digest(inside(repo, path)) != sha:
            raise ValueError('source changed during offline audit')
    out.mkdir(exist_ok=True)
    write_rows(out / 'requests.jsonl', results)
    dump(out / 'analysis.json', analysis)
    dump(out / 'manifest.json', {'declaredRequestAuditComplete': len(results) == len(selected),
                                'newHttpCalls': 0, 'challengeSolved': False,
                                'scriptSha256': digest(Path(__file__)), 'frozenInputHashes': used,
                                'artifactHashes': {n: digest(out / n) for n in ('requests.jsonl', 'analysis.json')}})
    print(json.dumps(analysis, indent=2))


if __name__ == '__main__':
    main()
