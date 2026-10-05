#!/usr/bin/env python3
"""Exact #7 refund-UA receiver comparison against frozen recovered notes.

One public status GET with --fetch; cache-only otherwise. No amount shortlist,
viewing keys, signing, ownership inference or changes to prior evidence files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analyze_challenge7_baseline import dump, write_rows, exit_note_packets
from trace_challenge7_free_near import CheckpointStop, digest
from trace_challenge7_user_origins import Reader
from reconcile_challenge7_account_flows import request_hash

DEPOSIT = 't1PdhpgwaocdDreLYVTMHjTjHFneYJJ5Xh9'
TARGET_TX = '2cfacbf8426140e3e7cc2827d3d410a6dd0749af43d96a1b96a2243e9c56df9c'
DESTINATION = '0x8d5A4fe39f7C4407431E48Bd6Bf727E5a159f98A'
STATUS_URL = 'https://1click.chaindefuser.com/v0/status?depositAddress=' + DEPOSIT
BASELINE_SHA = 'f9c7bc70f4013b8733cdfaac3d32d82a29dea8c7384dbd1d7d3c5a78c8cc7aaa'
RAW_PINS = {
    'challenge7-batch-note-data':'27ec40a9f131b10b75ee7d52e74db7413eb4f09d53140074cd8a148ab0b86bab',
    'challenge7-pending-raw-data':'65220f254d0b17e963e7ec14ea8fffed1b292bb5ad1a12a423bc242d68bb5b3a',
}
OLDER_LEDGER_SHA = '87c5da556410dee0dbf92b8b0ed6e787d5a519e8017f9e1505c1c6f7eb88fff0'


class StatusReader(Reader):
    """Bounded curl fallback for this one public GET, with identical caching."""
    def __init__(self, output, fetch, limit, delay, transport):
        super().__init__(output,fetch,limit,delay)
        self.transport = transport

    def request(self, url, body=None):
        if url != STATUS_URL or body is not None:
            raise ValueError('only the explicit public #7 status GET is allowed')
        path = self.output/'http-responses'/(request_hash(url,None)+'.json')
        if self.transport == 'curl' and not path.exists() and self.fetch:
            if self.calls >= self.limit:
                raise CheckpointStop('per-run HTTP limit reached')
            time.sleep(self.delay);self.calls += 1
            response = subprocess.run(['curl','--silent','--show-error','--max-time','30',
                '--header','accept: application/json','--write-out','\n%{http_code}',url],
                capture_output=True,check=True,timeout=35)
            raw, status = response.stdout.rsplit(b'\n',1)
            if status != b'200':
                raise CheckpointStop('public status GET HTTP '+status.decode()+'; no retry')
            value = json.loads(raw)
            dump(path,{'url':url,'request':None,'httpStatus':200,'transport':'curl',
                      'fetchedAt':datetime.now(timezone.utc).isoformat(),
                      'responseBytesSha256':hashlib.sha256(raw).hexdigest(),
                      'rawUtf8':raw.decode(),'response':value})
        return super().request(url,body)


def quote_refund(value):
    response = value['quoteResponse']; request = response['quoteRequest']
    quote, details = response['quote'], value['swapDetails']
    origins = details.get('originChainTxHashes') or []
    if (value.get('status') != 'SUCCESS' or quote.get('depositAddress') != DEPOSIT
            or request.get('originAsset') != 'nep141:zec.omft.near'
            or request.get('destinationAsset') != 'nep141:eth.omft.near'
            or request.get('depositType') != 'ORIGIN_CHAIN'
            or request.get('recipientType') != 'DESTINATION_CHAIN'
            or str(request.get('recipient')).lower() != DESTINATION.lower()
            or quote.get('amountIn') != '3939182' or details.get('depositedAmount') != '3939182'
            or quote.get('amountOut') != '22712389229785027'
            or details.get('amountOut') != quote['amountOut']
            or len(origins) != 1 or origins[0].get('hash') != TARGET_TX):
        raise ValueError('public status response does not identify the exact #7 exit route')
    refund = request.get('refundTo')
    if request.get('refundType') != 'ORIGIN_CHAIN' or not isinstance(refund, str) or not refund.startswith('u1'):
        raise ValueError('exact quote lacks a mainnet unified origin-chain refund address')
    return refund


def receiver_hex(decoded, address):
    if (decoded.get('ok') is not True or decoded.get('address') != address
            or decoded.get('network') != 'Main'):
        raise ValueError('valid exact mainnet UA decoding required')
    receivers = [r for r in decoded.get('receivers') or [] if r.get('kind') == 'orchard']
    if len(receivers) != 1 or receivers[0].get('bytes') != 43:
        raise ValueError('one 43-byte Orchard-compatible receiver required')
    raw = receivers[0]['rawHex']
    if len(raw) != 86 or len(bytes.fromhex(raw)) != 43:
        raise ValueError('malformed decoded receiver bytes')
    return raw.lower()


def recovered_outputs(packets):
    """Retain all recovered outputs, including zero/post-anchor controls."""
    result = {}
    opaque = Counter()
    for packet in packets:
        if packet.get('ok') is not True:
            raise ValueError('raw decoded ledger contains an unsuccessful record')
        for output in packet.get('outputs') or []:
            if not output.get('recovered'):
                opaque[output['pool']] += 1
                continue
            raw = output['receiverRaw']
            if len(raw) != 86 or len(bytes.fromhex(raw)) != 43:
                raise ValueError('recovered output has malformed receiver')
            identity = f"{packet['txid']}:{output['pool']}:{output['actionIndex']}:{output['cmx']}"
            row = {'id':identity,'txid':packet['txid'],'pool':output['pool'],
                   'actionIndex':output['actionIndex'],'cmx':output['cmx'],
                   'valueZat':output['valueZat'],'receiverRaw':raw.lower(),
                   'blockHeight':packet.get('blockHeight'),'isCanonical':packet.get('isCanonical')}
            if identity in result and result[identity] != row:
                raise ValueError('overlapping recovered-output identity disagrees')
            result[identity] = row
    return result, dict(opaque)


def compare(notes, outputs, raw):
    seen = set(); matches = []
    for note in notes:
        identity = note['id']
        if identity in seen:
            raise ValueError('duplicate baseline note identity')
        seen.add(identity)
        output = outputs.get(identity)
        if (not output or note['receiverBytes'] != [output['receiverRaw']]
                or note['valueZat'] != output['valueZat'] or note['valueZat'] <= 0
                or note['anchorEligibility'] != 'height-compatible'
                or note['txid'] != output['txid'] or note['pool'] != output['pool']
                or note['actionIndex'] != output['actionIndex'] or note['cmx'] != output['cmx']):
            raise ValueError('baseline note differs from exact recovered plaintext evidence')
        if output['receiverRaw'] == raw:
            matches.append(note)
    controls = [{**o,'inEligibleBaseline':o['id'] in seen} for o in outputs.values()
                if o['receiverRaw'] == raw and o['id'] not in seen]
    return matches, controls


def replay_older_ledger(inputs, outputs, raw, decoder):
    """Check all 96 older decoded transactions; replay original raw bytes.

    This is a distinct small historical sample, not the un-decoded Orchard
    payout summaries. Compare plaintext rather than changed metadata units.
    """
    path = Path('challenge7-output-ledger-data/decoded-transactions.jsonl')
    if digest(path) != OLDER_LEDGER_SHA:
        raise ValueError('older decoded sample changed; review scope explicitly')
    inputs[str(path.resolve())] = {'sha256':OLDER_LEDGER_SHA}
    older = list(map(json.loads,path.open()))
    if len(older) != 96:
        raise ValueError('declared older 96-transaction sample changed')
    packets = []
    for row in older:
        source = Path(row['rawCacheFile'])
        raw_response = json.loads(source.read_text())
        text = raw_response['hex']
        if hashlib.sha256(bytes.fromhex(text)).hexdigest() != row['rawHexSha256']:
            raise ValueError('older original raw hex hash mismatch')
        inputs[str(source.resolve())] = {'sha256':digest(source)}
        packets.append({'hex':text,'expectedTxid':row['txid'],'blockHeight':row.get('blockHeight'),
                        'blockTime':row.get('blockTime'),'isCanonical':row.get('isCanonical')})
    result = subprocess.run([str(decoder.resolve())],input=''.join(json.dumps(p)+'\n' for p in packets),
                            text=True,capture_output=True,check=True,timeout=60)
    replay = [json.loads(s) for s in result.stdout.splitlines()]
    if len(replay) != len(older) or any(r.get('ok') is not True for r in replay):
        raise ValueError('older raw replay incomplete or unsuccessful')
    def plaintext(packet):
        return (packet['txid'],[{k:o.get(k) for k in ('pool','actionIndex','cmx','nullifier',
                'recovered','valueZat','receiverRaw','memoHex')} for o in packet['outputs']])
    if [plaintext(p) for p in replay] != [plaintext(p) for p in older]:
        raise ValueError('older recovered plaintext differs from current raw replay')
    decoded, opaque = recovered_outputs(replay)
    for identity in outputs.keys() & decoded.keys():
        if any(outputs[identity][k] != decoded[identity][k] for k in
               ('txid','pool','actionIndex','cmx','receiverRaw','valueZat')):
            raise ValueError('older overlapping note plaintext disagreement')
    return {'transactionsReplayed':len(replay),'recoveredOutputs':len(decoded),
            'recoveredPools':dict(Counter(o['pool'] for o in decoded.values())),
            'alreadyComparedRecoveredOutputs':len(outputs.keys() & decoded.keys()),
            'additionalRecoveredOutputs':len(decoded.keys() - outputs.keys()),
            'exactReceiverMatches':[o for o in decoded.values() if o['receiverRaw'] == raw],
            'opaqueActions':opaque,'noteDecoderSha256':digest(decoder),
            'warning':'The older Orchard payout file contains aggregate summaries, not recovered-note plaintext, and is not treated as decoded evidence.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir',type=Path,default=Path('challenge7-refund-receiver-data'))
    p.add_argument('--decoder',type=Path,default=Path('decoder/target/release/unified_receivers'))
    p.add_argument('--note-decoder',type=Path,default=Path('decoder/target/release/note_ledger'))
    p.add_argument('--fetch',action='store_true')
    p.add_argument('--max-http-calls',type=int,default=1)
    p.add_argument('--delay',type=float,default=3)
    p.add_argument('--transport',choices=['urllib','curl'],default='curl')
    a = p.parse_args()
    protected = [Path(d).resolve() for d in RAW_PINS] + [Path('challenge7-decoded-baseline-v4-data').resolve(),
                    Path('challenge7-account-exit-data').resolve()]
    if (not 0 <= a.max_http_calls <= 1 or a.delay < 1 or a.output_dir.resolve() == Path.cwd()
            or any(a.output_dir.resolve() == d or d in a.output_dir.resolve().parents for d in protected)):
        raise ValueError('separate output directory and at most one paced public GET required')
    a.output_dir.mkdir(parents=True,exist_ok=True)
    notes_path = Path('challenge7-decoded-baseline-v4-data/decoded-notes.jsonl')
    if digest(notes_path) != BASELINE_SHA:
        raise ValueError('frozen 12,733-note baseline changed; review scope explicitly')
    notes = list(map(json.loads,notes_path.open()))
    if len(notes) != 12733:
        raise ValueError('declared complete eligible-note cohort changed')
    inputs = {str(notes_path.resolve()):{'sha256':BASELINE_SHA}}
    packets = []
    for directory, expected in RAW_PINS.items():
        path = Path(directory)/'decoded-transactions.jsonl'
        audit_path = Path(directory)/'offline-audit.json'
        audit = json.loads(audit_path.read_text())
        if (digest(path) != expected or audit.get('ledgerSha256') != expected
                or not audit.get('allScopedTransactionsDecoded') or not audit.get('offlineFullDecodedReplayMatches')):
            raise ValueError('frozen full decoded replay/hash audit mismatch')
        inputs[str(path.resolve())] = {'sha256':expected}
        inputs[str(audit_path.resolve())] = {'sha256':digest(audit_path)}
        packets.extend(map(json.loads,path.open()))
    supplemental, _ = exit_note_packets(Path('challenge7-account-exit-data/analysis.json'),inputs)
    packets.extend(supplemental)
    outputs, opaque = recovered_outputs(packets)
    reader = StatusReader(a.output_dir,a.fetch,a.max_http_calls,a.delay,a.transport)
    result = {'challengeSolved':False,'targetPrivateSpendLink':False,'completeComparison':False,
              'stopped':'unexpected failure','inputHashes':inputs}
    matched, controls = [], []
    try:
        value = reader.request(STATUS_URL)
        address = quote_refund(value)
        decoded = json.loads(subprocess.run([str(a.decoder.resolve())],input=json.dumps({'address':address})+'\n',
                             text=True,capture_output=True,check=True,timeout=30).stdout)
        raw = receiver_hex(decoded,address)
        matched, controls = compare(notes,outputs,raw)
        older_audit = replay_older_ledger(inputs,outputs,raw,a.note_decoder)
        result.update(completeComparison=True,stopped=None,refundAddress=address,decodedAddress=decoded,
                      refundReceiverRaw=raw,quoteTimestamp=value['quoteResponse']['timestamp'],
                      referral=value['quoteResponse']['quoteRequest'].get('referral'),
                      eligibleNotesCompared=len(notes),eligibleReceiverMatches=len(matched),
                      allRecoveredOutputsCompared=len(outputs),extraRecoveredMatches=len(controls),
                      olderLedgerAudit=older_audit,
                      unrecoveredActionsNotComparable=opaque,
                      decoderSha256=digest(a.decoder),
                      quoteSignatureIndependentlyVerified=False,
                      exclusionProvenByMismatch=False,
                      warning='Exact receiver comparison only. The API reports a refund address, not an authenticated wallet identity. A different diversified address can belong to the same wallet; opaque/uncollected notes remain outside this check. A match does not identify the target nullifier.')
    except (CheckpointStop,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        result['stopped'] = str(exc)
        print('checkpoint: '+str(exc),flush=True)
    finally:
        write_rows(a.output_dir/'eligible-matches.jsonl',matched)
        write_rows(a.output_dir/'extra-matches.jsonl',controls)
        dump(a.output_dir/'analysis.json',result)
        dump(a.output_dir/'manifest.json',{'challengeSolved':False,'stopped':result['stopped'],
             'scriptSha256':digest(Path(__file__)),'newHttpCalls':reader.calls,'responsesUsed':reader.index,
             'statusResponseBodySha256':None if not reader.index else
                json.loads(Path(reader.index[-1]['path']).read_text())['responseBytesSha256'],
             'inputHashes':inputs,'analysisSha256':digest(a.output_dir/'analysis.json'),
             'eligibleMatchesSha256':digest(a.output_dir/'eligible-matches.jsonl'),
             'extraMatchesSha256':digest(a.output_dir/'extra-matches.jsonl')})
    print(f"{'done' if result['completeComparison'] else 'checkpoint'}: eligible={len(notes)} matches={len(matched)} extraMatches={len(controls)} newHTTP={reader.calls}",flush=True)
    return 0 if result['completeComparison'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
