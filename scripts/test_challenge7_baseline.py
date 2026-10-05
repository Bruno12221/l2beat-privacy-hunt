#!/usr/bin/env python3
"""Offline regression tests; uses no repository data or network."""
import itertools
import argparse
import tempfile
from pathlib import Path
from unittest.mock import patch
import random
import json,hashlib
import unittest
from analyze_challenge7_baseline import (ACTIVATION, ANCHOR, balance_record, common_values,
    eligibility, normalized_address, pair_count, pair_indices, payout_txids, reported_value,
    route_link, route_class, main, zcash_txid, packet_metadata, verified_pending_packets)


class BaselineTests(unittest.TestCase):
    def test_all_destination_hashes_and_case(self):
        h = "aB" * 32
        self.assertEqual(payout_txids({"destinationChainTxHashes": ["AbCNEAR", h, "0x" + h]}), [h.lower()])
        self.assertIsNone(zcash_txid("AbCNEAR"))
        self.assertEqual(normalized_address("AbCNEAR"), "AbCNEAR")
        self.assertEqual(normalized_address("0x" + "AB" * 20), "0x" + "ab" * 20)

    def test_exact_decimal_amounts(self):
        self.assertEqual(reported_value({"amountOutFormatted": "0.03954182"}), 3954182)
        self.assertIsNone(reported_value({"amountOutFormatted": "0.000000001"}))
        self.assertEqual(reported_value({"amountOut": "0"}), 0)

    def test_missing_fields_are_not_shared(self):
        self.assertEqual(common_values([], ["sender"]), [])
        self.assertEqual(common_values(["same"], ["same"]), ["same"])

    def test_internal_routes_never_become_payouts(self):
        self.assertEqual(route_class({"recipientType": "INTENTS", "amountOut": "4000000"}), "internal-intents")
        self.assertEqual(route_class({"recipientType": "INTENTS", "destinationChainTxHashes": ["ab" * 32]}), "internal-intents")
        self.assertEqual(route_class({"recipientType": "DESTINATION_CHAIN"}), "unresolved-destination")

    def test_nonwallet_refunds_are_not_clustered(self):
        for address in ["0x" + "0" * 40, "0x" + "0" * 39 + "1", "1nc1nerator11111111111111111111111111111111"]:
            self.assertIsNone(route_link({"refundTo": address})["refundAddress"])

    def test_height_not_quote_date_controls_pool(self):
        summary = {"zcashPayoutTxid": "ab" * 32, "actualIronwoodValueCreatedZat": 10,
                   "zcashBlockHeight": ACTIVATION + 5, "blockTime": "2026-08-09T16:45:04Z"}
        links = [route_link({"createdAt": "2026-07-03T00:00:00Z", "recipientType": "DESTINATION_CHAIN"})]
        row = balance_record(summary, links, {"isCanonical": True})
        self.assertEqual(row["anchorEligibility"], "height-compatible")
        self.assertIn("NOT-a-decoded-note", row["valueConfidence"])

    def test_unverified_and_ineligible_heights(self):
        self.assertEqual(eligibility(None, True), "height-unverified")
        self.assertEqual(eligibility(ANCHOR + 1, True), "after-anchor")
        self.assertEqual(eligibility(ANCHOR, False), "noncanonical")
        self.assertEqual(eligibility(ANCHOR, None), "canonical-unverified")
        self.assertEqual(eligibility(ANCHOR, True, "2026-10-01T00:00:00Z"), "time-height-conflict")

    def test_pairs_retain_more_than_four_ties(self):
        rows = [{"id": str(i), "valueZat": 5} for i in range(12)]
        self.assertEqual(len(list(pair_indices(rows, 10, 0))), 66)
        self.assertEqual(pair_count(rows, 10, 0), 66)

    def test_explicit_metadata_does_not_silently_inherit_conflicting_summary(self):
        packet={"canonicalMetadataSource":{"path":"source"},"canonicalBlockHash":"block","isCanonical":True,
                "blockHeight":ACTIVATION+1,"blockTime":"2026-08-01T00:00:00Z"}
        self.assertEqual(packet_metadata(packet,{}, {},"tx"),(ACTIVATION+1,packet["blockTime"],True))
        for summary,canonical in (({"zcashBlockHeight":ACTIVATION+2},{}),
                                  ({"blockTime":"2026-08-02T00:00:00Z"},{}),({}, {"tx":False})):
            with self.assertRaises(ValueError):packet_metadata(packet,summary,canonical,"tx")

    def test_complete_pending_enrichment_replays_originals_and_rejects_tampering(self):
        from enrich_challenge7_pending_notes import API,enrich
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw_dir=root/'raw';out=root/'enriched';raw_dir.mkdir();out.mkdir()
            def put(path,value,rows=False):
                path.write_text((''.join(json.dumps(x)+'\n' for x in value) if rows else json.dumps(value)))
                return hashlib.sha256(path.read_bytes()).hexdigest()
            h='ab'*32;raw={"ok":True,"txid":h,"bundles":[{"pool":"ironwood"}],"outputs":[]}
            raw_hash=put(raw_dir/'decoded-transactions.jsonl',[raw],True)
            put(raw_dir/'manifest.json',{"scopeComplete":True,"decodedSha256":raw_hash})
            put(raw_dir/'offline-audit.json',{"ledgerSha256":raw_hash,"allScopedTransactionsDecoded":True,"offlineFullDecodedReplayMatches":True})
            detail={"txid":h,"isCanonical":True,"blockHash":"block","hasIronwood":True,"blockHeight":ANCHOR,"blockTime":1789812000}
            original=json.dumps(detail);source_path=out/'original.json'
            source_hash=put(source_path,{"url":API+h,"rawUtf8":original,"httpStatus":200,
                                       "responseBytesSha256":hashlib.sha256(original.encode()).hexdigest()})
            source={"path":str(source_path),"sha256":source_hash,"url":API+h}
            row,status=enrich(raw,detail,source);path=out/'eligible-decoded-transactions.jsonl'
            eligible_hash=put(path,[row],True)
            results_hash=put(out/'metadata-results.jsonl',[{"txid":h,"state":"metadata","detail":detail,"source":source}],True)
            completed={"rawLedgerSha256":raw_hash,"unresolvedTransactions":0,"anchor":ANCHOR,"eligibleLedgerSha256":eligible_hash,
                       "metadataResultsSha256":results_hash,"selectedIronwoodTransactions":1,"metadataTransactions":1,
                       "heightEligibleTransactions":1,"statusCounts":{status:1}}
            put(out/'manifest.json',completed)
            rows,audit=verified_pending_packets(path,raw_dir,{})
            self.assertEqual(rows,[row]);self.assertTrue(audit['eligibleLedgerReplayMatches']);self.assertEqual(audit['newHttpCalls'],0)
            put(out/'manifest.json',{**completed,"unresolvedTransactions":1})
            with self.assertRaises(ValueError):verified_pending_packets(path,raw_dir,{})
            put(out/'manifest.json',completed);source_path.write_text('{}')
            with self.assertRaises(ValueError):verified_pending_packets(path,raw_dir,{})

    def test_pair_enumeration_matches_bruteforce(self):
        rng = random.Random(7)
        for unused in range(80):
            rows = [{"id": str(i), "valueZat": rng.randrange(1, 30)} for i in range(18)]
            target, gap = rng.randrange(1, 60), rng.randrange(0, 15)
            expected = {tuple(sorted((x["id"], y["id"]))) for x, y in itertools.combinations(rows, 2)
                        if target <= x["valueZat"] + y["valueZat"] <= target + gap}
            actual = {tuple(sorted((x["id"], y["id"]))) for x, y in pair_indices(rows, target, gap)}
            self.assertEqual(actual, expected)
            self.assertEqual(pair_count(rows, target, gap), len(expected))
            self.assertEqual(pair_count(rows, target), sum(x["valueZat"] + y["valueZat"] >= target for x, y in itertools.combinations(rows, 2)))

    def test_end_to_end_multiple_outputs_and_route_links(self):
        txid = "ab" * 32
        routes = [
            {"recipientType": "INTENTS", "amountOut": "4000000"},
            {"recipientType": "DESTINATION_CHAIN", "createdAt": "2026-07-01T00:00:00Z",
             "destinationChainTxHashes": ["AbCNEAR", txid], "recipient": "ua-a"},
            {"recipientType": "DESTINATION_CHAIN", "destinationChainTxHashes": [txid], "recipient": "ua-b"},
        ]
        summary = {"zcashPayoutTxid": txid, "actualIronwoodValueCreatedZat": 3960000,
                   "zcashBlockHeight": ACTIVATION + 9, "blockTime": "2026-08-01T00:00:00Z"}
        packet = {"ok": True, "txid": txid,"pendingRequestProvenance":{"txid":txid,"requestedReceiver":"ua-a",
                  "evidenceClass":"successful-descendant-pending-ID-not-settlement-by-itself"}, "outputs": [
            {"pool": "ironwood", "recovered": True, "actionIndex": 0, "cmx": "01" * 32, "receiverRaw": "11" * 43, "valueZat": 2000000,
             "matchingUnifiedAddresses": ["ua-a"]},
            {"pool": "ironwood", "recovered": True, "actionIndex": 1, "cmx": "02" * 32, "receiverRaw": "22" * 43, "valueZat": 1960000},
        ]}
        migrations = [{"height": ACTIVATION + 3, "orchardValueLeavingZat": 1000, "ironwoodValueEnteringZat": 500},
                      {"height": ACTIVATION + 3, "orchardValueLeavingZat": 0, "ironwoodValueEnteringZat": 500}]
        captured = {}
        def record(path, value):
            captured[Path(path).name] = list(value) if not isinstance(value, dict) else value
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(routes=Path('routes'), summaries=Path('summaries'),
                summary_cache=Path('cache'), migrations=Path('migrations'), decoded=[Path('decoded')],
                output_dir=Path(tmp), pair_max_change_zat=100000)
            def fixture(path, manifest):
                return {'routes': routes, 'summaries': [summary], 'migrations': migrations, 'decoded': [packet]}[str(path)]
            with patch('analyze_challenge7_baseline.argparse.ArgumentParser.parse_args', return_value=args), \
                 patch('analyze_challenge7_baseline.load', side_effect=fixture), \
                 patch('analyze_challenge7_baseline.cache_detail', return_value={'isCanonical': True}), \
                 patch('analyze_challenge7_baseline.dump', side_effect=record), \
                 patch('analyze_challenge7_baseline.write_rows', side_effect=record), \
                 patch('analyze_challenge7_baseline.atomic_write'):
                main()
        self.assertEqual(len(captured['public-balances.jsonl']), 1)
        self.assertEqual(len(captured['public-balances.jsonl'][0]['routes']), 2)
        self.assertEqual(len(captured['decoded-notes.jsonl']), 2)
        self.assertEqual(len(captured['decoded-notes.jsonl'][0]['routes']), 1)
        self.assertEqual(len(captured['decoded-notes.jsonl'][1]['routes']), 0)
        self.assertFalse(captured['decoded-notes.jsonl'][1]['routeRecipientMatched'])
        self.assertEqual(captured['decoded-notes.jsonl'][0]['pendingConnectorProvenance'],packet['pendingRequestProvenance'])
        self.assertTrue(captured['decoded-notes.jsonl'][0]['pendingConnectorReceiverMatched'])
        self.assertFalse(captured['decoded-notes.jsonl'][1]['pendingConnectorReceiverMatched'])
        self.assertEqual(captured['manifest.json']['decodedNoteSearch']['pairsWritten'], 1)
        self.assertEqual(captured['manifest.json']['counts']['internalIntentsRoutesExcludedFromNoteUniverse'], 1)
        self.assertEqual(captured['manifest.json']['counts']['migrationBudgetsRetained'], 1)
        self.assertEqual(len(captured['other-mixed-pool-transactions.jsonl']), 1)


if __name__ == "__main__":
    unittest.main()
