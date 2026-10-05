import base64
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from trace_challenge7_free_near import decode_args, make_queue, nested, normalize, ns_iso, withdrawal_records, normalize_connector_request, fetch_batch, CheckpointStop


def call(method, args):
    return {"FunctionCall": {"method_name": method, "args": base64.b64encode(json.dumps(args).encode()).decode(), "deposit": "1"}}


def fixture(children=None):
    return {"transaction": {"hash": "Base58CaseSensitive", "signer_id": "relayer.near", "receiver_id": "intents.near",
                            "actions": [call("execute_intents", {"signed": "{\"withdraw\":{\"amount\":\"9007199254740993\"}}"})]},
            "execution_outcome": {"block_height": 100, "block_timestamp": 1788325884380267606,
                                  "outcome": {"receipt_ids": ["ReceiptA"], "status": {"SuccessReceiptId": "ReceiptA"}}},
            "receipts": [{"receipt": {"receipt_id": "ReceiptA", "predecessor_id": "intents.near", "receiver_id": "zec.omft.near",
                                      "receipt": {"Action": {"actions": [call("ft_transfer_call", {"msg": "{\"Withdraw\":{\"receiver\":\"u1example\"}}"})]}}},
                          "execution_outcome": {"block_height": 101, "block_timestamp": 1788325884756984232,
                                                "outcome": {"logs": ["EVENT_JSON:{\"event\":\"ft_transfer\"}"],
                                                            "receipt_ids": children or [], "status": {"Failure": {"error": "test"}}}}}]}


class FreeNearTests(unittest.TestCase):
    def test_nested_and_integer_precision(self):
        row = normalize(fixture())
        self.assertEqual(row["calls"][0]["args"]["signed"]["withdraw"]["amount"], "9007199254740993")
        self.assertEqual(row["calls"][1]["args"]["msg"]["Withdraw"]["receiver"], "u1example")
        self.assertEqual(row["logs"][0]["decoded"]["event"], "ft_transfer")

    def test_all_actions_and_failed_receipts_preserved(self):
        x = fixture()
        x["receipts"][0]["receipt"]["receipt"]["Action"]["actions"].append(call("second_method", {}))
        row = normalize(x)
        self.assertEqual(len(row["calls"]), 3)
        self.assertEqual(row["calls"][1]["executionStatus"], "Failure")
        self.assertTrue(row["treeReferencesComplete"])
        self.assertEqual(row["nearTransactionHash"], "Base58CaseSensitive")

    def test_create_account_unit_action_preserves_call_indexes(self):
        x = fixture()
        x["transaction"]["actions"].insert(0, "CreateAccount")
        actions = x["receipts"][0]["receipt"]["receipt"]["Action"]["actions"]
        actions.insert(0, "CreateAccount")
        actions.insert(1, {"Transfer": {"deposit": "1"}})
        row = normalize(x)
        self.assertEqual(len(row["calls"]), 2)
        self.assertEqual([c["actionIndex"] for c in row["calls"]], [1, 2])
        self.assertEqual(row["calls"][1]["method"], "ft_transfer_call")
        self.assertEqual(row["calls"][1]["executionStatus"], "Failure")
        self.assertTrue(row["treeReferencesComplete"])
        self.assertEqual(row["decodeErrors"], [])

    def test_unknown_action_shapes_are_reported_not_silently_skipped(self):
        for action in ("UnknownUnitAction", None, 12, {"FunctionCall": "bad"}):
            with self.subTest(action=action):
                x = fixture()
                x["receipts"][0]["receipt"]["receipt"]["Action"]["actions"].insert(0, action)
                row = normalize(x)
                self.assertFalse(row["treeReferencesComplete"])
                self.assertEqual(len(row["decodeErrors"]), 1)
                self.assertEqual(row["calls"][1]["actionIndex"], 1)

    def test_missing_child_is_not_complete(self):
        row = normalize(fixture(["MissingChild"]))
        self.assertFalse(row["treeReferencesComplete"])
        self.assertEqual(row["missingReferencedReceiptIds"], ["MissingChild"])

    def test_duplicate_receipts_invalidate_completeness(self):
        x = fixture()
        x["receipts"].append(x["receipts"][0])
        self.assertFalse(normalize(x)["treeReferencesComplete"])

    def test_malformed_args_and_nonjson_preserved(self):
        self.assertIsNotNone(decode_args("%%%%")[1])
        self.assertEqual(decode_args(base64.b64encode(b"\xff\x00").decode())[0], {"nonJsonHex": "ff00"})
        self.assertIsNone(decode_args(base64.b64encode(b"\xff\x00").decode())[1])
        self.assertEqual(nested("not JSON"), "not JSON")

    def test_binary_does_not_invalidate_receipt_structure(self):
        x = fixture()
        x["transaction"]["actions"][0]["FunctionCall"]["args"] = base64.b64encode(b"\xff\x00").decode()
        self.assertTrue(normalize(x)["treeReferencesComplete"])

    def test_legacy_withdrawal_execution_not_root_double_counted(self):
        x = fixture()
        body = {"amount": "9007199254740993", "receiver_id": "zec.omft.near", "memo": "WITHDRAW_TO:u1one"}
        x["receipts"][0]["receipt"]["receipt"]["Action"]["actions"] = [call("ft_transfer", body)]
        records = withdrawal_records(normalize(x), {"payoutTxids": ["a" * 64], "routes": [{"recipient": "u1one"}, {"recipient": "u1other"}]})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["withdrawalPath"], "legacy-token-self-transfer-memo")
        self.assertEqual(records[0]["requestedAmountZat"], "9007199254740993")
        self.assertEqual(len(records[0]["matchingExplorerRoutes"]), 1)
        self.assertEqual(records[0]["executionStatus"], "Failure")

    def test_nanosecond_precision(self):
        self.assertEqual(ns_iso(1788325884380267606), "2026-09-02T05:11:24.380267606Z")

    def test_all_hash_positions_and_route_bindings(self):
        txid = "a" * 64
        routes = [{"destinationChainTxHashes": ["notZcash", txid], "nearTxHashes": ["ABC", "AbC"], "recipient": "u1one"},
                  {"destinationChainTxHashes": [txid], "nearTxHashes": ["ABC"], "recipient": "u1two"}]
        queue = make_queue(routes, [txid])
        self.assertEqual(len(queue), 2)
        self.assertEqual(len(queue[0]["routes"]), 2)
        self.assertEqual(queue[1]["nearTransactionHash"], "AbC")

    def test_rate_limit_stops_without_retry_storm(self):
        exc = urllib.error.HTTPError("https://example.invalid", 429, "rate limited", {"Retry-After": "120"}, None)
        with tempfile.TemporaryDirectory() as directory, patch("trace_challenge7_free_near.time.sleep"), patch("trace_challenge7_free_near.urllib.request.urlopen", side_effect=exc) as request:
            with self.assertRaises(CheckpointStop):
                fetch_batch(["ABC"], Path(directory), 3, 30, 3)
            self.assertEqual(request.call_count, 1)

    def test_receipt_first_parser_does_not_assume_root_method(self):
        x = fixture()
        x["receipts"][0]["receipt"]["receiver_id"] = "zcash-connector.bridge.near"
        x["receipts"][0]["receipt"]["receipt"]["Action"]["actions"] = [call("ft_on_transfer", {"amount": "150000", "msg": json.dumps({"Withdraw": {"target_btc_address": "u1one", "input": ["abc:0"], "output": []}})})]
        receipt = {"transaction_hash": "Base58CaseSensitive", "receipt_id": "ReceiptA", "predecessor_account_id": "nzec.bridge.near", "block": {"block_timestamp": "1788325884756984232", "block_height": "101"}}
        result = normalize_connector_request(receipt, x, normalize(x))
        self.assertTrue(result["parseOk"])
        self.assertTrue(result["parsedFromExecutedReceipt"])
        self.assertEqual(result["targetAddress"], "u1one")
        self.assertEqual(result["requestedTokenAmountZat"], "150000")
        self.assertEqual(result["connectorInputs"], ["abc:0"])
        self.assertIn("Failure", result["receiptOutcome"])


if __name__ == "__main__":
    unittest.main()
