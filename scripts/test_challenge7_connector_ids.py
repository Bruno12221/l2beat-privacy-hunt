import copy
import json
import unittest
from audit_challenge7_connector_ids import rpc_pending_ids, full_tree_rpc_result


def fixture():
    return {"receipts_outcome": [
        {"id": "origin", "outcome": {"executor_id": "zcash-connector.bridge.near", "status": {"SuccessReceiptId": "child"}, "receipt_ids": ["child"], "logs": []}},
        {"id": "child", "outcome": {"executor_id": "zcash-connector.bridge.near", "status": {"SuccessValue": ""}, "receipt_ids": [],
          "logs": ["EVENT_JSON:"+json.dumps({"standard": "bridge", "event": "generate_btc_pending_info", "data": [{"btc_pending_id": "a"*64}]})]}}
    ]}


class ConnectorIdsTests(unittest.TestCase):
    def test_full_tree_original_outcomes_preserve_descendant_binding(self):
        v=fixture()
        tree={"transaction":{"hash":"root", "actions":[]},
              "execution_outcome":{"outcome":{"receipt_ids":["origin"]}}, "receipts":[]}
        for o in v["receipts_outcome"]:
            tree["receipts"].append({"receipt":{"receipt_id":o["id"], "receiver_id":o["outcome"]["executor_id"]},
                "execution_outcome":{"id":o["id"],"outcome":o["outcome"]}})
        self.assertEqual(rpc_pending_ids(full_tree_rpc_result(tree),"origin"),rpc_pending_ids(v,"origin"))
        bad=copy.deepcopy(tree);bad["receipts"][0]["execution_outcome"]["outcome"]["executor_id"]="other.near"
        with self.assertRaisesRegex(ValueError,"receiver/executor"):full_tree_rpc_result(bad)
        bad=copy.deepcopy(tree);bad["receipts"][0]["execution_outcome"]["id"]="wrong"
        with self.assertRaisesRegex(ValueError,"identity"):full_tree_rpc_result(bad)
        bad=copy.deepcopy(tree);bad["receipts"].pop()
        with self.assertRaisesRegex(ValueError,"incomplete"):full_tree_rpc_result(bad)

    def test_explicit_descendant_identity_not_receiver_correlation(self):
        found, error = rpc_pending_ids(fixture(), "origin")
        self.assertIsNone(error); self.assertEqual(found, [{"txid": "a"*64, "eventReceiptId": "child", "logIndex": 0}])

    def test_missing_failed_other_executor_and_unrelated_logs_stay_unresolved(self):
        v=fixture(); self.assertEqual(rpc_pending_ids(v,"missing")[1],"listed-receipt-outcome-missing")
        v=fixture(); v["receipts_outcome"][0]["outcome"]["status"]={"Failure":{}}
        self.assertIn("not-successful",rpc_pending_ids(v,"origin")[1])
        v=fixture(); v["receipts_outcome"][0]["outcome"]["executor_id"]="other.near"
        self.assertIn("executor-mismatch",rpc_pending_ids(v,"origin")[1])
        v=fixture(); v["receipts_outcome"][0]["outcome"]["receipt_ids"]=[]
        self.assertIn("without-descendant",rpc_pending_ids(v,"origin")[1])
        v=fixture(); v["receipts_outcome"][0]["outcome"]["receipt_ids"]=["missing"]
        self.assertIn("reference-missing",rpc_pending_ids(v,"origin")[1])
        v=fixture(); v["receipts_outcome"][1]["outcome"]["executor_id"]="other.near"
        self.assertIn("without-descendant",rpc_pending_ids(v,"origin")[1])

    def test_duplicate_outcomes_are_rejected(self):
        v=fixture(); v["receipts_outcome"].append(copy.deepcopy(v["receipts_outcome"][0]))
        with self.assertRaises(ValueError): rpc_pending_ids(v,"origin")


if __name__ == "__main__": unittest.main()
