import copy
import unittest

from investigate_challenge7_account_links import TRANSFER_TOPIC
from trace_challenge7_free_near import CheckpointStop
from trace_challenge7_user_origins import CUTOFF_NS
from verify_challenge7_origin_deposits import rpc_batch, transfer_logs, verify_receipt


def fixture():
    h, bh, token = "0x"+"a"*64, "0x"+"b"*64, "0x"+"c"*40
    clock = CUTOFF_NS//1000000000-1000
    deposit = {"memo": {"txHash": h, "networkType": "eth", "chainId": "1"},
               "token": "eth-"+token, "amountRaw": "9007199254740993",
               "blockTime": "2026-09-19T10:01:10Z"}
    tx = {"hash": h, "from": "0x"+"d"*40, "to": token, "blockHash": bh, "blockNumber": "0x123"}
    block = {"hash": bh, "number": "0x123", "timestamp": hex(clock)}
    log = {"address": token, "topics": [TRANSFER_TOPIC, "0x"+"0"*24+"e"*40, "0x"+"0"*24+"f"*40],
           "data": "0x"+format(9007199254740993, "064x"), "logIndex": "0x1",
           "transactionHash": h, "blockHash": bh, "blockNumber": "0x123", "removed": False}
    receipt = {"transactionHash": h, "blockHash": bh, "blockNumber": "0x123", "status": "0x1", "logs": [log]}
    return deposit, tx, receipt, block


class OriginDepositTests(unittest.TestCase):
    def test_submitter_is_not_token_transfer_sender(self):
        row = verify_receipt(*fixture())
        self.assertEqual(row["transactionSubmitter"], "0x"+"d"*40)
        self.assertEqual(row["uniqueExactMintAmountTransfer"]["sender"], "0x"+"e"*40)
        self.assertEqual(row["uniqueExactMintAmountTransfer"]["amountRaw"], "9007199254740993")

    def test_failed_or_mismatched_receipt_not_verified(self):
        for field, value in (("status", "0x0"), ("blockHash", "wrong"), ("transactionHash", "wrong"), ("blockNumber", "0x124")):
            deposit, tx, receipt, block = fixture()
            receipt[field] = value
            with self.assertRaises(ValueError):
                verify_receipt(deposit, tx, receipt, block)

    def test_external_clock_must_precede_bridge_and_target(self):
        deposit, tx, receipt, block = fixture()
        block["timestamp"] = hex(CUTOFF_NS//1000000000)
        with self.assertRaises(ValueError):
            verify_receipt(deposit, tx, receipt, block)
        block["timestamp"] = hex(CUTOFF_NS//1000000000-1000)
        deposit["blockTime"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            verify_receipt(deposit, tx, receipt, block)

    def test_wrong_chain_and_log_block_are_rejected(self):
        deposit, tx, receipt, block = fixture()
        deposit["memo"]["chainId"] = "42161"
        with self.assertRaises(ValueError):
            verify_receipt(deposit, tx, receipt, block)
        deposit, tx, receipt, block = fixture()
        receipt["logs"][0]["blockHash"] = "other-block"
        with self.assertRaises(ValueError):
            verify_receipt(deposit, tx, receipt, block)

    def test_removed_wrong_token_malformed_logs_are_not_sender_evidence(self):
        deposit, _, receipt, _ = fixture()
        token = deposit["token"][4:]
        for change in ({"removed": True}, {"address": "0x"+"0"*40}, {"data": "0x1"},
                       {"topics": [TRANSFER_TOPIC, "0x"+"1"*64, "0x"+"0"*24+"f"*40]}):
            changed = {"logs": [{**receipt["logs"][0], **change}]}
            self.assertEqual(transfer_logs(changed, token), [])

    def test_multiple_same_amount_logs_not_exclusive_source(self):
        deposit, tx, receipt, block = fixture()
        receipt["logs"].append(copy.deepcopy(receipt["logs"][0]))
        receipt["logs"][1]["logIndex"] = "0x2"
        row = verify_receipt(deposit, tx, receipt, block)
        self.assertIsNone(row["uniqueExactMintAmountTransfer"])
        self.assertEqual(len(row["exactMintAmountTransferMatches"]), 2)

    def test_rpc_write_methods_are_never_sent(self):
        class Reader:
            def request(self, *args):
                raise AssertionError("write method must be rejected before HTTP")
        with self.assertRaises(ValueError):
            rpc_batch(Reader(), [("eth_sendRawTransaction", ["anything"])])

    def test_base_requires_explicit_chain_and_token_prefix(self):
        deposit,tx,receipt,block=fixture()
        deposit['memo']['chainId']='8453';deposit['token']='base-'+deposit['token'][4:]
        result=verify_receipt(deposit,tx,receipt,block,chain_id=8453,token_prefix='base-')
        self.assertEqual(result['chainId'],8453)
        with self.assertRaises(ValueError):verify_receipt(deposit,tx,receipt,block)
        with self.assertRaises(ValueError):verify_receipt(deposit,tx,receipt,block,chain_id=8453,token_prefix='eth-')

    def test_rpc_ids_version_and_errors_are_checked(self):
        class Reader:
            def __init__(self, response):
                self.response = response
            def request(self, *args):
                return self.response
        queries = [("eth_chainId", []), ("eth_chainId", [])]
        for response in ([{"jsonrpc": "2.0", "id": 1, "result": "0x1"}]*2,
                         [{"jsonrpc": "1.0", "id": i, "result": "0x1"} for i in (1,2)]):
            with self.assertRaises(ValueError):
                rpc_batch(Reader(response), queries)
        with self.assertRaises(CheckpointStop):
            rpc_batch(Reader([{"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}}]), queries[:1])
        response = [{"jsonrpc": "2.0", "id": i, "result": str(i)} for i in (2,1)]
        self.assertEqual(rpc_batch(Reader(response), queries), ["1", "2"])


if __name__ == "__main__":
    unittest.main()
