import unittest
import base64
import json

from reconcile_challenge7_account_flows import accepted_intents, balance_audit, event_ledger, nep413_hash, reconcile_rows, validate_outgoing


ASSET="nep141:nzec.bridge.near"


def trace_fixture(kind="mt_transfer", failed=False):
    item={"token_ids":[ASSET],"amounts":["9007199254740993"]}
    if kind=="mt_transfer":
        item.update({"old_owner_id":"user","new_owner_id":"other"})
    else:
        item["owner_id"]="user"
    call={"source":"receipt","receiptId":"receipt","receiver":"intents.near","method":"execute_intents",
          "blockTimestampNs":"10000000123","blockTime":"1970-01-01T00:00:10.000000123Z","blockHeight":123,
          "executionStatus":"SuccessValue","args":{"signed":[{"public_key":"key","payload":{"message":{"signer_id":"user","intents":[]}}}]}}
    log={"receiver":"intents.near","receiptId":"receipt","index":0,
         "decoded":{"standard":"nep245","event":kind,"data":[item]}}
    return {"nearTransactionHash":"root","signer":"relayer.near","calls":[call],"logs":[log],
            "outcomes":[{"receiptId":"receipt","executionStatus":"Failure" if failed else "SuccessValue"}]}


def indexed(amount, clock="10000000123", index=1, height=123, start=None, end=None):
    return {"account_id":"user","amount":str(amount),"asset_id":"nep245:intents.near:"+ASSET,
            "receipt_id":"receipt","log_index":0,"other_account_id":"other","transaction_id":"root",
            "block_timestamp":clock,"transfer_index":index,"block_height":height,
            "start_of_block_balance":start,"end_of_block_balance":end}


class AccountFlowTests(unittest.TestCase):
    def test_outgoing_scopes_and_signs_checked(self):
        spec={"account_id":"user","asset_id":"nep245:intents.near:"+ASSET,"to_timestamp_ms":20000}
        row=indexed(-2)
        self.assertEqual(validate_outgoing({"transfers":[row]},spec,None)[0],[row])
        for change in ({"amount":"2"},{"account_id":"other"},{"asset_id":"wrong"},{"block_timestamp":"20000000000"}):
            with self.assertRaises(ValueError):
                validate_outgoing({"transfers":[{**row,**change}]},spec,None)

    def test_cursor_and_order_must_advance(self):
        spec={"account_id":"user","asset_id":"nep245:intents.near:"+ASSET,"to_timestamp_ms":20000}
        with self.assertRaises(ValueError):
            validate_outgoing({"transfers":[indexed(-2)],"resume_token":"same"},spec,"same")
        with self.assertRaises(ValueError):
            validate_outgoing({"transfers":[indexed(-2)]},spec,None,(10000000123,1))

    def test_exact_execution_uses_integer_signed_amount_and_clock(self):
        events=event_ledger(trace_fixture(),"user",{ASSET})
        self.assertEqual(events[0]["amountRaw"],"-9007199254740993")
        self.assertEqual(events[0]["counterparty"],"other")
        self.assertTrue(reconcile_rows([indexed(-9007199254740993)],events)["exactMultisetMatch"])
        self.assertFalse(reconcile_rows([indexed(-9007199254740993,clock="10000000124")],events)["exactMultisetMatch"])

    def test_failed_and_untrusted_logs_not_balance_events(self):
        self.assertEqual(event_ledger(trace_fixture(failed=True),"user",{ASSET}),[])
        trace=trace_fixture()
        trace["logs"][0]["receiver"]="fake.near"
        self.assertEqual(event_ledger(trace,"user",{ASSET}),[])

    def test_mint_burn_and_self_transfers_are_distinct(self):
        mint=event_ledger(trace_fixture("mt_mint"),"user",{ASSET})[0]
        burn=event_ledger(trace_fixture("mt_burn"),"user",{ASSET})[0]
        self.assertEqual(int(mint["amountRaw"]),-int(burn["amountRaw"]))
        self.assertIsNone(mint["counterparty"])
        trace=trace_fixture()
        trace["logs"][0]["decoded"]["data"][0]["new_owner_id"]="user"
        self.assertEqual(sum(int(e["amountRaw"]) for e in event_ledger(trace,"user",{ASSET})),0)

    def test_malformed_event_arrays_and_missing_clock_are_rejected(self):
        trace=trace_fixture()
        trace["logs"][0]["decoded"]["data"][0]["amounts"]=[]
        with self.assertRaises(ValueError):
            event_ledger(trace,"user",{ASSET})
        trace=trace_fixture()
        trace["calls"][0]["blockTimestampNs"]=None
        with self.assertRaises(ValueError):
            event_ledger(trace,"user",{ASSET})

    def test_reconciliation_preserves_missing_and_duplicate_events(self):
        events=event_ledger(trace_fixture(),"user",{ASSET})
        row=indexed(-9007199254740993)
        result=reconcile_rows([row,row],events)
        self.assertFalse(result["exactMultisetMatch"])
        self.assertEqual(result["indexedEventsMissingInExecution"][0]["count"],1)
        result=reconcile_rows([] ,events)
        self.assertEqual(result["executedEventsMissingInIndex"][0]["count"],1)

    def test_balance_carryover_not_assumed_zero_or_reset_on_disagreement(self):
        rows=[indexed(10,start="50",end="60"), indexed(-20,clock="11000000000",height=124,start="60",end="40")]
        result=balance_audit(rows)[0]
        self.assertEqual(result["openingBalanceRaw"],"50")
        self.assertEqual(result["closingBalanceRaw"],"40")
        self.assertEqual(result["blockBalanceMismatches"],[])
        rows[1]["end_of_block_balance"]="42"
        result=balance_audit(rows)[0]
        self.assertEqual(result["closingBalanceRaw"],"40")
        self.assertEqual(len(result["blockBalanceMismatches"]),1)

    def test_unknown_opening_and_negative_running_are_not_hidden(self):
        result=balance_audit([indexed(-1)])[0]
        self.assertIsNone(result["openingBalanceRaw"])
        self.assertIsNone(result["closingBalanceRaw"])
        result=balance_audit([indexed(-1,start="0",end="0")])[0]
        self.assertEqual(len(result["negativeRunningBalances"]),1)

    def test_accepted_account_instruction_not_relayer_or_failed_call(self):
        trace=trace_fixture()
        signed={"standard":"nep413","public_key":"key","payload":{"message":'{"signer_id":"user","intents":[]}',
                "recipient":"intents.near","nonce":base64.b64encode(bytes(range(32))).decode()}}
        trace["calls"][0]["argsBase64"]=base64.b64encode(json.dumps({"signed":[signed]}).encode()).decode()
        trace["logs"].append({"receiver":"intents.near","receiptId":"receipt","index":1,
                              "decoded":{"standard":"dip4","event":"intents_executed","data":[
                                  {"account_id":"user","intent_hash":nep413_hash(signed)}]}})
        self.assertEqual(accepted_intents(trace,"user")[0]["publicKey"],"key")
        self.assertTrue(accepted_intents(trace,"user")[0]["originalMessageHashMatched"])
        self.assertEqual(accepted_intents(trace,"relayer.near"),[])
        changed={**signed,"payload":{**signed["payload"],"message":'{"signer_id": "user", "intents": []}'}}
        trace["calls"][0]["argsBase64"]=base64.b64encode(json.dumps({"signed":[changed]}).encode()).decode()
        with self.assertRaises(ValueError):
            accepted_intents(trace,"user")
        trace["calls"][0]["executionStatus"]="Failure"
        self.assertEqual(accepted_intents(trace,"user"),[])

    def test_nep413_requires_original_string_and_fixed_nonce(self):
        signed={"standard":"nep413","payload":{"message":"hi","nonce":base64.b64encode(bytes(range(32))).decode(),"recipient":"myapp.com"}}
        original=nep413_hash(signed)
        self.assertNotEqual(original,nep413_hash({**signed,"payload":{**signed["payload"],"callbackUrl":"myapp.com/callback"}}))
        for change in ({"message":{}},{"nonce":"AA=="}):
            with self.assertRaises(ValueError):
                nep413_hash({**signed,"payload":{**signed["payload"],**change}})


if __name__=="__main__":
    unittest.main()
