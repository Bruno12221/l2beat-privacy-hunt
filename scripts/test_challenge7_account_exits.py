import unittest
import base64

from trace_challenge7_account_exits import compare_complete_packet, legacy_exits, legacy_transfers, modern_exits, validate_omni


def fixture():
    ins={"intent":"ft_withdraw","token":"nzec.bridge.near","receiver_id":"omni.bridge.near",
         "amount":"132000","msg":'{"recipient":"zcash:t1receiver"}'}
    accepted={"nearRoot":"root","receiptId":"execute","blockTime":"2026-08-04T08:45:06.147695501Z",
              "originalMessageHashMatched":True,"intentHash":"hash","message":{"intents":[ins]}}
    burn={"nearRoot":"root","receiptId":"execute","token":"nep141:nzec.bridge.near",
          "event":"mt_burn","amountRaw":"-132000"}
    analysis={"acceptedInstructions":[accepted],"executedEvents":[burn]}
    msg={"origin_nonce":225125,"sender":"near:intents.near","token":"near:nzec.bridge.near",
         "recipient":"zcash:t1receiver","amount":"132000"}
    trace={"outcomes":[{"receiptId":"execute","executionStatus":"SuccessValue","childReceiptIds":["init"]},
                        {"receiptId":"init","executionStatus":"SuccessValue","childReceiptIds":[]}],
           "logs":[{"receiver":"omni.bridge.near","receiptId":"init","index":0,
                     "decoded":{"InitTransferEvent":{"transfer_message":msg}}}]}
    return analysis,{"root":trace}


class AccountExitTests(unittest.TestCase):
    def test_nonce_link_requires_original_hash_and_executed_burn(self):
        a,t=fixture()
        row=modern_exits(a,t)[0]
        self.assertEqual(row["originNonce"],225125)
        self.assertTrue(row["publicExecutionVerified"])
        a["acceptedInstructions"][0]["originalMessageHashMatched"]=False
        with self.assertRaises(ValueError):modern_exits(a,t)
        a,t=fixture();a["executedEvents"][0]["amountRaw"]="-131999"
        with self.assertRaises(ValueError):modern_exits(a,t)

    def test_matching_init_must_be_successful_descendant_not_another_root(self):
        a,t=fixture();t["root"]["outcomes"][0]["childReceiptIds"]=[]
        with self.assertRaises(ValueError):modern_exits(a,t)
        a,t=fixture();t["root"]["outcomes"][1]["executionStatus"]="Failure"
        with self.assertRaises(ValueError):modern_exits(a,t)

    def test_same_amount_wrong_receiver_or_sender_not_linked(self):
        for change in ({"recipient":"zcash:other"},{"sender":"near:other"},{"token":"near:other"}):
            a,t=fixture();t["root"]["logs"][0]["decoded"]["InitTransferEvent"]["transfer_message"].update(change)
            with self.assertRaises(ValueError):modern_exits(a,t)

    def test_indexer_must_match_exact_nonce_origin_receipt_and_request(self):
        a,t=fixture();row=modern_exits(a,t)[0]
        indexed={"transfer_id":{"type":"nonce","chain":"Near","nonce":225125},
                 "sender":"near:intents.near","token_id":"near:nzec.bridge.near","amount":"132000",
                 "recipient":"zcash:t1receiver","initialised":{"transaction_hash":"root","details":{"receipt_id":"init"}}}
        self.assertEqual(validate_omni({"transfers":[indexed]},row),indexed)
        for change in ({"amount":"131999"},{"recipient":"zcash:other"},{"initialised":{"transaction_hash":"relayer-root","details":{"receipt_id":"init"}}}):
            with self.assertRaises(ValueError):validate_omni({"transfers":[{**indexed,**change}]},row)
        with self.assertRaises(ValueError):validate_omni({"transfers":[indexed,indexed]},row)

    def test_legacy_gross_transfer_preserved_without_inferred_future_exit(self):
        a,t=fixture()
        a["acceptedInstructions"][0]["message"]["intents"]=[{"intent":"transfer","receiver_id":"temporary",
                                                                "tokens":{"nep141:zec.omft.near":"154937"}}]
        transfers=legacy_transfers(a)
        self.assertEqual(transfers[0]["grossAmountRaw"],"154937")
        self.assertNotIn("payoutTxid",transfers[0])

    def test_shielded_packet_requires_exact_bundle_and_declared_expiry(self):
        packet={"input":["parent:0"],"output":[],"chain_specific_data":{
            "orchard_bundle_bytes":base64.b64encode(bytes.fromhex("010203")).decode(),"expiry_height":100}}
        decoded={"ok":True,"txid":"hash","transparentInputs":[{"prevTxid":"parent","prevVout":0}],
                 "transparentOutputs":[],"expiryHeight":100,"bundles":[{"pool":"ironwood","serializedBundleHex":"010203"}]}
        self.assertTrue(compare_complete_packet(packet,decoded)["verified"])
        decoded["bundles"][0]["serializedBundleHex"]="010204"
        self.assertFalse(compare_complete_packet(packet,decoded)["verified"])
        decoded["bundles"][0]["serializedBundleHex"]="010203"
        decoded["expiryHeight"]=101
        self.assertFalse(compare_complete_packet(packet,decoded)["verified"])
        decoded["expiryHeight"]=100;decoded["bundles"]*=2
        self.assertFalse(compare_complete_packet(packet,decoded)["verified"])

    def test_legacy_forwarded_account_and_failed_token_stage_are_distinct(self):
        amount,memo="154162","WITHDRAW_TO:t1destination"
        item={"account_id":"temporary","token":"zec.omft.near","receiver_id":"zec.omft.near",
              "amount":amount,"memo":memo,"intent_hash":"accepted-hash"}
        accepted={"nearRoot":"root","receiptId":"execute","blockTime":"2026-07-17T15:06:58.071888471Z",
                  "message":{"intents":[{"intent":"ft_withdraw",**{k:v for k,v in item.items() if k!="account_id"}}]}}
        call={"source":"receipt","method":"ft_transfer","receiver":"zec.omft.near","predecessor":"intents.near",
              "receiptId":"burn","executionStatus":"SuccessValue","args":{"memo":memo,"amount":amount}}
        trace={"calls":[call],"outcomes":[{"receiptId":"execute","executionStatus":"SuccessValue","childReceiptIds":["burn"]},
                                           {"receiptId":"burn","executionStatus":"SuccessValue","childReceiptIds":[]}],
               "logs":[{"receiver":"intents.near","receiptId":"execute","index":0,"decoded":{"standard":"dip4","event":"ft_withdraw","data":[item]}},
                        {"receiver":"zec.omft.near","receiptId":"burn","index":0,"decoded":{"standard":"nep141","event":"ft_burn",
                          "data":[{"owner_id":"intents.near","amount":amount,"memo":memo}]}}]}
        analysis={"acceptedInstructions":[accepted],"executedEvents":[]}
        self.assertEqual(legacy_exits(analysis,{"root":trace}),[])
        found=legacy_exits(analysis,{"root":trace},"temporary")
        self.assertTrue(found[0]["publicNearExecutionVerified"])
        trace["calls"][0]["executionStatus"]="Failure"
        found=legacy_exits(analysis,{"root":trace},"temporary")
        self.assertFalse(found[0]["publicNearExecutionVerified"])
        self.assertTrue(found[0]["unverifiedOrFailedTokenStage"])


if __name__=="__main__":unittest.main()
