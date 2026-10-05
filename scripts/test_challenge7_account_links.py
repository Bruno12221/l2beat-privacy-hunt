import unittest
from investigate_challenge7_account_links import timestamp_ns, route_before, account_credits, classify_credits, cross_chain_deposits, executed_intents_transfers, evm_transfers, TRANSFER_TOPIC, pending_payouts, compare_raw_packet


class AccountLinkTests(unittest.TestCase):
    def test_exact_nanosecond_chronology(self):
        self.assertEqual(timestamp_ns("2026-08-28T13:17:57.942622132Z") % 1_000_000_000, 942622132)
        self.assertFalse(route_before({"createdAt":"2026-08-28T13:17:57.942622133Z"}, {"blockTime":"2026-08-28T13:17:57.942622132Z"}))
        self.assertEqual(timestamp_ns("2026-08-28T15:17:57.942622132+02:00"), timestamp_ns("2026-08-28T13:17:57.942622132Z"))

    def test_credit_requires_trusted_contract_receiver_and_success(self):
        event = {"standard":"nep245","event":"mt_transfer","data":[{"old_owner_id":"solver","new_owner_id":"account","token_ids":["nep141:zec.omft.near"],"amounts":["9007199254740993"]}]}
        trace={"nearTransactionHash":"Root","outcomes":[{"receiptId":"Receipt","executionStatus":"SuccessValue"}],"logs":[{"receiptId":"Receipt","index":0,"receiver":"intents.near","decoded":event}]}
        self.assertEqual(account_credits(trace,"account")[0]["amountZat"],"9007199254740993")
        trace["logs"][0]["receiver"]="untrusted.near"
        self.assertEqual(account_credits(trace,"account"),[])
        trace["logs"][0]["receiver"]="intents.near"
        trace["outcomes"][0]["executionStatus"]="Failure"
        self.assertEqual(account_credits(trace,"account"),[])
        trace["outcomes"]=[]
        self.assertEqual(account_credits(trace,"account"),[])

    def test_credit_uses_execution_clock_not_quote_creation_time(self):
        cutoff="2026-07-29T16:50:06.052363060Z"
        clock=timestamp_ns(cutoff)
        credits=[{"blockTimestampNs":str(clock)}, {"blockTimestampNs":str(clock+1)}, {"blockTimestampNs":None}]
        before,later,unknown=classify_credits(credits,cutoff)
        self.assertEqual(before,[credits[0]])
        self.assertEqual(later,[credits[1]])
        self.assertEqual(unknown,[credits[2]])
        event={"standard":"nep245","event":"mt_mint","data":[{"owner_id":"account","token_ids":["nep141:zec.omft.near"],"amounts":["5"]}]}
        trace={"nearTransactionHash":"Root","outcomes":[{"receiptId":"R","executionStatus":"SuccessValue"}],
               "calls":[{"source":"receipt","receiptId":"R","blockTimestampNs":str(clock+1),"blockTime":cutoff}],
               "logs":[{"receiptId":"R","index":0,"receiver":"intents.near","decoded":event}]}
        extracted=account_credits(trace,"account")
        self.assertEqual(classify_credits(extracted,cutoff)[0],[])

    def test_cross_chain_memo_requires_executed_bridge_and_exact_identifiers(self):
        call={"source":"receipt","receiver":"omft.near","predecessor":"bridge-mng.near","method":"ft_deposit",
              "executionStatus":"SuccessReceiptId","receiptId":"R","args":{"memo":{"networkType":"eth","chainId":"42161","txHash":"0xABC"},"msg":{"receiver_id":"account"},"amount":"5"}}
        trace={"nearTransactionHash":"Root","calls":[call]}
        self.assertEqual(cross_chain_deposits(trace,"0xabc",42161)[0]["depositIntentsAccount"],"account")
        self.assertEqual(cross_chain_deposits(trace,"0xdef",42161),[])
        self.assertEqual(cross_chain_deposits(trace,"0xabc",1),[])
        call["predecessor"]="fake.near"
        self.assertEqual(cross_chain_deposits(trace,"0xabc",42161),[])

    def test_intent_transfer_preserves_signer_and_does_not_substitute_solver(self):
        event={"standard":"dip4","event":"transfer","data":[{"account_id":"deposit-account","receiver_id":"withdraw-account","intent_hash":"Intent","tokens":{"nep141:zec.omft.near":"5"}}]}
        trace={"nearTransactionHash":"Root","outcomes":[{"receiptId":"R","executionStatus":"SuccessValue"}],"logs":[{"receiptId":"R","index":0,"receiver":"intents.near","decoded":event}]}
        self.assertEqual(executed_intents_transfers(trace,"withdraw-account")[0]["account_id"],"deposit-account")
        self.assertEqual(executed_intents_transfers(trace,"wrong-account"),[])
        trace["outcomes"][0]["executionStatus"]="Failure"
        self.assertEqual(executed_intents_transfers(trace,"withdraw-account"),[])

    def test_credit_excludes_self_transfer_and_wrong_account(self):
        event={"standard":"nep245","event":"mt_transfer","data":[{"old_owner_id":"account","new_owner_id":"account","token_ids":["nep141:zec.omft.near"],"amounts":["5"]}]}
        trace={"nearTransactionHash":"Root","outcomes":[{"receiptId":"Receipt","executionStatus":"SuccessValue"}],"logs":[{"receiptId":"Receipt","index":0,"receiver":"intents.near","decoded":event}]}
        self.assertEqual(account_credits(trace,"account"),[])
        self.assertEqual(account_credits(trace,"other"),[])

    def test_evm_transfer_requires_exact_token_and_both_endpoints(self):
        sender="0x"+"11"*20; recipient="0x"+"22"*20; token="0x"+"33"*20
        receipt={"logs":[{"topics":[TRANSFER_TOPIC,"0x"+"00"*12+sender[2:],"0x"+"00"*12+recipient[2:]],"address":token,"data":hex(9007199254740993),"logIndex":"0x1"}]}
        self.assertEqual(evm_transfers(receipt,token,sender,recipient)[0]["amountRaw"],"9007199254740993")
        self.assertEqual(evm_transfers(receipt,token,recipient,sender),[])
        receipt["logs"][0]["removed"]=True
        self.assertEqual(evm_transfers(receipt,token,sender,recipient),[])

    def test_pending_id_requires_connector_execution_event(self):
        event={"standard":"bridge","event":"generate_btc_pending_info","data":[{"btc_pending_id":"a"*64}]}
        trace={"nearTransactionHash":"Builder","outcomes":[{"receiptId":"R","executionStatus":"SuccessValue"}],"logs":[{"receiptId":"R","index":0,"receiver":"zcash-connector.bridge.near","decoded":event}]}
        self.assertEqual(pending_payouts(trace)[0]["txid"],"a"*64)
        trace["logs"][0]["receiver"]="untrusted.near"
        self.assertEqual(pending_payouts(trace),[])
        trace["logs"][0]["receiver"]="zcash-connector.bridge.near"
        trace["outcomes"][0]["executionStatus"]="Failure"
        self.assertEqual(pending_payouts(trace),[])

    def test_raw_packet_requires_all_input_outpoints_and_output_scripts(self):
        packet={"input":["a:1"],"output":[{"value":112000,"script_pubkey":"AB"}]}
        decoded={"ok":True,"txid":"tx","transparentInputs":[{"prevTxid":"a","prevVout":1}],"transparentOutputs":[{"valueZat":112000,"scriptPubKeyHex":"ab"}],"bundles":[]}
        self.assertTrue(compare_raw_packet(packet,decoded)["verified"])
        decoded["transparentInputs"][0]["prevVout"]=0
        self.assertFalse(compare_raw_packet(packet,decoded)["verified"])
        decoded["transparentInputs"][0]["prevVout"]=1
        decoded["transparentOutputs"][0]["scriptPubKeyHex"]="ac"
        self.assertFalse(compare_raw_packet(packet,decoded)["verified"])


if __name__ == "__main__":
    unittest.main()
