import unittest
from trace_challenge7_public_branches import spends_outpoint, bundle_budget, trusted_deposits, internal_swap_funding


class PublicBranchTests(unittest.TestCase):
    def test_outpoint_requires_both_hash_and_output_index(self):
        detail={"inputs":[{"prev_txid":"a","prev_vout":1}]}
        self.assertTrue(spends_outpoint(detail,"a",1))
        self.assertFalse(spends_outpoint(detail,"a",0))
        self.assertFalse(spends_outpoint(detail,"b",1))

    def test_empty_anchor_bounds_outputs_without_claiming_recovery(self):
        decoded={"ok":True,"bundles":[{"pool":"ironwood","anchorIsEmptyTree":True,"spendsEnabled":True,"valueBalanceZat":-5001,"bundleVersion":"V3"}]}
        budget=bundle_budget(decoded)[0]
        self.assertTrue(budget["positivePrivateInputValueExcluded"])
        self.assertEqual(budget["maximumIndividualOutputValueZat"],5001)
        self.assertFalse(budget["outputValuesRecovered"])
        self.assertIn("V6 txid alone does not bind anchor",budget["assumptions"])

    def test_nonempty_anchor_does_not_turn_net_inflow_into_output_bound(self):
        decoded={"ok":True,"bundles":[{"pool":"ironwood","anchorIsEmptyTree":False,"spendsEnabled":True,"valueBalanceZat":-97000}]}
        budget=bundle_budget(decoded)[0]
        self.assertFalse(budget["positivePrivateInputValueExcluded"])
        self.assertIsNone(budget["maximumIndividualOutputValueZat"])

    def test_spends_disabled_bound_and_historical_circuit_warning(self):
        decoded={"ok":True,"bundles":[{"pool":"orchard","spendsEnabled":False,"valueBalanceZat":-197000,"bundleVersion":"InsecureV1"}]}
        budget=bundle_budget(decoded)[0]
        self.assertEqual(budget["totalOutputValueZat"],197000)
        self.assertTrue(budget["historicalCircuitWarning"])
        self.assertEqual(bundle_budget({"ok":False}),[])

    def test_deposit_needs_trusted_successful_receipt_exact_chain_and_mint(self):
        call={"source":"receipt","predecessor":"bridge-mng.near","receiver":"omft.near","method":"ft_deposit","executionStatus":"SuccessReceiptId","receiptId":"R","blockTime":"time",
              "args":{"memo":{"networkType":"zec","chainId":"mainnet","txHash":"tx"},"token":"zec","owner_id":"intents.near","amount":"645943","msg":{"receiver_id":"account"}}}
        event={"standard":"nep245","event":"mt_mint","data":[{"owner_id":"account","token_ids":["nep141:zec.omft.near"],"amounts":["645943"]}]}
        trace={"nearTransactionHash":"Root","calls":[call],"outcomes":[{"receiptId":"M","executionStatus":"SuccessValue"}],"logs":[{"receiver":"intents.near","receiptId":"M","index":0,"decoded":event}]}
        self.assertTrue(trusted_deposits(trace,{"tx"})[0]["mintAmountMatches"])
        self.assertEqual(trusted_deposits(trace,{"wrong"}),[])
        trace["outcomes"][0]["executionStatus"]="Failure"
        self.assertFalse(trusted_deposits(trace,{"tx"})[0]["mintAmountMatches"])
        call["predecessor"]="untrusted.near"
        self.assertEqual(trusted_deposits(trace,{"tx"}),[])

    def test_internal_swap_funding_requires_sender_recipient_token_and_amount(self):
        event={"standard":"nep245","event":"mt_transfer","data":[{"old_owner_id":"shared","new_owner_id":"temporary","token_ids":["usdc"],"amounts":["9007199254740993"]}]}
        trace={"nearTransactionHash":"Root","outcomes":[{"receiptId":"R","executionStatus":"SuccessValue"}],"logs":[{"receiver":"intents.near","receiptId":"R","index":0,"decoded":event}]}
        matches=internal_swap_funding(trace,"shared","temporary","usdc","9007199254740993")
        self.assertEqual(matches[0]["amountRaw"],"9007199254740993")
        self.assertEqual(internal_swap_funding(trace,"other","temporary","usdc","9007199254740993"),[])
        self.assertEqual(internal_swap_funding(trace,"shared","temporary","usdc","9007199254740992"),[])
        trace["logs"][0]["receiver"]="fake.near"
        self.assertEqual(internal_swap_funding(trace,"shared","temporary","usdc","9007199254740993"),[])


if __name__ == "__main__":
    unittest.main()
