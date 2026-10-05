import unittest
import json,hashlib,sqlite3,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from trace_challenge7_new_receiver_pairs import receiver_pairs,bound_builder_submission,accepted_internal_credit,exact_new_pairs,verify_selected_note,obtain_trees,indexed_origin,bound_internal_credit
from trace_challenge7_free_near import CheckpointStop


class NewReceiverPairsTests(unittest.TestCase):
    def test_callback_is_sibling_not_ancestor_require_common_exact_nonce_parent(self):
        trace={"nearTransactionHash":"root","calls":[
            {"source":"receipt","receiver":"omni.bridge.near","receiptId":"parent","executionStatus":"SuccessReceiptId",
             "method":"submit_transfer_to_utxo_chain_connector","args":{"transfer_id":{"origin_chain":"Near","origin_nonce":7}}},
            {"source":"receipt","receiver":"omni.bridge.near","receiptId":"callback","executionStatus":"SuccessValue",
             "method":"submit_transfer_to_btc_connector_callback","args":{"transfer_msg":{"origin_nonce":7}}}],
            "outcomes":[{"receiptId":"parent","executionStatus":"SuccessReceiptId","childReceiptIds":["builder","callback"]},
                        {"receiptId":"builder","executionStatus":"SuccessReceiptId","childReceiptIds":["pending"]},
                        {"receiptId":"pending","executionStatus":"SuccessValue","childReceiptIds":[]},
                        {"receiptId":"callback","executionStatus":"SuccessValue","childReceiptIds":[]}],
            "logs":[{"receiptId":"pending","index":0,"receiver":"zcash-connector.bridge.near","decoded":
                     {"standard":"bridge","event":"generate_btc_pending_info","data":[{"btc_pending_id":"a"*64}]}}]}
        self.assertEqual(bound_builder_submission(trace,"builder",7,"a"*64)["submission"]["receiptId"],"parent")
        with self.assertRaises(ValueError):bound_builder_submission(trace,"builder",8,"a"*64)
        trace["outcomes"][0]["childReceiptIds"]=["builder"]
        with self.assertRaises(ValueError):bound_builder_submission(trace,"builder",7,"a"*64)

    def test_actual_receiver_and_amount_gates_not_quote_dates(self):
        old=[{"id":"old","txid":"a","valueZat":2000000,"receiverBytes":["receiver"],"anchorEligibility":"height-compatible"}]
        raw=[{"txid":"b","outputs":[{"pool":"ironwood","actionIndex":0,"cmx":"cmx","recovered":True,"valueZat":2000000,"receiverRaw":"receiver"}]}]
        pairs=receiver_pairs(old,raw)
        self.assertEqual(len(pairs),1);self.assertFalse(pairs[0]["targetSpendProven"])
        self.assertEqual(pairs[0]["possibleChangeZat"],45818)
        raw[0]["outputs"][0]["receiverRaw"]="other"
        self.assertEqual(receiver_pairs(old,raw),[])
        raw[0]["outputs"][0]["receiverRaw"]="receiver";raw[0]["outputs"][0]["recovered"]=False
        self.assertEqual(receiver_pairs(old,raw),[])

    def test_ineligible_old_notes_do_not_supply_pairs(self):
        old=[{"id":"old","txid":"a","valueZat":2000000,"receiverBytes":["receiver"],"anchorEligibility":"after-anchor"}]
        raw=[{"txid":"b","outputs":[{"pool":"ironwood","actionIndex":0,"cmx":"cmx","recovered":True,"valueZat":2000000,"receiverRaw":"receiver"}]}]
        self.assertEqual(receiver_pairs(old,raw),[])

    def test_internal_credit_binds_same_receipt_accepted_transfer(self):
        event={"senderAccount":"sender","recipientAccount":"receiver","receiptId":"receipt",
               "token":"nep141:zec.omft.near","amountRaw":"123"}
        accepted={"receiptId":"receipt","message":{"intents":[{"intent":"transfer","receiver_id":"receiver",
                   "tokens":{"nep141:zec.omft.near":"123"}}]},"publicKey":"key","originalMessageHashMatched":True}
        with patch("trace_challenge7_new_receiver_pairs.accepted_intents",return_value=[accepted]) as mocked:
            result=accepted_internal_credit({},event)
        self.assertTrue(result["acceptedInstructionVerified"])
        mocked.assert_called_once_with({},"sender")
        self.assertIs(result["acceptedInstruction"],accepted)

    def test_internal_credit_rejects_wrong_receipt_amount_recipient_or_token(self):
        event={"senderAccount":"sender","recipientAccount":"receiver","receiptId":"receipt",
               "token":"nep141:zec.omft.near","amountRaw":"123"}
        for change in ("receipt","amount","recipient","token"):
            with self.subTest(change=change):
                instruction={"intent":"transfer","receiver_id":"receiver","tokens":{"nep141:zec.omft.near":"123"}}
                accepted={"receiptId":"receipt","message":{"intents":[instruction]}}
                if change=="receipt":accepted["receiptId"]="other"
                if change=="amount":instruction["tokens"]["nep141:zec.omft.near"]="124"
                if change=="recipient":instruction["receiver_id"]="other"
                if change=="token":instruction["tokens"]={"nep141:other":"123"}
                with patch("trace_challenge7_new_receiver_pairs.accepted_intents",return_value=[accepted]):
                    with self.assertRaises(CheckpointStop):accepted_internal_credit({},event)

    def test_internal_credit_rejects_ambiguous_accepted_instructions(self):
        event={"senderAccount":"sender","recipientAccount":"receiver","receiptId":"receipt",
               "token":"nep141:zec.omft.near","amountRaw":"123"}
        accepted={"receiptId":"receipt","message":{"intents":[{"intent":"transfer","receiver_id":"receiver",
                   "tokens":{"nep141:zec.omft.near":"123"}}]}}
        with patch("trace_challenge7_new_receiver_pairs.accepted_intents",return_value=[accepted,accepted]):
            with self.assertRaises(CheckpointStop):accepted_internal_credit({},event)

    def test_new_exact_pairs_keep_both_partners_and_do_not_require_same_receiver(self):
        rows=[{"id":"a","txid":"old","valueZat":2000000,"anchorEligibility":"height-compatible","receiverBytes":["a"]},
              {"id":"b","txid":"new","valueZat":1954182,"anchorEligibility":"height-compatible","receiverBytes":["b"]},
              {"id":"c","txid":"other-old","valueZat":1954182,"anchorEligibility":"height-compatible"},
              {"id":"d","txid":"late-new","valueZat":1954182,"anchorEligibility":"after-anchor"}]
        pairs=exact_new_pairs(rows,{"new","late-new"})
        self.assertEqual(len(pairs),1);self.assertEqual({pairs[0][s]['txid'] for s in ('left','right')},{'old','new'})
        self.assertFalse(pairs[0]['targetSpendProven']);self.assertEqual(pairs[0]['possibleChangeZat'],0)

    def test_selected_note_requires_exact_actual_raw_identity_value_receiver(self):
        decoded={"txid":"tx","outputs":[{"pool":"ironwood","recovered":True,"actionIndex":0,"cmx":"cmx","valueZat":12,"receiverRaw":"receiver"}]}
        note={"id":"tx:ironwood:0:cmx","valueZat":12,"receiverBytes":["receiver"]}
        verify_selected_note(note,decoded)
        for changes in ({"id":"other"},{"valueZat":13},{"receiverBytes":["other"]}):
            with self.assertRaises(ValueError):verify_selected_note({**note,**changes},decoded)

    def test_complete_ledger_tree_reused_only_with_original_source_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'original.json'
            source.write_text(json.dumps({"transactions":[{"transaction":{"hash":"root","signer_id":"signer","receiver_id":"receiver","actions":[]},
                                                         "execution_outcome":{"outcome":{"receipt_ids":[],"status":{"SuccessValue":""}}},"receipts":[]}]}))
            db=sqlite3.connect(root/'ledger.sqlite3')
            db.execute('CREATE TABLE roots(hash TEXT,done INTEGER,complete INTEGER,data TEXT)')
            db.execute('CREATE TABLE responses(path TEXT,sha256 TEXT)')
            db.execute('INSERT INTO roots VALUES(?,?,?,?)',('root',1,1,json.dumps({'sourceResponse':str(source)})))
            db.execute('INSERT INTO responses VALUES(?,?)',(str(source),hashlib.sha256(source.read_bytes()).hexdigest()))
            db.commit();db.close()
            reader=SimpleNamespace(reused={},request=lambda *unused:self.fail('cached tree must not fetch'))
            trees={};obtain_trees(['root'],reader,root,trees)
            self.assertTrue(trees['root']['treeReferencesComplete']);self.assertIn(str(source.resolve()),reader.reused)
            source.write_text('{}')
            with self.assertRaises(ValueError):obtain_trees(['root'],reader,root,{})

    def test_origin_uses_exact_withdrawal_account_not_unrelated_batch_solver(self):
        message={"origin_nonce":7,"sender":"near:intents.near","token":"near:zec.omft.near","recipient":"zcash:ua","amount":"5"}
        instruction={"intent":"ft_withdraw","receiver_id":"omni.bridge.near","token":"zec.omft.near","amount":"5","msg":{"recipient":"zcash:ua"}}
        withdrawal={"account_id":"user",**{k:v for k,v in instruction.items() if k!='intent'}}
        def log(receipt,receiver,decoded,index=0):return {"receiptId":receipt,"receiver":receiver,"decoded":decoded,"index":index}
        trace={"nearTransactionHash":"root","outcomes":[{"receiptId":"user-receipt","executionStatus":"SuccessReceiptId","childReceiptIds":["origin"]},
                   {"receiptId":"origin","executionStatus":"SuccessValue","childReceiptIds":[]}],"logs":[
            log("origin","omni.bridge.near",{"InitTransferEvent":{"transfer_message":message}}),
            log("user-receipt","intents.near",{"standard":"dip4","event":"intents_executed","data":[{"account_id":"user"},{"account_id":"unrelated-erc191-solver"}]}),
            log("user-receipt","intents.near",{"standard":"dip4","event":"ft_withdraw","data":[withdrawal]},1),
            log("user-receipt","intents.near",{"standard":"nep245","event":"mt_burn","data":[{"owner_id":"user","token_ids":["nep141:zec.omft.near"],"amounts":["5"]}]},2)]}
        indexed={"initialised":{"transaction_hash":"root","details":{"receipt_id":"origin"}},
                 "sender":message['sender'],"token_id":message['token'],"recipient":message['recipient'],"amount":"5"}
        accepted={"receiptId":"user-receipt","message":{"intents":[instruction]}}
        with patch('trace_challenge7_new_receiver_pairs.accepted_intents',return_value=[accepted]) as mocked:
            result=indexed_origin(indexed,trace,7,'ua','5')
        mocked.assert_called_once_with(trace,'user')
        self.assertEqual(result['directAcceptedIntentsUsers'][0]['account'],'user')

    def test_atomic_credit_is_recipient_authorized_not_a_direct_sender_transfer(self):
        event={"senderAccount":"solver","recipientAccount":"user","receiptId":"receipt","token":"zec","amountRaw":"5"}
        accepted={"receiptId":"receipt","message":{"intents":[{"intent":"token_diff","diff":{"zec":"5","usdc":"-100"}}]}}
        with patch('trace_challenge7_new_receiver_pairs.accepted_intents',return_value=[accepted]) as mocked:
            result=bound_internal_credit({},event)
        mocked.assert_called_once_with({},'user')
        self.assertTrue(result['recipientSwapInstructionVerified']);self.assertFalse(result['acceptedInstructionVerified'])
        self.assertFalse(result['senderInstructionHashVerified']);self.assertNotIn('acceptedInstruction',result)


if __name__=="__main__":unittest.main()
