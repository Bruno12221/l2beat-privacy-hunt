import base64
import unittest

from trace_challenge7_user_origins import connector_deposit_links, exact_origin, mint_deposits, validate_transfers, CUTOFF_NS


def origin_fixture():
    connector = {"selectedRequest": {"transferOriginNonce": 22631, "targetAddress": "t1receiver"},
                 "actualBuilderPacket": {"amountZat": "232000"}, "payoutTxid": "payout", "nearRoot": "builder"}
    intent = {"intent": "ft_withdraw", "token": "nzec.bridge.near", "receiver_id": "omni.bridge.near",
              "amount": "232000", "msg": {"recipient": "zcash:t1receiver"}}
    signed = {"payload": {"message": {"signer_id": "user", "intents": [intent]}}, "public_key": "key", "standard": "nep413"}
    call = {"source": "receipt", "receiptId": "execute", "receiver": "intents.near", "method": "execute_intents",
            "executionStatus": "SuccessValue", "args": {"signed": [signed]}, "blockTime": "clock"}
    event = {"InitTransferEvent": {"transfer_message": {"origin_nonce": 22631, "token": "near:nzec.bridge.near",
                                                       "amount": "232000", "recipient": "zcash:t1receiver", "sender": "near:intents.near"}}}
    withdrawal = {"standard": "dip4", "event": "ft_withdraw", "data": [{"account_id": "user", "intent_hash": "hash", **intent}]}
    burn = {"standard": "nep245", "event": "mt_burn", "data": [{"owner_id": "user", "token_ids": ["nep141:nzec.bridge.near"], "amounts": ["232000"]}]}
    trace = {"nearTransactionHash": "origin", "calls": [call],
             "outcomes": [{"receiptId": "execute", "executionStatus": "SuccessValue", "childReceiptIds": ["init"]},
                          {"receiptId": "init", "executionStatus": "SuccessValue"}],
             "logs": [{"receiver": "intents.near", "receiptId": "execute", "index": 0, "decoded": withdrawal},
                      {"receiver": "intents.near", "receiptId": "execute", "index": 1, "decoded": burn},
                      {"receiver": "omni.bridge.near", "receiptId": "init", "index": 0, "decoded": event}]}
    return trace, connector


def deposit_fixture():
    account, token = "user", "eth-0xtoken.omft.near"
    deposit = {"source": "receipt", "receiptId": "deposit", "predecessor": "bridge-mng.near", "receiver": "omft.near",
               "method": "ft_deposit", "executionStatus": "SuccessReceiptId", "blockTime": "clock",
               "args": {"owner_id": "intents.near", "token": "eth-0xtoken", "amount": "9007199254740993",
                        "msg": {"receiver_id": account}, "memo": {"networkType": "eth", "chainId": "1", "txHash": "external"}}}
    callback = {"source": "receipt", "receiptId": "mint", "predecessor": token, "receiver": "intents.near",
                "method": "ft_on_transfer", "executionStatus": "SuccessValue", "blockTime": "clock",
                "blockTimestampNs": str(CUTOFF_NS-1), "args": {"amount": "9007199254740993", "sender_id": "omft.near"}}
    event = {"standard": "nep245", "event": "mt_mint", "data": [{"owner_id": account, "token_ids": ["nep141:"+token], "amounts": ["9007199254740993"]}]}
    trace = {"nearTransactionHash": "root", "calls": [deposit, callback],
             "outcomes": [{"receiptId": "deposit", "executionStatus": "SuccessReceiptId", "childReceiptIds": ["mint"]},
                          {"receiptId": "mint", "executionStatus": "SuccessValue"}],
             "logs": [{"receiver": "intents.near", "receiptId": "mint", "index": 0, "decoded": event}]}
    return trace


def connector_fixture(wallet=False, v2=False):
    recipient, amount = ("user" if wallet else "intents.near"), "1190000"
    raw = b"serialized-public-transaction"
    verify = {"source": "receipt", "receiptId": "verify", "receiver": "zcash-connector.bridge.near",
              "predecessor": "any-public-relayer", "executionStatus": "SuccessReceiptId",
              "method": "verify_deposit_v2" if v2 else "verify_deposit",
              "args": {"deposit_msg": {"recipient_id": recipient}, "vout": 0,
                       "tx_bytes": base64.b64encode(raw).decode() if v2 else list(raw),
                       "tx_block_blockhash": "block"}}
    callback = {"source": "receipt", "receiptId": "callback", "receiver": "zcash-connector.bridge.near",
                "predecessor": "zcash-connector.bridge.near", "executionStatus": "SuccessReceiptId",
                "method": "verify_safe_deposit_callback", "args": {"recipient_id": recipient,
                "mint_amount": amount, "protocol_fee": "9000", "relayer_fee": "1000",
                "msg": None if wallet else {"receiver_id": "user"}, "pending_utxo_info": {
                    "tx_id": "tx", "utxo_storage_key": "tx@0", "utxo": {"balance": "1200000", "vout": 0}}}}
    mint = {"source": "receipt", "receiptId": "mint", "receiver": "nzec.bridge.near",
            "predecessor": "zcash-connector.bridge.near", "executionStatus": "SuccessValue", "method": "mint",
            "args": {"mint_account_id": recipient, "mint_amount": amount}}
    trace = {"nearTransactionHash": "root", "calls": [verify, callback, mint], "outcomes": [
        {"receiptId": "verify", "childReceiptIds": ["callback"]},
        {"receiptId": "callback", "childReceiptIds": ["mint"]}, {"receiptId": "mint"}]}
    return trace, recipient, amount, None if wallet else "user"


class UserOriginTests(unittest.TestCase):
    def test_connector_v1_and_v2_preserve_original_bytes_and_gross_net(self):
        for wallet in (False, True):
            for v2 in (False, True):
                trace, recipient, amount, account = connector_fixture(wallet, v2)
                row = connector_deposit_links(trace, "mint", recipient, amount, account)[0]
                self.assertEqual(bytes.fromhex(row["rawHex"]), b"serialized-public-transaction")
                self.assertEqual(int(row["grossDepositZat"]), int(row["netMintZat"])+int(row["protocolFeeZat"])+int(row["relayerFeeZat"]))

    def test_connector_callback_requires_trusted_predecessor_and_ancestry(self):
        for mutation in ("predecessor", "ancestry", "recipient", "amount", "failure"):
            trace, recipient, amount, account = connector_fixture()
            if mutation == "predecessor":
                trace["calls"][1]["predecessor"] = "fake.near"
            elif mutation == "ancestry":
                trace["outcomes"][1]["childReceiptIds"] = []
            elif mutation == "recipient":
                trace["calls"][1]["args"]["msg"]["receiver_id"] = "another-user"
            elif mutation == "amount":
                trace["calls"][1]["args"]["mint_amount"] = "1"
            else:
                trace["calls"][1]["executionStatus"] = "Failure"
            self.assertEqual(connector_deposit_links(trace, "mint", recipient, amount, account), [])

    def test_connector_storage_key_must_agree_with_outpoint(self):
        trace, recipient, amount, account = connector_fixture()
        trace["calls"][1]["args"]["pending_utxo_info"]["utxo_storage_key"] = "other-tx@0"
        with self.assertRaises(ValueError):
            connector_deposit_links(trace, "mint", recipient, amount, account)

    def test_wallet_mint_requires_exact_recipient_and_trusted_token_call(self):
        for field, value in (("predecessor", "fake.near"), ("method", "ft_transfer")):
            trace, recipient, amount, account = connector_fixture(wallet=True)
            trace["calls"][2][field] = value
            self.assertEqual(connector_deposit_links(trace, "mint", recipient, amount, account), [])
        trace, recipient, amount, account = connector_fixture(wallet=True)
        trace["calls"][2]["args"]["mint_account_id"] = "other-user"
        self.assertEqual(connector_deposit_links(trace, "mint", recipient, amount, account), [])

    def test_exact_nonce_and_accepted_user_not_root_relayer(self):
        trace, connector = origin_fixture()
        trace["signer"] = "intents.near"
        row = exact_origin(trace, connector)[0]
        self.assertEqual(row["intentsAccount"], "user")
        self.assertEqual(row["originNonce"], 22631)
        self.assertEqual(row["payoutTxid"], "payout")

    def test_nonce_mismatch_is_not_amount_time_link(self):
        trace, connector = origin_fixture()
        connector["selectedRequest"]["transferOriginNonce"] += 1
        self.assertEqual(exact_origin(trace, connector), [])

    def test_origin_must_descend_from_accepted_instruction(self):
        trace, connector = origin_fixture()
        trace["outcomes"][0]["childReceiptIds"] = []
        self.assertEqual(exact_origin(trace, connector), [])

    def test_burn_account_and_token_must_match(self):
        trace, connector = origin_fixture()
        trace["logs"][1]["decoded"]["data"][0]["owner_id"] = "another-user"
        self.assertEqual(exact_origin(trace, connector), [])
        trace, connector = origin_fixture()
        trace["logs"][1]["decoded"]["data"][0]["token_ids"] = ["nep141:zec.omft.near"]
        self.assertEqual(exact_origin(trace, connector), [])

    def test_failed_or_root_only_instruction_is_not_accepted_execution(self):
        trace, connector = origin_fixture()
        trace["calls"][0]["executionStatus"] = "Failure"
        self.assertEqual(exact_origin(trace, connector), [])
        trace["calls"][0].update({"executionStatus": "SuccessValue", "source": "transaction"})
        self.assertEqual(exact_origin(trace, connector), [])

    def test_untrusted_origin_event_is_not_nonce_evidence(self):
        trace, connector = origin_fixture()
        trace["logs"][2]["receiver"] = "fake.near"
        self.assertEqual(exact_origin(trace, connector), [])

    def test_mint_and_external_identifier_require_exact_execution_ancestry(self):
        trace = deposit_fixture()
        row = mint_deposits(trace, "user")[0]
        self.assertEqual(row["classification"], "explicit-external-bridge-deposit-and-executed-mint")
        self.assertEqual(row["amountRaw"], "9007199254740993")
        trace["outcomes"][0]["childReceiptIds"] = []
        self.assertEqual(mint_deposits(trace, "user")[0]["externalDeposits"], [])

    def test_untrusted_bridge_memo_is_not_an_external_link(self):
        trace = deposit_fixture()
        trace["calls"][0]["predecessor"] = "fake.near"
        self.assertEqual(mint_deposits(trace, "user")[0]["externalDeposits"], [])

    def test_refund_mint_preserved_without_new_funding_claim(self):
        trace = deposit_fixture()
        trace["calls"][1].update({"method": "ft_resolve_withdraw", "predecessor": "intents.near"})
        row = mint_deposits(trace, "user")[0]
        self.assertEqual(row["classification"], "refund-or-unclassified-mint")
        self.assertEqual(row["externalDeposits"], [])

    def test_mint_cutoff_and_failed_receipt(self):
        trace = deposit_fixture()
        trace["calls"][1]["blockTimestampNs"] = str(CUTOFF_NS)
        self.assertEqual(mint_deposits(trace, "user"), [])
        trace = deposit_fixture()
        trace["outcomes"][1]["executionStatus"] = "Failure"
        self.assertEqual(mint_deposits(trace, "user"), [])

    def test_transfer_scope_and_integer_order(self):
        spec = {"account_id": "user", "to_timestamp_ms": CUTOFF_NS//1000000, "ignore_system": True}
        row = {"account_id": "user", "amount": "9007199254740993", "block_timestamp": str(CUTOFF_NS-1), "transfer_index": "1"}
        self.assertEqual(validate_transfers({"transfers": [row]}, spec, None)[1], None)
        for change in [{"account_id": "wrong"}, {"amount": "-1"}, {"block_timestamp": str(CUTOFF_NS)}, {"other_account_id": "system"}]:
            with self.assertRaises(ValueError):
                validate_transfers({"transfers": [{**row, **change}]}, spec, None)

    def test_transfer_cursor_must_advance_and_order_not_repeat(self):
        spec = {"account_id": "user", "to_timestamp_ms": CUTOFF_NS//1000000}
        row = {"account_id": "user", "amount": "1", "block_timestamp": "123", "transfer_index": "1"}
        with self.assertRaises(ValueError):
            validate_transfers({"transfers": [row], "resume_token": "same"}, spec, "same")
        with self.assertRaises(ValueError):
            validate_transfers({"transfers": [row]}, spec, None, (123, 1))


if __name__ == "__main__":
    unittest.main()
