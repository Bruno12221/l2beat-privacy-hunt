import unittest
from audit_challenge7_receiver_chronology import classify,bind_status,hashes


class Tests(unittest.TestCase):
    def note(self):
        return {'id':'tx:ironwood:0:cm','txid':'tx','valueZat':3975000,'pool':'ironwood',
                'blockHeight':3470000,'blockTime':'2026-09-05T07:00:00Z'}

    def match(self):
        return {'field':'refundTo','receiverKind':'orchard','receiverRaw':'00'*43,
            'isTargetSelf':False,'source':'source','sourceSha256':'sha','rowIndex':0,'rowCanonicalSha256':'row',
            'metadata':{'createdAt':'2026-09-05T05:00:03Z','depositAddress':'deposit','depositMemo':None,
                'status':'REFUNDED','originAsset':'nep141:zec.omft.near','destinationAsset':'ltc',
                'recipient':'ltc-recipient','refundTo':'refund','amountIn':'4000000','amountOut':'76',
                'originChainTxHashes':['deposit-tx','tx'],'destinationChainTxHashes':[]}}

    def status(self):
        return {'status':'REFUNDED','quoteResponse':{'timestamp':'2026-09-05T05:00:00Z',
            'quote':{'depositAddress':'deposit','depositMemo':None,'amountIn':'4000000','amountOut':'76'},
            'quoteRequest':{'originAsset':'nep141:zec.omft.near','destinationAsset':'ltc',
                'refundTo':'refund','recipient':'ltc-recipient','refundType':'ORIGIN_CHAIN'}},
            'swapDetails':{'amountIn':None,'amountOut':None,'refundedAmount':'3968000',
                'depositedAmount':'4000000','refundFee':'32000',
                'originChainTxHashes':[{'hash':'deposit-tx'},{'hash':'tx'}],'destinationChainTxHashes':[]}}

    def test_later_note_listed_as_origin_is_not_called_a_spent_input(self):
        result=classify(self.note(),self.match())
        self.assertEqual(result['hashListRelation'],'origin-list')
        self.assertFalse(result['createdBeforeQuote']);self.assertFalse(result['noteConsumptionProven'])

    def test_prior_quote_clock_is_only_a_priority_not_spend_proof(self):
        note=self.note();note['blockTime']='2026-09-04T00:00:00Z'
        result=classify(note,self.match())
        self.assertTrue(result['createdBeforeQuote']);self.assertFalse(result['ownershipProven'])

    def test_refunded_null_actual_amounts_bind_to_quote_not_fake_execution(self):
        result=bind_status(self.status(),self.match(),self.note())
        self.assertEqual(result['explorerAmountBindings']['amountIn'],'quoted-not-executed')
        self.assertTrue(result['statusRouteBound']);self.assertIsNone(result['actualSwappedAmount'])
        self.assertFalse(result['exactReturnedNoteValueAndReceiver'])
        self.assertEqual(result['actualNoteMinusReportedRefundZat'],7000)
        self.assertEqual(result['grossUnswappedMinusActualNoteZat'],25000)

    def test_amount_mismatch_is_not_silently_ignored(self):
        status=self.status();status['quoteResponse']['quote']['amountOut']='77'
        with self.assertRaises(ValueError):bind_status(status,self.match(),self.note())

    def test_success_requires_actual_settlement_amounts(self):
        status=self.status();status['status']='SUCCESS'
        with self.assertRaises(ValueError):bind_status(status,self.match(),self.note())

    def test_route_binding_rejects_different_receiver(self):
        status=self.status();status['quoteResponse']['quoteRequest']['refundTo']='other'
        with self.assertRaises(ValueError):bind_status(status,self.match(),self.note())

    def test_hash_objects_and_strings_normalize_without_losing_case(self):
        self.assertEqual(hashes(['ABC',{'hash':'XYZ'}]),{'ABC','XYZ'})
        with self.assertRaises(ValueError):hashes([{}])


if __name__=='__main__':unittest.main()
