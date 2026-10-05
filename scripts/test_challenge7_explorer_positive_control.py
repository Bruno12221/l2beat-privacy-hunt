import unittest
import check_challenge7_explorer_positive_control as c

QUOTE='2026-09-19T10:00:02.472Z'


class Tests(unittest.TestCase):
    def row(self,**changes):
        return {'depositAddress':c.DEPOSIT,'status':'SUCCESS','originAsset':'nep141:zec.omft.near',
                'destinationAsset':'nep141:eth.omft.near','recipient':c.DESTINATION,
                'amountIn':'3862724','amountOut':'22712389229785027',
                'originChainTxHashes':[c.TARGET_TX],'createdAt':QUOTE,**changes}

    def test_queries_separate_chain_and_end_boundary(self):
        qs=dict(c.queries(QUOTE))
        self.assertNotIn('fromChainId',qs['deposit-unfiltered'])
        self.assertNotIn('endTimestamp',qs['deposit-zec-filter'])
        self.assertEqual(qs['deposit-original-end']['endTimestamp'],'2026-09-19T10:00:02.473000Z')
        self.assertEqual(qs['origin-tx-unfiltered']['search'],c.TARGET_TX)

    def test_known_route_binding(self):
        result=c.analyze_rows([self.row()],QUOTE)['exactDepositRows'][0]
        self.assertTrue(result['exactKnownRouteFields']);self.assertTrue(result['insideOriginalEndTimestamp'])
        self.assertFalse(result['targetPrivateSpendLink'])

    def test_delayed_explorer_creation_is_outside_original_window(self):
        result=c.analyze_rows([self.row(createdAt='2026-09-19T10:00:03Z')],QUOTE)['exactDepositRows'][0]
        self.assertTrue(result['exactKnownRouteFields']);self.assertFalse(result['insideOriginalEndTimestamp'])

    def test_wrong_deposit_is_not_positive_control(self):
        self.assertEqual(c.analyze_rows([self.row(depositAddress='other')],QUOTE)['exactDepositRows'],[])

    def test_amount_hash_or_destination_mismatch_not_known_route(self):
        for kw in ({'amountIn':'1'},{'originChainTxHashes':[]},{'recipient':'other'},{'status':'REFUNDED'}):
            self.assertFalse(c.analyze_rows([self.row(**kw)],QUOTE)['exactDepositRows'][0]['exactKnownRouteFields'])

    def test_dict_hash_representation_and_page_truncation_flag(self):
        self.assertTrue(c.analyze_rows([self.row(originChainTxHashes=[{'hash':c.TARGET_TX}])],QUOTE)
                        ['exactDepositRows'][0]['exactKnownRouteFields'])
        self.assertTrue(c.analyze_rows([self.row(depositAddress='other')]*1000,QUOTE)['pageMayBeTruncated'])

    def test_wrong_array_shape_rejected(self):
        for rows in ({},[None],[self.row()]*1001):
            with self.assertRaises(ValueError):c.analyze_rows(rows,QUOTE)

    def test_gross_deposit_not_the_explorer_swapped_amount(self):
        self.assertFalse(c.analyze_rows([self.row(amountIn='3939182')],QUOTE)
                         ['exactDepositRows'][0]['exactKnownRouteFields'])

    def test_expected_refund_and_execution_hashes_required(self):
        expected={'swappedAmountIn':'3862724','refundTo':'receiver','nearHashes':['near'],
                  'destinationHashes':['evm']}
        r=self.row(refundTo='receiver',nearTxHashes=['near'],destinationChainTxHashes=['evm'])
        self.assertTrue(c.analyze_rows([r],QUOTE,expected)['exactDepositRows'][0]['exactKnownRouteFields'])
        r['refundTo']='other'
        self.assertFalse(c.analyze_rows([r],QUOTE,expected)['exactDepositRows'][0]['exactKnownRouteFields'])


if __name__=='__main__':unittest.main()
