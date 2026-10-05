import unittest
from verify_challenge7_exact_pair_funding import verify_deposit_output,ANCHOR


def fixture():
    link={'zecTxid':'tx','vout':0,'grossDepositZat':'9007199254740993','proofBlockHash':'block'}
    detail={'txid':'tx','isCanonical':True,'blockHash':'block','blockHeight':ANCHOR,'blockTime':1789812000,
            'outputs':[{'vout_index':0,'value':'9007199254740993'}]}
    decoded={'ok':True,'txid':'tx','transparentOutputs':[{'index':0,'valueZat':9007199254740993,'scriptPubKeyHex':'abcd'}]}
    return link,detail,decoded,'2026-09-19T10:01:10Z'


class ExactPairFundingTests(unittest.TestCase):
    def test_exact_deposit_outpoint_and_value_not_float(self):
        row=verify_deposit_output(*fixture())
        self.assertEqual(row['outpoint'],'tx:0');self.assertEqual(row['valueZat'],'9007199254740993')
        self.assertTrue(row['rawOutpointVerified'])

    def test_raw_indexed_identity_canonicality_proof_block_and_value_gates(self):
        for field,value in (('txid','other'),('isCanonical',False),('blockHash','other'),('blockHeight',ANCHOR+1)):
            link,detail,decoded,clock=fixture();detail[field]=value
            with self.assertRaises(ValueError):verify_deposit_output(link,detail,decoded,clock)
        link,detail,decoded,clock=fixture();decoded['ok']=False
        with self.assertRaises(ValueError):verify_deposit_output(link,detail,decoded,clock)
        link,detail,decoded,clock=fixture();detail['outputs'][0]['value']='1'
        with self.assertRaises(ValueError):verify_deposit_output(link,detail,decoded,clock)
        link,detail,decoded,clock=fixture();link['vout']=1
        with self.assertRaises(ValueError):verify_deposit_output(link,detail,decoded,clock)

    def test_zcash_deposit_cannot_be_after_actual_near_mint(self):
        link,detail,decoded,clock=fixture();detail['blockTime']=1789813000
        with self.assertRaises(ValueError):verify_deposit_output(link,detail,decoded,clock)


if __name__=='__main__':unittest.main()
