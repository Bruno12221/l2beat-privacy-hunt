import unittest
import verify_challenge7_candidate_history as v
from trace_challenge7_candidate_history import CANDIDATE


class Tests(unittest.TestCase):
    def fixture(self):
        h='0x'+'a'*64;b='0x'+'b'*64
        row={'hash':h,'from':{'hash':CANDIDATE},'to':{'hash':'0x'+'1'*40},
             'value':'0','timestamp':'2026-01-01T00:00:00Z','status':'ok'}
        tx={'hash':h,'blockHash':b,'blockNumber':'0x1','from':CANDIDATE,
            'to':'0x'+'1'*40,'value':'0x0','nonce':'0x0'}
        receipt={'transactionHash':h,'blockHash':b,'blockNumber':'0x1','status':'0x0','logs':[]}
        block={'hash':b,'number':'0x1','timestamp':hex(1767225600)}
        return row,tx,receipt,block

    def test_failed_nonce_zero_requires_explicit_nonfunding_exception(self):
        data=self.fixture()
        with self.assertRaises(ValueError):v.verify(*data,'transactions')
        result=v.verify(*data,'transactions',allow_failed_nonce_zero=True)
        self.assertFalse(result['receiptSuccess']);self.assertTrue(result['indexerSuccessDisagreement'])

    def test_failed_positive_value_never_promoted(self):
        row,tx,r,b=self.fixture();row['value']='1';tx['value']='0x1'
        with self.assertRaises(ValueError):v.verify(row,tx,r,b,'transactions',True)

    def test_native_identity_and_clock_must_match(self):
        row,tx,r,b=self.fixture();r['status']='0x1';tx['to']='0x'+'2'*40
        with self.assertRaises(ValueError):v.verify(row,tx,r,b,'transactions')
        tx['to']=row['to']['hash'];row['timestamp']='2026-01-02T00:00:00Z'
        with self.assertRaises(ValueError):v.verify(row,tx,r,b,'transactions')

    def test_exact_wrapped_event_and_dns(self):
        name=b'\x04test\x03eth\x00'
        data=(128).to_bytes(32,'big')+bytes.fromhex(CANDIDATE[2:]).rjust(32,b'\x00')+b'\x00'*64
        data+=len(name).to_bytes(32,'big')+name
        log={'address':'0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401',
             'topics':['0x8ce7013e8abebc55c3890a68f5a27c67c3f7efa64e584de5fb22363c606fd340','0x'+'a'*64],
             'data':'0x'+data.hex()}
        self.assertEqual(v.wrapped_names([log])[0]['name'],'test.eth')
        self.assertEqual(v.wrapped_names([log])[0]['owner'],CANDIDATE)
        log['address']='0x'+'1'*40;self.assertEqual(v.wrapped_names([log]),[])


if __name__=='__main__':unittest.main()
