import hashlib
import json
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import check_challenge7_outgoing_quote_cache as check


class Tests(unittest.TestCase):
    def test_only_repository_source_directories(self):
        listing='\n'.join(['./challenge7-one/cache/near-bulk-api/1.json',
            './challenge7-one/cache/cipherscan/2.json','./challenge7-one/http-responses/3.json',
            './challenge7-one/analysis.json','./challenge6-one/pages/4.json',
            './decoder/target/test.json'])
        with patch.object(check.subprocess,'run',return_value=CompletedProcess([],0,listing,'')):
            paths=check.source_paths(Path('/explicit-repo'))
        self.assertEqual([str(p) for p in paths],['challenge7-one/cache/near-bulk-api/1.json',
                                                'challenge7-one/http-responses/3.json'])

    def test_original_response_bytes_required(self):
        raw='{"items":[]}\n'; value={'rawUtf8':raw,'response':{'items':[]},
            'responseBytesSha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertEqual(check.payload(value)[0],{'items':[]})
        value['response']={'items':[1]}
        with self.assertRaises(ValueError): check.payload(value)

    def test_nested_full_quote_is_counted_once(self):
        v={'status':'SUCCESS','quoteResponse':{'quoteRequest':{
            'originAsset':'nep141:zec.omft.near','destinationAsset':'nep141:eth.omft.near',
            'refundTo':'u1a'},'quote':{'depositAddress':'d'},'timestamp':'date'},
            'swapDetails':{'originChainTxHashes':[{'hash':'tx'}]}}
        nodes=list(check.route_nodes({'response':v}))
        self.assertEqual(len(nodes),1)
        self.assertEqual(nodes[0][0],'$/response')
        self.assertEqual(nodes[0][1]['depositAddress'],'d')
        self.assertEqual(nodes[0][2],'full-status-quote')

    def test_legacy_raw_only_body_and_failed_http_not_quote(self):
        raw='{"originAsset":"nep141:zec.omft.near","destinationAsset":"eth"}'
        v={'rawUtf8':raw,'responseBytesSha256':hashlib.sha256(raw.encode()).hexdigest(),
           'httpStatus':200}
        parsed,transport=check.payload(v)
        self.assertEqual(parsed['originAsset'],'nep141:zec.omft.near')
        self.assertFalse(transport['storedParsedResponsePresent'])
        v['httpStatus']=404
        self.assertIsNone(check.payload(v)[0])
        v['responseBytesSha256']='0'*64
        with self.assertRaises(ValueError): check.payload(v)

    def test_route_classes_do_not_hide_same_asset(self):
        a={'originAsset':'nep141:zec.omft.near','destinationAsset':'nep141:zec.omft.near'}
        self.assertEqual(check.classify(a),'zec-to-zec')
        a['destinationAsset']='nep141:eth.omft.near'
        self.assertEqual(check.classify(a),'zec-to-other-asset')
        a['originAsset']='nep141:eth.omft.near'
        self.assertEqual(check.classify(a),'non-zec-origin')

    def test_target_normalized_copy_is_not_new_evidence(self):
        self.assertTrue(check.self_status({'depositAddress':check.DEPOSIT},None))
        self.assertTrue(check.self_status({'originChainTxHashes':[{'hash':check.TARGET_TX}]},None))
        self.assertFalse(check.self_status({'depositAddress':'other'},None))
        with self.assertRaises(KeyError):
            check.self_status({'depositAddress':check.DEPOSIT},{'quoteResponse':{}})

    def test_metadata_fingerprint_stable_not_unique_wallet_identity(self):
        row={'depositAddress':'a','originAsset':'zec','destinationAsset':'eth','refundTo':'u1x'}
        self.assertEqual(check.route_key(row),check.route_key({**row,'unrelatedIndexerField':1}))
        self.assertNotEqual(check.route_key(row),check.route_key({**row,'refundTo':'u1y'}))


if __name__=='__main__': unittest.main()
