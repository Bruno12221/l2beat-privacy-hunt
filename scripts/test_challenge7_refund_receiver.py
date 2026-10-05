import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from check_challenge7_refund_receiver import (
    DEPOSIT, DESTINATION, TARGET_TX, STATUS_URL, StatusReader, quote_refund, receiver_hex, recovered_outputs, compare,
)
from trace_challenge7_free_near import CheckpointStop


def status():
    return {'status':'SUCCESS','quoteResponse':{
        'quoteRequest':{'originAsset':'nep141:zec.omft.near','destinationAsset':'nep141:eth.omft.near',
                        'depositType':'ORIGIN_CHAIN','recipientType':'DESTINATION_CHAIN',
                        'recipient':DESTINATION,'refundType':'ORIGIN_CHAIN','refundTo':'u1test'},
        'quote':{'depositAddress':DEPOSIT,'amountIn':'3939182','amountOut':'22712389229785027'}},
        'swapDetails':{'depositedAmount':'3939182','amountOut':'22712389229785027',
                       'originChainTxHashes':[{'hash':TARGET_TX}]}}


def note_fixture():
    raw='ab'*43
    output={'recovered':True,'pool':'ironwood','actionIndex':0,'cmx':'cd'*32,
            'valueZat':4_000_000,'receiverRaw':raw}
    packet={'ok':True,'txid':'ef'*32,'blockHeight':3488000,'isCanonical':True,'outputs':[output]}
    identity=f"{packet['txid']}:ironwood:0:{output['cmx']}"
    note={'id':identity,'txid':packet['txid'],'pool':'ironwood','actionIndex':0,'cmx':output['cmx'],
          'valueZat':output['valueZat'],'receiverBytes':[raw],'anchorEligibility':'height-compatible'}
    return raw,packet,note


class RefundReceiverTests(unittest.TestCase):
    def test_only_exact_target_exit_status_is_accepted(self):
        self.assertEqual(quote_refund(status()),'u1test')
        value=status();value['status']='FAILED'
        with self.assertRaises(ValueError):quote_refund(value)
        for path, key, new in [('quote','depositAddress','other'),('quote','amountIn','3939181'),
                              ('quoteRequest','recipient','0x'+'0'*40),('quoteRequest','originAsset','eth'),
                              ('quoteRequest','refundType','INTENTS'),('quoteRequest','refundTo','0x123')]:
            value=status();value['quoteResponse'][path][key]=new
            with self.assertRaises(ValueError):quote_refund(value)
        value=status();value['swapDetails']['originChainTxHashes']=[{'hash':'other'}]
        with self.assertRaises(ValueError):quote_refund(value)

    def test_mainnet_exact_address_and_receiver_length_required(self):
        decoded={'ok':True,'address':'u1test','network':'Main',
                 'receivers':[{'kind':'orchard','bytes':43,'rawHex':'ab'*43}]}
        self.assertEqual(receiver_hex(decoded,'u1test'),'ab'*43)
        for changes in ({'ok':False},{'address':'other'},{'network':'Test'},
                        {'receivers':[]},{'receivers':decoded['receivers']*2}):
            with self.assertRaises(ValueError):receiver_hex({**decoded,**changes},'u1test')

    def test_all_notes_are_compared_without_amount_shortlist(self):
        raw,packet,note=note_fixture()
        packet['outputs'][0]['valueZat']=note['valueZat']=1
        outputs,_=recovered_outputs([packet])
        matched,controls=compare([note],outputs,raw)
        self.assertEqual(matched,[note]);self.assertEqual(controls,[])

    def test_changed_diversifier_is_not_an_exact_receiver_match(self):
        raw,packet,note=note_fixture();outputs,_=recovered_outputs([packet])
        matched,_=compare([note],outputs,'00'+raw[2:])
        self.assertEqual(matched,[])

    def test_matching_unqualified_and_zero_outputs_remain_controls(self):
        raw,packet,_=note_fixture();packet['outputs'][0]['valueZat']=0
        packet['blockHeight']=None;packet['isCanonical']=None
        outputs,_=recovered_outputs([packet])
        matched,controls=compare([],outputs,raw)
        self.assertEqual(matched,[]);self.assertEqual(len(controls),1)
        self.assertFalse(controls[0]['inEligibleBaseline'])

    def test_opaque_outputs_cannot_be_compared_as_recovered_notes(self):
        raw,packet,note=note_fixture();packet['outputs'][0]={'pool':'ironwood','recovered':False}
        outputs,opaque=recovered_outputs([packet])
        self.assertEqual(opaque,{'ironwood':1});self.assertEqual(outputs,{})
        with self.assertRaises(ValueError):compare([note],outputs,raw)

    def test_duplicate_or_disagreeing_evidence_fails(self):
        raw,packet,note=note_fixture();outputs,_=recovered_outputs([packet])
        with self.assertRaises(ValueError):compare([note,note],outputs,raw)
        for changes in ({'valueZat':1},{'receiverBytes':['00'*43]}, {'anchorEligibility':'after-anchor'},
                        {'actionIndex':1},{'cmx':'00'*32}):
            with self.assertRaises(ValueError):compare([{**note,**changes}],outputs,raw)
        changed=copy.deepcopy(packet);changed['outputs'][0]['receiverRaw']='00'*43
        with self.assertRaises(ValueError):recovered_outputs([packet,changed])

    def test_curl_preserves_original_bytes_and_cache_prevents_new_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            raw=json.dumps(status()).encode()
            reader=StatusReader(Path(directory),True,1,3,'curl')
            with patch('check_challenge7_refund_receiver.time.sleep'), patch(
                    'check_challenge7_refund_receiver.subprocess.run',return_value=SimpleNamespace(stdout=raw+b'\n200')) as call:
                self.assertEqual(reader.request(STATUS_URL),status())
                self.assertEqual(reader.request(STATUS_URL),status())
                call.assert_called_once();self.assertEqual(reader.calls,1)
            path=next((Path(directory)/'http-responses').glob('*.json'))
            saved=json.loads(path.read_text());saved['rawUtf8']='{}'
            path.write_text(json.dumps(saved))
            with self.assertRaises(ValueError):reader.request(STATUS_URL)

    def test_transport_is_one_explicit_get_and_stops_on_rate_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            reader=StatusReader(Path(directory),True,1,3,'curl')
            with self.assertRaises(ValueError):reader.request('https://example.com')
            with self.assertRaises(ValueError):reader.request(STATUS_URL,{})
            with patch('check_challenge7_refund_receiver.time.sleep'), patch(
                    'check_challenge7_refund_receiver.subprocess.run',return_value=SimpleNamespace(stdout=b'{}\n429')) as call:
                with self.assertRaises(CheckpointStop):reader.request(STATUS_URL)
                with self.assertRaises(CheckpointStop):reader.request(STATUS_URL)
                call.assert_called_once()


if __name__=='__main__':unittest.main()
