import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

import check_challenge7_quote_receiver_reuse as check


def packet(raw='11'*43, kind='orchard', network='Main', address='u1control'):
    return {'ok':True, 'network':network, 'address':address, 'canonicalAddress':address,
            'receivers':[{'kind':kind, 'typecode':{'orchard':3, 'sapling':2}[kind],
                          'bytes':43, 'rawHex':raw}]}


class Tests(unittest.TestCase):
    def test_exact_typed_receiver_not_prefix_or_whole_address(self):
        target = {'orchard':'11'*43}
        self.assertEqual(check.matching_types(packet(address='u1different'), target), ['orchard'])
        self.assertEqual(check.matching_types(packet('22'+'11'*42), target), [])
        self.assertEqual(check.matching_types(packet(kind='sapling'), target), [])
        self.assertEqual(check.matching_types(packet(network='Test'), target), [])

    def test_sapling_is_compared_independently(self):
        self.assertEqual(check.matching_types(packet(kind='sapling'), {'sapling':'11'*43}), ['sapling'])

    def test_invalid_or_duplicate_receivers_stop(self):
        p = packet(); p['receivers'][0]['typecode'] = 2
        with self.assertRaises(ValueError): check.typed_receivers(p)
        p = packet(); p['receivers'] *= 2
        with self.assertRaises(ValueError): check.typed_receivers(p)

    def test_decoder_failures_position_mapped_and_partial_output_rejected(self):
        stdout = json.dumps({'ok':False, 'error':'bad checksum'})+'\n'
        with patch.object(check.subprocess, 'run', return_value=CompletedProcess([],0,stdout,'')):
            self.assertEqual(check.decode_batch(['u1bad'], Path('/decoder'))[0]['address'], 'u1bad')
            with self.assertRaises(ValueError): check.decode_batch(['u1a','u1b'], Path('/decoder'))

    def test_decoder_order_checked(self):
        stdout = json.dumps(packet(address='u1wrong'))+'\n'
        with patch.object(check.subprocess, 'run', return_value=CompletedProcess([],0,stdout,'')):
            with self.assertRaises(ValueError): check.decode_batch(['u1expected'], Path('/decoder'))

    def test_source_same_bytes_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'data.jsonl'
            # Test fixture creation only, never production evidence edits.
            raw = b'{"recipient":"u1control"}\n'; p.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            self.assertEqual(list(check.pinned_rows(p,sha,1))[0][1],sha)
            with self.assertRaises(ValueError): list(check.pinned_rows(p,'0'*64,1))
            with self.assertRaises(ValueError): list(check.pinned_rows(p,sha,2))

    def test_all_matches_retained_with_role_and_duplicate_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); raw = (json.dumps({'recipient':'u1same','refundTo':'u1same',
                'createdAt':'2026-01-01T00:00:00Z', 'depositAddress':'d'})+'\n').encode()
            for name in ('first','second'): (root/name).write_bytes(raw)
            pins = {name:(hashlib.sha256(raw).hexdigest(),1) for name in ('first','second')}
            with patch.object(check,'PINS',pins):
                rows = check.matching_occurrences(root,{'u1same':{'receiverTypesMatched':['orchard']}},
                                                {'quoteTimestamp':'2026-09-19T10:00:02.472Z'})
            self.assertEqual(len(rows),4)
            self.assertEqual({r['source'] for r in rows}, {'first','second'})
            self.assertEqual({r['field'] for r in rows}, {'recipient','refundTo'})
            self.assertTrue(all(r['timing']=='before' and not r['ownershipProven'] for r in rows))
            # Four file/field occurrences but only two distinct deposit-role keys.
            self.assertEqual(len({(r['metadata']['depositAddress'],r['field'],r['address']) for r in rows}),2)

    def test_time_no_silent_future_filter(self):
        target = '2026-09-19T10:00:02.472Z'
        self.assertEqual(check.time_class('2027-01-01T00:00:00Z',target), 'after')
        self.assertEqual(check.time_class(None,target), 'unknown')
        self.assertEqual(check.time_class('2026-01-01T00:00:00',target), 'unknown')


if __name__ == '__main__': unittest.main()
