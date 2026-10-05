import unittest
from unittest.mock import patch
import rescue_challenge7_missing_connector_trees as check


class Tests(unittest.TestCase):
    def test_unrequested_tree_cannot_enter_inventory(self):
        with self.assertRaises(ValueError):check.entries({'transactions':[{'transaction':{'hash':'other'}}]}, {'wanted'})

    def test_duplicate_tree_is_not_independent_evidence(self):
        entry={'transaction':{'hash':'wanted'}}
        with self.assertRaises(ValueError):check.entries({'transactions':[entry,entry]}, {'wanted'})

    def test_missing_returned_roots_remain_absent(self):
        self.assertEqual(check.entries({'transactions':[]},{'wanted'}),{})

    def test_tree_root_must_match_request(self):
        with self.assertRaises(ValueError):check.audit_request({'nearRoot':'wanted'}, {'transaction':{'hash':'other'}},{})

    def test_explicit_pending_identifier_never_becomes_settlement(self):
        request={'nearRoot':'root','listedReceiptId':'receipt','error':'RPC-root-cache-missing'}
        with patch.object(check,'full_tree_rpc_result',return_value={}), \
                patch.object(check,'rpc_pending_ids',return_value=([{'txid':'00'*32}],None)):
            result=check.audit_request(request,{'transaction':{'hash':'root'}},{'sha256':'source'})
        self.assertTrue(result['explicitPendingIdentifierRecovered'])
        self.assertFalse(result['settlementProven']);self.assertFalse(result['targetPrivateSpendLink'])
        self.assertIsNone(result['error'])

    def test_incomplete_tree_is_retained_as_unresolved(self):
        request={'nearRoot':'root','listedReceiptId':'receipt','error':'RPC-root-cache-missing'}
        with patch.object(check,'full_tree_rpc_result',side_effect=ValueError('incomplete')):
            result=check.audit_request(request,{'transaction':{'hash':'root'}},{})
        self.assertFalse(result['explicitPendingIdentifierRecovered'])
        self.assertEqual(result['error'],'full-tree-validation: incomplete')


if __name__=='__main__':unittest.main()
