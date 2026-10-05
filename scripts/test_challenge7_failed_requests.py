import unittest
from copy import deepcopy
from audit_challenge7_failed_requests import classify


def execution():
    return {'transaction': {'hash': 'root'}, 'receipts_outcome': [
        {'id': 'origin', 'outcome': {'executor_id': 'zcash-connector.bridge.near',
         'receipt_ids': ['callback'], 'status': {'SuccessReceiptId': 'callback'}, 'logs': []}},
        {'id': 'callback', 'outcome': {'executor_id': 'zcash-connector.bridge.near',
         'receipt_ids': [], 'status': {'Failure': {'ActionError': {'kind': {
         'FunctionCallError': {'ExecutionError': 'Smart contract panicked: UTXO ab@0 not exist'}}}}}, 'logs': []}}]}


class Tests(unittest.TestCase):
    def test_failed_callback_not_successful_withdrawal(self):
        value = classify(execution(), 'root', 'origin')
        self.assertEqual(value['classification'], 'failed-connector-descendant-no-pending-ID')
        self.assertEqual(value['connectorFailures'][0]['reason'], 'utxo-not-exist')
        for k in ('settlementProven', 'refundProven', 'walletExcluded', 'targetPrivateSpendLink'):
            self.assertFalse(value[k])

    def test_unrelated_failed_receipt_not_a_descendant(self):
        value = execution()
        value['receipts_outcome'][0]['outcome']['receipt_ids'] = []
        value['receipts_outcome'][0]['outcome']['status'] = {'SuccessValue': ''}
        result = classify(value, 'root', 'origin')
        self.assertEqual(result['connectorFailures'], [])

    def test_other_executor_failure_not_connector_failure(self):
        value = execution()
        value['receipts_outcome'][1]['outcome']['executor_id'] = 'other.near'
        self.assertEqual(classify(value, 'root', 'origin')['connectorFailures'], [])

    def test_root_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            classify(execution(), 'other-root', 'origin')

    def test_incomplete_descendant_graph_rejected(self):
        value = execution()
        value['receipts_outcome'].pop()
        with self.assertRaises(ValueError):
            classify(value, 'root', 'origin')

    def test_pending_event_cannot_be_classified_as_missing(self):
        value = deepcopy(execution())
        value['receipts_outcome'][0]['outcome']['logs'] = [
            'EVENT_JSON:{"standard":"bridge","event":"generate_btc_pending_info",'
            '"data":[{"btc_pending_id":"' + 'ab' * 32 + '"}]}']
        with self.assertRaises(ValueError):
            classify(value, 'root', 'origin')


if __name__ == '__main__':
    unittest.main()
