import hashlib
import json
import unittest
from audit_challenge7_rescued_quote_roles import KEEP, bind_match


class Tests(unittest.TestCase):
    def fixture(self):
        row = {'refundTo': 'ua', 'depositAddress': 'deposit', 'amountIn': '10'}
        match = {'rowCanonicalSha256': hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                 'metadata': {k: row.get(k) for k in KEEP}, 'field': 'refundTo',
                 'address': 'ua', 'receiverKind': 'orchard', 'receiverRaw': 'aa'}
        return row, match

    def test_exact_original_binding(self):
        row, match = self.fixture()
        bind_match(row, match, {'orchard': 'aa'})

    def test_changed_quote_rejected(self):
        row, match = self.fixture()
        row['amountIn'] = '11'
        with self.assertRaises(ValueError):
            bind_match(row, match, {'orchard': 'aa'})

    def test_other_receiver_type_rejected(self):
        row, match = self.fixture()
        with self.assertRaises(ValueError):
            bind_match(row, match, {'sapling': 'aa'})

    def test_changed_metadata_rejected(self):
        row, match = self.fixture()
        match['metadata']['amountIn'] = '12'
        with self.assertRaises(ValueError):
            bind_match(row, match, {'orchard': 'aa'})


if __name__ == '__main__':
    unittest.main()
