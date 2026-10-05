import copy
import unittest
from collect_challenge7_raw_batches import ANCHOR, selected_queue, selected_pending_queue, validate_batch


class RawBatchTests(unittest.TestCase):
    def test_pending_selection_does_not_invent_height_or_apply_amount_filter(self):
        r={"txid":"a"*64,"evidenceClass":"successful-descendant-pending-ID-not-settlement-by-itself",
           "nearTime":"2026-09-19T09:57:37Z","blockHeight":None}
        self.assertEqual(selected_pending_queue([r]),[r])
        self.assertIsNone(r["blockHeight"])
        for bad in ([r,r],[{**r,"evidenceClass":"nearest-time-guess"}],[{**r,"txid":"bad"}]):
            with self.assertRaises(ValueError):selected_pending_queue(bad)

    def test_success_failure_sets_must_partition_requested_ids(self):
        value = {"transactions": [{"txid": "a", "hex": "0001"}], "failed": [{"txid": "b", "success": False}], "total": 2, "successful": 1}
        raw, failed = validate_batch(value, ["a", "b"])
        self.assertEqual(set(raw), {"a"}); self.assertEqual(set(failed), {"b"})
        for bad in ({**value, "total": 3}, {**value, "successful": 2}, {**value, "failed": []},
                    {**value, "transactions": value["transactions"]*2},
                    {**value, "failed": [{"txid": "a"}]}, {**value, "failed": [{"txid": "other"}]}):
            with self.assertRaises(ValueError): validate_batch(bad, ["a", "b"])

    def test_raw_hex_must_be_present_and_decodable(self):
        for raw in (None, 3, "xyz", "0"):
            with self.assertRaises(ValueError):
                validate_batch({"transactions": [{"txid": "a", "hex": raw}], "total": 1, "successful": 1}, ["a"])

    def test_selection_includes_dust_and_arbitrary_large_change(self):
        rows = [{"txid": str(i)*64, "blockHeight": h, "ironwoodNetInflowZat": v} for i,(h,v) in enumerate(
            [(3428143, 1), (ANCHOR, 999999999999), (3428142, 10), (ANCHOR+1, 10), (ANCHOR, 0), (ANCHOR, -1)])]
        self.assertEqual([r["txid"] for r in selected_queue(rows)], ["0"*64, "1"*64])
        with self.assertRaises(ValueError): selected_queue([rows[0], copy.deepcopy(rows[0])])


if __name__ == "__main__": unittest.main()
