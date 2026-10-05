import unittest
from enrich_challenge7_pending_notes import enrich,ironwood_queue,validate_envelope,ANCHOR
import hashlib,json


class PendingEnrichmentTests(unittest.TestCase):
    def test_all_ironwood_including_opaque_and_small_notes_are_selected(self):
        rows=[{"ok":True,"txid":"a","bundles":[{"pool":"ironwood"}],"outputs":[]},
              {"ok":True,"txid":"b","bundles":[{"pool":"orchard"}],"outputs":[]}]
        self.assertEqual(ironwood_queue(rows),rows[:1])
        with self.assertRaises(ValueError):ironwood_queue(rows+rows[:1])

    def test_height_requires_matching_canonical_identity(self):
        raw={"txid":"a","isCanonical":None,"blockHeight":None}
        detail={"txid":"a","isCanonical":True,"blockHash":"block","hasIronwood":True,
                "blockHeight":ANCHOR,"blockTime":1789812000}
        row,status=enrich(raw,detail,{"path":"source"})
        self.assertEqual(status,"height-compatible");self.assertEqual(row["blockHeight"],ANCHOR)
        self.assertIsNone(raw["blockHeight"])
        self.assertEqual(enrich(raw,{**detail,"blockHeight":ANCHOR+1},{})[1],"after-target-anchor")
        self.assertEqual(enrich(raw,{**detail,"isCanonical":False},{})[1],"noncanonical-or-unverified")
        with self.assertRaises(ValueError):enrich(raw,{**detail,"txid":"b"},{})
        with self.assertRaises(ValueError):enrich(raw,{**detail,"hasIronwood":False},{})

    def test_source_hash_and_parsed_bytes_are_checked(self):
        payload=json.dumps({"txid":"a"})
        envelope={"url":"url","rawUtf8":payload,"responseBytesSha256":hashlib.sha256(payload.encode()).hexdigest()}
        self.assertEqual(validate_envelope(envelope,"url"),{"txid":"a"})
        with self.assertRaises(ValueError):validate_envelope({**envelope,"response":{}},"url")
        with self.assertRaises(ValueError):validate_envelope(envelope,"other")


if __name__=="__main__":unittest.main()
