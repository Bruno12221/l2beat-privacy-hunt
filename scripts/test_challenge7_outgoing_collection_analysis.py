import unittest
import json
import hashlib
import tempfile
from pathlib import Path
from urllib.parse import urlencode
from analyze_challenge7_outgoing_collection import window_chain, page_source, live_snapshot, exhausted_intervals, API


class Tests(unittest.TestCase):
    def state(self,address=None):return {'lastDepositAddress':address,'lastDepositMemo':None}
    def row(self,address='d',clock='2026-01-02T00:00:00Z'):
        return {'depositAddress':address,'depositMemo':None,'createdAt':clock}

    def test_terminal_short_page_is_exhausted(self):
        result=window_chain([(self.state(),[self.row()],{})])
        self.assertTrue(result['exhausted']);self.assertEqual(result['rowOccurrences'],1)

    def test_full_page_with_missing_cursor_is_incomplete(self):
        result=window_chain([(self.state(),[self.row()]*1000,{})])
        self.assertFalse(result['exhausted']);self.assertEqual(result['missingNextCursor'],['d',None])

    def test_linked_empty_final_page_is_exhausted(self):
        result=window_chain([(self.state(),[self.row()]*1000,{}),(self.state('d'),[],{})])
        self.assertTrue(result['exhausted']);self.assertEqual(result['pages'],2)

    def test_duplicate_cursor_fails(self):
        with self.assertRaises(ValueError):window_chain([(self.state(),[],{}),(self.state(),[],{})])

    def test_unreachable_page_fails(self):
        with self.assertRaises(ValueError):window_chain([(self.state(),[],{}),(self.state('other'),[],{})])

    def test_cycle_fails(self):
        with self.assertRaises(ValueError):window_chain([(self.state(),[self.row()]*1000,{}),
                                                        (self.state('d'),[self.row()]*1000,{})])

    def test_forward_time_on_following_page_fails(self):
        with self.assertRaises(ValueError):window_chain([(self.state(),[self.row()]*1000,{}),
            (self.state('d'),[self.row('e','2026-01-03T00:00:00Z')],{})])

    def test_new_status_scope_cannot_be_analyzed_as_old_scope(self):
        statuses='FAILED,INCOMPLETE_DEPOSIT,PROCESSING,REFUNDED,SUCCESS'
        url=API+'?'+urlencode({'numberOfTransactions':'1000','direction':'next','fromChainId':'zec',
            'statuses':statuses,'startTimestamp':'2026-01-01T00:00:00Z','endTimestamp':'2026-01-02T00:00:00Z'})
        env={'url':url,'request':None,'httpStatus':200,'response':[],
             'rawUtf8':'[]','responseBytesSha256':hashlib.sha256(b'[]').hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/(hashlib.sha256(url.encode()).hexdigest()+'.json');path.write_text(json.dumps(env))
            with self.assertRaises(ValueError):page_source(path)
            self.assertEqual(page_source(path,statuses)[0],[])

    def test_snapshot_never_claims_a_live_checkpoint_is_terminal_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);src=repo/'challenge7-live';src.mkdir()
            cp={'scope':{'statuses':'SUCCESS'},'successfulPages':0,'rowOccurrences':0,'complete':False}
            (src/'checkpoint.json').write_text(json.dumps(cp))
            target,out=live_snapshot(repo,src)
            result=json.loads((target/'manifest.json').read_text())
            self.assertTrue(result['snapshot']);self.assertFalse(result['retrievalComplete'])
            self.assertEqual((target/'checkpoint.json').read_bytes(),(src/'checkpoint.json').read_bytes())
            self.assertFalse((src/'manifest.json').exists())

    def test_snapshot_rejects_in_flight_page_count_disagreement(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);src=repo/'challenge7-live';src.mkdir()
            cp={'scope':{'statuses':'SUCCESS'},'successfulPages':1,'rowOccurrences':1,'complete':False}
            (src/'checkpoint.json').write_text(json.dumps(cp))
            with self.assertRaisesRegex(ValueError,'collector saving'):
                live_snapshot(repo,src)

    def test_only_exhausted_overlapping_intervals_merge(self):
        windows=[{'start':'2026-01-01T00:00:00Z','end':'2026-01-02T00:00:00Z','exhausted':True},
                 {'start':'2026-01-01T23:59:59Z','end':'2026-01-03T00:00:00Z','exhausted':True},
                 {'start':'2025-01-01T00:00:00Z','end':'2026-01-01T00:00:00Z','exhausted':False}]
        result=exhausted_intervals(windows)
        self.assertEqual(len(result),1);self.assertEqual(result[0]['durationSeconds'],172800)

    def test_touching_exclusive_query_bounds_do_not_hide_a_point_gap(self):
        windows=[{'start':'2026-01-01T00:00:00Z','end':'2026-01-02T00:00:00Z','exhausted':True},
                 {'start':'2026-01-02T00:00:00Z','end':'2026-01-03T00:00:00Z','exhausted':True}]
        self.assertEqual(len(exhausted_intervals(windows)),2)


if __name__=='__main__':unittest.main()
