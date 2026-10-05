import unittest
import argparse
import json
import tempfile
import urllib.error
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse,parse_qs
import collect_challenge7_outgoing_quotes as check


class Tests(unittest.TestCase):
    def state(self):
        return {'windowStart':'2026-01-01T00:00:00.000000Z',
                'windowEnd':'2026-01-08T00:00:00.000000Z',
                'lastDepositAddress':None,'lastDepositMemo':None,'complete':False}

    def row(self,**extra):
        return {'originAsset':'nep141:zec.omft.near','destinationAsset':'eth','depositAddress':'d',
                'depositMemo':None,'status':'SUCCESS','createdAt':'2026-01-02T00:00:00Z',**extra}

    def test_query_origin_not_destination_amount_or_referral(self):
        q=parse_qs(urlparse(check.query(self.state())).query)
        self.assertEqual(q['fromChainId'],['zec'])
        self.assertEqual(q['numberOfTransactions'],['1000'])
        self.assertNotIn('toChainId',q); self.assertNotIn('minUsdPrice',q)
        self.assertNotIn('referral',q)

    def test_rejects_unbounded_or_nonmatching_response(self):
        self.assertEqual(check.validate_page([self.row()],self.state())[0]['depositAddress'],'d')
        for rows in ({},[self.row(originAsset='eth')],[self.row(createdAt='2025-12-31T00:00:00Z')]):
            with self.assertRaises(ValueError): check.validate_page(rows,self.state())

    def test_cursor_memo_and_nonadvancing_page(self):
        rows=[self.row(depositMemo='m')]*1000
        state=self.state(); state['lastDepositAddress']='d'; state['lastDepositMemo']='m'
        with self.assertRaises(ValueError): check.validate_page(rows,state)
        result=check.advance(self.state(),rows,check.stamp('2025-01-01T00:00:00Z'),7)
        self.assertEqual(result['lastDepositMemo'],'m')
        self.assertEqual(parse_qs(urlparse(check.query(result)).query)['lastDepositMemo'],['m'])

    def test_exclusive_boundaries_overlap_and_completion(self):
        state=self.state(); floor=check.stamp('2025-12-01T00:00:00Z')
        result=check.advance(state,[],floor,7)
        self.assertEqual(check.stamp(result['windowEnd']),check.stamp(state['windowStart'])+check.OVERLAP)
        self.assertFalse(result['complete'])
        self.assertTrue(check.advance(state,[],check.stamp(state['windowStart']),7)['complete'])

    def test_server_error_shrinks_time_interval_without_repeating_cursor(self):
        state=self.state(); state['lastDepositAddress']='d'
        result=check.shrink(state)
        self.assertGreater(check.stamp(result['windowStart']),check.stamp(state['windowStart']))
        self.assertEqual(result['windowEnd'],state['windowEnd'])
        self.assertIsNone(result['lastDepositAddress'])
        result['windowStart']=check.iso(check.stamp(result['windowEnd'])-timedelta(hours=1))
        with self.assertRaises(ValueError): check.shrink(result)

    def test_explicit_timezone_required(self):
        with self.assertRaises(ValueError): check.stamp('2026-01-01T00:00:00')

    def test_credentials_never_forwarded_on_redirect(self):
        self.assertIsNone(check.NoRedirect().redirect_request(None,None,302,None,None,
                                                             'https://other.example/'))

    def test_reduced_status_scope_is_explicit_and_validated(self):
        state=self.state();state['scope']={'statuses':'FAILED,INCOMPLETE_DEPOSIT,PROCESSING,REFUNDED,SUCCESS'}
        q=parse_qs(urlparse(check.query(state)).query)
        self.assertNotIn('PENDING_DEPOSIT',q['statuses'][0])
        with self.assertRaises(ValueError):check.validate_page([self.row(status='PENDING_DEPOSIT')],state)
        self.assertEqual(check.validate_page([self.row()],state)[0]['status'],'SUCCESS')

    def test_only_timeouts_qualify_for_transport_recovery(self):
        self.assertTrue(check.is_timeout(TimeoutError('timed out')))
        self.assertTrue(check.is_timeout(urllib.error.URLError(TimeoutError('timed out'))))
        self.assertFalse(check.is_timeout(urllib.error.URLError('DNS failed')))
        self.assertFalse(check.is_timeout(ValueError('timed out')))

    def test_adaptive_windows_cover_the_older_failed_half_without_reexpanding(self):
        original=self.state(); narrowed=check.shrink(original,'transport timeout')
        after=check.advance(narrowed,[],check.stamp('2025-12-01T00:00:00Z'),
                            narrowed['adaptiveWindowDays'])
        self.assertEqual(check.stamp(after['windowEnd']),
                         check.stamp(narrowed['windowStart'])+check.OVERLAP)
        self.assertLessEqual(check.stamp(after['windowStart']),check.stamp(original['windowStart'])+check.OVERLAP)
        self.assertEqual(after['adaptiveWindowDays'],3.5)

    def args(self):
        return argparse.Namespace(output_dir='challenge7-test',statuses=check.ALL_STATUSES,
            since='2026-01-01T00:00:00Z',until='2026-01-08T00:00:00Z',window_days=7,
            max_http_calls=3,fetch=True,timeout=30)

    def test_timeout_then_short_pages_preserve_scope_and_finish(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self):return b'[]'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(check,'__file__',str(root/'scripts'/'collector.py')), \
                    patch.dict(check.os.environ,{'NEAR_INTENTS_JWT':'test-only'}), \
                    patch.object(check.time,'sleep'),patch.object(check.urllib.request,'build_opener') as build:
                build.return_value.open.side_effect=[TimeoutError('timed out'),Response(),Response(),Response()]
                args=self.args();args.max_http_calls=4
                check.collect(args)
                state=json.loads((root/'challenge7-test'/'checkpoint.json').read_text())
                manifest=json.loads((root/'challenge7-test'/'manifest.json').read_text())
                self.assertTrue(state['complete']);self.assertEqual(state['successfulPages'],3)
                self.assertEqual(state['timeoutWindows'],1)
                self.assertEqual(state['scope']['windowDays'],7)
                self.assertEqual(state['adaptiveWindowDays'],3.5)
                self.assertEqual(manifest['newHttpCallsThisRun'],4)
                self.assertFalse((root/'challenge7-test'/'collector.lock').exists())

    def test_rate_limit_stops_without_retry_or_shrink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(check,'__file__',str(root/'scripts'/'collector.py')), \
                    patch.dict(check.os.environ,{'NEAR_INTENTS_JWT':'test-only'}), \
                    patch.object(check.time,'sleep'),patch.object(check.urllib.request,'build_opener') as build:
                build.return_value.open.side_effect=urllib.error.HTTPError('https://example.test',429,'rate',{},None)
                with self.assertRaises(SystemExit):check.collect(self.args())
                state=json.loads((root/'challenge7-test'/'checkpoint.json').read_text())
                self.assertNotIn('adaptiveWindowDays',state)
                self.assertEqual(build.return_value.open.call_count,1)

    def test_minimum_window_timeout_stops_and_preserves_checkpoint(self):
        state=self.state()
        state['windowStart']=check.iso(check.stamp(state['windowEnd'])-timedelta(hours=1))
        with self.assertRaisesRegex(ValueError,'checkpointed'):
            check.shrink(state,'transport timeout')


if __name__=='__main__': unittest.main()
