import unittest
import trace_challenge7_candidate_history as c


def row(address=c.CANDIDATE,peer='0x'+'1'*40,**kw):
    return {'from':{'hash':peer,'is_contract':False},'to':{'hash':address,'is_contract':False},
            'timestamp':'2026-01-01T00:00:00.000000Z','hash':'0x'+'a'*64,
            'status':'ok','value':'1',**kw}


class Tests(unittest.TestCase):
    def test_event_identity_ignores_nested_dictionary_order(self):
        r=row();r.update(transaction_hash=r['hash'],log_index=1,token={'address_hash':'token'},
                        total={'value':'10','decimals':'18'})
        second={**r,'total':{'decimals':'18','value':'10'}}
        self.assertEqual(c.item_id(r,'token-transfers'),c.item_id(second,'token-transfers'))

    def test_exact_subject_and_forward_cursor_checks(self):
        c.validate_page({'items':[row()],'next_page_params':None},c.CANDIDATE,'transactions')
        with self.assertRaises(ValueError):c.validate_page({'items':[row(address='other') ]},c.CANDIDATE,'transactions')
        with self.assertRaises(ValueError):c.validate_page({'items':[row()]},c.CANDIDATE,'transactions','2025-01-01')
        with self.assertRaises(ValueError):c.validate_page({'items':[],'next_page_params':{'index':1}},c.CANDIDATE,'transactions')

    def test_zero_failed_and_unknown_clock_not_promoted(self):
        self.assertIsNone(c.native_edge(row(value='0'),c.CANDIDATE))
        self.assertIsNone(c.native_edge(row(status='error'),c.CANDIDATE))
        self.assertEqual(c.temporal(row(timestamp=None)),'unknown')
        self.assertEqual(c.temporal(row(timestamp='2026-10-01T00:00:00Z')),'post-target')

    def test_eip7702_not_silently_classed_as_service(self):
        r=row();r['from'].update(is_contract=True,proxy_type='eip7702')
        self.assertTrue(c.native_edge(r,c.CANDIDATE)['isDelegatedAccountReported'])

    def test_shared_positive_value_peer_not_wallet_ownership(self):
        seed=next(iter(c.SEEDS))
        fs=[{'chain':'Ethereum','address':a,'kind':'transactions','pages':1,
             'indexerPaginationComplete':True,'rows':[row(address=a)]} for a in (c.CANDIDATE,seed)]
        result=c.analyze(fs)
        self.assertEqual(len(result['sharedPreTargetValuePeers']),1)
        self.assertFalse(result['sharedPreTargetValuePeers'][0]['ownershipProven'])
        self.assertFalse(result['allDeclaredFeedsComplete'])

    def test_spoofable_token_contact_not_native_peer_or_ownership(self):
        seed=next(iter(c.SEEDS));r=row(peer=seed)
        r.update(transaction_hash=r['hash'],log_index=1,token={'address_hash':'0x'+'2'*40})
        result=c.analyze([{'chain':'Ethereum','address':c.CANDIDATE,'kind':'token-transfers',
            'pages':1,'indexerPaginationComplete':True,'rows':[r]}])
        self.assertEqual(result['directSeedContacts'][0]['evidenceClass'],'token-log-claimed-contact')
        self.assertEqual(result['sharedPreTargetValuePeers'],[])
        self.assertEqual(result['ensCustodyEvents'],[])

    def test_only_official_mainnet_ens_contract_address(self):
        r=row();r.update(transaction_hash=r['hash'],log_index=1,
                        token={'address_hash':next(iter(c.ENS_CONTRACTS))})
        def feed(chain):return {'chain':chain,'address':c.CANDIDATE,'kind':'token-transfers',
                               'pages':1,'indexerPaginationComplete':True,'rows':[r]}
        self.assertEqual(len(c.analyze([feed('Ethereum')])['ensCustodyEvents']),1)
        self.assertEqual(len(c.analyze([feed('Base')])['ensCustodyEvents']),0)


if __name__=='__main__':unittest.main()
