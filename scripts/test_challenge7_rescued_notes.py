import unittest
from merge_challenge7_rescued_notes import merge


class Tests(unittest.TestCase):
    def note(self,ident='a'):
        return {'id':ident,'txid':ident,'pool':'ironwood','actionIndex':0,'cmx':ident,
                'valueZat':4000000,'receiverBytes':['raw'],'blockHeight':3480000,
                'blockTime':'2026-09-01T00:00:00Z','sourceSenders':['old-attribution']}

    def test_overlap_preserves_original_attribution_without_counting_twice(self):
        old=self.note();new={**old,'sourceSenders':['new-metadata']}
        rows,added,overlap=merge([old],[new])
        self.assertEqual(rows,[old]);self.assertEqual(added,[]);self.assertEqual(overlap,['a'])

    def test_conflicting_plaintext_or_height_cannot_replace_frozen_note(self):
        for field,value in [('valueZat',4000001),('receiverBytes',['other']),('blockHeight',3480001)]:
            with self.assertRaises(ValueError):merge([self.note()],[{**self.note(),field:value}])

    def test_post_anchor_output_is_not_admitted(self):
        with self.assertRaises(ValueError):merge([],[{**self.note(),'blockHeight':3488704}])

    def test_orchard_output_is_not_a_direct_ironwood_input(self):
        with self.assertRaises(ValueError):merge([],[{**self.note(),'pool':'orchard'}])

    def test_new_actual_note_is_added(self):
        rows,added,overlap=merge([self.note('a')],[self.note('b')])
        self.assertEqual(len(rows),2);self.assertEqual(added,[self.note('b')]);self.assertEqual(overlap,[])

    def test_duplicate_supplement_is_not_counted_as_old_baseline_overlap(self):
        with self.assertRaises(ValueError):merge([],[self.note(),self.note()])


if __name__=='__main__':unittest.main()
