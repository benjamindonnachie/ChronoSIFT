"""Audit corrections preserve original rows and require raw-observation proof."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

import duckdb
import pandas as pd

BENCH=Path(__file__).resolve().parents[1]/'benchmarks'
sys.path.insert(0,str(BENCH))
from review_groundtruth_anchors import reviewed_ledger
sys.path.remove(str(BENCH))


class AnchorReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.con=duckdb.connect();self.addCleanup(self.con.close)
        self.ledger=dict(source='original-ledger',sha256='original-hash',rows=[
            dict(event_id='GT-1',event_description='Remote logon',anchor_ids=[1]),
            dict(event_id='GT-2',event_description='Unreviewed',anchor_ids=[3])])
        self.changes={'GT-1':dict(primary_ids=[2],excluded_original_ids=[1],observation='Explicit remote logon',
            rationale='Original row is background',checks=[dict(id=1,parser='auth',contains=['local']),
                dict(id=2,parser='auth',contains=['remote'],fields_equal={'status':200},xml_data_equals={'User':'alice'})])}
        pd.DataFrame(dict(chronosift_row_id=[1,2,3],parser=['auth']*3,message=['local','remote','ordinary'],
            filename=['']*3,status=[200]*3,xml_string=['','<Event><EventData><Data Name="User">alice</Data></EventData></Event>',''])).to_parquet(self.root/'raw.parquet',index=False)

    def test_originals_and_unreviewed_references_are_preserved(self):
        before=deepcopy(self.ledger)
        result,proof=reviewed_ledger(self.con,self.root,self.ledger,self.changes)
        self.assertEqual(before,self.ledger)
        self.assertEqual(result['rows'][0]['anchor_ids'],[1,2])
        self.assertEqual(result['rows'][0]['primary_anchor_ids'],[2])
        self.assertEqual(result['rows'][0]['misassigned_original_ids'],[1])
        self.assertEqual(result['rows'][1]['unreviewed_anchor_ids'],[3])
        self.assertEqual(proof['reviewed_rows'],2);self.assertEqual(len(proof['raw_rows_sha256']),64)

    def test_observation_mismatch_fails(self):
        for change in ({'contains':['absent']},{'parser':'wrong'},{'fields_equal':{'status':404}},
                       {'xml_data_equals':{'User':'bob'}}):
            edits=deepcopy(self.changes);edits['GT-1']['checks'][1].update(change)
            with self.assertRaises(ValueError):reviewed_ledger(self.con,self.root,self.ledger,edits)

    def test_unknown_event_missing_proof_and_conflicting_roles_fail(self):
        edits=deepcopy(self.changes);edits['GT-other']=edits.pop('GT-1')
        with self.assertRaises(ValueError):reviewed_ledger(self.con,self.root,self.ledger,edits)
        for change in ({'primary_ids':[1]},{'excluded_original_ids':[99]},{'checks':[]},
                       {'additional_supporting_ids':[2]}):
            edits=deepcopy(self.changes);edits['GT-1'].update(change)
            with self.assertRaises(ValueError):reviewed_ledger(self.con,self.root,self.ledger,edits)


if __name__=='__main__':unittest.main()
