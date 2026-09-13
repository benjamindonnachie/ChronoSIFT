"""Storage-only F04 boundary: preserve forensic values and sparse-state ownership."""
import re
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
import pyarrow as pa
import chronoSIFT_v2_31 as c


class CopyForbidden:
    def __deepcopy__(self,memo):raise AssertionError('sparse metadata was copied')


class ArrowTextStorageTest(unittest.TestCase):
    def test_text_values_and_missing_positions_preserved(self):
        source=['','-', 'None',' leading ',None,pd.NA,np.nan,'a\x00b','İ','ΟΣ','é','\u00a0']
        data=pd.DataFrame({'text':pd.Series(source,dtype=object)})
        missing=data.text.isna().to_numpy()
        c._prepare_arrow_text_columns(data)
        self.assertEqual(data.text.dtype.storage,'pyarrow')
        np.testing.assert_array_equal(data.text.isna(),missing)
        for i,value in enumerate(source):
            if not missing[i]:self.assertEqual(data.text.iloc[i],value)

    def test_numeric_boolean_binary_and_nested_evidence_not_stringified(self):
        nested=[{'x':[1,2]},np.array(['one','two'],dtype=object)]
        data=pd.DataFrame({'text':pd.Series(['x','y'],dtype=object),
            'number':pd.Series([1,2],dtype=object),'mixed':pd.Series(['1',2],dtype=object),
            'bytes':pd.Series([b'x',b'y'],dtype=object),'nested':pd.Series(nested,dtype=object),
            'flag':[True,False],'integer':pd.Series([1,None],dtype='Int64')})
        arrays={name:data[name].to_numpy(copy=False) for name in ('number','mixed','bytes','nested','flag')}
        c._prepare_arrow_text_columns(data)
        for name,array in arrays.items():
            self.assertTrue(np.shares_memory(data[name].to_numpy(copy=False),array),name)
        self.assertIs(data.nested.iloc[0],nested[0]);self.assertIs(data.nested.iloc[1],nested[1])
        self.assertEqual(str(data.integer.dtype),'Int64')

    def test_inspection_is_not_a_sample(self):
        source=['text']*10000+[{'late':'evidence'}]
        data=pd.DataFrame({'mixed':pd.Series(source,dtype=object)})
        c._prepare_arrow_text_columns(data)
        self.assertEqual(data.mixed.dtype,object);self.assertIs(data.mixed.iloc[-1],source[-1])

    def test_compact_null_and_all_null_object_are_not_expanded(self):
        data=pd.DataFrame({'missing':c._compact_null_series(pd.RangeIndex(1000)),
                           'old_null':pd.Series([None]*1000,dtype=object)})
        before=data.missing.array
        c._prepare_arrow_text_columns(data)
        self.assertTrue(c._is_compact_null(data.missing));self.assertIs(data.missing.array,before)
        self.assertEqual(data.missing.array.nbytes,0);self.assertEqual(data.old_null.dtype,object)

    def test_existing_arrow_buffers_and_second_pass_are_reused(self):
        data=pd.DataFrame({'text':pd.Series(['a','b',None],dtype='string[pyarrow]')})
        before=data.text.array
        c._prepare_arrow_text_columns(data);c._prepare_arrow_text_columns(data)
        self.assertIs(data.text.array,before)

    def test_explicit_python_string_preserves_na_kind(self):
        for missing in (pd.NA,np.nan):
            with self.subTest(missing=missing):
                data=pd.DataFrame({'text':pd.Series(['a',None],dtype=pd.StringDtype(storage='python',na_value=missing))})
                before=str(data.text.dtype)
                c._prepare_arrow_text_columns(data)
                self.assertEqual(data.text.dtype.storage,'pyarrow')
                self.assertEqual(str(data.text.dtype),before)
                self.assertTrue(pd.isna(data.text.iloc[1]))

    def test_explicit_storage_does_not_change_global_pandas_options(self):
        with pd.option_context('mode.string_storage','python'):
            data=pd.DataFrame({'text':pd.Series(['a',None],dtype=object)})
            c._prepare_arrow_text_columns(data)
            self.assertEqual(data.text.dtype.storage,'pyarrow')
            self.assertEqual(pd.options.mode.string_storage,'python')

    def test_no_frame_copy_or_sparse_metadata_copy(self):
        data=pd.DataFrame({'text':pd.Series(['a',None],dtype=object)})
        state={'guard':CopyForbidden(),'signal_map':{0:{'example':1}},'explain_map':{}}
        data.attrs['chronosift_sparse']=state
        with patch.object(pd.DataFrame,'copy',side_effect=AssertionError('frame copy')):
            self.assertIsNone(c._prepare_arrow_text_columns(data))
        self.assertIs(data.attrs['chronosift_sparse'],state)
        self.assertEqual(state['signal_map'],{0:{'example':1}})

    def test_invalid_unicode_retains_original_evidence(self):
        data=pd.DataFrame({'text':pd.Series(['okay','\ud800'],dtype=object)})
        before=data.text.to_numpy(copy=False)
        with self.assertLogs(c.logger,level='WARNING'):
            c._prepare_arrow_text_columns(data)
        self.assertEqual(data.text.iloc[1],'\ud800');self.assertEqual(data.text.dtype,object)
        self.assertTrue(np.shares_memory(before,data.text.to_numpy(copy=False)))

    def test_row_ids_and_wide_timestamps_untouched(self):
        index=pd.DatetimeIndex(np.array(['2500-01-01T00:00:00.000123']*2,dtype='datetime64[us]')).tz_localize('UTC')
        data=pd.DataFrame({'text':pd.Series(['a','b'],dtype=object).array,'chronosift_row_id':[9007199254740993,9007199254740994]},index=index)
        ids=data.chronosift_row_id.to_numpy(copy=False)
        c._prepare_arrow_text_columns(data)
        self.assertIs(data.index,index);self.assertTrue(np.shares_memory(ids,data.chronosift_row_id.to_numpy(copy=False)))
        self.assertEqual(list(data.chronosift_row_id),[9007199254740993,9007199254740994])

    def test_regex_and_unicode_operations_match_existing_string_casts(self):
        values=['İ','ΟΣ','é１２','abc abc','prefix suffix','a\x00b',None,'']
        data=pd.DataFrame({'text':pd.Series(values,dtype=object)})
        expected=data.text.astype('string')
        c._prepare_arrow_text_columns(data)
        for operation in ('lower','strip','casefold'):
            pd.testing.assert_series_equal(getattr(expected.str,operation)(),getattr(data.text.str,operation)())
        for pattern in [r'\w+',r'\d+',r'(?<=prefix )suffix',r'(abc) \1',re.compile('é',re.I)]:
            with self.subTest(pattern=pattern):
                pd.testing.assert_series_equal(expected.str.contains(pattern,na=False),data.text.str.contains(pattern,na=False))


if __name__=='__main__':unittest.main()
