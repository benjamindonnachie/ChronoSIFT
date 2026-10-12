"""Native paired-rate windows: mathematical oracle and public partition parity."""
from copy import deepcopy
from pathlib import Path
import logging,tempfile,unittest
import duckdb,numpy as np,pandas as pd
import chronoSIFT_v2_31 as c
ROOT=Path(c.__file__).resolve().parent

def policy(**edits):
 doc=c._load_unique_yaml_mapping(ROOT/'rules/rules_evidence_calibrated_v27.yaml','rules')
 raw=deepcopy(doc['detector_policy']['detectors']['web_service_disruption']);raw.update(edits)
 return c._parse_rate_change_window_policy(raw,'test.rate')

def data(times,values,routes=None,hosts=None):
 return pd.DataFrame(dict(chronosift_web_status_code=values,hostname='asset',chronosift_web_host=hosts or ['site']*len(values),chronosift_web_endpoint=routes or ['/product.php']*len(values)),index=pd.DatetimeIndex(times))

def oracle(df,p):
 # Independent scans; intentionally slow and only used on tiny random fixtures.
 valid=[];q=p.bucket_period
 for i,(t,row) in enumerate(df.iterrows()):
  x=row[p.value_field]
  if isinstance(x,(bool,np.bool_)) or pd.isna(x):continue
  try:x=float(x)
  except (TypeError,ValueError):continue
  if not np.isfinite(x) or int(x)!=x or not any(a<=x<b for a,b in p.denominator_ranges):continue
  if any(pd.isna(row[k]) or not str(row[k]).strip() for k in p.required_key_fields):continue
  key=tuple('' if pd.isna(row[k]) else str(row[k]) for k in p.key_fields)
  b=t.floor(q);num=p.numerator_range[0]<=x<p.numerator_range[1];valid.append((i,b,key,num))
 result={}
 for i,b,key,num in valid:
  recent=[z for z in valid if z[2]==key and b-q*(p.recent_window//q-1)<=z[1]<=b]
  ref=[z for z in valid if z[2]==key and b-p.recent_window-p.reference_window+q<=z[1]<=b-p.recent_window]
  n=sum(z[3] for z in recent);rn=sum(z[3] for z in ref)
  if len(recent)<p.minimum_recent_count or len(ref)<p.minimum_reference_count or n<p.minimum_numerator_count or len({z[1] for z in recent})<p.minimum_recent_buckets:continue
  excess=n/len(recent)-rn/len(ref)
  if excess>p.minimum_rate_increase and (p.emit_on=='denominator' or num):result[i]=excess
 return result

class RateWindowTest(unittest.TestCase):
 def test_random_oracle_and_unsorted_duplicate_buckets(self):
  rng=np.random.default_rng(19);p=policy(bucket_period='1m',recent_window='3m',reference_window='5m',minimum_recent_count=2,minimum_reference_count=2,minimum_numerator_count=1,minimum_recent_buckets=1,minimum_rate_increase=0)
  for _ in range(25):
   n=50;times=pd.Timestamp('2024-06-06T00:00Z')+pd.to_timedelta(rng.integers(0,900,n),unit='s')
   df=data(times,rng.choice([200,206,302,404,500,503],n).tolist(),rng.choice(['/a','/A','/b'],n).tolist(),rng.choice(['a','b'],n).tolist())
   expected=oracle(df,p);got={i:v for i,v,_ in c._rate_change_window_rows(df,p)}
   self.assertEqual(got.keys(),expected.keys())
   for i in got:self.assertAlmostEqual(got[i],expected[i],places=14)
 def test_constant_failure_has_no_rate_increase(self):
  df=data(pd.date_range('2024-06-06',periods=120,freq='min',tz='UTC'),[500]*120)
  self.assertEqual(c._rate_change_window_rows(df,policy()),[])
 def test_zero_reference_missing_route_and_bad_status(self):
  df=data(pd.date_range('2024-06-06',periods=12,freq='min',tz='UTC'),[500]*12)
  self.assertEqual(c._rate_change_window_rows(df,policy()),[])
  df=data(pd.date_range('2024-06-06',periods=8,freq='min',tz='UTC'),[200,206,500,500.5,np.nan,np.inf,True,'bad'],['/a','/a','/a','/a','/a','/a','/a','/a'])
  self.assertEqual(np.flatnonzero(c._rate_window_admission(df,policy())[0]).tolist(),[0,1,2])
  df.chronosift_web_endpoint='';self.assertFalse(c._rate_window_admission(df,policy())[0].any())
 def test_other_hosts_routes_and_case_do_not_supply_reference(self):
  times=pd.date_range('2024-06-06',periods=100,freq='min',tz='UTC');df=data(times,[200]*70+[500]*30,['/product.php']*70+['/Product.php']*30)
  self.assertEqual(c._rate_change_window_rows(df,policy()),[])
  df.chronosift_web_endpoint='/product.php';df.iloc[70:,df.columns.get_loc('chronosift_web_host')]='other';self.assertEqual(c._rate_change_window_rows(df,policy()),[])
 def test_nullable_numeric_optional_namespace_is_empty(self):
  df=data(pd.date_range('2024-06-06',periods=100,freq='min',tz='UTC'),[200]*70+[500]*30)
  df['hostname']=pd.array([None]*100,dtype='Int32')
  df['chronosift_web_host']=pd.array([None]*100,dtype='Int32')
  rows=c._rate_change_window_rows(df,policy());self.assertTrue(rows)
  for _,_,e in rows:
   self.assertEqual(e['key']['hostname'],'');self.assertEqual(e['key']['chronosift_web_host'],'')
 def test_future_buckets_cannot_change_old_buckets(self):
  times=pd.date_range('2024-06-06',periods=100,freq='min',tz='UTC');df=data(times,[200]*70+[500]*30)
  short=c._rate_change_window_rows(df.iloc[:90],policy());full=c._rate_change_window_rows(df,policy())
  self.assertEqual(short,[x for x in full if x[0]<90]);self.assertTrue(short)
 def test_extended_dates_and_utc_offsets(self):
  times=pd.date_range('2024-06-06',periods=100,freq='min',tz='UTC');df=data(times,[200]*70+[500]*30)
  base=[(i,v) for i,v,_ in c._rate_change_window_rows(df,policy())]
  df.index=df.index.tz_convert('Europe/London');self.assertEqual(base,[(i,v) for i,v,_ in c._rate_change_window_rows(df,policy())])
  df.index=pd.date_range('3850-01-01',periods=100,freq='min',tz='UTC').as_unit('us');self.assertEqual(base,[(i,v) for i,v,_ in c._rate_change_window_rows(df,policy())])
 def test_strict_schema(self):
  edits=[dict(bucket_period='0m'),dict(recent_window='91s'),dict(numerator_range={'minimum':True,'maximum_exclusive':600}),dict(numerator_range={'minimum':100,'maximum_exclusive':200}),dict(minimum_recent_count=True),dict(minimum_rate_increase=1),dict(emit_on='arbitrary'),dict(key={'fields':['route'],'required_fields':['other']})]
  for edit in edits:
   with self.subTest(edit=edit),self.assertRaises(ValueError):policy(**edit)

class NativeRateTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  logging.getLogger().setLevel(logging.ERROR)
  cls.engine=c.ChronoSiftEngine.from_yaml(str(ROOT/'rules/rules_evidence_calibrated_v27.yaml'),str(ROOT/'rules/weights_evidence_calibrated_v23.yaml'))
 def fixture(self):
  times=pd.date_range('2024-06-30T22:50Z',periods=100,freq='min')
  return pd.DataFrame(dict(chronosift_row_id=range(1000,1100),parser='text/apache_access',http_request='GET http://shop.example.org/product.php?product=computer HTTP/1.1',http_response_code=[200]*70+[500]*30,hostname='asset'),index=pd.DatetimeIndex(times,name='datetime'))
 def test_public_score_and_zero_baseline_candidate_retention(self):
  df=self.fixture();out=self.engine.apply(df,apply_profiling=False)
  added=[r for _,r in out.iterrows() if (r.chronosift_signals or {}).get('web_service_disruption',0)>0]
  self.assertTrue(added)
  for r in added:
   self.assertGreater(r.chronosift_score,0);self.assertLessEqual(r.chronosift_score,8)
   e=[e for e in r.chronosift_explain if e['rule_id']=='WEB_SERVICE_DISRUPTION'];self.assertEqual(len(e),1)
   self.assertAlmostEqual(e[0]['score_contribution'],8*(r.chronosift_signals or {})['web_service_disruption'])
   self.assertEqual(e[0]['evidence']['key']['chronosift_web_endpoint'],'/product.php')
  atomic=self.engine.apply_atomic(df,apply_profiling=False)
  self.assertTrue(self.engine._temporal_candidate_base_mask(atomic,{}).iloc[:70].all())
 def test_public_partitioned_compact_and_eager_parity(self):
  df=self.fixture();expected=self.engine.apply(df,apply_profiling=False).set_index('chronosift_row_id').chronosift_score.to_dict()
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);raw=root/'raw';con=duckdb.connect();con.execute("SET TimeZone='UTC'");con.register('fixture',df.reset_index());con.execute('COPY (SELECT *,year(datetime) AS year,month(datetime) AS month FROM fixture) TO ? (FORMAT PARQUET,PARTITION_BY(year,month))',[str(raw)])
   for mode in ['sidecar','full']:
    dest=root/mode;self.engine.process_parquet_dataset_partitioned(str(raw),str(dest),output_mode=mode,profile_manifest={'validation':{'accepted':False}})
    got=dict(con.execute('SELECT chronosift_row_id,chronosift_score FROM read_parquet(?,union_by_name=true)',[str(dest/'**/*.parquet')]).fetchall());self.assertEqual(got,expected)

if __name__=='__main__':unittest.main()
