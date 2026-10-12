"""Confidence repair: numeric tails, joint calibration and block behaviour."""
import importlib.util
import math
from pathlib import Path
import sys
import unittest

import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'chronoSIFT_v2_31.py'
if not SOURCE.exists():
    SOURCE=Path('/private/tmp/chronosift_confidence_fixed.py')
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('profile_bounds_under_test',SOURCE)
cs=importlib.util.module_from_spec(spec);sys.modules[spec.name]=cs;spec.loader.exec_module(cs)


def resamples(counts,seed=3,b=2000):
    n=len(counts);rng=np.random.default_rng(seed)
    multiplicities=rng.multinomial(n,np.full(n,1/n),size=b)
    bootstrap=multiplicities@counts
    p=(counts.sum(0)+1)/(counts.sum()+168)
    pb=(bootstrap+1)/(bootstrap.sum(1,keepdims=True)+168)
    return p,pb


def bounds(counts,confidence=.95):
    p,pb=resamples(counts)
    upper,meta=cs._simultaneous_hour_probability_bounds(counts,p,pb,alpha=1,confidence_level=confidence)
    return p,pb,upper,meta


class ConfidenceBoundsTest(unittest.TestCase):
    def test_student_t_tails_against_analytic_df_one_two_three(self):
        for df in [1,2,3]:
            for tail in [.05,.05/168,1e-6]:
                x=cs._student_t_upper_quantile(tail,df)
                if df==1:
                    actual=math.atan(1/x)/math.pi
                elif df==2:
                    actual=1/(math.sqrt(2+x*x)*(math.sqrt(2+x*x)+x))
                else:
                    y=x/math.sqrt(3)
                    actual=(math.atan(1/y)-y/(1+y*y))/math.pi
                self.assertAlmostEqual(actual/tail,1,places=6)

    def test_student_t_high_df_reference_and_invalid_args(self):
        self.assertAlmostEqual(cs._student_t_upper_quantile(.05,16),1.7458836763,places=7)
        for tail,df in [(0,3),(.5,3),(.1,0)]:
            with self.assertRaises(ValueError):cs._student_t_upper_quantile(tail,df)

    def test_quiet_hour_not_overwhelmed_by_busy_hour_variability(self):
        rng=np.random.default_rng(12)
        counts=np.full((4,168),20.)
        counts[:,:40]=10000+rng.normal(0,1800,(4,40))
        counts[:,40:]+=rng.normal(0,1,(4,128))
        p,pb,upper,meta=bounds(counts)
        old=p+np.quantile((pb-p).max(1),.95)
        self.assertTrue(np.all(upper[40:]<1/168))
        self.assertTrue(np.all(upper[:40]>1/168))
        self.assertGreater(old[40:].min(),upper[40:].max())
        self.assertEqual(meta['uncertainty_degrees_of_freedom'],3)
        self.assertGreaterEqual(meta['simultaneous_standardized_critical_value'],meta['bonferroni_t_critical_value'])

    def test_joint_basic_bootstrap_coverage_and_boundedness(self):
        counts=np.random.default_rng(19).lognormal(7,1,(8,168))
        p,pb,upper,meta=bounds(counts)
        self.assertGreaterEqual(np.mean(np.all((p-pb)<=(upper-p)+1e-14,axis=1)),.95)
        self.assertTrue(np.all(upper>=p));self.assertTrue(np.all(upper<=1))
        self.assertAlmostEqual(meta['simultaneous_upper_radius'],np.max(upper-p))

    def test_confidence_monotonicity_and_hour_permutation(self):
        counts=np.random.default_rng(11).lognormal(7,1,(8,168))
        _,_,lo,_=bounds(counts,.90);_,_,hi,_=bounds(counts,.99)
        self.assertTrue(np.all(hi>=lo))
        perm=np.random.default_rng(5).permutation(168)
        _,_,reordered,_=bounds(counts[:,perm],.90)
        np.testing.assert_allclose(reordered,lo[perm],rtol=1e-12,atol=1e-14)

    def test_more_rows_do_not_create_more_independent_blocks(self):
        counts=np.random.default_rng(13).lognormal(9,.4,(4,168))
        p,_,u,_=bounds(counts);p2,_,u2,_=bounds(counts*1000)
        np.testing.assert_allclose(u-p,u2-p2,rtol=.003,atol=1e-8)

    def test_uniform_insufficient_and_unstable_profiles_stay_neutral(self):
        kwargs=dict(alpha=1,minimum_complete_weeks=3,confidence_level=.95,
            bootstrap_resamples=2000,random_seed=0,amplification_gate='require_positive_activity_deficit')
        for counts in [np.ones((8,168)),np.ones((2,168)),np.eye(168)[:8]*10000]:
            result=cs._validate_weekly_hour_profile(pd.DataFrame(counts),**kwargs)
            self.assertFalse(result['accepted'])

    def test_constant_cells_are_finite_and_degeneracy_is_reported(self):
        counts=np.full((4,168),20.)
        p,_,upper,meta=bounds(counts)
        self.assertTrue(np.isfinite(upper).all())
        self.assertEqual(meta['zero_empirical_variance_hour_count'],168)
        np.testing.assert_array_equal(upper,p)


if __name__=='__main__':unittest.main()
