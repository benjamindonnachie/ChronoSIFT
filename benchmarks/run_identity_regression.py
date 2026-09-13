"""Run the complete suite with an explicit source-bound machine receipt."""
import argparse
import logging
import os
from pathlib import Path
import sys
import time
import unittest

from run_final_dataset_validation import sha,save,stamp

ROOT=Path(__file__).resolve().parents[1]


def run(out):
    os.chdir(ROOT);sys.path.insert(0,str(ROOT));logging.Formatter.converter=time.gmtime
    files=list(ROOT.glob('*.py'))+list((ROOT/'rules').glob('*.yaml'))+list((ROOT/'tests').glob('*.py'))
    files+=list((ROOT/'benchmarks').glob('*.py'))+list((ROOT/'benchmarks').glob('*.json'))
    hashes={str(path):sha(path) for path in files}
    started=time.monotonic();suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    unchanged=all(sha(Path(path))==digest for path,digest in hashes.items())
    receipt=dict(utc=stamp(),successful=result.wasSuccessful() and unchanged,tests=result.testsRun,
        skipped=len(result.skipped),failures=len(result.failures),errors=len(result.errors),
        source_unchanged=unchanged,seconds=time.monotonic()-started,sha256=hashes)
    save(out/'regression.json',receipt)
    return 0 if receipt['successful'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    sys.exit(run(parser.parse_args().output.resolve()))
