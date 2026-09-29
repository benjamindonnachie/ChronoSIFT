"""Explicit evidence document-root configuration; never infer roots from GT.

Apply to a freshly loaded YAML mapping before constructing the engine. This
updates existing general detectors, not an additional payload-name detector.
"""
import argparse
from pathlib import Path
import re
import yaml


def configure_web_roots(document, additional_roots):
    """Mutate configuration only, preserving existing roots and path case.

    Roots describe the analysed filesystem's URL mapping, not local Mac paths.
    No basename join, mount guessing or implicit CMS-directory inference.
    """
    detectors=document['detector_policy']['detectors']
    roots=detectors['referenced_file_correlation']['matching']['web_document_roots']
    added=[]
    for root in additional_roots:
        if (not isinstance(root,str) or not root.startswith('/') or root.startswith('//')
                or root=='/' or root.strip()!=root or re.search(r'[\x00-\x1f\x7f\\]',root)
                or any(part in ('.','..') for part in root.split('/'))):
            raise ValueError('web document roots must be absolute POSIX evidence paths without traversal or control characters')
        root=root.rstrip('/')
        if not root:raise ValueError('filesystem root is not a document-root mapping')
        if root not in roots and root not in added:added.append(root)
    all_roots=sorted([*roots,*added],key=lambda value:len(value),reverse=True)
    # Longest root first for nested deployments; otherwise /site would swallow
    # /site/cms. Multiple roots producing one URL still fail identity ambiguity.
    patterns=[]
    for root in all_roots:
        root=root.replace('\\','/').rstrip('/')
        patterns.append(re.escape(root) if root.startswith('/') else r'(?i:(?:(?:[a-zA-Z]|NTFS):)?/'+re.escape(root)+')')
    relative=next(spec for spec in document['normalisation'] if spec['name']=='evidence_web_file_relative')
    relative['pattern']=r'^(?:'+'|'.join(patterns)+r')(/.+)$'
    path_regex=detectors['file_lifecycle']['classification'].get('path_regex')
    if path_regex is not None:
        path_regex['web_root']=relative['pattern']
    roots[:]=all_roots
    # These are the existing detector policy surfaces sharing root vocabulary.
    targets=[detectors['webshell_artifact']['conditions']['path_contains'],
        detectors['file_lifecycle']['classification']['path_contains']['web_root'],
        detectors['web_upload_execution_chain']['target']['where']['path']['contains_any']]
    for target in targets:
        for root in added:
            item=root+'/'
            if item not in target:target.append(item)
    return document


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rules_yaml',type=Path)
    parser.add_argument('output_yaml',type=Path)
    parser.add_argument('--web-document-root',action='append',required=True)
    args=parser.parse_args()
    document=yaml.safe_load(args.rules_yaml.read_text())
    configure_web_roots(document,args.web_document_root)
    # Exclusive creation preserves both the source policy and prior run receipts.
    with args.output_yaml.open('x') as handle:
        handle.write('# Explicit evidence web-document-root configuration; source: '+str(args.rules_yaml)+'\n')
        yaml.safe_dump(document,handle,sort_keys=False,width=120)


if __name__=='__main__':main()
