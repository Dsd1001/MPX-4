#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def run_validate(repo):
    return subprocess.run([sys.executable,str(repo/'tools/validate.py'),'--root',str(repo)],capture_output=True,text=True)


def copy_repo(tmp):
    dst=Path(tmp)/'repo'
    shutil.copytree(ROOT,dst,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
    return dst


def expect_failure(name,mutate,regenerate_tcp=False):
    with tempfile.TemporaryDirectory(prefix='mpx4-mutation-') as tmp:
        repo=copy_repo(tmp); mutate(repo)
        if regenerate_tcp:
            r=subprocess.run([sys.executable,str(repo/'tools/generate_tcp_fixtures.py'),'--root',str(repo)],capture_output=True,text=True)
            if r.returncode!=0: raise AssertionError(f'{name}: fixture regeneration failed: {r.stdout}{r.stderr}')
        r=run_validate(repo)
        if r.returncode==0:
            raise AssertionError(f'{name}: validator incorrectly returned PASS')
        print(f'mutation {name}: rejected')


def mutate_varint_valid(repo):
    p=repo/'test-vectors/varint.json'; d=json.loads(p.read_text()); d['vectors'][0]['hex']='01'; p.write_text(json.dumps(d,indent=2)+'\n')

def mutate_varint_invalid(repo):
    p=repo/'test-vectors/varint.json'; d=json.loads(p.read_text()); d['invalid'][3]['hex']='00'; p.write_text(json.dumps(d,indent=2)+'\n')

def mutate_frame_fields(repo):
    p=repo/'test-vectors/frame-encoding.json'; d=json.loads(p.read_text()); c=next(x for x in d['vectors'] if x['name']=='stream-data-small'); c['fields']['stream_id']='2'; p.write_text(json.dumps(d,indent=2)+'\n')

def mutate_state_expected(repo):
    p=repo/'test-vectors/reordering-reliability.json'; d=json.loads(p.read_text()); c=next(x for x in d['cases'] if x['name']=='stream-credit-stale-reordering'); c['expected']='SESSION_CLOSE_FLOW_CONTROL_ERROR'; p.write_text(json.dumps(d,indent=2)+'\n')

def mutate_secure_wire(repo):
    p=repo/'test-vectors/secure-record.json'; d=json.loads(p.read_text()); d['records'][0]['wire_record_hex']='ff'+d['records'][0]['wire_record_hex'][2:]; p.write_text(json.dumps(d,indent=2)+'\n')

def main():
    expect_failure('varint-valid-corruption',mutate_varint_valid)
    expect_failure('varint-invalid-accepted',mutate_varint_invalid)
    expect_failure('frame-fields-vs-wire',mutate_frame_fields)
    expect_failure('state-oracle-expected',mutate_state_expected)
    expect_failure('secure-record-wire',mutate_secure_wire,regenerate_tcp=True)
    print('mutation-tests: PASS (5 corruptions rejected)')

if __name__=='__main__': main()
