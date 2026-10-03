#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TV = ROOT / 'test-vectors'
OUT = TV / 'tcp-binding.json'


def chunks(hexstr, cuts):
    b = bytes.fromhex(hexstr)
    out=[]; pos=0
    for n in cuts:
        out.append(b[pos:pos+n].hex()); pos += n
    if pos < len(b): out.append(b[pos:].hex())
    return out


def build():
    ks=json.loads((TV/'key-schedule.json').read_text())
    sr=json.loads((TV/'secure-record.json').read_text())
    pre=ks['inputs']['connection_preface_hex']
    ci=ks['inputs']['client_init_hex']
    recs={int(r['sequence_number']):r for r in sr['records']}
    r0=recs[0]['wire_record_hex']; r1=recs[1]['wire_record_hex']
    return {
      'protocol':'MPX/4','revision':'Draft 09','binding':'TCP',
      'purpose':'Byte-stream framing and transport-loss conformance generated from the canonical Draft 09 handshake and Secure Record fixtures',
      'source_fixtures':{'handshake':'key-schedule.json','secure_records':'secure-record.json'},
      'fixtures':{
        'connection_preface_hex':pre,
        'client_init_hex':ci,
        'secure_record_seq0_hex':r0,
        'secure_record_seq1_hex':r1,
        'secure_record_seq1_plaintext_hex':recs[1]['plaintext_hex'],
        'secure_record_seq1_meaning':'PING token=1'
      },
      'cases':[
        {'name':'preface-one-byte-fragments','input_chunks_hex':[pre[i:i+2] for i in range(0,len(pre),2)],'expected_units':[{'type':'connection_preface','hex':pre}]},
        {'name':'preface-coalesced-with-client-init','input_chunks_hex':[pre+ci],'expected_units':[{'type':'connection_preface','hex':pre},{'type':'handshake_message','name':'CLIENT_INIT','hex':ci}]},
        {'name':'secure-record-fragmented','input_chunks_hex':chunks(r0,[1,4,7]),'expected_units':[{'type':'secure_record','sequence_number':'0','hex':r0}]},
        {'name':'two-secure-records-coalesced','input_chunks_hex':[r0+r1],'expected_units':[{'type':'secure_record','sequence_number':'0','hex':r0},{'type':'secure_record','sequence_number':'1','hex':r1}]},
        {'name':'first-record-plus-partial-second','input_chunks_hex':[r0+r1[:8],r1[8:]],'expected_units':[{'type':'secure_record','sequence_number':'0','hex':r0},{'type':'secure_record','sequence_number':'1','hex':r1}]},
        {'name':'eof-mid-record','input_chunks_hex':[r0[:16]],'transport_event':'EOF','expected_units':[],'expected_result':'carrier_lost','expected_sequence_advance':False}
      ]
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--check',action='store_true'); args=ap.parse_args()
    text=json.dumps(build(),indent=2)+'\n'
    if args.check:
        current=OUT.read_text() if OUT.exists() else ''
        if current != text:
            raise SystemExit('test-vectors/tcp-binding.json is not generated from current canonical fixtures')
        print('tcp-fixture-generation: ok')
    else:
        OUT.write_text(text)
        print(OUT)

if __name__=='__main__': main()
