#!/usr/bin/env python3
import hashlib, hmac, json, re, subprocess, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=Path(__file__).resolve().parents[1]
TV=ROOT/'test-vectors'
MAX_VARINT=(1<<62)-1
JS_SAFE=(1<<53)-1


def vi_enc(v):
    if not 0 <= v <= MAX_VARINT: raise ValueError(v)
    if v < 1<<6:n,p=1,0
    elif v < 1<<14:n,p=2,1
    elif v < 1<<30:n,p=4,2
    else:n,p=8,3
    return (v | (p<<(8*n-2))).to_bytes(n,'big')

def vi_dec(b,i=0):
    n=(1,2,4,8)[b[i]>>6]
    if i+n>len(b): raise ValueError('truncated varint')
    raw=int.from_bytes(b[i:i+n],'big'); v=raw&((1<<(8*n-2))-1)
    if len(vi_enc(v)) != n: raise ValueError('non-canonical varint')
    return v,i+n

def all_json(): return sorted(list(TV.glob('*.json')) + list((ROOT/'extensions').glob('*.json')))

def walk_numbers(x,path='$'):
    if isinstance(x,bool) or x is None: return
    if isinstance(x,int):
        if abs(x)>JS_SAFE: raise AssertionError(f'unsafe JSON integer at {path}: {x}; use decimal string')
    elif isinstance(x,list):
        for i,v in enumerate(x): walk_numbers(v,f'{path}[{i}]')
    elif isinstance(x,dict):
        for k,v in x.items(): walk_numbers(v,f'{path}.{k}')

def json_and_revision():
    for p in all_json():
        d=json.loads(p.read_text()); walk_numbers(d,p.name)
        if p.parent==TV: assert d.get('revision')=='Draft 09',(p,d.get('revision'))
        elif 'core_revision' in d: assert d['core_revision']=='Draft 09',(p,d['core_revision'])
    print('json/revision/safe-integer: ok')

def markdown_links():
    pat=re.compile(r'\[[^\]]+\]\(([^)]+)\)'); missing=[]
    for p in ROOT.rglob('*.md'):
        if '.git' in p.parts: continue
        for t in pat.findall(p.read_text()):
            if t.startswith(('http://','https://','mailto:','#')): continue
            t=t.split('#',1)[0]
            if t and not (p.parent/t).resolve().exists(): missing.append((str(p.relative_to(ROOT)),t))
    assert not missing,missing[:20]
    print('markdown-links: ok')

def parse_msg(h):
    b=bytes.fromhex(h); typ,i=vi_dec(b); ln,i=vi_dec(b,i); assert i+ln==len(b)
    ps=[]; end=i+ln
    while i<end:
        pt,i=vi_dec(b,i); flags=b[i]; i+=1; plen,i=vi_dec(b,i); val=b[i:i+plen]; i+=plen; ps.append((pt,flags,val))
    return typ,ps,b

def handshake_and_crypto():
    ks=json.loads((TV/'key-schedule.json').read_text()); sr=json.loads((TV/'secure-record.json').read_text())
    ct,cp,ci=parse_msg(ks['inputs']['client_init_hex']); st,sp,si=parse_msg(ks['inputs']['server_init_hex'])
    assert ct==1 and st==2
    assert [x[0] for x in cp]==[1,2,3,4,5,7,8,9,10]
    assert [x[0] for x in sp]==[6,7,8,9,10]
    assert 0x10 not in [x[0] for x in cp+sp] and 0x11 not in [x[0] for x in cp+sp]
    def extract(salt,ikm): return hmac.new(salt,ikm,hashlib.sha256).digest()
    def expand(prk,info,L):
        o=b''; last=b''; n=1
        while len(o)<L:
            last=hmac.new(prk,last+info+bytes([n]),hashlib.sha256).digest(); o+=last; n+=1
        return o[:L]
    def label(secret,name,ctx,L):
        lb=b'mpx4 '+name.encode(); return expand(secret,L.to_bytes(2,'big')+bytes([len(lb)])+lb+bytes([len(ctx)])+ctx,L)
    pre=bytes.fromhex(ks['inputs']['connection_preface_hex']); tk=bytes.fromhex(ks['inputs']['transport_key_hex'])
    h0=hashlib.sha256(pre+ci+si).digest(); early=extract(b'\0'*32,tk); hs=label(early,'handshake',h0,32)
    cfk=label(hs,'client finished',b'',32); sfk=label(hs,'server finished',b'',32); cv=hmac.new(cfk,h0,hashlib.sha256).digest(); cf=vi_enc(3)+vi_enc(32)+cv
    h1=hashlib.sha256(pre+ci+si+cf).digest(); sv=hmac.new(sfk,h1,hashlib.sha256).digest(); sf=vi_enc(4)+vi_enc(32)+sv; h2=hashlib.sha256(pre+ci+si+cf+sf).digest()
    cas=label(hs,'client application',h2,32); sas=label(hs,'server application',h2,32); ck=label(cas,'key',b'',32); civ=label(cas,'iv',b'',12); sk=label(sas,'key',b'',32); siv=label(sas,'iv',b'',12)
    checks={'h0_hex':h0,'early_secret_hex':early,'handshake_secret_hex':hs,'client_finished_key_hex':cfk,'server_finished_key_hex':sfk,'client_verify_data_hex':cv,'client_finished_hex':cf,'h1_hex':h1,'server_verify_data_hex':sv,'server_finished_hex':sf,'h2_hex':h2,'client_application_secret_hex':cas,'server_application_secret_hex':sas,'client_traffic_key_hex':ck,'client_traffic_iv_hex':civ,'server_traffic_key_hex':sk,'server_traffic_iv_hex':siv}
    for k,v in checks.items(): assert ks['derived'][k]==v.hex(),k
    assert sr['traffic_key_hex']==ck.hex() and sr['traffic_iv_hex']==civ.hex()
    for rec in sr['records']:
        seq=int(rec['sequence_number']); seq96=b'\0'*4+seq.to_bytes(8,'big'); nonce=bytes(a^b for a,b in zip(civ,seq96)); aad=bytes.fromhex(rec['aad_hex']); c=bytes.fromhex(rec['ciphertext_hex']); tag=bytes.fromhex(rec['authentication_tag_hex']); pt=bytes.fromhex(rec['plaintext_hex'])
        assert AESGCM(ck).decrypt(nonce,c+tag,aad)==pt
        assert AESGCM(ck).encrypt(nonce,pt,aad)==c+tag
    print('handshake/key-schedule/secure-record: ok')

def varint_and_frames():
    vv=json.loads((TV/'varint.json').read_text())
    for c in vv.get('valid',vv.get('valid_cases',[])):
        if 'value' not in c: continue
        v=int(c['value']); hx=c.get('hex') or c.get('encoded_hex'); assert vi_enc(v).hex()==hx
        d,j=vi_dec(bytes.fromhex(hx)); assert d==v and j==len(bytes.fromhex(hx))
    fv=json.loads((TV/'frame-encoding.json').read_text())
    names=set()
    for c in fv['vectors']:
        b=bytes.fromhex(c['hex']); typ,i=vi_dec(b); ln,j=vi_dec(b,i); assert j+ln==len(b)==c['length']; names.add(c['name'])
    assert 'transmission-retire' in names
    print('varint/frame-vectors: ok')

def semantic_vectors():
    rr=json.loads((TV/'reordering-reliability.json').read_text())
    names={c['name'] for c in rr['cases']}
    needed={'stream-credit-stale-reordering','session-credit-stale-reordering','crossed-credit-error','preopen-stop-reset-before-reject','terminal-ack-loss-before-retire','max-record-size-join-mismatch'}
    assert needed <= names
    vc=json.loads((TV/'version-compatibility.json').read_text()); vn={c['name'] for c in vc['cases']}
    assert {'vn-pipelined-client-init-server-side','vn-client-already-sent-init','vn-after-server-init'} <= vn
    cg=json.loads((TV/'carrier-generation.json').read_text()); case=next(c for c in cg['cases'] if c['name']=='maximum-generation-no-wrap'); assert isinstance(case['highest_accepted_generation'],str) and int(case['highest_accepted_generation'])==MAX_VARINT
    print('semantic-vectors: ok')

def registry():
    s=(ROOT/'REGISTRIES.md').read_text()
    assert '| 0x1a | TRANSMISSION_RETIRE | Session / Transmission namespace | Core |' in s
    assert '| 0x1b–0x1f | — | — | Core-reserved |' in s
    print('registry: ok')

def tcp_generated():
    r=subprocess.run([sys.executable,str(ROOT/'tools/generate_tcp_fixtures.py'),'--check'],capture_output=True,text=True)
    assert r.returncode==0,r.stdout+r.stderr
    print(r.stdout.strip())

def main():
    json_and_revision(); markdown_links(); registry(); varint_and_frames(); handshake_and_crypto(); semantic_vectors(); tcp_generated(); print('validation: PASS')
if __name__=='__main__': main()
