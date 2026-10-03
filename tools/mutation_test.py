#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]


def run_validate(repo, optimized=False):
    cmd=[sys.executable]
    if optimized:
        cmd.append('-O')
    cmd += [str(repo/'tools/validate.py'),'--root',str(repo)]
    return subprocess.run(cmd,capture_output=True,text=True)


def copy_repo(tmp):
    dst=Path(tmp)/'repo'
    shutil.copytree(ROOT,dst,ignore=shutil.ignore_patterns('.git','.venv','__pycache__','*.pyc'))
    return dst


def expect_failure(name, mutate, regenerate_tcp=False, optimized=False):
    with tempfile.TemporaryDirectory(prefix='mpx4-mutation-') as tmp:
        repo=copy_repo(tmp)
        mutate(repo)
        if regenerate_tcp:
            r=subprocess.run([sys.executable,str(repo/'tools/generate_tcp_fixtures.py'),'--root',str(repo)],capture_output=True,text=True)
            if r.returncode!=0:
                raise RuntimeError(f'{name}: fixture regeneration failed: {r.stdout}{r.stderr}')
        r=run_validate(repo,optimized=optimized)
        if r.returncode==0:
            raise RuntimeError(f'{name}: validator incorrectly returned PASS')
        print(f'mutation {name}: rejected')


def load(repo,name):
    p=repo/'test-vectors'/name
    return p,json.loads(p.read_text())


def save(p,d):
    p.write_text(json.dumps(d,indent=2)+'\n')


def mutate_varint_valid(repo):
    p,d=load(repo,'varint.json'); d['vectors'][0]['hex']='01'; save(p,d)


def mutate_varint_invalid(repo):
    p,d=load(repo,'varint.json'); d['invalid'][3]['hex']='00'; save(p,d)


def mutate_frame_fields(repo):
    p,d=load(repo,'frame-encoding.json')
    next(x for x in d['vectors'] if x['name']=='stream-data-small')['fields']['stream_id']='2'
    save(p,d)


def mutate_state_expected(repo):
    p,d=load(repo,'reordering-reliability.json')
    next(x for x in d['cases'] if x['name']=='stream-credit-stale-reordering')['expected']='SESSION_CLOSE_FLOW_CONTROL_ERROR'
    save(p,d)


def mutate_secure_wire(repo):
    p,d=load(repo,'secure-record.json')
    d['records'][0]['wire_record_hex']='ff'+d['records'][0]['wire_record_hex'][2:]
    save(p,d)


def mutate_structurally_invalid_stale_credit(repo):
    p,d=load(repo,'reordering-reliability.json')
    c=next(x for x in d['cases'] if x['name']=='stream-credit-stale-reordering')
    c['receive_order'][1]={'consumed':'2048','maximum':'1024'}
    save(p,d)


def mutate_join_same_limit_still_conflict(repo):
    p,d=load(repo,'reordering-reliability.json')
    c=next(x for x in d['cases'] if x['name']=='max-record-size-join-mismatch')
    c['join_same_endpoint_max_record_size']=c['create_receive_max_record_size']
    save(p,d)


def mutate_oversize_reinjection(repo):
    p,d=load(repo,'reordering-reliability.json')
    next(x for x in d['cases'] if x['name']=='max-record-size-reinjection')['frame_plaintext_length']='65537'
    save(p,d)


def mutate_fin_settle_before_ack(repo):
    p,d=load(repo,'reordering-reliability.json')
    c=next(x for x in d['cases'] if x['name']=='fin-supersession-retirement')
    events=c['events']; events.remove('sender_settle_FIN_tx2')
    events.insert(events.index('peer_receive_late_FIN_tx2_same_final_and_ACK'),'sender_settle_FIN_tx2')
    save(p,d)


def mutate_final_size_frame_to_ping(repo):
    p,d=load(repo,'state-validity.json')
    next(x for x in d['cases'] if x['name']=='data-beyond-fin')['frame']='PING'
    save(p,d)


def mutate_reset_late_data_delivery(repo):
    p,d=load(repo,'state-validity.json')
    next(x for x in d['cases'] if x['name']=='late-data-after-reset')['expected']='apply'
    save(p,d)


def mutate_future_retire_ignored(repo):
    p,d=load(repo,'state-validity.json')
    next(x for x in d['cases'] if x['name']=='transmission-retire-future')['expected']='ignore'
    save(p,d)


def mutate_secure_flags_self_consistent(repo):
    p,d=load(repo,'secure-record.json')
    key=bytes.fromhex(d['traffic_key_hex']); iv=bytes.fromhex(d['traffic_iv_hex']); rec=d['records'][0]
    seq=int(rec['sequence_number']); pt=bytes.fromhex(rec['plaintext_hex']); flags=b'\xff'
    clen_vi=bytes.fromhex(rec['ciphertext_length_varint_hex']); aad=flags+clen_vi
    seq96=b'\x00'*4+seq.to_bytes(8,'big'); nonce=bytes(a^b for a,b in zip(iv,seq96))
    enc=AESGCM(key).encrypt(nonce,pt,aad)
    rec['record_flags_hex']='ff'; rec['aad_hex']=aad.hex(); rec['seq96_hex']=seq96.hex(); rec['nonce_hex']=nonce.hex()
    rec['ciphertext_hex']=enc[:-16].hex(); rec['authentication_tag_hex']=enc[-16:].hex(); rec['wire_record_hex']=(aad+enc).hex()
    save(p,d)


def mutate_max_carriers_expected(repo):
    p,d=load(repo,'max-carriers.json')
    next(x for x in d['active_count_cases'] if x['name']=='third-new-id-over-limit')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_session_lifecycle_expected(repo):
    p,d=load(repo,'session-lifecycle.json')
    next(x for x in d['cases'] if x['name']=='dormant-no-new-stream')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_version_expected(repo):
    p,d=load(repo,'version-compatibility.json')
    next(x for x in d['cases'] if x['name']=='same-version-join')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_handshake_reject_expected(repo):
    p,d=load(repo,'handshake-reject.json')
    next(x for x in d['behavior_cases'] if x['name']=='join-session-not-found')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_identity_expected(repo):
    p,d=load(repo,'identity-lifecycle.json')
    next(x for x in d['transmission_id_cases'] if x['name']=='skip-is-forbidden')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_generation_expected(repo):
    p,d=load(repo,'carrier-generation.json')
    next(x for x in d['cases'] if x['name']=='stale-lower-generation')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_error_scope_expected(repo):
    p,d=load(repo,'error-scope.json')
    next(x for x in d['cases'] if x['name']=='stream-flow-control-violation')['expected_action']='__IMPOSSIBLE__'
    save(p,d)


def mutate_ambiguous_recovery_expected(repo):
    p,d=load(repo,'handshake-ambiguity.json')
    next(x for x in d['cases'] if x['name']=='replacement-server-finished-lost')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_recovery_progress_expected(repo):
    p,d=load(repo,'recovery-progress.json')
    next(x for x in d['cases'] if x['name']=='dormant-recovery-session-credit')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_transmission_allocation_expected(repo):
    p,d=load(repo,'transmission-allocation.json')
    next(x for x in d['cases'] if x['name']=='allocated-cannot-disappear')['expected']='__IMPOSSIBLE__'
    save(p,d)


def mutate_terminal_flow_expected(repo):
    p,d=load(repo,'terminal-flow-control.json')
    next(x for x in d['cases'] if x['name']=='fin-beyond-stream-credit')['expected']='apply'
    save(p,d)


def mutate_close_order_expected(repo):
    p,d=load(repo,'close-ordering.json')
    next(x for x in d['cases'] if x['name']=='session-close-trailing-frame')['expected']='valid_terminal_record'
    save(p,d)


def main():
    tests=[
        ('varint-valid-corruption',mutate_varint_valid,False,False),
        ('varint-valid-corruption-python-O',mutate_varint_valid,False,True),
        ('varint-invalid-accepted',mutate_varint_invalid,False,False),
        ('frame-fields-vs-wire',mutate_frame_fields,False,False),
        ('state-oracle-expected',mutate_state_expected,False,False),
        ('secure-record-wire',mutate_secure_wire,True,False),
        ('stale-credit-structural-invalid',mutate_structurally_invalid_stale_credit,False,False),
        ('join-same-limit-still-conflict',mutate_join_same_limit_still_conflict,False,False),
        ('oversize-reinjection',mutate_oversize_reinjection,False,False),
        ('fin-settle-before-ack',mutate_fin_settle_before_ack,False,False),
        ('final-size-frame-to-ping',mutate_final_size_frame_to_ping,False,False),
        ('reset-late-data-delivery',mutate_reset_late_data_delivery,False,False),
        ('future-retire-ignored',mutate_future_retire_ignored,False,False),
        ('secure-record-self-consistent-flags',mutate_secure_flags_self_consistent,True,False),
        ('max-carriers-expected',mutate_max_carriers_expected,False,False),
        ('session-lifecycle-expected',mutate_session_lifecycle_expected,False,False),
        ('version-compatibility-expected',mutate_version_expected,False,False),
        ('handshake-reject-expected',mutate_handshake_reject_expected,False,False),
        ('identity-lifecycle-expected',mutate_identity_expected,False,False),
        ('carrier-generation-expected',mutate_generation_expected,False,False),
        ('error-scope-expected',mutate_error_scope_expected,False,False),
        ('ambiguous-recovery-expected',mutate_ambiguous_recovery_expected,False,False),
        ('recovery-progress-expected',mutate_recovery_progress_expected,False,False),
        ('transmission-allocation-expected',mutate_transmission_allocation_expected,False,False),
        ('terminal-flow-control-expected',mutate_terminal_flow_expected,False,False),
        ('close-ordering-expected',mutate_close_order_expected,False,False),
    ]
    for name,fn,regen,opt in tests:
        expect_failure(name,fn,regenerate_tcp=regen,optimized=opt)
    print(f'mutation-tests: PASS ({len(tests)} corruptions rejected)')


if __name__=='__main__':
    main()
