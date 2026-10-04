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


def require_baseline():
    for optimized in (False, True):
        r=run_validate(ROOT,optimized=optimized)
        mode='python -O' if optimized else 'ordinary'
        if r.returncode!=0 or 'validation: PASS' not in r.stdout:
            raise RuntimeError(f'baseline validator failed in {mode} mode: exit={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}')
    print('mutation baseline: PASS (ordinary + python -O)')


def expect_success(name, mutate, regenerate_tcp=False):
    with tempfile.TemporaryDirectory(prefix='mpx4-positive-') as tmp:
        repo=copy_repo(tmp)
        mutate(repo)
        if regenerate_tcp:
            r=subprocess.run([sys.executable,str(repo/'tools/generate_tcp_fixtures.py'),'--root',str(repo)],capture_output=True,text=True)
            if r.returncode!=0:
                raise RuntimeError(f'{name}: fixture regeneration failed: {r.stdout}{r.stderr}')
        for optimized in (False, True):
            r=run_validate(repo,optimized=optimized)
            mode='python -O' if optimized else 'ordinary'
            if r.returncode!=0 or 'validation: PASS' not in r.stdout:
                raise RuntimeError(f'{name}: positive control failed in {mode}; exit={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}')
        print(f'positive {name}: accepted')


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
        if r.returncode!=2 or 'validation: FAIL:' not in r.stderr:
            raise RuntimeError(f'{name}: validator did not report a semantic validation failure; exit={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}')
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
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,flags=b'\xff'); save(p,d)


def vi(v):
    for width,prefix in ((1,0),(2,1),(4,2),(8,3)):
        if 0<=v<(1<<(8*width-2)):
            return (v|(prefix<<(8*width-2))).to_bytes(width,'big')
    raise ValueError(v)


def reencrypt_record(d, record_index=0, flags=None, seq=None, plain=None):
    rec=d['records'][record_index]
    key=bytes.fromhex(d['traffic_key_hex']); iv=bytes.fromhex(d['traffic_iv_hex'])
    pt=bytes.fromhex(rec['plaintext_hex']) if plain is None else plain
    fl=bytes.fromhex(rec['record_flags_hex']) if flags is None else flags
    number=int(rec['sequence_number']) if seq is None else seq
    seq96=b'\x00'*4+number.to_bytes(8,'big')
    nonce=bytes(a^b for a,b in zip(iv,seq96))
    aad=fl+vi(len(pt)); enc=AESGCM(key).encrypt(nonce,pt,aad)
    rec.update(
        sequence_number=str(number), plaintext_hex=pt.hex(), record_flags_hex=fl.hex(),
        ciphertext_length=str(len(pt)), ciphertext_length_varint_hex=vi(len(pt)).hex(),
        aad_hex=aad.hex(), seq96_hex=seq96.hex(), nonce_hex=nonce.hex(),
        ciphertext_hex=enc[:-16].hex(), authentication_tag_hex=enc[-16:].hex(),
        wire_record_hex=(aad+enc).hex()
    )


def mutate_record_zero_plaintext(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b''); save(p,d)


def mutate_record_oversize(repo):
    p,d=load(repo,'secure-record.json')
    plain=vi(0)+vi(65532)+b'\x00'*65532
    if len(plain)!=65537:
        raise RuntimeError(len(plain))
    reencrypt_record(d,plain=plain); save(p,d)


def mutate_record_sequence_exhausted(repo):
    p,d=load(repo,'secure-record.json')
    d['records'].append(json.loads(json.dumps(d['records'][0])))
    reencrypt_record(d,record_index=-1,seq=1<<24)
    save(p,d)


def mutate_record_incomplete_frame(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b'\x01'); save(p,d)


def mutate_state_below_final_still_error(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='data-beyond-fin')
    c['conditions']={'end_offset':'<= final_offset','bytes':'consistent'}
    save(p,d)


def mutate_state_recv_active_still_final_error(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='data-beyond-fin')
    c['state']='RECV_ACTIVE'; c['conditions']={'end_offset':'within retained credit','bytes':'consistent'}
    save(p,d)


def mutate_state_add_unhandled_invalid_case(repo):
    p,d=load(repo,'state-validity.json')
    d['cases'].append({'name':'review-extra-invalid-open','state':'UNSEEN responder','frame':'STREAM_DATA','expected':'apply'})
    save(p,d)


def mutate_ambiguity_discard_identity(repo):
    p,d=load(repo,'handshake-ambiguity.json')
    c=next(x for x in d['cases'] if x['name']=='create-server-finished-lost')
    c['session_id_retained']=False; c['recovery_action']='CREATE_same_session_id'
    save(p,d)


def mutate_recovery_terminal_stream(repo):
    p,d=load(repo,'recovery-progress.json')
    next(x for x in d['cases'] if x['name']=='stream-probe-after-recovery')['stream_state']='terminal'
    save(p,d)


def mutate_recovery_closed_session(repo):
    p,d=load(repo,'recovery-progress.json')
    c=next(x for x in d['cases'] if x['name']=='dormant-recovery-session-credit')
    c['session_state']='CLOSED'; c['retained_session_credit']=False
    save(p,d)


def mutate_recovery_zero_retire(repo):
    p,d=load(repo,'recovery-progress.json')
    c=next(x for x in d['cases'] if x['name']=='retire-refresh-after-recovery')
    c['retired_through']=0; c['can_release_peer_state']=False
    save(p,d)


def mutate_terminal_below_commitment(repo):
    p,d=load(repo,'terminal-flow-control.json')
    next(x for x in d['cases'] if x['name']=='fin-at-stream-credit')['final_offset']=7
    save(p,d)


def mutate_terminal_frame_ping(repo):
    p,d=load(repo,'terminal-flow-control.json')
    next(x for x in d['cases'] if x['name']=='fin-beyond-stream-credit')['frame']='PING'
    save(p,d)


def mutate_state_case_expected(repo, case_name):
    p,d=load(repo,'state-validity.json')
    next(x for x in d['cases'] if x['name']==case_name)['expected']='__IMPOSSIBLE_OUTCOME__'
    save(p,d)


def reencrypt_all_records(d):
    for i in range(len(d['records'])):
        reencrypt_record(d,record_index=i)


def positive_record_valid_ping(repo):
    p,d=load(repo,'secure-record.json')
    reencrypt_record(d,plain=b'\x01\x01\x01')
    save(p,d)


def positive_record_max_padding(repo):
    p,d=load(repo,'secure-record.json')
    plain=vi(0)+vi(65531)+b'\x00'*65531
    if len(plain)!=65536:
        raise RuntimeError(len(plain))
    reencrypt_record(d,plain=plain)
    save(p,d)


def positive_record_server_direction(repo):
    kp,ks=load(repo,'key-schedule.json')
    p,d=load(repo,'secure-record.json')
    d['direction']='server_to_client'
    d['traffic_key_hex']=ks['derived']['server_traffic_key_hex']
    d['traffic_iv_hex']=ks['derived']['server_traffic_iv_hex']
    reencrypt_all_records(d)
    save(p,d)


def positive_named_state_case_made_legal(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='data-beyond-fin')
    c['conditions']={'end_offset':'<= final_offset','bytes':'consistent'}
    c['expected']='apply'
    c.pop('error',None)
    save(p,d)


def mutate_cancel_open_ok_data_tx(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='opening-cancel-acceptance-wins')
    c['conditions']={'transmission_id':'allocated STREAM_DATA','stream_id':'matches'}
    save(p,d)


def mutate_cancel_open_ok_wrong_stream(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='opening-cancel-acceptance-wins')
    c['conditions']={'transmission_id':'original STREAM_OPEN','stream_id':'different'}
    save(p,d)


def mutate_record_wrong_direction_key(repo):
    p,d=load(repo,'secure-record.json')
    d['direction']='server_to_client'
    save(p,d)


def mutate_decoded_record_limit_override(repo):
    kp,ks=load(repo,'key-schedule.json')
    ks['decoded_handshake']['server_receive_limits']['max_record_size']='65537'
    save(kp,ks)
    p,d=load(repo,'secure-record.json')
    plain=vi(0)+vi(65532)+b'\x00'*65532
    if len(plain)!=65537:
        raise RuntimeError(len(plain))
    reencrypt_record(d,plain=plain)
    save(p,d)


def mutate_record_ping_missing_token(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b'\x01\x00'); save(p,d)


def mutate_record_ping_truncated_token(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b'\x01\x01\x40'); save(p,d)


def mutate_record_ping_extra_body(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b'\x01\x02\x01\x00'); save(p,d)


def mutate_record_empty_stream_data(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=b'\x13\x00'); save(p,d)


def mutate_record_close_then_ping(repo):
    p,d=load(repo,'secure-record.json'); reencrypt_record(d,plain=bytes.fromhex('0303000000010101')); save(p,d)


def mutate_recovery_stream_probe_session_closed(repo):
    p,d=load(repo,'recovery-progress.json')
    c=next(x for x in d['cases'] if x['name']=='stream-probe-after-recovery')
    c['session_state']='CLOSED'
    save(p,d)


def mutate_recovery_retire_session_closed(repo):
    p,d=load(repo,'recovery-progress.json')
    c=next(x for x in d['cases'] if x['name']=='retire-refresh-after-recovery')
    c['session_state']='CLOSED'
    save(p,d)


def mutate_closed_probe_claims_writable(repo):
    p,d=load(repo,'recovery-progress.json')
    c=next(x for x in d['cases'] if x['name']=='stream-probe-after-session-closed')
    c['authenticated_writable_carrier']=True
    save(p,d)


def mutate_retired_open_without_coverage(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='retired-open')
    c['conditions']={'transmission_id':'> peer_retired_through'}
    save(p,d)


def mutate_retired_open_drop_replay(repo):
    p,d=load(repo,'state-validity.json')
    c=next(x for x in d['cases'] if x['name']=='retired-open-replay-before-retire')
    c['conditions'].pop('confirmation_replay_retained',None)
    save(p,d)


def mutate_session_lifecycle_state_flip(repo):
    p,d=load(repo,'session-lifecycle.json')
    c=next(x for x in d['cases'] if x['name']=='dormant-no-new-stream')
    c['state']='ACTIVE'
    save(p,d)


def mutate_session_lifecycle_join_not_closed(repo):
    p,d=load(repo,'session-lifecycle.json')
    c=next(x for x in d['cases'] if x['name']=='join-after-dormant-discard')
    c['state']='DORMANT'
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
        ('record-zero-plaintext',mutate_record_zero_plaintext,True,False),
        ('record-oversize-plaintext',mutate_record_oversize,True,False),
        ('record-sequence-key-limit',mutate_record_sequence_exhausted,True,False),
        ('record-incomplete-frame',mutate_record_incomplete_frame,True,False),
        ('record-wrong-direction-key',mutate_record_wrong_direction_key,False,False),
        ('decoded-record-limit-overrides-wire',mutate_decoded_record_limit_override,True,False),
        ('record-ping-missing-token',mutate_record_ping_missing_token,True,False),
        ('record-ping-truncated-token',mutate_record_ping_truncated_token,True,False),
        ('record-ping-extra-body',mutate_record_ping_extra_body,True,False),
        ('record-empty-stream-data',mutate_record_empty_stream_data,True,False),
        ('record-close-then-ping',mutate_record_close_then_ping,True,False),
        ('state-input-below-final',mutate_state_below_final_still_error,False,False),
        ('state-input-recv-active',mutate_state_recv_active_still_final_error,False,False),
        ('state-unhandled-case-fail-closed',mutate_state_add_unhandled_invalid_case,False,False),
        ('ambiguity-retained-identity',mutate_ambiguity_discard_identity,False,False),
        ('recovery-terminal-stream',mutate_recovery_terminal_stream,False,False),
        ('recovery-closed-session',mutate_recovery_closed_session,False,False),
        ('recovery-zero-retire',mutate_recovery_zero_retire,False,False),
        ('recovery-stream-probe-session-closed',mutate_recovery_stream_probe_session_closed,False,False),
        ('recovery-retire-session-closed',mutate_recovery_retire_session_closed,False,False),
        ('closed-session-writable-contradiction',mutate_closed_probe_claims_writable,False,False),
        ('cancel-open-ok-data-tx',mutate_cancel_open_ok_data_tx,False,False),
        ('cancel-open-ok-wrong-stream',mutate_cancel_open_ok_wrong_stream,False,False),
        ('retired-open-without-retire-or-replay',mutate_retired_open_without_coverage,False,False),
        ('retired-open-missing-replay-state',mutate_retired_open_drop_replay,False,False),
        ('session-lifecycle-state-flip',mutate_session_lifecycle_state_flip,False,False),
        ('session-lifecycle-join-not-closed',mutate_session_lifecycle_join_not_closed,False,False),
        ('terminal-final-below-commitment',mutate_terminal_below_commitment,False,False),
        ('terminal-nonterminal-frame',mutate_terminal_frame_ping,False,False),
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
    require_baseline()
    positives=[
        ('valid-ping-record',positive_record_valid_ping,True),
        ('valid-max-padding-record',positive_record_max_padding,True),
        ('valid-server-direction-records',positive_record_server_direction,True),
        ('same-named-state-case-with-legal-input',positive_named_state_case_made_legal,False),
    ]
    for name,fn,regen in positives:
        expect_success(name,fn,regenerate_tcp=regen)

    for name,fn,regen,opt in tests:
        expect_failure(name,fn,regenerate_tcp=regen,optimized=opt)

    state=json.loads((ROOT/'test-vectors/state-validity.json').read_text())
    state_names=[c['name'] for c in state['cases'] if 'expected' in c]
    for case_name in state_names:
        expect_failure(
            'state-expected-'+case_name,
            lambda repo,n=case_name: mutate_state_case_expected(repo,n),
        )
    print(f'mutation-tests: PASS ({len(tests)+len(state_names)} corruptions rejected; state expected coverage {len(state_names)}/{len(state_names)}; {len(positives)} paired positive controls)')


if __name__=='__main__':
    main()
