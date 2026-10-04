#!/usr/bin/env python3
import json
from pathlib import Path

MAX_VARINT=(1<<62)-1

class SemanticValidationError(Exception):
    pass

def _load(root,name):
    return json.loads((Path(root)/'test-vectors'/name).read_text())

def _i(v):
    if isinstance(v,int): return v
    if isinstance(v,str):
        return int(v,16) if v.startswith('0x') else int(v)
    raise SemanticValidationError(v)

def _cases(d,key='cases'):
    xs=d.get(key)
    if not isinstance(xs,list) or not xs:
        raise SemanticValidationError(f'{key} missing/empty')
    seen=set()
    for c in xs:
        if not isinstance(c,dict) or not c.get('name'):
            raise SemanticValidationError(f'case missing name: {c!r}')
        if c['name'] in seen:
            raise SemanticValidationError(f'duplicate case name: {c["name"]}')
        seen.add(c['name'])
    return xs

def _expect(check,case,actual,field='expected'):
    check(field in case,(case.get('name'),f'missing {field}'))
    check(case[field]==actual,(case.get('name'),field,case.get(field),actual))

def validate_max_carriers(root,check,vi_enc):
    d=_load(root,'max-carriers.json')
    check(d.get('critical_flag_required') is True,'MAX_CARRIERS critical flag')
    for c in d.get('encoding_cases',[]):
        v=_i(c['value']); raw=vi_enc(v)
        check(raw.hex()==c['value_varint_hex'],('max-carriers-encoding',v))
        param=vi_enc(0x0a)+b'\x01'+vi_enc(len(raw))+raw
        check(param.hex()==c['parameter_hex'],('max-carriers-parameter',v))
    for c in _cases({'cases':d['invalid_parameter_cases']}):
        n=c['name']
        if n=='zero': actual='PROTOCOL_VIOLATION' if _i(c['value'])==0 else 'valid'
        elif n=='noncritical': actual='PROTOCOL_VIOLATION' if _i(c.get('flags','0'))&1==0 else 'valid'
        elif n in {'missing-create-client','missing-create-server'}: actual='handshake_reject' if 'CREATE' in c['message'] else 'valid'
        elif n=='changed-on-join': actual='SESSION_CONFLICT' if _i(c['create_client_value'])!=_i(c['join_client_value']) else 'valid'
        else: raise SemanticValidationError(f'unhandled MAX_CARRIERS invalid case {n}')
        _expect(check,c,actual)
    for c in d.get('negotiation_cases',[]):
        check(_i(c['effective_carrier_limit'])==min(_i(c['client_max_carriers']),_i(c['server_max_carriers'])),c)
    for c in _cases({'cases':d['active_count_cases']}):
        n=c['name']; limit=_i(c['effective_limit'])
        if n=='sparse-id-does-not-imply-count':
            actual='valid' if len(set(c['active_carrier_ids']))==_i(c['active_count'])<=limit else 'invalid'
            _expect(check,c,actual)
        elif n=='third-new-id-over-limit':
            active=set(c['active_carrier_ids']); cand=c['candidate_carrier_id']
            actual='RESOURCE_LIMIT' if cand not in active and len(active)>=limit else 'may_establish'
            _expect(check,c,actual)
        elif n=='active-replacement-at-limit':
            active=set(c['active_carrier_ids']); cand=c['candidate_carrier_id']
            actual='accept_replacement' if cand in active and _i(c['candidate_generation'])>0 and len(active)<=limit else 'RESOURCE_LIMIT'
            _expect(check,c,actual); check(_i(c['active_count_after'])==len(active),c)
        elif n=='loss-releases-slot':
            before=set(c['active_carrier_ids_before']); after=before-{c['lost_carrier_id']}
            check(set(c['active_carrier_ids_after'])==after,c); check(_i(c['expected_active_count'])==len(after),c)
        elif n=='historical-id-does-not-reserve-slot':
            active=set(c['active_carrier_ids']); cand=c['candidate_carrier_id']
            actual='may_establish' if cand not in active and len(active)<limit else 'RESOURCE_LIMIT'
            _expect(check,c,actual); check(_i(c['active_count_after'])==len(active)+1,c)
        elif n=='inactive-replacement-needs-free-slot':
            active=set(c['active_carrier_ids']); hist=set(c['historical_carrier_ids']); cand=c['candidate_carrier_id']
            actual='RESOURCE_LIMIT' if cand in hist and cand not in active and len(active)>=limit else 'accept_replacement'
            _expect(check,c,actual)
        else: raise SemanticValidationError(f'unhandled active-count case {n}')
    for c in d.get('carrier_id_cases',[]):
        v=_i(c['value']); actual='valid' if 1<=v<=MAX_VARINT else 'PROTOCOL_VIOLATION'
        _expect(check,c,actual)
    return len(d.get('encoding_cases',[]))+len(d['invalid_parameter_cases'])+len(d.get('negotiation_cases',[]))+len(d['active_count_cases'])+len(d.get('carrier_id_cases',[]))

def validate_session_lifecycle(root,check):
    d=_load(root,'session-lifecycle.json'); count=0
    for c in _cases(d):
        n=c['name']
        if n=='first-carrier-establishes-active':
            check(c['before']=='CREATING' and c['event']=='first_carrier_established' and c['after']=='ACTIVE' and c['active_carrier_count_after']==1,c)
        elif n in {'last-carrier-loss-retained','last-carrier-close-retained'}:
            check(c['before']=='ACTIVE' and c['active_carrier_count_before']==1 and c['retain_session'] is True and c['active_carrier_count_after']==0 and c['after']=='DORMANT',c)
        elif n=='last-carrier-loss-not-retained':
            check(c['retain_session'] is False and c['active_carrier_count_after']==0 and c['after']=='CLOSED',c)
        elif n=='dormant-preserves-state':
            required={'session_protocol_version','stream_state','stream_and_session_credit','carrier_generation_history','outstanding_transmissions','settled_transmission_identity','tombstones','retired_stream_ids'}
            check(set(c['expected_preserved'])==required,c)
        elif n in {'dormant-no-new-stream','dormant-no-new-data-commit'}:
            _expect(check,c,'forbidden_until_active')
        elif n=='dormant-no-attempt': _expect(check,c,'no_eligible_carrier')
        elif n in {'dormant-join-handshaking','dormant-failed-join'}:
            check(c['before']=='DORMANT' and c['after']=='DORMANT',c)
        elif n=='dormant-recovery':
            check(c['before']=='DORMANT' and c['after']=='ACTIVE' and c['active_carrier_count_after']>=1,c)
        elif n=='dormant-reinjection-preserves-identity':
            check(c['expected_transmission_id']==c['outstanding_transmission_id'] and c['additional_logical_credit']==0,c)
        elif n=='dormant-retention-expiry': check(c['before']=='DORMANT' and c['after']=='CLOSED',c)
        elif n=='join-after-dormant-discard': _expect(check,c,'SESSION_NOT_FOUND')
        elif n=='session-close-is-not-dormant': check(c['expected_path']==['CLOSING','CLOSED'],c)
        else: raise SemanticValidationError(f'unhandled session lifecycle case {n}')
        count+=1
    return count

def validate_version_compatibility(root,check):
    d=_load(root,'version-compatibility.json'); pv=d['protocol_version']; count=0
    for c in _cases(d):
        n=c['name']
        if n=='draft-revision-not-on-wire':
            _expect(check,c,'draft_revision_not_encoded'); check(c['connection_preface_version']==pv,c)
        elif n=='create-binds-session-version': check(c['expected_session_protocol_version']==c['connection_preface_version']==pv,c)
        elif n=='same-version-join': _expect(check,c,'version_match' if c['session_protocol_version']==c['candidate_protocol_version'] else 'reject_candidate')
        elif n=='supported-cross-version-join':
            actual='reject_candidate' if c['session_protocol_version']!=c['candidate_protocol_version'] else 'version_match'
            _expect(check,c,actual); check(c['error']=='SESSION_CONFLICT' and c['session_modified'] is False,c)
        elif n=='unsupported-preface-version':
            actual='VERSION_NEGOTIATION_or_close' if c['candidate_protocol_version'] not in c['locally_supported_versions'] else 'continue'
            _expect(check,c,actual)
        elif n=='downgrade-does-not-enable-disabled-version':
            allowed=[v for v in c['version_negotiation_list'] if v in c['locally_enabled_versions']]
            check(c['expected_retry_versions']==allowed,c)
        elif n=='downgrade-respects-minimum':
            allowed=[v for v in c['version_negotiation_list'] if v in c['locally_supported_versions'] and v>=c['minimum_acceptable_version']]
            _expect(check,c,'no_retry_below_minimum' if not allowed else 'retry_permitted')
        elif n in {'authentication-failure-does-not-trigger-downgrade','handshake-reject-does-not-trigger-downgrade'}:
            _expect(check,c,'no_automatic_lower_version_retry')
        elif n=='stable-version-new-mandatory-core-parameter': _expect(check,c,'new_protocol_version_required')
        elif n=='stable-version-optional-negotiated-extension': _expect(check,c,'same_protocol_version_permitted')
        elif n=='vn-pipelined-client-init-server-side':
            _expect(check,c,['server_may_send_VERSION_NEGOTIATION','server_does_not_parse_pipelined_client_init_under_unsupported_version','close_candidate'])
        elif n=='vn-client-already-sent-init':
            actual='permitted_then_fresh_connection_retry' if c['client_sent_client_init'] and not c['client_accepted_server_init'] else 'reject_candidate_no_downgrade'
            _expect(check,c,actual)
        elif n=='vn-after-server-init':
            _expect(check,c,'reject_candidate_no_downgrade' if c['client_accepted_server_init'] else 'permitted_then_fresh_connection_retry')
        elif n=='permitted-fallback-not-highest-proof':
            _expect(check,c,'policy_permits_but_no_authenticated_highest_version_proof')
        else: raise SemanticValidationError(f'unhandled version case {n}')
        count+=1
    return count

def validate_handshake_reject(root,check,vi_enc):
    d=_load(root,'handshake-reject.json'); allowed={'INTERNAL_ERROR','PROTOCOL_VIOLATION','AUTHENTICATION_FAILED','RESOURCE_LIMIT','SESSION_NOT_FOUND','SESSION_CONFLICT','CARRIER_CONFLICT','UNSUPPORTED_PARAMETER'}; count=0
    for c in d.get('encoding_cases',[]):
        code=_i(c['error_code']); wire=vi_enc(0x06)+vi_enc(len(vi_enc(code)))+vi_enc(code)
        check(c['error'] in allowed and wire.hex()==c['wire_hex'],c); count+=1
    for c in d.get('invalid_core_error_cases',[]):
        actual='use_VERSION_NEGOTIATION_or_close' if c['error']=='VERSION_UNSUPPORTED' else 'invalid_in_core_HANDSHAKE_REJECT'
        _expect(check,c,actual); check(c['error'] not in allowed,c); count+=1
    for c in _cases({'cases':d['behavior_cases']}):
        n=c['name']
        if n in {'join-session-not-found','join-carrier-conflict','create-session-id-collision','unknown-critical-parameter'}:
            _expect(check,c,'send_reject_if_safely_reportable_then_close_candidate')
        elif n=='client-finished-auth-failure': _expect(check,c,'may_send_reject_then_close_candidate')
        elif n=='malformed-no-safe-boundary': _expect(check,c,'close_candidate_without_reject' if c.get('safe_response_boundary') is False else 'send_reject_if_safely_reportable_then_close_candidate')
        elif n=='unsupported-preface-version': _expect(check,c,'VERSION_NEGOTIATION_or_close_not_HANDSHAKE_REJECT')
        elif n=='reject-is-unauthenticated':
            _expect(check,c,['terminate_candidate','do_not_authenticate_peer','do_not_modify_existing_session','do_not_downgrade_version'])
        elif n=='unknown-extension-error-code': _expect(check,c,['terminate_candidate','diagnostic_reason_unknown','do_not_reply_with_reject'])
        elif n=='successful-transcript-excludes-reject': _expect(check,c,'HANDSHAKE_REJECT_absent_from_H0_H1_H2')
        else: raise SemanticValidationError(f'unhandled handshake reject behavior {n}')
        count+=1
    return count

def validate_identity_lifecycle(root,check):
    d=_load(root,'identity-lifecycle.json'); count=0
    for c in d['transmission_id_cases']:
        n=c['name']
        if n=='allocation-is-consecutive':
            actual='valid' if c['allocated']==[str(i) for i in range(1,len(c['allocated'])+1)] and _i(c['next_transmission_id'])==len(c['allocated'])+1 else 'invalid_allocation_gap'
        elif n=='skip-is-forbidden':
            actual='invalid_allocation_gap' if _i(c['candidate'])!=_i(c['allocated'][-1])+1 else 'valid'
        elif n=='final-id-allocation':
            actual='allocate_once_then_namespace_exhausted' if _i(c['candidate'])==_i(c['next_transmission_id'])==MAX_VARINT else 'invalid'
        elif n=='no-wrap-after-final':
            actual='forbidden_reuse_or_wrap' if _i(c['last_allocated'])==MAX_VARINT and _i(c['candidate'])<=_i(c['last_allocated']) else 'valid'
        elif n=='retransmit-final-id': actual='retransmit_or_reinject_same_id_permitted' if _i(c['outstanding_transmission_id'])==_i(c['last_allocated']) else 'invalid'
        elif n=='new-reliable-after-exhaustion': actual='SESSION_CLOSE_RESOURCE_LIMIT_when_possible' if _i(c['last_allocated'])==MAX_VARINT and c['requires_new_reliable_transmission'] else 'valid'
        else: raise SemanticValidationError(n)
        _expect(check,c,actual); count+=1
    for c in d['stream_id_cases']:
        n=c['name']
        if n=='odd-consecutive-space':
            vals=list(map(_i,c['allocated'])); actual='valid' if vals==list(range(1,2*len(vals),2)) and _i(c['next_stream_id'])==vals[-1]+2 else 'invalid'
        elif n=='final-stream-id': actual='allocate_once_then_stream_namespace_exhausted' if _i(c['candidate'])==MAX_VARINT else 'invalid'
        elif n=='no-stream-wrap': actual='forbidden_reuse_or_wrap' if _i(c['last_allocated'])==MAX_VARINT and _i(c['candidate'])<=MAX_VARINT else 'valid'
        elif n=='open-after-stream-exhaustion': actual='fail_locally_no_new_stream' if _i(c['last_allocated'])==MAX_VARINT and c['local_open_request'] else 'valid'
        else: raise SemanticValidationError(n)
        _expect(check,c,actual); count+=1
    for c in d['session_id_cases']:
        n=c['name']; retained=c.get('retained_state')
        if c.get('initiator_retains_state') and c.get('reuse_same_session_id'):
            actual='forbidden'
        elif retained in {'ACTIVE','DORMANT','CLOSING','CLOSED_retirement'} and c.get('create_same_session_id'):
            actual='HANDSHAKE_REJECT_SESSION_CONFLICT_if_reportable'
        elif retained=='none':
            actual='normal_CREATE_processing'
        else:
            raise SemanticValidationError(n)
        _expect(check,c,actual); count+=1
    return count

def validate_carrier_generation(root,check):
    d=_load(root,'carrier-generation.json'); count=0
    for c in _cases(d):
        n=c['name']
        if n=='first-incarnation-generation-zero':
            actual='accept' if c['carrier_id_state']=='UNUSED' and _i(c['candidate_generation'])==0 and c['candidate_result']=='authenticated_and_validated' else 'reject_candidate'
            _expect(check,c,actual); check(c['highest_accepted_generation']==0,c)
        elif n=='first-incarnation-nonzero':
            _expect(check,c,'reject_candidate' if c['carrier_id_state']=='UNUSED' and _i(c['candidate_generation'])!=0 else 'accept')
        elif n=='higher-generation-before-authentication':
            _expect(check,c,'no_generation_change'); check(c['current_generation']==c['highest_accepted_generation'],c)
        elif n=='failed-higher-generation-handshake':
            _expect(check,c,'reject_candidate'); check(c['highest_accepted_generation_after']==c['highest_accepted_generation'],c)
        elif n in {'stale-lower-generation','equal-generation-live-conflict','equal-generation-after-loss-still-conflict'}:
            h=_i(c['highest_accepted_generation']); g=_i(c['candidate_generation'])
            _expect(check,c,'reject_candidate' if g<=h else 'replace'); check(c['error']=='CARRIER_CONFLICT',c)
        elif n=='higher-generation-commit':
            h=_i(c['highest_accepted_generation']); g=_i(c['candidate_generation']); _expect(check,c,'replace' if g>h and c['candidate_result']=='established' else 'reject_candidate'); check(_i(c['highest_accepted_generation_after'])==g,c)
        elif n=='superseded-carrier-not-schedulable': _expect(check,c,'forbidden' if c['carrier_state']=='SUPERSEDED' else 'allowed')
        elif n=='superseded-record-after-commit': _expect(check,c,'ignore_as_new_protocol_state')
        elif n=='processed-old-record-before-commit-remains-applied': _expect(check,c,'retain_applied_effect')
        elif n=='replacement-preserves-transmission-id': check(c['expected_transmission_id']==c['outstanding_transmission_id'],c)
        elif n=='simultaneous-equal-generation-candidates':
            check(c['candidate_generations'][0]==c['candidate_generations'][1],c); _expect(check,c,['accept_generation_5','reject_candidate']); check(c['error_for_later']=='CARRIER_CONFLICT',c)
        elif n=='later-still-higher-candidate': check(c['expected_highest_accepted_generation']==max(c['candidate_generations']),c)
        elif n=='maximum-generation-no-wrap': _expect(check,c,'no_valid_higher_generation' if _i(c['highest_accepted_generation'])==MAX_VARINT else 'replace')
        elif n=='join-during-session-closing': _expect(check,c,'reject_candidate' if c['session_state']=='CLOSING' else 'accept')
        else: raise SemanticValidationError(f'unhandled generation case {n}')
        count+=1
    return count

def validate_error_scope(root,check):
    d=_load(root,'error-scope.json'); count=0
    base={
      'STREAM_LIMIT':('stream_opening','STREAM_OPEN_REJECT'),
      'AUTHENTICATION_FAILED':('carrier',None),
      'FRAME_ENCODING_ERROR':('carrier','CARRIER_CLOSE_if_safely_reportable'),
      'FLOW_CONTROL_ERROR':('session','SESSION_CLOSE'),
      'FINAL_SIZE_ERROR':('session','SESSION_CLOSE'),
      'TRANSMISSION_ID_ERROR':('session','SESSION_CLOSE'),
      'STREAM_STATE_ERROR':('session','SESSION_CLOSE'),
    }
    for c in _cases(d):
        n=c['name']
        if n=='retired-open-with-compacted-state': scope,action='retired_identity','ignore_without_recreating_stream'
        elif n=='session-error-atomicity': _expect(check,c,'must_not_create_new_stream'); count+=1; continue
        elif c.get('error')=='RESOURCE_LIMIT':
            rs=c.get('resource_scope')
            if rs=='one_stream': scope,action='stream_opening','STREAM_OPEN_REJECT'
            elif rs=='active_logical_carrier_count': scope,action='pre_establishment_carrier','HANDSHAKE_REJECT_if_safely_reportable_then_reject_candidate'
            elif rs=='one_carrier': scope,action='carrier','CARRIER_CLOSE'
            elif rs=='shared_session_state': scope,action='session','SESSION_CLOSE'
            else: raise SemanticValidationError(c)
        elif c.get('error') in {'SESSION_NOT_FOUND','SESSION_CONFLICT','CARRIER_CONFLICT'}:
            scope,action='pre_establishment_carrier','HANDSHAKE_REJECT_if_safely_reportable_then_reject_candidate'
        elif n=='finished-authentication-failure': scope,action='carrier','HANDSHAKE_REJECT_if_safely_reportable_or_terminate_carrier'
        elif n=='secure-record-authentication-failure': scope,action='carrier','terminate_carrier'
        elif n=='preopen-cancellation-late-open': scope,action='stream_opening','STREAM_OPEN_REJECT'
        elif c.get('error')=='INTERNAL_ERROR': scope,action='session','SESSION_CLOSE'
        else:
            scope,action=base[c.get('error')]
        check(c.get('expected_scope')==scope,(n,c.get('expected_scope'),scope))
        if 'expected_action' in c: check(c['expected_action']==action,(n,c['expected_action'],action))
        count+=1
    return count

def validate_reordering_edges(root,check):
    d=_load(root,'reordering-reliability.json'); by={c['name']:c for c in _cases(d)}
    c=by['max-record-size-join-mismatch']
    actual='SESSION_CONFLICT_candidate_rejected' if _i(c['create_receive_max_record_size'])!=_i(c['join_same_endpoint_max_record_size']) else 'join_limit_matches'
    _expect(check,c,actual)
    c=by['max-record-size-reinjection']
    actual='same_frame_may_reinject_on_carrier_b' if _i(c['frame_plaintext_length'])<=_i(c['session_receive_max_record_size']) else 'frame_exceeds_session_record_limit'
    _expect(check,c,actual)
    return 2

def _parse_pair(value):
    if not isinstance(value,str) or not (value.startswith('(') and value.endswith(')')):
        raise SemanticValidationError(f'invalid pair expression: {value!r}')
    a,b=value[1:-1].split(',',1)
    return int(a.strip()),int(b.strip())

def _state_outcome(c):
    state=c.get('state')
    frame=c.get('frame')
    cond=c.get('conditions') or {}

    if state=='UNSEEN responder':
        if frame=='STREAM_OPEN':
            return 'apply',None,None
        if frame=='RESET_STREAM':
            if cond.get('final_offset')=='0':
                return 'preopen_cancellation',None,'TRANSMISSION_ACK'
            return 'session_error','STREAM_STATE_ERROR',None
        if frame=='STOP_SENDING':
            return 'preopen_cancellation',None,['TRANSMISSION_ACK','RESET_STREAM(final_offset=0)']
        return 'session_error','STREAM_STATE_ERROR',None

    if state=='OPEN responder' and frame=='STREAM_OPEN':
        tx=cond.get('transmission_id')
        if tx=='same as original':
            return 'idempotent',None,'repeat STREAM_OPEN_OK'
        if tx=='different from original':
            return 'session_error','TRANSMISSION_ID_ERROR',None
        raise SemanticValidationError(f'unhandled OPEN responder STREAM_OPEN conditions: {cond!r}')

    if state=='OPENING initiator':
        if frame=='STREAM_CREDIT':
            return 'acceptance_evidence',None,None
        if frame=='STREAM_DATA':
            return 'session_error','STREAM_STATE_ERROR',None
        if frame=='STREAM_FIN':
            return ('acceptance_evidence',None,None) if cond.get('final_offset')=='0' else ('session_error','STREAM_STATE_ERROR',None)
        if frame=='TRANSMISSION_ACK':
            if cond.get('transmission_id')=='outstanding STREAM_OPEN' and cond.get('stream_id')=='matches':
                return 'session_error','TRANSMISSION_ID_ERROR',None
            raise SemanticValidationError(f'unhandled OPENING ACK conditions: {cond!r}')
        if frame in {'STREAM_OPEN_OK','STREAM_OPEN_REJECT'}:
            tx=cond.get('transmission_id')
            stream=cond.get('stream_id')
            if tx=='allocated STREAM_DATA' or stream=='different':
                return 'session_error','TRANSMISSION_ID_ERROR',None
            if tx=='original STREAM_OPEN' and stream=='matches':
                return ('apply_acceptance',None,None) if frame=='STREAM_OPEN_OK' else ('apply_rejection',None,None)
            raise SemanticValidationError(f'unhandled OPENING decision conditions: {cond!r}')
        raise SemanticValidationError(f'unhandled OPENING frame: {frame!r}')

    if state=='OPENING_CANCEL_PENDING initiator':
        if frame=='RESET_STREAM' and cond.get('final_offset')=='0' and cond.get('matches_outstanding_preopen_stop') is True:
            return 'cancellation_response_not_acceptance_evidence',None,None
        if frame=='STREAM_OPEN_REJECT' and cond.get('error')=='STREAM_STATE_ERROR' and cond.get('matches_cancelled_open') is True:
            return 'cancelled_open_complete_no_session_error',None,None
        if frame=='STREAM_OPEN_OK':
            return 'accepted_then_apply_pending_cancellation',None,None
        raise SemanticValidationError(f'unhandled OPENING_CANCEL_PENDING case: {frame!r} {cond!r}')

    if state=='FIN_RECEIVED':
        if frame=='STREAM_DATA':
            relation=cond.get('end_offset')
            if relation=='> final_offset':
                return 'session_error','FINAL_SIZE_ERROR',None
            if relation=='<= final_offset':
                if cond.get('bytes','consistent')=='consistent':
                    return 'apply',None,None
                return 'session_error','PROTOCOL_VIOLATION',None
            raise SemanticValidationError(f'unhandled FIN_RECEIVED DATA conditions: {cond!r}')
        if frame=='RESET_STREAM':
            relation=cond.get('final_offset')
            if relation=='different from established final_offset':
                return 'session_error','FINAL_SIZE_ERROR',None
            if relation=='same as established final_offset':
                return 'apply_reset_semantics',None,None
            raise SemanticValidationError(f'unhandled FIN_RECEIVED RESET conditions: {cond!r}')
        raise SemanticValidationError(f'unhandled FIN_RECEIVED frame: {frame!r}')

    if state=='RESET_RECEIVED':
        if frame=='STREAM_DATA':
            relation=cond.get('end_offset')
            if relation=='<= final_offset':
                return 'stale_duplicate_no_application_delivery',None,None
            if relation=='> final_offset':
                return 'session_error','FINAL_SIZE_ERROR',None
            raise SemanticValidationError(f'unhandled RESET_RECEIVED DATA conditions: {cond!r}')
        if frame=='STREAM_FIN':
            relation=cond.get('final_offset')
            if relation in {'same','same as established final_offset'}:
                return 'acknowledge_without_changing_reset_semantics',None,'TRANSMISSION_ACK'
            if relation in {'different','different from established final_offset'}:
                return 'session_error','FINAL_SIZE_ERROR',None
            raise SemanticValidationError(f'unhandled RESET_RECEIVED FIN conditions: {cond!r}')
        raise SemanticValidationError(f'unhandled RESET_RECEIVED frame: {frame!r}')

    if state=='RECV_ACTIVE':
        if frame!='STREAM_DATA':
            raise SemanticValidationError(f'unhandled RECV_ACTIVE frame: {frame!r}')
        relation=cond.get('end_offset')
        byte_rule=cond.get('bytes','consistent')
        if byte_rule!='consistent':
            return 'session_error','PROTOCOL_VIOLATION',None
        if relation in {'within retained credit','<= retained credit','<= maximum_offset'}:
            return 'apply',None,None
        if relation in {'> retained credit','> maximum_offset'}:
            return 'session_error','FLOW_CONTROL_ERROR',None
        raise SemanticValidationError(f'unhandled RECV_ACTIVE DATA conditions: {cond!r}')

    if state=='Session active':
        if frame=='TRANSMISSION_ACK':
            tx=cond.get('transmission_id')
            if tx=='outstanding':
                return 'settle_transmission',None,None
            if tx=='previously settled':
                return 'ignore_duplicate',None,None
            if tx=='>= next unallocated local Transmission ID':
                return 'session_error','TRANSMISSION_ID_ERROR',None
            raise SemanticValidationError(f'unhandled ACK conditions: {cond!r}')
        if frame=='TRANSMISSION_RETIRE':
            relation=cond.get('retired_through')
            if relation=='<= largest_contiguous_peer_tx_processed':
                return 'advance_peer_retired_through_if_newer',None,None
            if relation=='> largest_contiguous_peer_tx_processed':
                return 'session_error','TRANSMISSION_ID_ERROR',None
            raise SemanticValidationError(f'unhandled retirement conditions: {cond!r}')
        raise SemanticValidationError(f'unhandled Session active frame: {frame!r}')

    if state=='SEND_CLOSED' and frame=='STREAM_CREDIT':
        if cond.get('consumed_offset')=='<= local_final_offset':
            return 'validate_then_ignore',None,None
        raise SemanticValidationError(f'unhandled SEND_CLOSED credit conditions: {cond!r}')

    if state=='FIN_PENDING' and frame=='STREAM_CONSUMED':
        relation=cond.get('final_offset')
        if relation=='different from local final_offset':
            return 'session_error','FINAL_SIZE_ERROR',None
        if relation=='same as local final_offset':
            return 'apply',None,None
        raise SemanticValidationError(f'unhandled FIN_PENDING consumed conditions: {cond!r}')

    if state=='TOMBSTONE':
        if frame in {'STREAM_FIN','RESET_STREAM'}:
            relation=cond.get('final_offset')
            terminal_match=(cond.get('transmission_id')=='same terminal TxID' or cond.get('matches_recorded_terminal') is True)
            not_retired=cond.get('transmission_id')!='<= peer_retired_through'
            if (relation in {'same','same as established final_offset'} or (relation is None and cond.get('matches_recorded_terminal') is True)) and terminal_match and not_retired:
                return 'idempotent',None,'TRANSMISSION_ACK'
            if relation in {'different','different from established final_offset'}:
                return 'session_error','FINAL_SIZE_ERROR',None
            raise SemanticValidationError(f'unhandled TOMBSTONE terminal conditions: {cond!r}')
        if frame=='STREAM_DATA':
            relation=cond.get('end_offset')
            if relation=='> recorded peer final_offset':
                return 'session_error','FINAL_SIZE_ERROR',None
            if relation=='<= recorded peer final_offset':
                return 'ignore',None,None
            raise SemanticValidationError(f'unhandled TOMBSTONE DATA conditions: {cond!r}')
        raise SemanticValidationError(f'unhandled TOMBSTONE frame: {frame!r}')

    if state=='RETIRED_ID':
        if frame=='STREAM_DATA':
            if cond.get('transmission_id')=='<= peer_retired_through':
                return 'ignore',None,None
            raise SemanticValidationError(f'unhandled RETIRED_ID DATA conditions: {cond!r}')
        if frame=='STREAM_OPEN':
            return 'ignore',None,None
        raise SemanticValidationError(f'unhandled RETIRED_ID frame: {frame!r}')

    if state=='CLOSING' and frame=='SESSION_CLOSE':
        return 'idempotent',None,None

    if state=='Stream sending' and frame=='STREAM_CREDIT':
        retained=_parse_pair(cond.get('retained'))
        received=_parse_pair(cond.get('received'))
        c0,m0=retained; c1,m1=received
        if not (0<=c0<=m0<=MAX_VARINT and 0<=c1<=m1<=MAX_VARINT and m0-c0<=16*1024*1024 and m1-c1<=16*1024*1024):
            return 'session_error','FLOW_CONTROL_ERROR',None
        if c1>=c0 and m1>=m0:
            return 'apply_update',None,None
        if c1<=c0 and m1<=m0:
            return 'ignore_stale',None,None
        return 'session_error','FLOW_CONTROL_ERROR',None

    if state=='RESET_PENDING with superseded FIN outstanding' and frame=='local reliability':
        if cond.get('fin_ack_received') is False and cond.get('eligible_carrier') is True:
            return 'continue_FIN_retransmit_or_reinject_same_txid',None,None
        if cond.get('fin_ack_received') is False and cond.get('eligible_carrier') is False:
            return 'retain_FIN_without_attempt',None,None
        if cond.get('fin_ack_received') is True:
            return 'FIN_settled_no_retransmission',None,None
        raise SemanticValidationError(f'unhandled superseded FIN conditions: {cond!r}')

    raise SemanticValidationError(f'unhandled state-validity case inputs: state={state!r} frame={frame!r} conditions={cond!r}')

def validate_state_edges(root,check):
    cases=_cases(_load(root,'state-validity.json'))
    for c in cases:
        actual,error,response=_state_outcome(c)
        _expect(check,c,actual)
        if error is None:
            check('error' not in c,(c['name'],'unexpected error field',c.get('error')))
        else:
            check(c.get('error')==error,(c['name'],'error',c.get('error'),error))
        if response is None:
            check('response' not in c,(c['name'],'unexpected response field',c.get('response')))
        else:
            check(c.get('response')==response,(c['name'],'response',c.get('response'),response))
    return len(cases)

def _validate_ambiguity_vectors(root,check):
    cases=_cases(_load(root,'handshake-ambiguity.json'))
    for c in cases:
        if {'local_highest_accepted_generation','ambiguous_attempt_generation','next_retry_generation'} <= c.keys():
            actual='higher_than_accepted_and_ambiguous_attempt' if c.get('server_commit')=='unknown' and c['next_retry_generation']>max(c['local_highest_accepted_generation'],c['ambiguous_attempt_generation']) else 'invalid_retry_generation'
            _expect(check,c,actual)
        elif {'carrier_id_state','ambiguous_attempt_generation','expected_recovery','same_id_generation_1'} <= c.keys():
            expected_recovery='different_unused_carrier_id_generation_0' if c['carrier_id_state']=='UNUSED_locally' and c['ambiguous_attempt_generation']==0 else 'authenticated_acceptance_required'
            same_id='forbidden_without_authenticated_acceptance' if c['carrier_id_state']=='UNUSED_locally' and c['ambiguous_attempt_generation']==0 else 'depends_on_authenticated_state'
            check(c['expected_recovery']==expected_recovery,(c['name'],'expected_recovery',c['expected_recovery'],expected_recovery))
            check(c['same_id_generation_1']==same_id,(c['name'],'same_id_generation_1',c['same_id_generation_1'],same_id))
        elif {'session_id_retained','recovery_action','authenticated_join_success','unauthenticated_SESSION_NOT_FOUND'} <= c.keys():
            valid=(c['session_id_retained'] is True and c['recovery_action']=='JOIN_same_session_new_unused_carrier_gen0' and c['authenticated_join_success']=='confirms_session_retained' and c['unauthenticated_SESSION_NOT_FOUND']=='advisory_only')
            _expect(check,c,'do_not_reuse_reject_as_existence_proof' if valid else 'invalid_ambiguous_create_recovery')
        elif {'local_policy','old_session_id','new_create_session_id'} <= c.keys():
            valid=c['local_policy']=='abandon' and c['old_session_id']=='retained_ambiguous' and c['new_create_session_id']=='fresh_random'
            _expect(check,c,'fresh_session_id_required' if valid else 'invalid_abandon_recovery')
        else:
            raise SemanticValidationError(f'unhandled handshake ambiguity schema: {c!r}')
    return len(cases)

def _validate_recovery_progress(root,check):
    cases=_cases(_load(root,'recovery-progress.json'))
    for c in cases:
        writable=c.get('authenticated_writable_carrier') is True
        if not writable:
            actual='refresh_deferred'
        elif 'retained_session_credit' in c:
            actual='eventual_SESSION_CREDIT_refresh' if c.get('session_state')=='ACTIVE_after_DORMANT' and c.get('retained_session_credit') is True else 'no_refresh_required'
        elif 'probe_stream_id' in c:
            actual=['eventual_STREAM_CREDIT','eventual_SESSION_CREDIT'] if c.get('stream_state')=='retained' and int(c.get('probe_stream_id',0))>0 else 'no_refresh_required'
        elif 'retired_through' in c:
            actual='eventual_TRANSMISSION_RETIRE_refresh' if int(c.get('retired_through',0))>0 and c.get('can_release_peer_state') is True else 'no_refresh_required'
        else:
            raise SemanticValidationError(f'unhandled recovery-progress schema: {c!r}')
        _expect(check,c,actual)
    return len(cases)

def _terminal_flow_outcome(c):
    if c.get('frame') not in {'STREAM_FIN','RESET_STREAM'}:
        return 'invalid_terminal_frame'
    final=int(c['final_offset'])
    previous_end=int(c['previous_authenticated_end_offset'])
    previous_committed=int(c['previous_committed_offset'])
    stream_max=int(c['stream_maximum'])
    session_before=int(c['session_committed_before'])
    session_max=int(c['session_maximum'])
    if not (0<=final<=MAX_VARINT and 0<=previous_end<=MAX_VARINT and 0<=previous_committed<=MAX_VARINT):
        return 'FINAL_SIZE_ERROR'
    if 'established_final' in c and final!=int(c['established_final']):
        return 'FINAL_SIZE_ERROR'
    if final<previous_end or final<previous_committed:
        return 'FINAL_SIZE_ERROR'
    delta=final-previous_committed
    if final>stream_max or session_before+delta>session_max:
        return 'FLOW_CONTROL_ERROR'
    return 'apply'

def validate_new_vectors(root,check):
    count=0
    count+=_validate_ambiguity_vectors(root,check)
    count+=_validate_recovery_progress(root,check)
    for c in _cases(_load(root,'transmission-allocation.json')):
        n=c['name']
        if n=='tentative-reservation-not-allocation': actual='not_allocated' if not c['immutable_reliable_state_committed'] else 'allocated'
        elif n=='formal-allocation':
            check(c['expected_allocated']==c['next_protocol_transmission_id'] and c['next_after']==c['expected_allocated']+1,c); count+=1; continue
        elif n=='allocated-cannot-disappear': actual='remains_outstanding_eventual_attempt' if not c['confirmation_received'] and c['session_open'] and c['eligible_carrier'] else 'may_end'
        elif n=='resource-failure-after-allocation': actual='SESSION_CLOSE_RESOURCE_LIMIT_when_possible' if c['cannot_preserve_reliability_state'] else 'remain_outstanding'
        else: raise SemanticValidationError(n)
        _expect(check,c,actual); count+=1
    for c in _cases(_load(root,'terminal-flow-control.json')):
        _expect(check,c,_terminal_flow_outcome(c)); count+=1
    for c in _cases(_load(root,'close-ordering.json')):
        n=c['name']
        if 'frames' in c:
            frames=c['frames']; idx=next((i for i,x in enumerate(frames) if x in {'CARRIER_CLOSE','SESSION_CLOSE'}),None)
            actual='valid_terminal_record' if idx==len(frames)-1 else 'trailing_frame_must_not_create_state'
        elif c['frame']=='CARRIER_CLOSE' and c['range']=='negotiated_extension': actual='close_carrier_reason_unknown'
        elif c['frame']=='SESSION_CLOSE' and c['range']=='negotiated_extension': actual='close_session_reason_unknown'
        else: raise SemanticValidationError(n)
        _expect(check,c,actual); count+=1
    return count

def validate_extended_vectors(root,check,vi_enc):
    total=0
    total+=validate_max_carriers(root,check,vi_enc)
    total+=validate_session_lifecycle(root,check)
    total+=validate_version_compatibility(root,check)
    total+=validate_handshake_reject(root,check,vi_enc)
    total+=validate_identity_lifecycle(root,check)
    total+=validate_carrier_generation(root,check)
    total+=validate_error_scope(root,check)
    total+=validate_reordering_edges(root,check)
    total+=validate_state_edges(root,check)
    total+=validate_new_vectors(root,check)
    print(f'extended-semantic-vectors: ok ({total} executed cases/checks)')
    return total
