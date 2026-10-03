import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from semantic_validation import validate_extended_vectors
MAX_VARINT = (1 << 62) - 1
JS_SAFE = (1 << 53) - 1


class ValidationError(Exception):
    pass

def check(condition, detail='validation check failed'):
    if not condition:
        raise ValidationError(str(detail))

def vi_enc(v):
    if not 0 <= v <= MAX_VARINT:
        raise ValueError(v)
    if v < 1 << 6:
        n, p = (1, 0)
    elif v < 1 << 14:
        n, p = (2, 1)
    elif v < 1 << 30:
        n, p = (4, 2)
    else:
        n, p = (8, 3)
    return (v | p << 8 * n - 2).to_bytes(n, 'big')

def vi_dec(b, i=0):
    if i >= len(b):
        raise ValueError('truncated varint')
    n = (1, 2, 4, 8)[b[i] >> 6]
    if i + n > len(b):
        raise ValueError('truncated varint')
    raw = int.from_bytes(b[i:i + n], 'big')
    v = raw & (1 << 8 * n - 2) - 1
    if len(vi_enc(v)) != n:
        raise ValueError('non-canonical varint')
    return (v, i + n)

def walk_numbers(x, path='$'):
    if isinstance(x, bool) or x is None:
        return
    if isinstance(x, int):
        if abs(x) > JS_SAFE:
            raise AssertionError(f'unsafe JSON integer at {path}: {x}; use decimal string')
    elif isinstance(x, list):
        for i, v in enumerate(x):
            walk_numbers(v, f'{path}[{i}]')
    elif isinstance(x, dict):
        for k, v in x.items():
            walk_numbers(v, f'{path}.{k}')

def parse_registry(root):
    text = (root / 'REGISTRIES.md').read_text()
    start = text.index('## 4. Frame Types')
    end = text.index('## 5. Error Codes')
    out = {}
    for line in text[start:end].splitlines():
        if not line.startswith('|'):
            continue
        cols = [c.strip() for c in line.strip('|').split('|')]
        if len(cols) < 2 or not re.fullmatch('0x[0-9A-Fa-f]+', cols[0]):
            continue
        if re.fullmatch('[A-Z][A-Z0-9_]*', cols[1]):
            out[cols[1]] = int(cols[0], 16)
    return out

def json_and_revision(root):
    tv = root / 'test-vectors'
    files = sorted(list(tv.glob('*.json')) + list((root / 'extensions').glob('*.json')))
    check(files, 'no JSON vectors found')
    for p in files:
        d = json.loads(p.read_text())
        walk_numbers(d, p.name)
        if p.parent == tv:
            check(d.get('revision') == 'Draft 11', (p, d.get('revision')))
        elif 'core_revision' in d:
            check(d['core_revision'] == 'Draft 11', (p, d['core_revision']))
    print(f'json/revision/safe-integer: ok ({len(files)} files)')

def markdown_links(root):
    pat = re.compile('\\[[^\\]]+\\]\\(([^)]+)\\)')
    missing = []
    checked = 0
    for p in root.rglob('*.md'):
        if '.git' in p.parts:
            continue
        for t in pat.findall(p.read_text()):
            if t.startswith(('http://', 'https://', 'mailto:', '#')):
                continue
            t = t.split('#', 1)[0]
            checked += 1
            if t and (not (p.parent / t).resolve().exists()):
                missing.append((str(p.relative_to(root)), t))
    check(not missing, missing[:20])
    print(f'markdown-links: ok ({checked} relative links)')

def validate_varints(root):
    d = json.loads((root / 'test-vectors/varint.json').read_text())
    check(isinstance(d.get('vectors'), list) and d['vectors'], 'varint vectors missing/empty')
    check(isinstance(d.get('invalid'), list) and d['invalid'], 'varint invalid cases missing/empty')
    good = bad = 0
    for c in d['vectors']:
        check({'value', 'hex', 'length'} <= c.keys(), c)
        v = int(c['value'])
        hx = c['hex']
        raw = bytes.fromhex(hx)
        check(vi_enc(v) == raw, c)
        got, j = vi_dec(raw)
        check(got == v and j == len(raw), c)
        check(len(raw) == int(c['length']), c)
        good += 1
    for c in d['invalid']:
        check({'hex', 'reason'} <= c.keys(), c)
        raw = bytes.fromhex(c['hex'])
        try:
            vi_dec(raw)
        except ValueError:
            pass
        else:
            raise AssertionError(f'invalid VarInt accepted: {c}')
        bad += 1
    print(f'varint: ok ({good} valid, {bad} invalid)')

def frame_body_from_fields(name, fields):
    i = lambda k: vi_enc(int(fields[k]))
    if name == 'PADDING':
        return bytes.fromhex(fields.get('padding_hex', ''))
    if name in {'STREAM_OPEN', 'STREAM_OPEN_OK'}:
        return i('stream_id') + i('transmission_id')
    if name == 'STREAM_OPEN_REJECT':
        return i('stream_id') + i('transmission_id') + i('error_code')
    if name == 'STREAM_DATA':
        data = fields.get('data_hex')
        payload = bytes.fromhex(data) if data is not None else fields['data_utf8'].encode()
        return i('stream_id') + i('offset') + i('transmission_id') + payload
    if name == 'TRANSMISSION_ACK':
        return i('stream_id') + i('transmission_id') + i('receiver_timestamp_us')
    if name == 'STREAM_CREDIT':
        return i('stream_id') + i('consumed_offset') + i('maximum_offset')
    if name == 'STREAM_FIN':
        return i('stream_id') + i('transmission_id') + i('final_offset')
    if name == 'RESET_STREAM':
        return i('stream_id') + i('transmission_id') + i('final_offset') + i('stream_error_code')
    if name == 'STOP_SENDING':
        return i('stream_id') + i('transmission_id') + i('stream_error_code')
    if name == 'STREAM_CONSUMED':
        return i('stream_id') + i('transmission_id') + i('final_offset')
    if name == 'TRANSMISSION_RETIRE':
        return i('retired_through')
    if name == 'SESSION_CREDIT':
        return i('consumed_bytes') + i('maximum_bytes')
    if name == 'CREDIT_PROBE':
        return i('stream_id')
    if name in {'PING', 'PONG'}:
        return i('token')
    if name in {'CARRIER_CLOSE', 'SESSION_CLOSE'}:
        reason = fields.get('reason_utf8', '').encode('utf-8')
        return i('error_code') + i('trigger_frame_type') + vi_enc(len(reason)) + reason
    raise AssertionError(f'no validator body schema for {name}')

def decode_body(name, body):
    pos = 0

    def get(k):
        nonlocal pos
        v, pos = vi_dec(body, pos)
        out[k] = str(v)
    out = {}
    if name == 'PADDING':
        out['padding_hex'] = body.hex()
        pos = len(body)
    elif name in {'STREAM_OPEN', 'STREAM_OPEN_OK'}:
        get('stream_id')
        get('transmission_id')
    elif name == 'STREAM_OPEN_REJECT':
        get('stream_id')
        get('transmission_id')
        get('error_code')
    elif name == 'STREAM_DATA':
        get('stream_id')
        get('offset')
        get('transmission_id')
        out['data_hex'] = body[pos:].hex()
        pos = len(body)
    elif name == 'TRANSMISSION_ACK':
        get('stream_id')
        get('transmission_id')
        get('receiver_timestamp_us')
    elif name == 'STREAM_CREDIT':
        get('stream_id')
        get('consumed_offset')
        get('maximum_offset')
    elif name == 'STREAM_FIN':
        get('stream_id')
        get('transmission_id')
        get('final_offset')
    elif name == 'RESET_STREAM':
        get('stream_id')
        get('transmission_id')
        get('final_offset')
        get('stream_error_code')
    elif name == 'STOP_SENDING':
        get('stream_id')
        get('transmission_id')
        get('stream_error_code')
    elif name == 'STREAM_CONSUMED':
        get('stream_id')
        get('transmission_id')
        get('final_offset')
    elif name == 'TRANSMISSION_RETIRE':
        get('retired_through')
    elif name == 'SESSION_CREDIT':
        get('consumed_bytes')
        get('maximum_bytes')
    elif name == 'CREDIT_PROBE':
        get('stream_id')
    elif name in {'PING', 'PONG'}:
        get('token')
    elif name in {'CARRIER_CLOSE', 'SESSION_CLOSE'}:
        get('error_code')
        get('trigger_frame_type')
        ln, pos2 = vi_dec(body, pos)
        pos = pos2
        if pos + ln > len(body):
            raise AssertionError(f'truncated reason in {name}')
        out['reason_utf8'] = body[pos:pos + ln].decode('utf-8')
        pos += ln
    else:
        raise AssertionError(f'no decoder schema for {name}')
    if name not in {'STREAM_DATA', 'PADDING'} and pos != len(body):
        raise AssertionError(f'extra bytes in {name}')
    return out

def validate_frames(root):
    registry = parse_registry(root)
    d = json.loads((root / 'test-vectors/frame-encoding.json').read_text())
    check(isinstance(d.get('vectors'), list) and d['vectors'], 'frame vectors missing/empty')
    count = 0
    seen = set()
    for c in d['vectors']:
        check({'name', 'frame_type', 'fields', 'hex', 'length'} <= c.keys(), c)
        name = c['frame_type']
        check(name in registry, (name, 'missing registry assignment'))
        seen.add(name)
        body = frame_body_from_fields(name, c['fields'])
        encoded = vi_enc(registry[name]) + vi_enc(len(body)) + body
        check(encoded.hex() == c['hex'], (c['name'], 'fields do not encode to hex', encoded.hex(), c['hex']))
        raw = bytes.fromhex(c['hex'])
        typ, i = vi_dec(raw)
        ln, j = vi_dec(raw, i)
        check(typ == registry[name] and j + ln == len(raw) == int(c['length']), c)
        decoded = decode_body(name, raw[j:])
        for k, v in c['fields'].items():
            if k == 'data_utf8':
                check(bytes.fromhex(decoded['data_hex']).decode() == v, c)
            elif k == 'data_hex':
                check(decoded['data_hex'] == v, c)
            else:
                check(decoded[k] == str(v), (c['name'], k, decoded.get(k), v))
        count += 1
    check(seen == set(registry), (sorted(set(registry) - seen), sorted(seen - set(registry))))
    print(f'frame-vectors: ok ({count} full encode/decode cases; all Core Frame types covered)')

def parse_msg(h):
    b = bytes.fromhex(h)
    typ, i = vi_dec(b)
    ln, i = vi_dec(b, i)
    check(i + ln == len(b), 'validation check failed')
    ps = []
    end = i + ln
    while i < end:
        pt, i = vi_dec(b, i)
        flags = b[i]
        i += 1
        plen, i = vi_dec(b, i)
        val = b[i:i + plen]
        i += plen
        ps.append((pt, flags, val))
    return (typ, ps, b)

def handshake_crypto_records(root):
    tv = root / 'test-vectors'
    ks = json.loads((tv / 'key-schedule.json').read_text())
    sr = json.loads((tv / 'secure-record.json').read_text())
    ct, cp, ci = parse_msg(ks['inputs']['client_init_hex'])
    st, sp, si = parse_msg(ks['inputs']['server_init_hex'])
    check(ct == 1 and st == 2, 'validation check failed')
    check([x[0] for x in cp] == [1, 2, 3, 4, 5, 7, 8, 9, 10], 'validation check failed')
    check([x[0] for x in sp] == [6, 7, 8, 9, 10], 'validation check failed')
    check(dict(((t, (f, v)) for t, f, v in cp))[10][0] == 1 and dict(((t, (f, v)) for t, f, v in sp))[10][0] == 1, 'validation check failed')

    def extract(salt, ikm):
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def expand(prk, info, L):
        o = b''
        last = b''
        n = 1
        while len(o) < L:
            last = hmac.new(prk, last + info + bytes([n]), hashlib.sha256).digest()
            o += last
            n += 1
        return o[:L]

    def label(secret, name, ctx, L):
        lb = b'mpx4 ' + name.encode()
        return expand(secret, L.to_bytes(2, 'big') + bytes([len(lb)]) + lb + bytes([len(ctx)]) + ctx, L)
    pre = bytes.fromhex(ks['inputs']['connection_preface_hex'])
    tk = bytes.fromhex(ks['inputs']['transport_key_hex'])
    h0 = hashlib.sha256(pre + ci + si).digest()
    early = extract(b'\x00' * 32, tk)
    hs = label(early, 'handshake', h0, 32)
    cfk = label(hs, 'client finished', b'', 32)
    sfk = label(hs, 'server finished', b'', 32)
    cv = hmac.new(cfk, h0, hashlib.sha256).digest()
    cf = vi_enc(3) + vi_enc(32) + cv
    h1 = hashlib.sha256(pre + ci + si + cf).digest()
    sv = hmac.new(sfk, h1, hashlib.sha256).digest()
    sf = vi_enc(4) + vi_enc(32) + sv
    h2 = hashlib.sha256(pre + ci + si + cf + sf).digest()
    cas = label(hs, 'client application', h2, 32)
    sas = label(hs, 'server application', h2, 32)
    ck = label(cas, 'key', b'', 32)
    civ = label(cas, 'iv', b'', 12)
    sk = label(sas, 'key', b'', 32)
    siv = label(sas, 'iv', b'', 12)
    checks = {'h0_hex': h0, 'early_secret_hex': early, 'handshake_secret_hex': hs, 'client_finished_key_hex': cfk, 'server_finished_key_hex': sfk, 'client_verify_data_hex': cv, 'client_finished_hex': cf, 'h1_hex': h1, 'server_verify_data_hex': sv, 'server_finished_hex': sf, 'h2_hex': h2, 'client_application_secret_hex': cas, 'server_application_secret_hex': sas, 'client_traffic_key_hex': ck, 'client_traffic_iv_hex': civ, 'server_traffic_key_hex': sk, 'server_traffic_iv_hex': siv}
    for k, v in checks.items():
        check(ks['derived'][k] == v.hex(), k)
    check(sr['traffic_key_hex'] == ck.hex() and sr['traffic_iv_hex'] == civ.hex(), 'validation check failed')
    for rec in sr['records']:
        seq = int(rec['sequence_number'])
        pt = bytes.fromhex(rec['plaintext_hex'])
        flags = bytes.fromhex(rec['record_flags_hex'])
        check(len(flags) == 1, 'validation check failed')
        check(flags == b'\x00', ('record flags must be zero', rec.get('record_flags_hex')))
        clen = int(rec['ciphertext_length'])
        check(clen == len(pt), 'validation check failed')
        clen_vi = vi_enc(clen)
        check(rec['ciphertext_length_varint_hex'] == clen_vi.hex(), 'validation check failed')
        aad = flags + clen_vi
        check(rec['aad_hex'] == aad.hex(), 'validation check failed')
        seq96 = b'\x00' * 4 + seq.to_bytes(8, 'big')
        check(rec['seq96_hex'] == seq96.hex(), 'validation check failed')
        nonce = bytes((a ^ b for a, b in zip(civ, seq96)))
        check(rec['nonce_hex'] == nonce.hex(), 'validation check failed')
        enc = AESGCM(ck).encrypt(nonce, pt, aad)
        c, tag = (enc[:-16], enc[-16:])
        check(rec['ciphertext_hex'] == c.hex() and rec['authentication_tag_hex'] == tag.hex(), 'validation check failed')
        wire = aad + c + tag
        check(rec['wire_record_hex'] == wire.hex(), 'validation check failed')
        wr = bytes.fromhex(rec['wire_record_hex'])
        check(wr[0:1] == flags, 'validation check failed')
        parsed_len, hdr_end = vi_dec(wr, 1)
        check(parsed_len == clen and hdr_end + clen + 16 == len(wr), 'validation check failed')
        check(AESGCM(ck).decrypt(nonce, wr[hdr_end:hdr_end + clen] + wr[-16:], wr[:hdr_end]) == pt, 'validation check failed')
    print(f'handshake/key-schedule/secure-record: ok ({len(sr['records'])} complete records)')

def credit_merge(retained, received, max_window):
    c, m = retained
    cp, mp = received
    if not (0 <= c <= m <= MAX_VARINT and 0 <= cp <= mp <= MAX_VARINT):
        return 'FLOW_CONTROL_ERROR'
    if m - c > max_window or mp - cp > max_window:
        return 'FLOW_CONTROL_ERROR'
    if cp >= c and mp >= m:
        return 'update'
    if cp <= c and mp <= m:
        return 'ignore_stale'
    return 'FLOW_CONTROL_ERROR'

def required_confirmation(frame_type):
    if frame_type == 'STREAM_OPEN':
        return 'OPEN_DECISION'
    if frame_type in {'STREAM_DATA', 'STREAM_FIN', 'RESET_STREAM', 'STOP_SENDING', 'STREAM_CONSUMED'}:
        return 'TRANSMISSION_ACK'
    raise ValueError(frame_type)

def contiguous_prefix(values):
    n = 0
    while n + 1 in values:
        n += 1
    return n

def simulate_preopen_cancel(events):
    client = 'OPENING'
    server = 'UNSEEN'
    acceptance = False
    out = []
    for e in events:
        if e == 'client_send_STREAM_OPEN':
            pass
        elif e == 'client_send_STOP_SENDING':
            client = 'OPENING_CANCEL_PENDING'
        elif e == 'server_receive_STOP_before_OPEN':
            server = 'PREOPEN_CANCELLED'
        elif e == 'server_send_RESET_STREAM_0':
            check(server == 'PREOPEN_CANCELLED', 'validation check failed')
        elif e == 'client_receive_RESET_before_OPEN_result':
            check(client == 'OPENING_CANCEL_PENDING', 'validation check failed')
            out.append('RESET_is_cancellation_response_not_acceptance')
            check(not acceptance, 'validation check failed')
        elif e == 'server_receive_STREAM_OPEN':
            check(server == 'PREOPEN_CANCELLED', 'validation check failed')
        elif e == 'server_send_STREAM_OPEN_REJECT_STREAM_STATE_ERROR':
            check(server == 'PREOPEN_CANCELLED', 'validation check failed')
        elif e == 'client_receive_reject':
            check(client == 'OPENING_CANCEL_PENDING', 'validation check failed')
            client = 'CANCELLED'
            out.extend(['matching_REJECT_completes_cancellation', 'no_session_error'])
        else:
            raise AssertionError(f'unknown pre-open event {e}')
    check(client == 'CANCELLED', 'validation check failed')
    return out

def simulate_terminal_ack_loss(events):
    processed = set(range(1, 7))
    settled = set(range(1, 7))
    replay = set()
    out = []
    for e in events:
        if e == 'A_send_RESET_tx7':
            replay.add(7)
        elif e == 'B_process_RESET':
            processed.add(7)
        elif e == 'B_send_ACK_tx7_lost':
            check(7 in replay and 7 in processed, 'validation check failed')
            out.append('B_retains_confirmation_replay_until_retire')
        elif e == 'A_reinject_RESET_tx7':
            check(7 not in settled, 'validation check failed')
        elif e == 'B_repeat_ACK_tx7':
            check(7 in replay, 'validation check failed')
            out.append('duplicate_RESET_confirmed_again')
        elif e == 'A_settle_tx7':
            settled.add(7)
        elif e == 'A_send_TRANSMISSION_RETIRE_7':
            check(contiguous_prefix(settled) == 7, 'validation check failed')
        elif e == 'B_receive_retire_7':
            check(contiguous_prefix(processed) >= 7, 'validation check failed')
            replay = {x for x in replay if x > 7}
            out.append('B_may_compact_after_retire')
        else:
            raise AssertionError(f'unknown retirement event {e}')
    return out

def simulate_fin_supersession(events):
    allocated = {1}
    settled = {1}
    processed = {1}
    fin_outstanding = False
    fin_ack_received = False
    reset_authoritative = False
    out = []
    for e in events:
        if e == 'OPEN_tx1_settled':
            check(settled == {1}, 'validation check failed')
        elif e == 'FIN_tx2_attempt_on_carrier_A_lost_before_peer_processing':
            allocated.add(2)
            fin_outstanding = True
            check(2 not in processed, 'validation check failed')
        elif e == 'peer_STOP_SENDING_on_carrier_B':
            check(fin_outstanding, 'validation check failed')
        elif e == 'sender_create_RESET_tx3_same_final':
            allocated.add(3)
            reset_authoritative = True
            out.append('FIN_tx2_remains_reliable_after_RESET_tx3')
        elif e == 'peer_process_RESET_tx3_and_ACK':
            processed.add(3)
            settled.add(3)
        elif e == 'sender_continue_FIN_tx2_reinjection':
            check(fin_outstanding and 2 not in settled, 'validation check failed')
        elif e == 'peer_receive_late_FIN_tx2_same_final_and_ACK':
            processed.add(2)
            fin_ack_received = True
            check(reset_authoritative, 'validation check failed')
            out.append('late_FIN_same_final_is_ACKed_without_restoring_graceful_EOF')
        elif e == 'sender_settle_FIN_tx2':
            check(fin_ack_received, 'FIN cannot settle before its required acknowledgement')
            settled.add(2)
            fin_outstanding = False
        elif e == 'sender_compute_contiguous_settled_prefix_3':
            check(contiguous_prefix(settled) == 3, 'validation check failed')
            out.append('settled_through_advances_to_3')
        elif e == 'sender_send_TRANSMISSION_RETIRE_3':
            check(contiguous_prefix(processed) >= 3, 'validation check failed')
            out.append('TRANSMISSION_RETIRE_3_is_valid')
        else:
            raise AssertionError(f'unknown FIN supersession event {e}')
    return out

def validate_semantic_oracles(root):
    tv = root / 'test-vectors'
    rr = json.loads((tv / 'reordering-reliability.json').read_text())
    check(isinstance(rr.get('cases'), list) and rr['cases'], 'review trace cases missing/empty')
    cases = {c['name']: c for c in rr['cases']}
    for name in ('stream-credit-stale-reordering', 'session-credit-stale-reordering'):
        c = cases[name]
        order = [(int(x['consumed']), int(x['maximum'])) for x in c['receive_order']]
        retained = order[0]
        max_window = 16 * 1024 * 1024 if name.startswith('stream-') else 128 * 1024 * 1024
        result = credit_merge(retained, order[1], max_window)
        check(result == 'ignore_stale' and c['expected'] == 'second_received_pair_is_stale_ignore', c)
    c = cases['crossed-credit-error']
    retained = (int(c['retained']['consumed']), int(c['retained']['maximum']))
    received = (int(c['received']['consumed']), int(c['received']['maximum']))
    check(credit_merge(retained, received, 16 * 1024 * 1024) == 'FLOW_CONTROL_ERROR' and c['expected'] == 'FLOW_CONTROL_ERROR', c)
    c = cases['preopen-stop-reset-before-reject']
    check(c['client_state'] == 'OPENING_CANCEL_PENDING', 'validation check failed')
    check(simulate_preopen_cancel(c['events']) == c['expected'], c)
    c = cases['terminal-ack-loss-before-retire']
    check(simulate_terminal_ack_loss(c['events']) == c['expected'], c)
    c = cases['fin-supersession-retirement']
    check(simulate_fin_supersession(c['events']) == c['expected'], c)
    check(cases['max-record-size-join-mismatch']['expected'] == 'SESSION_CONFLICT_candidate_rejected', 'validation check failed')
    cv = json.loads((tv / 'confirmation-validity.json').read_text())
    check(isinstance(cv.get('cases'), list) and cv['cases'], 'validation check failed')
    for c in cv['cases']:
        req = required_confirmation(c['original_frame'])
        got = c['confirmation']
        if not c.get('allocated', True) or not c.get('stream_matches', True):
            outcome = 'TRANSMISSION_ID_ERROR'
        elif req == 'TRANSMISSION_ACK' and got == 'TRANSMISSION_ACK' or (req == 'OPEN_DECISION' and got in {'STREAM_OPEN_OK', 'STREAM_OPEN_REJECT'}):
            outcome = 'settle'
        else:
            outcome = 'TRANSMISSION_ID_ERROR'
        check(c['expected'] == outcome, c)
    sv = json.loads((tv / 'state-validity.json').read_text())
    by = {c['name']: c for c in sv['cases']}
    for name in ('data-beyond-fin', 'conflicting-terminal-size', 'stream-consumed-wrong-final', 'tombstone-data-beyond-final'):
        c = by[name]
        check(c['expected'] == 'session_error' and c['error'] == 'FINAL_SIZE_ERROR', c)
    print(f'semantic-oracles: ok ({len(rr['cases'])} review traces, {len(cv['cases'])} confirmation cases)')

def registry(root):
    s = (root / 'REGISTRIES.md').read_text()
    check('| 0x1a | TRANSMISSION_RETIRE | Session / Transmission namespace | Core |' in s, 'validation check failed')
    print('registry: ok')

def tcp_generated(root):
    r = subprocess.run([sys.executable, str(root / 'tools/generate_tcp_fixtures.py'), '--root', str(root), '--check'], capture_output=True, text=True)
    check(r.returncode == 0, r.stdout + r.stderr)
    print(r.stdout.strip())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    root = args.root.resolve()
    json_and_revision(root)
    markdown_links(root)
    registry(root)
    validate_varints(root)
    validate_frames(root)
    handshake_crypto_records(root)
    validate_semantic_oracles(root)
    validate_extended_vectors(root, check, vi_enc)
    tcp_generated(root)
    print('validation: PASS')
if __name__ == '__main__':
    main()
