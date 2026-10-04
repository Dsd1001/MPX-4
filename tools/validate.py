import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from semantic_validation import SemanticValidationError, validate_extended_vectors
MAX_VARINT = (1 << 62) - 1
JS_SAFE = (1 << 53) - 1


class ValidationError(Exception):
    pass

def check(condition, detail='validation check failed'):
    if not condition:
        raise ValidationError(str(detail))

def vi_enc(v):
    if not 0 <= v <= MAX_VARINT:
        raise ValidationError(str(v))
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
        raise ValidationError('truncated varint')
    n = (1, 2, 4, 8)[b[i] >> 6]
    if i + n > len(b):
        raise ValidationError('truncated varint')
    raw = int.from_bytes(b[i:i + n], 'big')
    v = raw & (1 << 8 * n - 2) - 1
    if len(vi_enc(v)) != n:
        raise ValidationError('non-canonical varint')
    return (v, i + n)

def walk_numbers(x, path='$'):
    if isinstance(x, bool) or x is None:
        return
    if isinstance(x, int):
        if abs(x) > JS_SAFE:
            raise ValidationError(f'unsafe JSON integer at {path}: {x}; use decimal string')
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
        except ValidationError:
            pass
        else:
            raise ValidationError(f'invalid VarInt accepted: {c}')
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
    raise ValidationError(f'no validator body schema for {name}')

def decode_body(name, body, max_frame_payload=None):
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
        data = body[pos:]
        check(len(data) >= 1, 'STREAM_DATA Data must be non-empty')
        if max_frame_payload is not None:
            check(len(data) <= max_frame_payload, ('STREAM_DATA exceeds peer MAX_FRAME_PAYLOAD', len(data), max_frame_payload))
        out['data_hex'] = data.hex()
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
            raise ValidationError(f'truncated reason in {name}')
        check(ln <= 256, (name, 'Reason exceeds 256 UTF-8 octets', ln))
        try:
            out['reason_utf8'] = body[pos:pos + ln].decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValidationError(f'invalid UTF-8 reason in {name}') from exc
        pos += ln
    else:
        raise ValidationError(f'no decoder schema for {name}')
    if name not in {'STREAM_DATA', 'PADDING'} and pos != len(body):
        raise ValidationError(f'extra bytes in {name}')
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
    check(ln <= 4096, ('handshake message too large', ln))
    check(i + ln == len(b), 'validation check failed')
    ps = []
    end = i + ln
    previous_type = -1
    while i < end:
        pt, i = vi_dec(b, i)
        check(pt > previous_type, ('duplicate or out-of-order handshake Parameter', pt, previous_type))
        previous_type = pt
        check(i < end, ('missing Parameter Flags', pt))
        flags = b[i]
        i += 1
        check(flags & 0xfe == 0, ('reserved Parameter Flags set', pt, flags))
        plen, i = vi_dec(b, i)
        check(i + plen <= end, ('truncated Parameter value', pt, plen, end - i))
        val = b[i:i + plen]
        i += plen
        ps.append((pt, flags, val))
    check(i == end, 'handshake Parameter parse did not end on Message boundary')
    return (typ, ps, b)

def _param_map(params):
    return {t: (flags, value) for t, flags, value in params}


def _decode_param_varint(params, parameter_type, name, minimum=0, maximum=MAX_VARINT):
    check(parameter_type in params, ('missing handshake Parameter', name))
    flags, raw = params[parameter_type]
    value, end = vi_dec(raw)
    check(end == len(raw), ('extra bytes in handshake VarInt Parameter', name))
    check(minimum <= value <= maximum, ('handshake Parameter out of range', name, value, minimum, maximum))
    return value


def _handshake_context(cp, sp, decoded):
    client=_param_map(cp)
    server=_param_map(sp)

    check(list(client) == [1,2,3,4,5,7,8,9,10], ('CLIENT_INIT Core Parameter set/order', list(client)))
    check(list(server) == [6,7,8,9,10], ('SERVER_INIT Core Parameter set/order', list(server)))
    check(client[10][0] == 1 and server[10][0] == 1, 'MAX_CARRIERS must set CRITICAL=1')

    session_id=client[1][1]
    check(len(session_id)==16 and session_id != b'\x00'*16, 'invalid SESSION_ID')
    action=_decode_param_varint(client,2,'SESSION_ACTION',0,1)
    carrier_id=_decode_param_varint(client,3,'CARRIER_ID',1,MAX_VARINT)
    generation=_decode_param_varint(client,4,'CARRIER_GENERATION',0,MAX_VARINT)
    client_nonce=client[5][1]
    server_nonce=server[6][1]
    check(len(client_nonce)==32 and len(server_nonce)==32, 'invalid handshake nonce length')

    client_limits={
        'max_frame_payload': _decode_param_varint(client,7,'client MAX_FRAME_PAYLOAD',1,32768),
        'max_record_size': _decode_param_varint(client,8,'client MAX_RECORD_SIZE',1024,65536),
        'max_streams': _decode_param_varint(client,9,'client MAX_STREAMS',1,2048),
    }
    server_limits={
        'max_frame_payload': _decode_param_varint(server,7,'server MAX_FRAME_PAYLOAD',1,32768),
        'max_record_size': _decode_param_varint(server,8,'server MAX_RECORD_SIZE',1024,65536),
        'max_streams': _decode_param_varint(server,9,'server MAX_STREAMS',1,2048),
    }
    client_max_carriers=_decode_param_varint(client,10,'client MAX_CARRIERS',1,MAX_VARINT)
    server_max_carriers=_decode_param_varint(server,10,'server MAX_CARRIERS',1,MAX_VARINT)

    expected={
        'session_id_hex':session_id.hex(),
        'session_action':'CREATE' if action==0 else 'JOIN',
        'carrier_id':str(carrier_id),
        'carrier_generation':str(generation),
        'client_nonce_hex':client_nonce.hex(),
        'server_nonce_hex':server_nonce.hex(),
        'client_receive_limits':{k:str(v) for k,v in client_limits.items()},
        'server_receive_limits':{k:str(v) for k,v in server_limits.items()},
        'client_max_carriers':str(client_max_carriers),
        'server_max_carriers':str(server_max_carriers),
        'effective_carrier_limit':str(min(client_max_carriers,server_max_carriers)),
    }
    check(decoded == expected, ('decoded_handshake metadata differs from authoritative wire', decoded, expected))

    return {
        'client_receive_limits':client_limits,
        'server_receive_limits':server_limits,
        'client_max_carriers':client_max_carriers,
        'server_max_carriers':server_max_carriers,
    }


def validate_record_plaintext(pt, registry, max_frame_payload):
    check(len(pt) >= 1, 'Secure Record plaintext must be non-empty')
    pos = 0
    reverse = {v: k for k, v in registry.items()}
    while pos < len(pt):
        frame_type, pos = vi_dec(pt, pos)
        frame_length, pos = vi_dec(pt, pos)
        check(pos + frame_length <= len(pt), ('truncated Frame in Secure Record', frame_type, frame_length, len(pt) - pos))
        body=pt[pos:pos+frame_length]
        frame_end=pos+frame_length
        if frame_type <= 0x3f:
            check(frame_type in reverse, ('unknown Core Frame in Secure Record', frame_type))
            name=reverse[frame_type]
            decode_body(name, body, max_frame_payload=max_frame_payload)
            if name in {'CARRIER_CLOSE','SESSION_CLOSE'}:
                check(frame_end == len(pt), (name,'must be final Frame in Secure Record'))
        elif frame_type <= 0x3fff:
            # Extension Frames are safely skipped by their authenticated length.
            pass
        elif frame_type <= 0x7fff:
            raise ValidationError(f'Private Use Frame requires negotiated profile: {frame_type}')
        else:
            raise ValidationError(f'reserved Frame Type in Draft 11: {frame_type}')
        pos = frame_end
    check(pos == len(pt), 'Secure Record plaintext did not end on a Frame boundary')


def handshake_crypto_records(root):
    tv = root / 'test-vectors'
    ks = json.loads((tv / 'key-schedule.json').read_text())
    sr = json.loads((tv / 'secure-record.json').read_text())
    ct, cp, ci = parse_msg(ks['inputs']['client_init_hex'])
    st, sp, si = parse_msg(ks['inputs']['server_init_hex'])
    check(ct == 1 and st == 2, 'validation check failed')
    context=_handshake_context(cp,sp,ks['decoded_handshake'])

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
    checks = {
        'h0_hex': h0,
        'early_secret_hex': early,
        'handshake_secret_hex': hs,
        'client_finished_key_hex': cfk,
        'server_finished_key_hex': sfk,
        'client_verify_data_hex': cv,
        'client_finished_hex': cf,
        'h1_hex': h1,
        'server_verify_data_hex': sv,
        'server_finished_hex': sf,
        'h2_hex': h2,
        'client_application_secret_hex': cas,
        'server_application_secret_hex': sas,
        'client_traffic_key_hex': ck,
        'client_traffic_iv_hex': civ,
        'server_traffic_key_hex': sk,
        'server_traffic_iv_hex': siv,
    }
    for k, v in checks.items():
        check(ks['derived'][k] == v.hex(), k)

    direction = sr.get('direction')
    if direction == 'client_to_server':
        traffic_key,traffic_iv=ck,civ
        peer_limits=context['server_receive_limits']
    elif direction == 'server_to_client':
        traffic_key,traffic_iv=sk,siv
        peer_limits=context['client_receive_limits']
    else:
        raise ValidationError(f'unknown Secure Record direction: {direction!r}')

    check(sr['traffic_key_hex'] == traffic_key.hex() and sr['traffic_iv_hex'] == traffic_iv.hex(), ('Secure Record key/IV do not match direction',direction))
    peer_max_record_size=peer_limits['max_record_size']
    frame_registry = parse_registry(root)

    for rec in sr['records']:
        seq = int(rec['sequence_number'])
        check(0 <= seq < (1 << 24), ('record sequence outside traffic-key lifetime', seq))
        pt = bytes.fromhex(rec['plaintext_hex'])
        flags = bytes.fromhex(rec['record_flags_hex'])
        check(len(flags) == 1, 'validation check failed')
        check(flags == b'\x00', ('record flags must be zero', rec.get('record_flags_hex')))
        clen = int(rec['ciphertext_length'])
        check(clen == len(pt), 'validation check failed')
        check(1 <= clen <= peer_max_record_size, ('Ciphertext Length outside peer MAX_RECORD_SIZE', clen, peer_max_record_size))
        validate_record_plaintext(pt, frame_registry, peer_limits['max_frame_payload'])
        clen_vi = vi_enc(clen)
        check(rec['ciphertext_length_varint_hex'] == clen_vi.hex(), 'validation check failed')
        aad = flags + clen_vi
        check(rec['aad_hex'] == aad.hex(), 'validation check failed')
        seq96 = b'\x00' * 4 + seq.to_bytes(8, 'big')
        check(rec['seq96_hex'] == seq96.hex(), 'validation check failed')
        nonce = bytes((a ^ b for a, b in zip(traffic_iv, seq96)))
        check(rec['nonce_hex'] == nonce.hex(), 'validation check failed')
        enc = AESGCM(traffic_key).encrypt(nonce, pt, aad)
        ciphertext, tag = (enc[:-16], enc[-16:])
        check(rec['ciphertext_hex'] == ciphertext.hex() and rec['authentication_tag_hex'] == tag.hex(), 'validation check failed')
        wire = aad + ciphertext + tag
        check(rec['wire_record_hex'] == wire.hex(), 'validation check failed')
        wr = bytes.fromhex(rec['wire_record_hex'])
        check(wr[0:1] == flags, 'validation check failed')
        parsed_len, hdr_end = vi_dec(wr, 1)
        check(parsed_len == clen and hdr_end + clen + 16 == len(wr), 'validation check failed')
        check(AESGCM(traffic_key).decrypt(nonce, wr[hdr_end:hdr_end + clen] + wr[-16:], wr[:hdr_end]) == pt, 'validation check failed')
    print(f"handshake/key-schedule/secure-record: ok ({len(sr['records'])} complete records)")


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
    raise ValidationError(str(frame_type))

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
            raise ValidationError(f'unknown pre-open event {e}')
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
            raise ValidationError(f'unknown retirement event {e}')
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
            raise ValidationError(f'unknown FIN supersession event {e}')
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
    print(f"semantic-oracles: ok ({len(rr['cases'])} review traces, {len(cv['cases'])} confirmation cases)")

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
    try:
        main()
    except (ValidationError, SemanticValidationError) as exc:
        print(f'validation: FAIL: {exc}', file=sys.stderr)
        raise SystemExit(2)
