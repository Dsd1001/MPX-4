#!/usr/bin/env python3
"""Independent executable MPX/4 Draft 11 reference core.

This module intentionally does not import tools/validate.py or semantic_validation.py.
It implements only the runtime subset needed by the Gate 1 reference integration:
CREATE, Finished, Secure Records, Session/Stream credit, STREAM_OPEN/OK,
bidirectional STREAM_DATA, TRANSMISSION_ACK, STREAM_FIN, PING/PONG and
SESSION_CLOSE.
"""

from __future__ import annotations

import asyncio
import bisect
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_VARINT = (1 << 62) - 1
MAGIC = b"MPX\x00"
VERSION = 4
MAX_KEY_RECORDS = 1 << 24

MSG_CLIENT_INIT = 0x01
MSG_SERVER_INIT = 0x02
MSG_CLIENT_FINISHED = 0x03
MSG_SERVER_FINISHED = 0x04
MSG_VERSION_NEGOTIATION = 0x05
MSG_HANDSHAKE_REJECT = 0x06

PARAM_SESSION_ID = 0x01
PARAM_SESSION_ACTION = 0x02
PARAM_CARRIER_ID = 0x03
PARAM_CARRIER_GENERATION = 0x04
PARAM_CLIENT_NONCE = 0x05
PARAM_SERVER_NONCE = 0x06
PARAM_MAX_FRAME_PAYLOAD = 0x07
PARAM_MAX_RECORD_SIZE = 0x08
PARAM_MAX_STREAMS = 0x09
PARAM_MAX_CARRIERS = 0x0A

FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_PONG = 0x02
FRAME_CARRIER_CLOSE = 0x03
FRAME_SESSION_CLOSE = 0x04
FRAME_STREAM_OPEN = 0x10
FRAME_STREAM_OPEN_OK = 0x11
FRAME_STREAM_OPEN_REJECT = 0x12
FRAME_STREAM_DATA = 0x13
FRAME_TRANSMISSION_ACK = 0x14
FRAME_STREAM_CREDIT = 0x15
FRAME_STREAM_FIN = 0x16
FRAME_RESET_STREAM = 0x17
FRAME_STOP_SENDING = 0x18
FRAME_STREAM_CONSUMED = 0x19
FRAME_TRANSMISSION_RETIRE = 0x1A
FRAME_SESSION_CREDIT = 0x20
FRAME_CREDIT_PROBE = 0x21

FRAME_NAMES = {
    FRAME_PADDING: "PADDING",
    FRAME_PING: "PING",
    FRAME_PONG: "PONG",
    FRAME_CARRIER_CLOSE: "CARRIER_CLOSE",
    FRAME_SESSION_CLOSE: "SESSION_CLOSE",
    FRAME_STREAM_OPEN: "STREAM_OPEN",
    FRAME_STREAM_OPEN_OK: "STREAM_OPEN_OK",
    FRAME_STREAM_OPEN_REJECT: "STREAM_OPEN_REJECT",
    FRAME_STREAM_DATA: "STREAM_DATA",
    FRAME_TRANSMISSION_ACK: "TRANSMISSION_ACK",
    FRAME_STREAM_CREDIT: "STREAM_CREDIT",
    FRAME_STREAM_FIN: "STREAM_FIN",
    FRAME_RESET_STREAM: "RESET_STREAM",
    FRAME_STOP_SENDING: "STOP_SENDING",
    FRAME_STREAM_CONSUMED: "STREAM_CONSUMED",
    FRAME_TRANSMISSION_RETIRE: "TRANSMISSION_RETIRE",
    FRAME_SESSION_CREDIT: "SESSION_CREDIT",
    FRAME_CREDIT_PROBE: "CREDIT_PROBE",
}
FRAME_TYPES = {v: k for k, v in FRAME_NAMES.items()}


class ProtocolError(Exception):
    pass


class FrameTypeProtocolError(ProtocolError):
    def __init__(self, frame_type: int, message: str) -> None:
        super().__init__(message)
        self.frame_type = frame_type


class AuthenticationError(ProtocolError):
    pass


class FlowControlError(ProtocolError):
    pass


class FinalSizeError(ProtocolError):
    pass


class TransmissionError(ProtocolError):
    pass


def vi_enc(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= MAX_VARINT:
        raise ProtocolError(f"VarInt out of range: {value!r}")
    if value < (1 << 6):
        width, prefix = 1, 0
    elif value < (1 << 14):
        width, prefix = 2, 1
    elif value < (1 << 30):
        width, prefix = 4, 2
    else:
        width, prefix = 8, 3
    return (value | (prefix << (8 * width - 2))).to_bytes(width, "big")


def vi_dec(data: bytes, pos: int = 0) -> Tuple[int, int]:
    if pos >= len(data):
        raise ProtocolError("truncated VarInt")
    first = data[pos]
    width = (1, 2, 4, 8)[first >> 6]
    if pos + width > len(data):
        raise ProtocolError("truncated VarInt")
    raw = int.from_bytes(data[pos : pos + width], "big")
    value = raw & ((1 << (8 * width - 2)) - 1)
    if len(vi_enc(value)) != width:
        raise ProtocolError("non-canonical VarInt")
    return value, pos + width


async def read_varint(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    first = await reader.readexactly(1)
    width = (1, 2, 4, 8)[first[0] >> 6]
    rest = await reader.readexactly(width - 1)
    raw = first + rest
    value, end = vi_dec(raw)
    if end != len(raw):
        raise ProtocolError("invalid stream VarInt")
    return value, raw


def encode_message(message_type: int, body: bytes) -> bytes:
    if len(body) > 4096:
        raise ProtocolError("handshake message too large")
    return vi_enc(message_type) + vi_enc(len(body)) + body


async def read_message(reader: asyncio.StreamReader) -> Tuple[int, bytes, bytes]:
    message_type, type_raw = await read_varint(reader)
    length, length_raw = await read_varint(reader)
    if length > 4096:
        raise ProtocolError("handshake message too large")
    body = await reader.readexactly(length)
    return message_type, body, type_raw + length_raw + body


def encode_parameter(parameter_type: int, flags: int, value: bytes) -> bytes:
    if flags & 0xFE:
        raise ProtocolError("reserved Parameter flag set")
    return vi_enc(parameter_type) + bytes([flags]) + vi_enc(len(value)) + value


def parse_parameters(body: bytes) -> Dict[int, Tuple[int, bytes]]:
    pos = 0
    previous = -1
    out: Dict[int, Tuple[int, bytes]] = {}
    while pos < len(body):
        parameter_type, pos = vi_dec(body, pos)
        if parameter_type <= previous:
            raise ProtocolError("duplicate or out-of-order Parameter")
        previous = parameter_type
        if pos >= len(body):
            raise ProtocolError("missing Parameter flags")
        flags = body[pos]
        pos += 1
        if flags & 0xFE:
            raise ProtocolError("reserved Parameter flag set")
        length, pos = vi_dec(body, pos)
        if pos + length > len(body):
            raise ProtocolError("truncated Parameter")
        value = body[pos : pos + length]
        pos += length
        out[parameter_type] = (flags, value)
    if pos != len(body):
        raise ProtocolError("Parameter parse did not end on message boundary")
    return out


def param_varint(params: Dict[int, Tuple[int, bytes]], ptype: int, name: str) -> int:
    if ptype not in params:
        raise ProtocolError(f"missing {name}")
    _, raw = params[ptype]
    value, end = vi_dec(raw)
    if end != len(raw):
        raise ProtocolError(f"extra bytes in {name}")
    return value


@dataclass(frozen=True)
class Limits:
    max_frame_payload: int = 32768
    max_record_size: int = 65536
    max_streams: int = 32
    max_carriers: int = 2

    def validate(self) -> None:
        if not 1 <= self.max_frame_payload <= 32768:
            raise ProtocolError("MAX_FRAME_PAYLOAD out of range")
        if not 1024 <= self.max_record_size <= 65536:
            raise ProtocolError("MAX_RECORD_SIZE out of range")
        if not 1 <= self.max_streams <= 2048:
            raise ProtocolError("MAX_STREAMS out of range")
        if not 1 <= self.max_carriers <= MAX_VARINT:
            raise ProtocolError("MAX_CARRIERS out of range")


@dataclass
class InitContext:
    session_id: bytes
    session_action: int
    carrier_id: int
    generation: int
    client_nonce: bytes
    client_limits: Limits
    server_nonce: Optional[bytes] = None
    server_limits: Optional[Limits] = None


def encode_client_init(
    session_id: bytes,
    carrier_id: int,
    generation: int,
    client_nonce: bytes,
    limits: Limits,
    session_action: int = 0,
) -> bytes:
    limits.validate()
    if len(session_id) != 16 or session_id == b"\x00" * 16:
        raise ProtocolError("invalid SESSION_ID")
    if session_action not in (0, 1):
        raise ProtocolError("invalid SESSION_ACTION")
    if not 1 <= carrier_id <= MAX_VARINT:
        raise ProtocolError("invalid CARRIER_ID")
    if not 0 <= generation <= MAX_VARINT:
        raise ProtocolError("invalid CARRIER_GENERATION")
    if len(client_nonce) != 32:
        raise ProtocolError("invalid CLIENT_NONCE")
    parts = [
        encode_parameter(PARAM_SESSION_ID, 0, session_id),
        encode_parameter(PARAM_SESSION_ACTION, 0, vi_enc(session_action)),
        encode_parameter(PARAM_CARRIER_ID, 0, vi_enc(carrier_id)),
        encode_parameter(PARAM_CARRIER_GENERATION, 0, vi_enc(generation)),
        encode_parameter(PARAM_CLIENT_NONCE, 0, client_nonce),
        encode_parameter(PARAM_MAX_FRAME_PAYLOAD, 0, vi_enc(limits.max_frame_payload)),
        encode_parameter(PARAM_MAX_RECORD_SIZE, 0, vi_enc(limits.max_record_size)),
        encode_parameter(PARAM_MAX_STREAMS, 0, vi_enc(limits.max_streams)),
        encode_parameter(PARAM_MAX_CARRIERS, 1, vi_enc(limits.max_carriers)),
    ]
    return encode_message(MSG_CLIENT_INIT, b"".join(parts))


def parse_client_init(raw_message: bytes) -> InitContext:
    message_type, pos = vi_dec(raw_message)
    length, pos = vi_dec(raw_message, pos)
    if message_type != MSG_CLIENT_INIT or pos + length != len(raw_message):
        raise ProtocolError("invalid CLIENT_INIT message")
    params = parse_parameters(raw_message[pos:])
    required = {
        PARAM_SESSION_ID,
        PARAM_SESSION_ACTION,
        PARAM_CARRIER_ID,
        PARAM_CARRIER_GENERATION,
        PARAM_CLIENT_NONCE,
        PARAM_MAX_FRAME_PAYLOAD,
        PARAM_MAX_RECORD_SIZE,
        PARAM_MAX_STREAMS,
        PARAM_MAX_CARRIERS,
    }
    missing = required - set(params)
    if missing:
        raise ProtocolError(f"missing CLIENT_INIT Parameters: {sorted(missing)}")
    unknown_critical = sorted(ptype for ptype, (flags, _) in params.items() if ptype not in required and (flags & 0x01))
    if unknown_critical:
        raise ProtocolError(f"unsupported critical CLIENT_INIT Parameters: {unknown_critical}")
    session_id = params[PARAM_SESSION_ID][1]
    client_nonce = params[PARAM_CLIENT_NONCE][1]
    if len(session_id) != 16 or session_id == b"\x00" * 16:
        raise ProtocolError("invalid SESSION_ID")
    if len(client_nonce) != 32:
        raise ProtocolError("invalid CLIENT_NONCE")
    if params[PARAM_MAX_CARRIERS][0] != 1:
        raise ProtocolError("MAX_CARRIERS must be critical")
    limits = Limits(
        max_frame_payload=param_varint(params, PARAM_MAX_FRAME_PAYLOAD, "MAX_FRAME_PAYLOAD"),
        max_record_size=param_varint(params, PARAM_MAX_RECORD_SIZE, "MAX_RECORD_SIZE"),
        max_streams=param_varint(params, PARAM_MAX_STREAMS, "MAX_STREAMS"),
        max_carriers=param_varint(params, PARAM_MAX_CARRIERS, "MAX_CARRIERS"),
    )
    limits.validate()
    action = param_varint(params, PARAM_SESSION_ACTION, "SESSION_ACTION")
    carrier_id = param_varint(params, PARAM_CARRIER_ID, "CARRIER_ID")
    generation = param_varint(params, PARAM_CARRIER_GENERATION, "CARRIER_GENERATION")
    if action not in (0, 1):
        raise ProtocolError("invalid SESSION_ACTION")
    if carrier_id == 0:
        raise ProtocolError("CARRIER_ID must be non-zero")
    return InitContext(
        session_id=session_id,
        session_action=action,
        carrier_id=carrier_id,
        generation=generation,
        client_nonce=client_nonce,
        client_limits=limits,
    )


def encode_server_init(server_nonce: bytes, limits: Limits) -> bytes:
    limits.validate()
    if len(server_nonce) != 32:
        raise ProtocolError("invalid SERVER_NONCE")
    parts = [
        encode_parameter(PARAM_SERVER_NONCE, 0, server_nonce),
        encode_parameter(PARAM_MAX_FRAME_PAYLOAD, 0, vi_enc(limits.max_frame_payload)),
        encode_parameter(PARAM_MAX_RECORD_SIZE, 0, vi_enc(limits.max_record_size)),
        encode_parameter(PARAM_MAX_STREAMS, 0, vi_enc(limits.max_streams)),
        encode_parameter(PARAM_MAX_CARRIERS, 1, vi_enc(limits.max_carriers)),
    ]
    return encode_message(MSG_SERVER_INIT, b"".join(parts))


def parse_server_init(raw_message: bytes) -> Tuple[bytes, Limits]:
    message_type, pos = vi_dec(raw_message)
    length, pos = vi_dec(raw_message, pos)
    if message_type != MSG_SERVER_INIT or pos + length != len(raw_message):
        raise ProtocolError("invalid SERVER_INIT message")
    params = parse_parameters(raw_message[pos:])
    required = {
        PARAM_SERVER_NONCE,
        PARAM_MAX_FRAME_PAYLOAD,
        PARAM_MAX_RECORD_SIZE,
        PARAM_MAX_STREAMS,
        PARAM_MAX_CARRIERS,
    }
    missing = required - set(params)
    if missing:
        raise ProtocolError(f"missing SERVER_INIT Parameters: {sorted(missing)}")
    unknown_critical = sorted(ptype for ptype, (flags, _) in params.items() if ptype not in required and (flags & 0x01))
    if unknown_critical:
        raise ProtocolError(f"unsupported critical SERVER_INIT Parameters: {unknown_critical}")
    if params[PARAM_MAX_CARRIERS][0] != 1:
        raise ProtocolError("MAX_CARRIERS must be critical")
    nonce = params[PARAM_SERVER_NONCE][1]
    if len(nonce) != 32:
        raise ProtocolError("invalid SERVER_NONCE")
    limits = Limits(
        max_frame_payload=param_varint(params, PARAM_MAX_FRAME_PAYLOAD, "MAX_FRAME_PAYLOAD"),
        max_record_size=param_varint(params, PARAM_MAX_RECORD_SIZE, "MAX_RECORD_SIZE"),
        max_streams=param_varint(params, PARAM_MAX_STREAMS, "MAX_STREAMS"),
        max_carriers=param_varint(params, PARAM_MAX_CARRIERS, "MAX_CARRIERS"),
    )
    limits.validate()
    return nonce, limits


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def mpx_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full = ("mpx4 " + label).encode("ascii")
    if len(full) > 255 or len(context) > 255:
        raise ProtocolError("HKDF label/context too large")
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


@dataclass
class TrafficSecrets:
    client_finished_key: bytes
    server_finished_key: bytes
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes


def derive_traffic(
    transport_key: bytes,
    preface: bytes,
    client_init: bytes,
    server_init: bytes,
    client_finished: Optional[bytes] = None,
    server_finished: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes, TrafficSecrets]:
    if len(transport_key) != 32:
        raise ProtocolError("transport key must be 32 octets")
    h0 = hashlib.sha256(preface + client_init + server_init).digest()
    early = hkdf_extract(b"\x00" * 32, transport_key)
    handshake = mpx_expand_label(early, "handshake", h0, 32)
    cfk = mpx_expand_label(handshake, "client finished", b"", 32)
    sfk = mpx_expand_label(handshake, "server finished", b"", 32)

    if client_finished is None:
        client_verify = hmac.new(cfk, h0, hashlib.sha256).digest()
        client_finished = encode_message(MSG_CLIENT_FINISHED, client_verify)
    h1 = hashlib.sha256(preface + client_init + server_init + client_finished).digest()
    if server_finished is None:
        server_verify = hmac.new(sfk, h1, hashlib.sha256).digest()
        server_finished = encode_message(MSG_SERVER_FINISHED, server_verify)
    h2 = hashlib.sha256(preface + client_init + server_init + client_finished + server_finished).digest()

    cas = mpx_expand_label(handshake, "client application", h2, 32)
    sas = mpx_expand_label(handshake, "server application", h2, 32)
    secrets = TrafficSecrets(
        client_finished_key=cfk,
        server_finished_key=sfk,
        client_key=mpx_expand_label(cas, "key", b"", 32),
        client_iv=mpx_expand_label(cas, "iv", b"", 12),
        server_key=mpx_expand_label(sas, "key", b"", 32),
        server_iv=mpx_expand_label(sas, "iv", b"", 12),
    )
    return client_finished, server_finished, h0, secrets


def validate_finished(raw_message: bytes, expected_type: int, key: bytes, transcript_hash: bytes) -> None:
    message_type, pos = vi_dec(raw_message)
    length, pos = vi_dec(raw_message, pos)
    if message_type != expected_type or length != 32 or pos + length != len(raw_message):
        raise AuthenticationError("invalid Finished message")
    expected = hmac.new(key, transcript_hash, hashlib.sha256).digest()
    if not hmac.compare_digest(raw_message[pos:], expected):
        raise AuthenticationError("Finished verification failed")


def xor_nonce(iv: bytes, seq: int) -> bytes:
    seq96 = b"\x00" * 4 + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, seq96))


def encode_frame(frame_type: int, body: bytes) -> bytes:
    return vi_enc(frame_type) + vi_enc(len(body)) + body


def frame_body(frame_type: int, **fields: object) -> bytes:
    def i(name: str) -> bytes:
        return vi_enc(int(fields[name]))

    if frame_type == FRAME_PING or frame_type == FRAME_PONG:
        return i("token")
    if frame_type == FRAME_STREAM_OPEN or frame_type == FRAME_STREAM_OPEN_OK:
        return i("stream_id") + i("transmission_id")
    if frame_type == FRAME_STREAM_OPEN_REJECT:
        return i("stream_id") + i("transmission_id") + i("error_code")
    if frame_type == FRAME_STREAM_DATA:
        data = fields["data"]
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError("STREAM_DATA data must be bytes")
        return i("stream_id") + i("offset") + i("transmission_id") + bytes(data)
    if frame_type == FRAME_TRANSMISSION_ACK:
        return i("stream_id") + i("transmission_id") + i("receiver_timestamp_us")
    if frame_type == FRAME_STREAM_CREDIT:
        return i("stream_id") + i("consumed_offset") + i("maximum_offset")
    if frame_type == FRAME_SESSION_CREDIT:
        return i("consumed_bytes") + i("maximum_bytes")
    if frame_type == FRAME_STREAM_FIN:
        return i("stream_id") + i("transmission_id") + i("final_offset")
    if frame_type == FRAME_RESET_STREAM:
        return i("stream_id") + i("transmission_id") + i("final_offset") + i("stream_error_code")
    if frame_type == FRAME_STOP_SENDING:
        return i("stream_id") + i("transmission_id") + i("stream_error_code")
    if frame_type == FRAME_STREAM_CONSUMED:
        return i("stream_id") + i("transmission_id") + i("final_offset")
    if frame_type == FRAME_TRANSMISSION_RETIRE:
        return i("retired_through")
    if frame_type == FRAME_CREDIT_PROBE:
        return i("stream_id")
    if frame_type == FRAME_CARRIER_CLOSE or frame_type == FRAME_SESSION_CLOSE:
        reason = str(fields.get("reason", "")).encode("utf-8")
        if len(reason) > 256:
            raise ProtocolError("close Reason exceeds 256 octets")
        return i("error_code") + i("trigger_frame_type") + vi_enc(len(reason)) + reason
    raise ProtocolError(f"unsupported reference Frame type: {frame_type}")


def parse_frame_body(frame_type: int, body: bytes, max_frame_payload: int) -> Dict[str, object]:
    pos = 0
    out: Dict[str, object] = {}

    def get(name: str) -> int:
        nonlocal pos
        value, pos = vi_dec(body, pos)
        out[name] = value
        return value

    if frame_type == FRAME_PADDING:
        out["padding_length"] = len(body)
        pos = len(body)
    elif frame_type in (FRAME_PING, FRAME_PONG):
        get("token")
    elif frame_type in (FRAME_STREAM_OPEN, FRAME_STREAM_OPEN_OK):
        get("stream_id")
        get("transmission_id")
    elif frame_type == FRAME_STREAM_OPEN_REJECT:
        get("stream_id")
        get("transmission_id")
        get("error_code")
    elif frame_type == FRAME_STREAM_DATA:
        get("stream_id")
        get("offset")
        get("transmission_id")
        data = body[pos:]
        if not 1 <= len(data) <= max_frame_payload:
            raise ProtocolError(f"STREAM_DATA length {len(data)} outside negotiated limit")
        out["data"] = data
        pos = len(body)
    elif frame_type == FRAME_TRANSMISSION_ACK:
        get("stream_id")
        get("transmission_id")
        get("receiver_timestamp_us")
    elif frame_type == FRAME_STREAM_CREDIT:
        get("stream_id")
        get("consumed_offset")
        get("maximum_offset")
    elif frame_type == FRAME_SESSION_CREDIT:
        get("consumed_bytes")
        get("maximum_bytes")
    elif frame_type == FRAME_STREAM_FIN:
        get("stream_id")
        get("transmission_id")
        get("final_offset")
    elif frame_type == FRAME_RESET_STREAM:
        get("stream_id")
        get("transmission_id")
        get("final_offset")
        get("stream_error_code")
    elif frame_type == FRAME_STOP_SENDING:
        get("stream_id")
        get("transmission_id")
        get("stream_error_code")
    elif frame_type == FRAME_STREAM_CONSUMED:
        get("stream_id")
        get("transmission_id")
        get("final_offset")
    elif frame_type == FRAME_TRANSMISSION_RETIRE:
        get("retired_through")
    elif frame_type == FRAME_CREDIT_PROBE:
        get("stream_id")
    elif frame_type in (FRAME_CARRIER_CLOSE, FRAME_SESSION_CLOSE):
        get("error_code")
        get("trigger_frame_type")
        length = get("reason_length")
        if length > 256 or pos + length > len(body):
            raise ProtocolError("invalid close Reason")
        reason_bytes = body[pos : pos + length]
        try:
            out["reason"] = reason_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("invalid UTF-8 close Reason") from exc
        pos += length
    else:
        raise ProtocolError(f"unsupported reference Frame type: 0x{frame_type:x}")

    if pos != len(body):
        raise ProtocolError(f"extra bytes in {FRAME_NAMES.get(frame_type, hex(frame_type))}")
    return out


def parse_frames(plaintext: bytes, max_frame_payload: int) -> List[Tuple[int, Dict[str, object]]]:
    if not plaintext:
        raise ProtocolError("empty Secure Record")
    frames: List[Tuple[int, Dict[str, object]]] = []
    pos = 0
    while pos < len(plaintext):
        frame_type, pos = vi_dec(plaintext, pos)
        frame_length, pos = vi_dec(plaintext, pos)
        if pos + frame_length > len(plaintext):
            raise ProtocolError("truncated Frame")
        body = plaintext[pos : pos + frame_length]
        end = pos + frame_length
        if frame_type <= 0x3F:
            if frame_type not in FRAME_NAMES:
                raise FrameTypeProtocolError(frame_type, f"unknown Core Frame 0x{frame_type:x}")
            parsed = parse_frame_body(frame_type, body, max_frame_payload)
            frames.append((frame_type, parsed))
            if frame_type in (FRAME_CARRIER_CLOSE, FRAME_SESSION_CLOSE) and end != len(plaintext):
                raise ProtocolError("close Frame must be final in Secure Record")
        elif frame_type <= 0x3FFF:
            # Unknown Extension Frames are authenticated and skipped by length.
            pass
        elif frame_type <= 0x7FFF:
            raise FrameTypeProtocolError(frame_type, "Private Use Frame without negotiated profile")
        else:
            raise FrameTypeProtocolError(frame_type, "reserved Frame Type")
        pos = end
    return frames


class Trace:
    def __init__(self, path: Path, role: str) -> None:
        self.path = path
        self.role = role
        self.seq = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("w", encoding="utf-8")

    def emit(self, event: str, **fields: object) -> None:
        self.seq += 1
        record = {
            "event_seq": self.seq,
            "monotonic_ns": time.monotonic_ns(),
            "role": self.role,
            "pid": os.getpid(),
            "event": event,
            **fields,
        }
        self.file.write(json.dumps(record, sort_keys=True) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


@dataclass
class SegmentStore:
    """Sorted, non-overlapping receive fragments.

    DATA can arrive out of order and may overlap an earlier fragment.  Keeping
    fragments disjoint means each incoming frame only compares against the
    intervals it actually intersects, instead of scanning every queued frame.
    Removed prefix entries stay as tombstones until the list is compacted so
    delivering a long stream does not repeatedly shift the whole list.
    """

    _segments: Dict[int, bytes] = field(default_factory=dict)
    _starts: List[int] = field(default_factory=list)
    _head: int = 0

    def _compact(self) -> None:
        if self._head and self._head * 2 >= len(self._starts):
            self._starts = self._starts[self._head :]
            self._head = 0

    def _add_gap(self, start: int, data: bytes) -> None:
        if not data:
            return
        index = bisect.bisect_left(self._starts, start, lo=self._head)
        self._segments[start] = data
        self._starts.insert(index, start)

    def insert(self, start: int, data: bytes) -> None:
        """Insert a fragment, rejecting conflicting overlapping bytes."""
        if not data:
            return
        end = start + len(data)
        index = bisect.bisect_left(self._starts, start, lo=self._head)
        if index > self._head:
            previous_start = self._starts[index - 1]
            if previous_start + len(self._segments[previous_start]) > start:
                index -= 1
        cursor = start
        gaps: List[Tuple[int, int]] = []
        while index < len(self._starts):
            old_start = self._starts[index]
            old_data = self._segments[old_start]
            old_end = old_start + len(old_data)
            if old_start >= end:
                break
            if old_end <= start:
                index += 1
                continue
            overlap_start = max(start, old_start)
            overlap_end = min(end, old_end)
            incoming = data[overlap_start - start : overlap_end - start]
            existing = old_data[overlap_start - old_start : overlap_end - old_start]
            if incoming != existing:
                raise ProtocolError("conflicting overlapping Stream bytes")
            if cursor < overlap_start:
                gaps.append((cursor, overlap_start))
            cursor = max(cursor, overlap_end)
            index += 1
        if cursor < end:
            gaps.append((cursor, end))
        for gap_start, gap_end in gaps:
            self._add_gap(gap_start, data[gap_start - start : gap_end - start])

    def pop_contiguous(self, offset: int) -> Optional[bytes]:
        if self._head >= len(self._starts) or self._starts[self._head] != offset:
            return None
        start = self._starts[self._head]
        data = self._segments.pop(start)
        self._head += 1
        self._compact()
        return data


@dataclass
class StreamState:
    stream_id: int
    peer_consumed: int = 0
    peer_maximum: int = 0
    local_maximum: int = 0
    send_offset: int = 0
    recv_committed: int = 0
    recv_next: int = 0
    recv_final: Optional[int] = None
    send_final: Optional[int] = None
    recv_data: bytearray = field(default_factory=bytearray)
    recv_segments: SegmentStore = field(default_factory=SegmentStore)
    open_event: asyncio.Event = field(default_factory=asyncio.Event)
    credit_event: asyncio.Event = field(default_factory=asyncio.Event)
    recv_done_event: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class Outstanding:
    txid: int
    frame_type: int
    stream_id: int
    event: asyncio.Event = field(default_factory=asyncio.Event)


class Carrier:
    def __init__(
        self,
        role: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        trace: Trace,
        local_limits: Limits,
        peer_limits: Limits,
        send_key: bytes,
        send_iv: bytes,
        recv_key: bytes,
        recv_iv: bytes,
        session_id: bytes,
        carrier_id: int,
        generation: int,
        write_chunk: int = 0,
    ) -> None:
        self.role = role
        self.reader = reader
        self.writer = writer
        self.trace = trace
        self.local_limits = local_limits
        self.peer_limits = peer_limits
        self.send_key = send_key
        self.send_iv = send_iv
        self.recv_key = recv_key
        self.recv_iv = recv_iv
        self.session_id = session_id
        self.carrier_id = carrier_id
        self.generation = generation
        self.write_chunk = write_chunk
        self.send_seq = 0
        self.recv_seq = 0
        self.output_usable = True
        self.write_lock = asyncio.Lock()
        self.session_epoch_ns = time.monotonic_ns()

    def base_trace(self) -> Dict[str, object]:
        return {
            "session_id": self.session_id.hex(),
            "carrier_id": self.carrier_id,
            "generation": self.generation,
        }

    async def write_bytes(self, data: bytes) -> None:
        if self.write_chunk and self.write_chunk > 0:
            for i in range(0, len(data), self.write_chunk):
                self.writer.write(data[i : i + self.write_chunk])
                await self.writer.drain()
        else:
            self.writer.write(data)
            await self.writer.drain()

    def max_stream_data_payload(self, stream_id: int, transmission_id: int, offset: int) -> int:
        """Return the largest DATA payload that fits both peer limits."""
        upper = min(self.peer_limits.max_frame_payload, 32768)
        if upper < 1:
            raise ProtocolError("peer MAX_FRAME_PAYLOAD is zero")

        metadata_size = sum(len(vi_enc(value)) for value in (stream_id, offset, transmission_id))

        def fits(size: int) -> bool:
            body_size = metadata_size + size
            return 1 + len(vi_enc(body_size)) + body_size <= self.peer_limits.max_record_size

        if fits(upper):
            return upper
        low, high = 1, upper
        while low < high:
            middle = (low + high + 1) // 2
            if fits(middle):
                low = middle
            else:
                high = middle - 1
        if not fits(low):
            raise ProtocolError("peer MAX_RECORD_SIZE cannot carry STREAM_DATA")
        return low

    async def send_frame(self, frame_type: int, **fields: object) -> None:
        body = frame_body(frame_type, **fields)
        if frame_type == FRAME_STREAM_DATA:
            data = fields["data"]
            if not isinstance(data, (bytes, bytearray)):
                raise ProtocolError("STREAM_DATA data must be bytes")
            if len(data) > self.peer_limits.max_frame_payload:
                raise ProtocolError("STREAM_DATA exceeds peer MAX_FRAME_PAYLOAD")
        frame = encode_frame(frame_type, body)
        if len(frame) > self.peer_limits.max_record_size:
            raise ProtocolError("Frame does not fit peer MAX_RECORD_SIZE")
        await self.send_plaintext(frame, frame_type, fields)

    async def send_plaintext(
        self, plaintext: bytes, frame_type: Optional[int] = None, fields: Optional[Dict[str, object]] = None
    ) -> None:
        if not 1 <= len(plaintext) <= self.peer_limits.max_record_size:
            raise ProtocolError("Secure Record plaintext outside peer MAX_RECORD_SIZE")
        async with self.write_lock:
            if not self.output_usable:
                raise ConnectionError("Carrier ordered output is no longer usable")
            if self.send_seq >= MAX_KEY_RECORDS:
                # Key usage exhaustion is an output-terminal condition for this
                # Carrier incarnation.  Keeping it eligible would make callers
                # retry the same impossible send forever and could starve a
                # healthy alternate Carrier.
                self.output_usable = False
                try:
                    self.writer.close()
                except Exception:
                    pass
                raise ProtocolError("traffic key Record limit exhausted")
            seq = self.send_seq
            header = b"\x00" + vi_enc(len(plaintext))
            nonce = xor_nonce(self.send_iv, seq)
            encrypted = AESGCM(self.send_key).encrypt(nonce, plaintext, header)
            wire = header + encrypted
            committed = False
            try:
                if self.write_chunk and self.write_chunk > 0:
                    for i in range(0, len(wire), self.write_chunk):
                        self.writer.write(wire[i : i + self.write_chunk])
                        committed = True
                else:
                    self.writer.write(wire)
                    committed = True
                # The complete serialized Record is now committed to this
                # Carrier's ordered output. Consume the implicit sequence
                # number before the first cancellation point.
                self.send_seq = seq + 1
                await self.writer.drain()
            except BaseException as exc:
                if committed or isinstance(exc, OSError):
                    # A transport OSError from write()/drain() is Carrier-output
                    # failure even if write() rejected before committing bytes.
                    # Any post-commit failure/cancellation is likewise terminal
                    # because delivery is ambiguous and the Record nonce cannot
                    # be reused. Keep this scope inside the writer operation so
                    # unrelated later I/O (for example trace persistence) is not
                    # misclassified as transport failure.
                    self.output_usable = False
                    try:
                        self.writer.close()
                    except Exception:
                        pass
                raise
        info = self.base_trace()
        info.update(
            {
                "record_seq": seq,
                "plaintext_length": len(plaintext),
                "frame_type": FRAME_NAMES.get(frame_type, frame_type) if frame_type is not None else None,
            }
        )
        if fields:
            for key in ("stream_id", "transmission_id", "offset", "final_offset"):
                if key in fields:
                    info[key] = int(fields[key])
            if frame_type == FRAME_STREAM_DATA:
                info["data_length"] = len(fields["data"])  # type: ignore[arg-type]
        self.trace.emit("record_send", **info)

    async def recv_record(self) -> List[Tuple[int, Dict[str, object]]]:
        flags = await self.reader.readexactly(1)
        if flags != b"\x00":
            raise ProtocolError("non-zero Secure Record Flags")
        length, length_raw = await read_varint(self.reader)
        if not 1 <= length <= self.local_limits.max_record_size:
            raise ProtocolError("Ciphertext Length outside local MAX_RECORD_SIZE")
        ciphertext = await self.reader.readexactly(length)
        tag = await self.reader.readexactly(16)
        if self.recv_seq >= MAX_KEY_RECORDS:
            raise ProtocolError("receive traffic key Record limit exhausted")
        seq = self.recv_seq
        header = flags + length_raw
        nonce = xor_nonce(self.recv_iv, seq)
        try:
            plaintext = AESGCM(self.recv_key).decrypt(nonce, ciphertext + tag, header)
        except Exception as exc:
            raise AuthenticationError("Secure Record authentication failure") from exc
        frames = parse_frames(plaintext, self.local_limits.max_frame_payload)
        self.recv_seq += 1
        base = self.base_trace()
        self.trace.emit(
            "record_recv",
            **base,
            record_seq=seq,
            plaintext_length=len(plaintext),
            frame_count=len(frames),
        )
        return frames

    def timestamp_us(self) -> int:
        return max(0, (time.monotonic_ns() - self.session_epoch_ns) // 1000)


def application_payload(sender_role: str, stream_id: int, length: int) -> bytes:
    seed = f"mpx4-ref:{sender_role}:{stream_id}:".encode("ascii")
    if not seed:
        raise RuntimeError("empty payload seed")
    copies = (length + len(seed) - 1) // len(seed)
    return (seed * copies)[:length]


class ReferenceSession:
    def __init__(
        self,
        role: str,
        carrier: Carrier,
        trace: Trace,
        stream_count: int,
        bytes_per_stream: int,
    ) -> None:
        self.role = role
        self.carrier = carrier
        self.trace = trace
        self.stream_count = stream_count
        self.bytes_per_stream = bytes_per_stream
        self.streams: Dict[int, StreamState] = {}
        self.next_txid = 1
        self.outstanding: Dict[int, Outstanding] = {}
        self.settled: Dict[int, Tuple[int, int]] = {}
        self.peer_open_tx: Dict[int, int] = {}
        self.stream_open_tx: Dict[int, int] = {}
        self.session_peer_consumed = 0
        self.session_peer_maximum = 0
        self.session_send_committed = 0
        self.session_recv_committed = 0
        self.session_local_maximum = max(4 * 1024 * 1024, stream_count * bytes_per_stream * 2)
        self.session_credit_event = asyncio.Event()
        self.streams_ready_event = asyncio.Event()
        self.first_data_received_event = asyncio.Event()
        self.session_close_event = asyncio.Event()
        self.receive_task: Optional[asyncio.Task[None]] = None
        self.sender_tasks: List[asyncio.Task[None]] = []
        self.tx_application_bytes = 0
        self.rx_application_bytes = 0
        self.max_outstanding_reliable = 0

    def merge_credit_pair(
        self,
        old_consumed: int,
        old_maximum: int,
        new_consumed: int,
        new_maximum: int,
        window_limit: int,
    ) -> Tuple[int, int]:
        if new_maximum < new_consumed or new_maximum - new_consumed > window_limit:
            raise FlowControlError("invalid credit")
        if new_consumed >= old_consumed and new_maximum >= old_maximum:
            return new_consumed, new_maximum
        if new_consumed <= old_consumed and new_maximum <= old_maximum:
            return old_consumed, old_maximum
        raise FlowControlError("crossed credit pair")

    def alloc_tx(self, frame_type: int, stream_id: int) -> Outstanding:
        txid = self.next_txid
        self.next_txid += 1
        item = Outstanding(txid=txid, frame_type=frame_type, stream_id=stream_id)
        self.outstanding[txid] = item
        self.max_outstanding_reliable = max(self.max_outstanding_reliable, len(self.outstanding))
        return item

    def settle_tx(self, txid: int, expected_frame: Optional[int] = None) -> None:
        item = self.outstanding.get(txid)
        if item is None:
            prior = self.settled.get(txid)
            if prior is not None and (expected_frame is None or prior[1] == expected_frame):
                return
            raise TransmissionError(f"ACK for unknown Transmission {txid}")
        if expected_frame is not None and item.frame_type != expected_frame:
            raise TransmissionError("wrong confirmation class")
        item.event.set()
        del self.outstanding[txid]
        self.settled[txid] = (item.stream_id, item.frame_type)

    async def send_initial_session_credit(self) -> None:
        await self.carrier.send_frame(
            FRAME_SESSION_CREDIT,
            consumed_bytes=0,
            maximum_bytes=self.session_local_maximum,
        )
        self.trace.emit(
            "credit_advertise",
            **self.carrier.base_trace(),
            scope="session",
            consumed=0,
            maximum=self.session_local_maximum,
        )

    async def send_stream_credit(self, stream: StreamState) -> None:
        stream.local_maximum = self.bytes_per_stream
        await self.carrier.send_frame(
            FRAME_STREAM_CREDIT,
            stream_id=stream.stream_id,
            consumed_offset=0,
            maximum_offset=stream.local_maximum,
        )
        self.trace.emit(
            "credit_advertise",
            **self.carrier.base_trace(),
            scope="stream",
            stream_id=stream.stream_id,
            consumed=0,
            maximum=stream.local_maximum,
        )

    async def run_receiver(self) -> None:
        try:
            while not self.session_close_event.is_set():
                frames = await self.carrier.recv_record()
                for frame_type, fields in frames:
                    await self.handle_frame(frame_type, fields)
                    if frame_type == FRAME_SESSION_CLOSE:
                        return
        except asyncio.IncompleteReadError:
            if not self.session_close_event.is_set():
                raise

    async def handle_frame(self, frame_type: int, fields: Dict[str, object]) -> None:
        name = FRAME_NAMES.get(frame_type, f"0x{frame_type:x}")
        trace_fields = self.carrier.base_trace()
        trace_fields["frame_type"] = name
        for key in ("stream_id", "transmission_id", "offset", "final_offset"):
            if key in fields:
                trace_fields[key] = int(fields[key])
        if frame_type == FRAME_STREAM_DATA:
            trace_fields["data_length"] = len(fields["data"])  # type: ignore[arg-type]
        self.trace.emit("frame_recv", **trace_fields)

        if frame_type == FRAME_PADDING:
            return

        if frame_type == FRAME_SESSION_CREDIT:
            consumed = int(fields["consumed_bytes"])
            maximum = int(fields["maximum_bytes"])
            self.session_peer_consumed, self.session_peer_maximum = self.merge_credit_pair(
                self.session_peer_consumed,
                self.session_peer_maximum,
                consumed,
                maximum,
                128 * 1024 * 1024,
            )
            self.session_credit_event.set()
            return

        if frame_type == FRAME_STREAM_OPEN:
            if self.role != "server":
                raise ProtocolError("Server-only STREAM_OPEN received by client")
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            prior_stream = self.peer_open_tx.get(txid)
            if prior_stream is not None:
                if prior_stream != stream_id:
                    raise TransmissionError("STREAM_OPEN Transmission identity mismatch")
                if stream_id not in self.streams:
                    raise TransmissionError("STREAM_OPEN replay has no Stream")
                await self.carrier.send_frame(
                    FRAME_STREAM_OPEN_OK,
                    stream_id=stream_id,
                    transmission_id=txid,
                )
                self.trace.emit(
                    "frame_send",
                    **self.carrier.base_trace(),
                    frame_type="STREAM_OPEN_OK",
                    stream_id=stream_id,
                    transmission_id=txid,
                )
                return
            prior_txid = self.stream_open_tx.get(stream_id)
            if prior_txid is not None and prior_txid != txid:
                raise TransmissionError("STREAM_OPEN Stream identity mismatch")
            if stream_id <= 0 or stream_id % 2 == 0 or stream_id in self.streams:
                raise ProtocolError("invalid client Stream ID")
            if len(self.streams) >= self.carrier.local_limits.max_streams:
                raise ProtocolError("reference Gate 1 stream limit exceeded")
            stream = StreamState(stream_id=stream_id)
            self.streams[stream_id] = stream
            self.peer_open_tx[txid] = stream_id
            self.stream_open_tx[stream_id] = txid
            if len(self.streams) == self.stream_count:
                self.streams_ready_event.set()
            await self.carrier.send_frame(
                FRAME_STREAM_OPEN_OK,
                stream_id=stream_id,
                transmission_id=txid,
            )
            self.trace.emit(
                "frame_send",
                **self.carrier.base_trace(),
                frame_type="STREAM_OPEN_OK",
                stream_id=stream_id,
                transmission_id=txid,
            )
            await self.send_stream_credit(stream)
            task = asyncio.create_task(self.send_application_stream(stream))
            self.sender_tasks.append(task)
            return

        if frame_type == FRAME_STREAM_OPEN_OK:
            if self.role != "client":
                raise ProtocolError("unexpected STREAM_OPEN_OK on server")
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            stream = self.streams.get(stream_id)
            if stream is None:
                raise TransmissionError("OPEN_OK for unknown Stream")
            item = self.outstanding.get(txid)
            if item is None:
                prior = self.settled.get(txid)
                if prior != (stream_id, FRAME_STREAM_OPEN):
                    raise TransmissionError("OPEN_OK identity mismatch")
                stream.open_event.set()
                return
            if item.frame_type != FRAME_STREAM_OPEN or item.stream_id != stream_id:
                raise TransmissionError("OPEN_OK identity mismatch")
            self.settle_tx(txid, FRAME_STREAM_OPEN)
            stream.open_event.set()
            await self.send_stream_credit(stream)
            return

        if frame_type == FRAME_STREAM_CREDIT:
            stream_id = int(fields["stream_id"])
            stream = self.streams.get(stream_id)
            if stream is None:
                raise ProtocolError("STREAM_CREDIT for unknown Stream")
            consumed = int(fields["consumed_offset"])
            maximum = int(fields["maximum_offset"])
            stream.peer_consumed, stream.peer_maximum = self.merge_credit_pair(
                stream.peer_consumed,
                stream.peer_maximum,
                consumed,
                maximum,
                16 * 1024 * 1024,
            )
            stream.credit_event.set()
            return

        if frame_type == FRAME_STREAM_DATA:
            await self.handle_stream_data(fields)
            return

        if frame_type == FRAME_TRANSMISSION_ACK:
            txid = int(fields["transmission_id"])
            stream_id = int(fields["stream_id"])
            item = self.outstanding.get(txid)
            if item is None:
                prior = self.settled.get(txid)
                if prior is None or prior[0] != stream_id or prior[1] not in (FRAME_STREAM_DATA, FRAME_STREAM_FIN):
                    raise TransmissionError("TRANSMISSION_ACK identity mismatch")
                return
            if item.stream_id != stream_id:
                raise TransmissionError("TRANSMISSION_ACK identity mismatch")
            if item.frame_type not in (FRAME_STREAM_DATA, FRAME_STREAM_FIN):
                raise TransmissionError("TRANSMISSION_ACK wrong confirmation class")
            self.settle_tx(txid)
            return

        if frame_type == FRAME_STREAM_FIN:
            await self.handle_stream_fin(fields)
            return

        if frame_type == FRAME_PING:
            token = int(fields["token"])
            await self.carrier.send_frame(FRAME_PONG, token=token)
            self.trace.emit(
                "frame_send",
                **self.carrier.base_trace(),
                frame_type="PONG",
                token=token,
            )
            return

        if frame_type == FRAME_PONG:
            return

        if frame_type == FRAME_SESSION_CLOSE:
            self.session_close_event.set()
            return

        raise ProtocolError(f"Gate 1 runtime received unsupported Frame {name}")

    async def handle_stream_data(self, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        offset = int(fields["offset"])
        txid = int(fields["transmission_id"])
        data = bytes(fields["data"])  # type: ignore[arg-type]
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("STREAM_DATA for unknown Stream")
        end = offset + len(data)
        if stream.recv_final is not None and end > stream.recv_final:
            raise FinalSizeError("STREAM_DATA exceeds established Final Offset")
        if end > stream.local_maximum:
            raise FlowControlError("STREAM_DATA exceeds Stream credit")
        previous_committed = stream.recv_committed
        stream.recv_committed = max(stream.recv_committed, end)
        delta = stream.recv_committed - previous_committed
        if self.session_recv_committed + delta > self.session_local_maximum:
            raise FlowControlError("STREAM_DATA exceeds Session credit")
        self.session_recv_committed += delta

        self.first_data_received_event.set()

        if offset < stream.recv_next:
            committed_end = min(end, stream.recv_next)
            if bytes(stream.recv_data[offset:committed_end]) != data[: committed_end - offset]:
                raise ProtocolError("conflicting duplicate STREAM_DATA")
            if end <= stream.recv_next:
                data = b""
            else:
                data = data[stream.recv_next - offset :]
                offset = stream.recv_next
        stream.recv_segments.insert(offset, data)
        while True:
            chunk = stream.recv_segments.pop_contiguous(stream.recv_next)
            if chunk is None:
                break
            stream.recv_data.extend(chunk)
            stream.recv_next += len(chunk)
            self.rx_application_bytes += len(chunk)

        await self.carrier.send_frame(
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=self.carrier.timestamp_us(),
        )
        self.trace.emit(
            "frame_send",
            **self.carrier.base_trace(),
            frame_type="TRANSMISSION_ACK",
            stream_id=stream_id,
            transmission_id=txid,
        )
        self.maybe_mark_recv_done(stream)

    async def handle_stream_fin(self, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        final_offset = int(fields["final_offset"])
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("STREAM_FIN for unknown Stream")
        if final_offset < stream.recv_committed:
            raise FinalSizeError("Final Offset below committed data")
        if stream.recv_final is not None and stream.recv_final != final_offset:
            raise FinalSizeError("contradictory Final Offset")
        if final_offset > stream.local_maximum:
            raise FlowControlError("Final Offset exceeds Stream credit")
        delta = max(0, final_offset - stream.recv_committed)
        if self.session_recv_committed + delta > self.session_local_maximum:
            raise FlowControlError("Final Offset exceeds Session credit")
        self.session_recv_committed += delta
        stream.recv_committed = max(stream.recv_committed, final_offset)
        stream.recv_final = final_offset

        await self.carrier.send_frame(
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=self.carrier.timestamp_us(),
        )
        self.trace.emit(
            "frame_send",
            **self.carrier.base_trace(),
            frame_type="TRANSMISSION_ACK",
            stream_id=stream_id,
            transmission_id=txid,
        )
        self.maybe_mark_recv_done(stream)

    def maybe_mark_recv_done(self, stream: StreamState) -> None:
        if stream.recv_final is not None and stream.recv_next == stream.recv_final:
            stream.recv_done_event.set()
            self.trace.emit(
                "application_stream_complete",
                **self.carrier.base_trace(),
                stream_id=stream.stream_id,
                bytes=len(stream.recv_data),
                sha256=hashlib.sha256(stream.recv_data).hexdigest(),
            )

    async def open_streams(self) -> None:
        if self.role != "client":
            return
        for index in range(self.stream_count):
            stream_id = 1 + 2 * index
            stream = StreamState(stream_id=stream_id)
            self.streams[stream_id] = stream
            tx = self.alloc_tx(FRAME_STREAM_OPEN, stream_id)
            await self.carrier.send_frame(
                FRAME_STREAM_OPEN,
                stream_id=stream_id,
                transmission_id=tx.txid,
            )
            self.trace.emit(
                "frame_send",
                **self.carrier.base_trace(),
                frame_type="STREAM_OPEN",
                stream_id=stream_id,
                transmission_id=tx.txid,
            )
            task = asyncio.create_task(self.send_application_stream(stream))
            self.sender_tasks.append(task)

        await asyncio.wait_for(
            asyncio.gather(*(s.open_event.wait() for s in self.streams.values())),
            timeout=10,
        )
        self.streams_ready_event.set()

    async def send_application_stream(self, stream: StreamState) -> None:
        await asyncio.wait_for(self.session_credit_event.wait(), timeout=10)
        await asyncio.wait_for(stream.credit_event.wait(), timeout=10)

        payload = application_payload(self.role, stream.stream_id, self.bytes_per_stream)
        offset = 0
        chunk_index = 0
        ack_events: List[asyncio.Event] = []
        while offset < len(payload):
            chunk_size = self.carrier.max_stream_data_payload(stream.stream_id, self.next_txid, offset)
            chunk = payload[offset : offset + chunk_size]
            end = offset + len(chunk)
            if end > stream.peer_maximum:
                raise FlowControlError("sender lacks Stream credit")
            if self.session_send_committed + len(chunk) > self.session_peer_maximum:
                raise FlowControlError("sender lacks Session credit")
            tx = self.alloc_tx(FRAME_STREAM_DATA, stream.stream_id)
            await self.carrier.send_frame(
                FRAME_STREAM_DATA,
                stream_id=stream.stream_id,
                offset=offset,
                transmission_id=tx.txid,
                data=chunk,
            )
            self.trace.emit(
                "frame_send",
                **self.carrier.base_trace(),
                frame_type="STREAM_DATA",
                stream_id=stream.stream_id,
                transmission_id=tx.txid,
                offset=offset,
                data_length=len(chunk),
            )
            ack_events.append(tx.event)
            self.session_send_committed += len(chunk)
            self.tx_application_bytes += len(chunk)
            stream.send_offset = end
            offset = end
            chunk_index += 1
            if chunk_index == 1 and offset < len(payload):
                self.trace.emit(
                    "full_duplex_barrier_wait",
                    **self.carrier.base_trace(),
                    stream_id=stream.stream_id,
                )
                await asyncio.wait_for(self.first_data_received_event.wait(), timeout=10)

        fin = self.alloc_tx(FRAME_STREAM_FIN, stream.stream_id)
        stream.send_final = stream.send_offset
        await self.carrier.send_frame(
            FRAME_STREAM_FIN,
            stream_id=stream.stream_id,
            transmission_id=fin.txid,
            final_offset=stream.send_final,
        )
        self.trace.emit(
            "frame_send",
            **self.carrier.base_trace(),
            frame_type="STREAM_FIN",
            stream_id=stream.stream_id,
            transmission_id=fin.txid,
            final_offset=stream.send_final,
        )
        ack_events.append(fin.event)
        await asyncio.wait_for(asyncio.gather(*(ev.wait() for ev in ack_events)), timeout=15)
        self.trace.emit(
            "application_send_complete",
            **self.carrier.base_trace(),
            stream_id=stream.stream_id,
            bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )

    async def wait_application_complete(self) -> None:
        if self.sender_tasks:
            await asyncio.wait_for(asyncio.gather(*self.sender_tasks), timeout=20)
        await asyncio.wait_for(
            asyncio.gather(*(s.recv_done_event.wait() for s in self.streams.values())),
            timeout=20,
        )

    def result(self) -> Dict[str, object]:
        return {
            "role": self.role,
            "session_id": self.carrier.session_id.hex(),
            "carrier_id": self.carrier.carrier_id,
            "generation": self.carrier.generation,
            "streams": self.stream_count,
            "bytes_per_stream": self.bytes_per_stream,
            "tx_application_bytes": self.tx_application_bytes,
            "rx_application_bytes": self.rx_application_bytes,
            "max_outstanding_reliable": self.max_outstanding_reliable,
            "send_record_count": self.carrier.send_seq,
            "recv_record_count": self.carrier.recv_seq,
            "stream_results": {
                str(stream_id): {
                    "recv_bytes": len(stream.recv_data),
                    "recv_sha256": hashlib.sha256(stream.recv_data).hexdigest(),
                    "recv_final": stream.recv_final,
                    "send_final": stream.send_final,
                }
                for stream_id, stream in sorted(self.streams.items())
            },
        }
