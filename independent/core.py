#!/usr/bin/env python3
"""Source-isolated MPX/4 Draft 11 Implementation B core.

This module intentionally has no dependency on reference/, tools/, or the
repository validator.  It re-implements the wire format, handshake key
schedule, Secure Records, Frame codec, trace surface, and the Gate 4 basic
Session runtime from the protocol documents and public test vectors.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_VARINT = (1 << 62) - 1
MAX_KEY_RECORDS = 1 << 24
MAGIC = b"MPX\x00"
VERSION = 4

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
FRAME_TYPES = {name: code for code, name in FRAME_NAMES.items()}


class ProtocolError(Exception):
    pass


class AuthenticationError(ProtocolError):
    pass


class FlowControlError(ProtocolError):
    pass


class FinalSizeError(ProtocolError):
    pass


class TransmissionError(ProtocolError):
    pass


def vi_enc(value: int) -> bytes:
    if not isinstance(value, int) or value < 0 or value > MAX_VARINT:
        raise ProtocolError("VarInt range")
    if value <= 63:
        size = 1
    elif value <= 16383:
        size = 2
    elif value <= 1073741823:
        size = 4
    else:
        size = 8
    prefix = {1: 0, 2: 1, 4: 2, 8: 3}[size]
    encoded = value | (prefix << (size * 8 - 2))
    return encoded.to_bytes(size, "big")


def vi_dec(data: bytes, pos: int = 0) -> Tuple[int, int]:
    if pos >= len(data):
        raise ProtocolError("truncated VarInt")
    size = (1, 2, 4, 8)[data[pos] >> 6]
    stop = pos + size
    if stop > len(data):
        raise ProtocolError("truncated VarInt")
    raw = int.from_bytes(data[pos:stop], "big")
    value = raw & ((1 << (size * 8 - 2)) - 1)
    if len(vi_enc(value)) != size:
        raise ProtocolError("non-canonical VarInt")
    return value, stop


async def read_varint(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    first = await reader.readexactly(1)
    size = (1, 2, 4, 8)[first[0] >> 6]
    raw = first + await reader.readexactly(size - 1)
    value, stop = vi_dec(raw)
    if stop != len(raw):
        raise ProtocolError("stream VarInt boundary")
    return value, raw


def encode_message(kind: int, body: bytes) -> bytes:
    if len(body) > 4096:
        raise ProtocolError("handshake message too large")
    return vi_enc(kind) + vi_enc(len(body)) + body


async def read_message(reader: asyncio.StreamReader) -> Tuple[int, bytes, bytes]:
    kind, kr = await read_varint(reader)
    size, sr = await read_varint(reader)
    if size > 4096:
        raise ProtocolError("handshake message too large")
    body = await reader.readexactly(size)
    return kind, body, kr + sr + body


def encode_parameter(kind: int, flags: int, value: bytes) -> bytes:
    if flags & 0xFE:
        raise ProtocolError("reserved Parameter flags")
    return vi_enc(kind) + bytes((flags,)) + vi_enc(len(value)) + value


def parse_parameters(body: bytes) -> Dict[int, Tuple[int, bytes]]:
    result: Dict[int, Tuple[int, bytes]] = {}
    pos = 0
    previous = -1
    while pos < len(body):
        kind, pos2 = vi_dec(body, pos)
        if kind <= previous:
            raise ProtocolError("duplicate/out-of-order Parameter")
        previous = kind
        pos = pos2
        if pos >= len(body):
            raise ProtocolError("missing Parameter flags")
        flags = body[pos]
        pos += 1
        if flags & 0xFE:
            raise ProtocolError("reserved Parameter flags")
        size, pos = vi_dec(body, pos)
        if pos + size > len(body):
            raise ProtocolError("truncated Parameter")
        result[kind] = (flags, body[pos : pos + size])
        pos += size
    return result


def param_varint(params: Dict[int, Tuple[int, bytes]], kind: int, label: str) -> int:
    if kind not in params:
        raise ProtocolError(f"missing {label}")
    raw = params[kind][1]
    value, stop = vi_dec(raw)
    if stop != len(raw):
        raise ProtocolError(f"extra {label} bytes")
    return value


@dataclass(frozen=True)
class Limits:
    max_frame_payload: int = 32768
    max_record_size: int = 65536
    max_streams: int = 32
    max_carriers: int = 2

    def validate(self) -> None:
        if self.max_frame_payload < 1 or self.max_frame_payload > 32768:
            raise ProtocolError("MAX_FRAME_PAYLOAD")
        if self.max_record_size < 1024 or self.max_record_size > 65536:
            raise ProtocolError("MAX_RECORD_SIZE")
        if self.max_streams < 1 or self.max_streams > 2048:
            raise ProtocolError("MAX_STREAMS")
        if self.max_carriers < 1 or self.max_carriers > MAX_VARINT:
            raise ProtocolError("MAX_CARRIERS")


@dataclass
class InitContext:
    session_id: bytes
    session_action: int
    carrier_id: int
    generation: int
    client_nonce: bytes
    client_limits: Limits


def _decode_message(raw: bytes, expected: int) -> bytes:
    kind, pos = vi_dec(raw)
    size, pos = vi_dec(raw, pos)
    if kind != expected or pos + size != len(raw):
        raise ProtocolError("handshake message envelope")
    return raw[pos:]


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
        raise ProtocolError("SESSION_ID")
    if session_action not in (0, 1):
        raise ProtocolError("SESSION_ACTION")
    if not 1 <= carrier_id <= MAX_VARINT:
        raise ProtocolError("CARRIER_ID")
    if not 0 <= generation <= MAX_VARINT:
        raise ProtocolError("Generation")
    if len(client_nonce) != 32:
        raise ProtocolError("CLIENT_NONCE")
    params = (
        (PARAM_SESSION_ID, 0, session_id),
        (PARAM_SESSION_ACTION, 0, vi_enc(session_action)),
        (PARAM_CARRIER_ID, 0, vi_enc(carrier_id)),
        (PARAM_CARRIER_GENERATION, 0, vi_enc(generation)),
        (PARAM_CLIENT_NONCE, 0, client_nonce),
        (PARAM_MAX_FRAME_PAYLOAD, 0, vi_enc(limits.max_frame_payload)),
        (PARAM_MAX_RECORD_SIZE, 0, vi_enc(limits.max_record_size)),
        (PARAM_MAX_STREAMS, 0, vi_enc(limits.max_streams)),
        (PARAM_MAX_CARRIERS, 1, vi_enc(limits.max_carriers)),
    )
    return encode_message(MSG_CLIENT_INIT, b"".join(encode_parameter(*p) for p in params))


def parse_client_init(raw: bytes) -> InitContext:
    body = _decode_message(raw, MSG_CLIENT_INIT)
    p = parse_parameters(body)
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
    if set(p) != required:
        raise ProtocolError("CLIENT_INIT Parameter set")
    if p[PARAM_MAX_CARRIERS][0] != 1:
        raise ProtocolError("MAX_CARRIERS criticality")
    sid = p[PARAM_SESSION_ID][1]
    nonce = p[PARAM_CLIENT_NONCE][1]
    if len(sid) != 16 or sid == b"\x00" * 16 or len(nonce) != 32:
        raise ProtocolError("CLIENT_INIT fixed-width field")
    action = param_varint(p, PARAM_SESSION_ACTION, "SESSION_ACTION")
    cid = param_varint(p, PARAM_CARRIER_ID, "CARRIER_ID")
    generation = param_varint(p, PARAM_CARRIER_GENERATION, "Generation")
    if action not in (0, 1) or cid == 0:
        raise ProtocolError("CLIENT_INIT identity")
    limits = Limits(
        param_varint(p, PARAM_MAX_FRAME_PAYLOAD, "MAX_FRAME_PAYLOAD"),
        param_varint(p, PARAM_MAX_RECORD_SIZE, "MAX_RECORD_SIZE"),
        param_varint(p, PARAM_MAX_STREAMS, "MAX_STREAMS"),
        param_varint(p, PARAM_MAX_CARRIERS, "MAX_CARRIERS"),
    )
    limits.validate()
    return InitContext(sid, action, cid, generation, nonce, limits)


def encode_server_init(server_nonce: bytes, limits: Limits) -> bytes:
    limits.validate()
    if len(server_nonce) != 32:
        raise ProtocolError("SERVER_NONCE")
    params = (
        (PARAM_SERVER_NONCE, 0, server_nonce),
        (PARAM_MAX_FRAME_PAYLOAD, 0, vi_enc(limits.max_frame_payload)),
        (PARAM_MAX_RECORD_SIZE, 0, vi_enc(limits.max_record_size)),
        (PARAM_MAX_STREAMS, 0, vi_enc(limits.max_streams)),
        (PARAM_MAX_CARRIERS, 1, vi_enc(limits.max_carriers)),
    )
    return encode_message(MSG_SERVER_INIT, b"".join(encode_parameter(*p) for p in params))


def parse_server_init(raw: bytes) -> Tuple[bytes, Limits]:
    p = parse_parameters(_decode_message(raw, MSG_SERVER_INIT))
    required = {
        PARAM_SERVER_NONCE,
        PARAM_MAX_FRAME_PAYLOAD,
        PARAM_MAX_RECORD_SIZE,
        PARAM_MAX_STREAMS,
        PARAM_MAX_CARRIERS,
    }
    if set(p) != required or p[PARAM_MAX_CARRIERS][0] != 1:
        raise ProtocolError("SERVER_INIT Parameter set/criticality")
    nonce = p[PARAM_SERVER_NONCE][1]
    if len(nonce) != 32:
        raise ProtocolError("SERVER_NONCE")
    limits = Limits(
        param_varint(p, PARAM_MAX_FRAME_PAYLOAD, "MAX_FRAME_PAYLOAD"),
        param_varint(p, PARAM_MAX_RECORD_SIZE, "MAX_RECORD_SIZE"),
        param_varint(p, PARAM_MAX_STREAMS, "MAX_STREAMS"),
        param_varint(p, PARAM_MAX_CARRIERS, "MAX_CARRIERS"),
    )
    limits.validate()
    return nonce, limits


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    name = ("mpx4 " + label).encode("ascii")
    info = length.to_bytes(2, "big") + bytes((len(name),)) + name + bytes((len(context),)) + context
    return _expand(secret, info, length)


@dataclass(frozen=True)
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
        raise ProtocolError("transport key")
    h0 = hashlib.sha256(preface + client_init + server_init).digest()
    early = _extract(b"\x00" * 32, transport_key)
    hs = _label(early, "handshake", h0, 32)
    cfk = _label(hs, "client finished", b"", 32)
    sfk = _label(hs, "server finished", b"", 32)
    if client_finished is None:
        client_finished = encode_message(MSG_CLIENT_FINISHED, hmac.new(cfk, h0, hashlib.sha256).digest())
    h1 = hashlib.sha256(preface + client_init + server_init + client_finished).digest()
    if server_finished is None:
        server_finished = encode_message(MSG_SERVER_FINISHED, hmac.new(sfk, h1, hashlib.sha256).digest())
    h2 = hashlib.sha256(preface + client_init + server_init + client_finished + server_finished).digest()
    ca = _label(hs, "client application", h2, 32)
    sa = _label(hs, "server application", h2, 32)
    return (
        client_finished,
        server_finished,
        h0,
        TrafficSecrets(
            cfk,
            sfk,
            _label(ca, "key", b"", 32),
            _label(ca, "iv", b"", 12),
            _label(sa, "key", b"", 32),
            _label(sa, "iv", b"", 12),
        ),
    )


def validate_finished(raw: bytes, expected_type: int, key: bytes, transcript_hash: bytes) -> None:
    body = _decode_message(raw, expected_type)
    if len(body) != 32:
        raise AuthenticationError("Finished length")
    want = hmac.new(key, transcript_hash, hashlib.sha256).digest()
    if not hmac.compare_digest(body, want):
        raise AuthenticationError("Finished verification")


def xor_nonce(iv: bytes, seq: int) -> bytes:
    seq_bytes = b"\x00" * 4 + seq.to_bytes(8, "big")
    return bytes(x ^ y for x, y in zip(iv, seq_bytes))


def encode_frame(frame_type: int, body: bytes) -> bytes:
    return vi_enc(frame_type) + vi_enc(len(body)) + body


def frame_body(frame_type: int, **f: object) -> bytes:
    def v(name: str) -> bytes:
        return vi_enc(int(f[name]))

    if frame_type in (FRAME_PING, FRAME_PONG):
        return v("token")
    if frame_type in (FRAME_STREAM_OPEN, FRAME_STREAM_OPEN_OK):
        return v("stream_id") + v("transmission_id")
    if frame_type == FRAME_STREAM_OPEN_REJECT:
        return v("stream_id") + v("transmission_id") + v("error_code")
    if frame_type == FRAME_STREAM_DATA:
        payload = f["data"]
        if not isinstance(payload, (bytes, bytearray)):
            raise ProtocolError("DATA payload")
        return v("stream_id") + v("offset") + v("transmission_id") + bytes(payload)
    if frame_type == FRAME_TRANSMISSION_ACK:
        return v("stream_id") + v("transmission_id") + v("receiver_timestamp_us")
    if frame_type == FRAME_STREAM_CREDIT:
        return v("stream_id") + v("consumed_offset") + v("maximum_offset")
    if frame_type == FRAME_SESSION_CREDIT:
        return v("consumed_bytes") + v("maximum_bytes")
    if frame_type == FRAME_STREAM_FIN:
        return v("stream_id") + v("transmission_id") + v("final_offset")
    if frame_type == FRAME_RESET_STREAM:
        return v("stream_id") + v("transmission_id") + v("final_offset") + v("stream_error_code")
    if frame_type == FRAME_STOP_SENDING:
        return v("stream_id") + v("transmission_id") + v("stream_error_code")
    if frame_type == FRAME_STREAM_CONSUMED:
        return v("stream_id") + v("transmission_id") + v("final_offset")
    if frame_type == FRAME_TRANSMISSION_RETIRE:
        return v("retired_through")
    if frame_type == FRAME_CREDIT_PROBE:
        return v("stream_id")
    if frame_type in (FRAME_CARRIER_CLOSE, FRAME_SESSION_CLOSE):
        reason = str(f.get("reason", "")).encode("utf-8")
        if len(reason) > 256:
            raise ProtocolError("close reason")
        return v("error_code") + v("trigger_frame_type") + vi_enc(len(reason)) + reason
    if frame_type == FRAME_PADDING:
        raw = f.get("padding", b"")
        if not isinstance(raw, (bytes, bytearray)):
            raise ProtocolError("padding")
        return bytes(raw)
    raise ProtocolError("unsupported Frame")


def _get(body: bytes, pos: int) -> Tuple[int, int]:
    return vi_dec(body, pos)


def parse_frame_body(frame_type: int, body: bytes, max_frame_payload: int) -> Dict[str, object]:
    pos = 0
    out: Dict[str, object] = {}

    def take(name: str) -> int:
        nonlocal pos
        value, pos = _get(body, pos)
        out[name] = value
        return value

    if frame_type == FRAME_PADDING:
        out["padding_length"] = len(body)
        pos = len(body)
    elif frame_type in (FRAME_PING, FRAME_PONG):
        take("token")
    elif frame_type in (FRAME_STREAM_OPEN, FRAME_STREAM_OPEN_OK):
        take("stream_id"); take("transmission_id")
    elif frame_type == FRAME_STREAM_OPEN_REJECT:
        take("stream_id"); take("transmission_id"); take("error_code")
    elif frame_type == FRAME_STREAM_DATA:
        take("stream_id"); take("offset"); take("transmission_id")
        payload = body[pos:]
        if len(payload) < 1 or len(payload) > max_frame_payload:
            raise ProtocolError("DATA length")
        out["data"] = payload
        pos = len(body)
    elif frame_type == FRAME_TRANSMISSION_ACK:
        take("stream_id"); take("transmission_id"); take("receiver_timestamp_us")
    elif frame_type == FRAME_STREAM_CREDIT:
        take("stream_id"); take("consumed_offset"); take("maximum_offset")
    elif frame_type == FRAME_SESSION_CREDIT:
        take("consumed_bytes"); take("maximum_bytes")
    elif frame_type == FRAME_STREAM_FIN:
        take("stream_id"); take("transmission_id"); take("final_offset")
    elif frame_type == FRAME_RESET_STREAM:
        take("stream_id"); take("transmission_id"); take("final_offset"); take("stream_error_code")
    elif frame_type == FRAME_STOP_SENDING:
        take("stream_id"); take("transmission_id"); take("stream_error_code")
    elif frame_type == FRAME_STREAM_CONSUMED:
        take("stream_id"); take("transmission_id"); take("final_offset")
    elif frame_type == FRAME_TRANSMISSION_RETIRE:
        take("retired_through")
    elif frame_type == FRAME_CREDIT_PROBE:
        take("stream_id")
    elif frame_type in (FRAME_CARRIER_CLOSE, FRAME_SESSION_CLOSE):
        take("error_code"); take("trigger_frame_type")
        n = take("reason_length")
        if n > 256 or pos + n != len(body):
            raise ProtocolError("close reason length")
        raw = body[pos:pos+n]
        try:
            out["reason"] = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("close reason UTF-8") from exc
        pos += n
    else:
        raise ProtocolError("unsupported Core Frame")
    if pos != len(body):
        raise ProtocolError("extra Frame body bytes")
    return out


def parse_frames(plaintext: bytes, max_frame_payload: int) -> List[Tuple[int, Dict[str, object]]]:
    result: List[Tuple[int, Dict[str, object]]] = []
    pos = 0
    terminal = False
    while pos < len(plaintext):
        ftype, pos = vi_dec(plaintext, pos)
        size, pos = vi_dec(plaintext, pos)
        stop = pos + size
        if stop > len(plaintext):
            raise ProtocolError("Frame Length beyond plaintext")
        if terminal:
            raise ProtocolError("Frame follows terminal close")
        if ftype in FRAME_NAMES:
            fields = parse_frame_body(ftype, plaintext[pos:stop], max_frame_payload)
            result.append((ftype, fields))
            if ftype in (FRAME_CARRIER_CLOSE, FRAME_SESSION_CLOSE):
                terminal = True
        elif 0x22 <= ftype <= 0x3FFF:
            pass
        elif ftype <= 0x7FFF:
            raise ProtocolError("Private Use Frame without profile")
        else:
            raise ProtocolError("reserved Frame")
        pos = stop
    return result


class Trace:
    def __init__(self, path: Path, role: str) -> None:
        self.path = path
        self.role = role
        self.seq = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = path.open("w", encoding="utf-8")

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
        self._fp.write(json.dumps(record, sort_keys=True) + "\n")
        self._fp.flush()

    def close(self) -> None:
        self._fp.close()


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
        self._lock = asyncio.Lock()
        self._epoch = time.monotonic_ns()

    def base_trace(self) -> Dict[str, object]:
        return {
            "session_id": self.session_id.hex(),
            "carrier_id": self.carrier_id,
            "generation": self.generation,
        }

    async def _write(self, data: bytes) -> None:
        if self.write_chunk > 0:
            for pos in range(0, len(data), self.write_chunk):
                self.writer.write(data[pos:pos+self.write_chunk])
                await self.writer.drain()
        else:
            self.writer.write(data)
            await self.writer.drain()

    async def send_frame(self, frame_type: int, **fields: object) -> None:
        if frame_type == FRAME_STREAM_DATA:
            data = fields.get("data")
            if not isinstance(data, (bytes, bytearray)) or len(data) > self.peer_limits.max_frame_payload:
                raise ProtocolError("DATA send limit")
        body = frame_body(frame_type, **fields)
        frame = encode_frame(frame_type, body)
        if len(frame) > self.peer_limits.max_record_size:
            raise ProtocolError("Frame exceeds record limit")
        await self.send_plaintext(frame, frame_type, fields)

    async def send_plaintext(self, plaintext: bytes, frame_type: Optional[int] = None, fields: Optional[Dict[str, object]] = None) -> None:
        if len(plaintext) < 1 or len(plaintext) > self.peer_limits.max_record_size:
            raise ProtocolError("record plaintext size")
        async with self._lock:
            if self.send_seq >= MAX_KEY_RECORDS:
                raise ProtocolError("record key limit")
            seq = self.send_seq
            header = b"\x00" + vi_enc(len(plaintext))
            ciphertext = AESGCM(self.send_key).encrypt(xor_nonce(self.send_iv, seq), plaintext, header)
            await self._write(header + ciphertext)
            self.send_seq += 1
        info = self.base_trace()
        info.update({"record_seq": seq, "plaintext_length": len(plaintext), "frame_type": FRAME_NAMES.get(frame_type, frame_type)})
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
            raise ProtocolError("non-zero record Flags")
        size, size_raw = await read_varint(self.reader)
        if size < 1 or size > self.local_limits.max_record_size:
            raise ProtocolError("record length")
        ciphertext = await self.reader.readexactly(size)
        tag = await self.reader.readexactly(16)
        if self.recv_seq >= MAX_KEY_RECORDS:
            raise ProtocolError("receive key limit")
        seq = self.recv_seq
        header = flags + size_raw
        try:
            plaintext = AESGCM(self.recv_key).decrypt(xor_nonce(self.recv_iv, seq), ciphertext + tag, header)
        except Exception as exc:
            raise AuthenticationError("record authentication") from exc
        frames = parse_frames(plaintext, self.local_limits.max_frame_payload)
        self.recv_seq += 1
        self.trace.emit("record_recv", **self.base_trace(), record_seq=seq, plaintext_length=len(plaintext), frame_count=len(frames))
        return frames

    def timestamp_us(self) -> int:
        return max(0, (time.monotonic_ns() - self._epoch) // 1000)


@dataclass
class StreamState:
    stream_id: int
    peer_maximum: int = 0
    local_maximum: int = 0
    send_offset: int = 0
    recv_committed: int = 0
    recv_next: int = 0
    recv_final: Optional[int] = None
    send_final: Optional[int] = None
    recv_data: bytearray = field(default_factory=bytearray)
    recv_segments: Dict[int, bytes] = field(default_factory=dict)
    open_event: asyncio.Event = field(default_factory=asyncio.Event)
    credit_event: asyncio.Event = field(default_factory=asyncio.Event)
    recv_done_event: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class Outstanding:
    txid: int
    frame_type: int
    stream_id: int
    event: asyncio.Event = field(default_factory=asyncio.Event)


def application_payload(sender_role: str, stream_id: int, length: int) -> bytes:
    # This byte pattern is part of the interoperability harness contract, not
    # protocol state. Both implementations intentionally generate the same
    # deterministic application bytes so either peer can verify the other.
    seed = f"mpx4-ref:{sender_role}:{stream_id}:".encode("ascii")
    return (seed * ((length + len(seed) - 1) // len(seed)))[:length]


class PeerSession:
    def __init__(self, role: str, carrier: Carrier, trace: Trace, stream_count: int, bytes_per_stream: int) -> None:
        self.role = role
        self.carrier = carrier
        self.trace = trace
        self.stream_count = stream_count
        self.bytes_per_stream = bytes_per_stream
        self.streams: Dict[int, StreamState] = {}
        self.next_txid = 1
        self.outstanding: Dict[int, Outstanding] = {}
        self.peer_session_max = 0
        self.send_committed = 0
        self.recv_committed = 0
        self.local_session_max = max(4 * 1024 * 1024, stream_count * bytes_per_stream * 2)
        self.session_credit = asyncio.Event()
        self.streams_ready = asyncio.Event()
        self.first_rx = asyncio.Event()
        self.close_seen = asyncio.Event()
        self.receiver_task: Optional[asyncio.Task[None]] = None
        self.sender_tasks: List[asyncio.Task[None]] = []
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.max_outstanding = 0

    def allocate(self, frame_type: int, stream_id: int) -> Outstanding:
        item = Outstanding(self.next_txid, frame_type, stream_id)
        self.next_txid += 1
        self.outstanding[item.txid] = item
        self.max_outstanding = max(self.max_outstanding, len(self.outstanding))
        return item

    def settle(self, txid: int, stream_id: int, frame_type: Optional[int] = None) -> None:
        item = self.outstanding.get(txid)
        if item is None or item.stream_id != stream_id or (frame_type is not None and item.frame_type != frame_type):
            raise TransmissionError("confirmation identity")
        item.event.set()
        del self.outstanding[txid]

    async def send_session_credit(self) -> None:
        await self.carrier.send_frame(FRAME_SESSION_CREDIT, consumed_bytes=0, maximum_bytes=self.local_session_max)
        self.trace.emit("credit_advertise", **self.carrier.base_trace(), scope="session", consumed=0, maximum=self.local_session_max)

    async def send_stream_credit(self, st: StreamState) -> None:
        st.local_maximum = self.bytes_per_stream
        await self.carrier.send_frame(FRAME_STREAM_CREDIT, stream_id=st.stream_id, consumed_offset=0, maximum_offset=st.local_maximum)
        self.trace.emit("credit_advertise", **self.carrier.base_trace(), scope="stream", stream_id=st.stream_id, consumed=0, maximum=st.local_maximum)

    async def receive_loop(self) -> None:
        try:
            while not self.close_seen.is_set():
                for frame_type, fields in await self.carrier.recv_record():
                    await self.handle(frame_type, fields)
                    if frame_type == FRAME_SESSION_CLOSE:
                        return
        except asyncio.IncompleteReadError:
            if not self.close_seen.is_set():
                raise

    async def handle(self, frame_type: int, fields: Dict[str, object]) -> None:
        name = FRAME_NAMES.get(frame_type, f"0x{frame_type:x}")
        info = self.carrier.base_trace()
        info["frame_type"] = name
        for key in ("stream_id", "transmission_id", "offset", "final_offset"):
            if key in fields:
                info[key] = int(fields[key])
        if frame_type == FRAME_STREAM_DATA:
            info["data_length"] = len(fields["data"])  # type: ignore[arg-type]
        self.trace.emit("frame_recv", **info)

        if frame_type == FRAME_SESSION_CREDIT:
            consumed = int(fields["consumed_bytes"]); maximum = int(fields["maximum_bytes"])
            if consumed > maximum:
                raise FlowControlError("Session credit")
            self.peer_session_max = max(self.peer_session_max, maximum)
            self.session_credit.set()
            return
        if frame_type == FRAME_STREAM_OPEN:
            if self.role != "server":
                raise ProtocolError("client received STREAM_OPEN")
            sid = int(fields["stream_id"]); txid = int(fields["transmission_id"])
            if sid <= 0 or sid % 2 == 0 or sid in self.streams:
                raise ProtocolError("Stream identity")
            if len(self.streams) >= self.carrier.local_limits.max_streams:
                raise ProtocolError("Stream limit")
            st = StreamState(sid)
            self.streams[sid] = st
            if len(self.streams) == self.stream_count:
                self.streams_ready.set()
            await self.carrier.send_frame(FRAME_STREAM_OPEN_OK, stream_id=sid, transmission_id=txid)
            self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="STREAM_OPEN_OK", stream_id=sid, transmission_id=txid)
            await self.send_stream_credit(st)
            self.sender_tasks.append(asyncio.create_task(self.send_application(st)))
            return
        if frame_type == FRAME_STREAM_OPEN_OK:
            sid = int(fields["stream_id"]); txid = int(fields["transmission_id"])
            st = self.streams.get(sid)
            if self.role != "client" or st is None:
                raise TransmissionError("OPEN_OK state")
            self.settle(txid, sid, FRAME_STREAM_OPEN)
            st.open_event.set()
            await self.send_stream_credit(st)
            return
        if frame_type == FRAME_STREAM_CREDIT:
            sid = int(fields["stream_id"])
            st = self.streams.get(sid)
            if st is None:
                raise ProtocolError("credit unknown Stream")
            consumed = int(fields["consumed_offset"]); maximum = int(fields["maximum_offset"])
            if consumed > maximum:
                raise FlowControlError("Stream credit")
            st.peer_maximum = max(st.peer_maximum, maximum)
            st.credit_event.set()
            return
        if frame_type == FRAME_STREAM_DATA:
            await self._data(fields)
            return
        if frame_type == FRAME_TRANSMISSION_ACK:
            sid = int(fields["stream_id"]); txid = int(fields["transmission_id"])
            item = self.outstanding.get(txid)
            if item is None or item.stream_id != sid or item.frame_type not in (FRAME_STREAM_DATA, FRAME_STREAM_FIN):
                raise TransmissionError("ACK")
            self.settle(txid, sid)
            return
        if frame_type == FRAME_STREAM_FIN:
            await self._fin(fields)
            return
        if frame_type == FRAME_PING:
            token = int(fields["token"])
            await self.carrier.send_frame(FRAME_PONG, token=token)
            self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="PONG", token=token)
            return
        if frame_type == FRAME_PONG:
            return
        if frame_type == FRAME_SESSION_CLOSE:
            self.close_seen.set()
            return
        raise ProtocolError(f"unsupported Gate 4 basic Frame {name}")

    async def _data(self, fields: Dict[str, object]) -> None:
        sid = int(fields["stream_id"]); offset = int(fields["offset"]); txid = int(fields["transmission_id"])
        data = bytes(fields["data"])  # type: ignore[arg-type]
        st = self.streams.get(sid)
        if st is None:
            raise ProtocolError("DATA unknown Stream")
        end = offset + len(data)
        if end > st.local_maximum:
            raise FlowControlError("Stream credit")
        old = st.recv_committed
        st.recv_committed = max(old, end)
        delta = st.recv_committed - old
        if self.recv_committed + delta > self.local_session_max:
            raise FlowControlError("Session credit")
        self.recv_committed += delta
        self.first_rx.set()
        old_bytes = st.recv_segments.get(offset)
        if old_bytes is not None and old_bytes != data:
            raise ProtocolError("conflicting DATA")
        st.recv_segments[offset] = data
        while st.recv_next in st.recv_segments:
            chunk = st.recv_segments.pop(st.recv_next)
            st.recv_data.extend(chunk)
            st.recv_next += len(chunk)
            self.rx_bytes += len(chunk)
        await self.carrier.send_frame(FRAME_TRANSMISSION_ACK, stream_id=sid, transmission_id=txid, receiver_timestamp_us=self.carrier.timestamp_us())
        self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="TRANSMISSION_ACK", stream_id=sid, transmission_id=txid)
        self._mark_done(st)

    async def _fin(self, fields: Dict[str, object]) -> None:
        sid = int(fields["stream_id"]); txid = int(fields["transmission_id"]); final = int(fields["final_offset"])
        st = self.streams.get(sid)
        if st is None:
            raise ProtocolError("FIN unknown Stream")
        if final < st.recv_committed or (st.recv_final is not None and st.recv_final != final):
            raise FinalSizeError("final size")
        if final > st.local_maximum:
            raise FlowControlError("final Stream credit")
        delta = max(0, final - st.recv_committed)
        if self.recv_committed + delta > self.local_session_max:
            raise FlowControlError("final Session credit")
        self.recv_committed += delta
        st.recv_committed = max(st.recv_committed, final)
        st.recv_final = final
        await self.carrier.send_frame(FRAME_TRANSMISSION_ACK, stream_id=sid, transmission_id=txid, receiver_timestamp_us=self.carrier.timestamp_us())
        self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="TRANSMISSION_ACK", stream_id=sid, transmission_id=txid)
        self._mark_done(st)

    def _mark_done(self, st: StreamState) -> None:
        if st.recv_final is not None and st.recv_next == st.recv_final:
            st.recv_done_event.set()
            self.trace.emit("application_stream_complete", **self.carrier.base_trace(), stream_id=st.stream_id, bytes=len(st.recv_data), sha256=hashlib.sha256(st.recv_data).hexdigest())

    async def open_streams(self) -> None:
        if self.role != "client":
            return
        for i in range(self.stream_count):
            sid = 1 + 2 * i
            st = StreamState(sid)
            self.streams[sid] = st
            tx = self.allocate(FRAME_STREAM_OPEN, sid)
            await self.carrier.send_frame(FRAME_STREAM_OPEN, stream_id=sid, transmission_id=tx.txid)
            self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="STREAM_OPEN", stream_id=sid, transmission_id=tx.txid)
            self.sender_tasks.append(asyncio.create_task(self.send_application(st)))
        await asyncio.wait_for(asyncio.gather(*(st.open_event.wait() for st in self.streams.values())), timeout=10)
        self.streams_ready.set()

    async def send_application(self, st: StreamState) -> None:
        await asyncio.wait_for(self.session_credit.wait(), timeout=10)
        await asyncio.wait_for(st.credit_event.wait(), timeout=10)
        payload = application_payload(self.role, st.stream_id, self.bytes_per_stream)
        offset = 0
        first = True
        waiters: List[asyncio.Event] = []
        chunk_size = min(self.carrier.peer_limits.max_frame_payload, 32768)
        while offset < len(payload):
            chunk = payload[offset:offset+chunk_size]
            end = offset + len(chunk)
            if end > st.peer_maximum or self.send_committed + len(chunk) > self.peer_session_max:
                raise FlowControlError("sender credit")
            tx = self.allocate(FRAME_STREAM_DATA, st.stream_id)
            await self.carrier.send_frame(FRAME_STREAM_DATA, stream_id=st.stream_id, offset=offset, transmission_id=tx.txid, data=chunk)
            self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="STREAM_DATA", stream_id=st.stream_id, transmission_id=tx.txid, offset=offset, data_length=len(chunk))
            waiters.append(tx.event)
            self.send_committed += len(chunk)
            self.tx_bytes += len(chunk)
            st.send_offset = end
            offset = end
            if first and offset < len(payload):
                first = False
                self.trace.emit("full_duplex_barrier_wait", **self.carrier.base_trace(), stream_id=st.stream_id)
                await asyncio.wait_for(self.first_rx.wait(), timeout=10)
        fin = self.allocate(FRAME_STREAM_FIN, st.stream_id)
        st.send_final = st.send_offset
        await self.carrier.send_frame(FRAME_STREAM_FIN, stream_id=st.stream_id, transmission_id=fin.txid, final_offset=st.send_final)
        self.trace.emit("frame_send", **self.carrier.base_trace(), frame_type="STREAM_FIN", stream_id=st.stream_id, transmission_id=fin.txid, final_offset=st.send_final)
        waiters.append(fin.event)
        await asyncio.wait_for(asyncio.gather(*(ev.wait() for ev in waiters)), timeout=15)
        self.trace.emit("application_send_complete", **self.carrier.base_trace(), stream_id=st.stream_id, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())

    async def wait_complete(self) -> None:
        if self.sender_tasks:
            await asyncio.wait_for(asyncio.gather(*self.sender_tasks), timeout=20)
        await asyncio.wait_for(asyncio.gather(*(st.recv_done_event.wait() for st in self.streams.values())), timeout=20)

    def result(self) -> Dict[str, object]:
        return {
            "role": self.role,
            "session_id": self.carrier.session_id.hex(),
            "carrier_id": self.carrier.carrier_id,
            "generation": self.carrier.generation,
            "streams": self.stream_count,
            "bytes_per_stream": self.bytes_per_stream,
            "tx_application_bytes": self.tx_bytes,
            "rx_application_bytes": self.rx_bytes,
            "max_outstanding_reliable": self.max_outstanding,
            "send_record_count": self.carrier.send_seq,
            "recv_record_count": self.carrier.recv_seq,
            "stream_results": {
                str(sid): {
                    "recv_bytes": len(st.recv_data),
                    "recv_sha256": hashlib.sha256(st.recv_data).hexdigest(),
                    "recv_final": st.recv_final,
                    "send_final": st.send_final,
                }
                for sid, st in sorted(self.streams.items())
            },
        }
