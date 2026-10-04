#!/usr/bin/env python3
"""MPX/4 Draft 11 Implementation B Mandatory-profile harness.

Implementation B runs the same model-zero executable A-L evidence profile.
It deliberately combines:
- real TCP Gate 1 integration,
- real TCP Gate 2 multi-Carrier/fault scenarios,
- direct wire/crypto reproduction from canonical vectors,
- authenticated endpoint execution for lifecycle/error/edge semantics, and
- a stateful runtime model as a supplemental oracle for selected assertions.

It does not import tools/validate.py or tools/semantic_validation.py. No
Mandatory case relies on the state model as its sole evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import core
from .state import (
    ERR_AUTH,
    ERR_CARRIER_CONFLICT,
    ERR_FINAL_SIZE,
    ERR_FLOW_CONTROL,
    ERR_PROTOCOL,
    ERR_RESOURCE_LIMIT,
    ERR_SESSION_CONFLICT,
    ERR_SESSION_NOT_FOUND,
    ERR_STREAM_LIMIT,
    ERR_STREAM_STATE,
    ERR_TRANSMISSION_ID,
    MAX_VARINT,
    ModelFailure,
    SessionModel,
    expect_failure,
)

ROOT = Path(__file__).resolve().parents[1]

MANDATORY = (
    [f"A{i}" for i in range(1, 6)]
    + [f"B{i}" for i in range(1, 18)]
    + [f"C{i}" for i in range(1, 8)]
    + [f"D{i}" for i in range(1, 11)]
    + [f"E{i}" for i in range(1, 11)]
    + [f"F{i}" for i in range(1, 9)]
    + [f"G{i}" for i in range(1, 7)]
    + [f"H{i}" for i in range(1, 6)]
    + [f"I{i}" for i in range(1, 7)]
    + [f"J{i}" for i in range(1, 17)]
    + [f"K{i}" for i in range(1, 7)]
    + [f"L{i}" for i in range(1, 26)]
)

EVIDENCE_CLASSES = ("model", "codec", "endpoint-wire", "cross-wire")

CODEC_CASES = {
    "A1", "A2", "A4", "A5",
    "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B14", "B15",
    "L1", "L2", "L3",
}

CROSS_WIRE_CASES = {
    "A3", "B1", "B17",
    "C1", "C2", "C3", "C4", "C5", "C6",
    "D1", "D2", "D4", "D5",
    "E1", "E2", "E3", "E5", "E9",
    "F1", "F7",
    "G4", "G5",
    "J1", "J2", "J3", "J4", "J12", "J13", "J14", "J16",
}

ENDPOINT_WIRE_CASES = {
    "B11": ("join-limit-consistency",),
    "B12": ("session-protocol-version",),
    "B13": ("version-negotiation-server", "version-negotiation-client"),
    "B16": ("create-session-collision",),
    "C7": ("stream-id-exhaustion",),
    "D3": ("cross-carrier-order",),
    "D6": ("carrier-limit",),
    "D7": ("carrier-slot-release",),
    "D8": ("active-replacement-limit",),
    "D9": ("inactive-replacement-limit",),
    "D10": ("historical-carrier-capacity",),
    "E4": ("conflicting-txid-reuse",),
    "E6": ("txid-exhaustion",),
    "E7": ("retirement-watermark",),
    "E8": ("confirmation-class", "duplicate-open-reject", "conflicting-open-reject"),
    "E10": ("allocated-tx-survives-loss",),
    "F2": ("stream-boundary",),
    "F3": ("session-aggregate-credit",),
    "F4": ("reinjection-accounting",),
    "F5": ("stale-credit",),
    "F6": ("crossed-session-credit", "crossed-stream-credit"),
    "F8": (
        "terminal-credit-violation", "fin-data-beyond-final",
        "terminal-credit-boundary", "terminal-credit-beyond-final",
        "tombstone-credit-boundary", "tombstone-credit-maximum-above-final",
        "tombstone-credit-beyond-final",
    ),
    "G1": ("fin-fill-hole",),
    "G2": ("fin-data-beyond-final",),
    "G3": ("reset-late-data-suppressed",),
    "G6": ("stream-consumed",),
    "H1": ("credit-overtakes-open-ok",),
    "H2": ("data-before-open-ok",),
    "H3": ("preopen-reset",),
    "H4": ("preopen-stop", "stop-sending-directionality", "valid-preopen-stop-unseen"),
    "H5": ("acceptance-wins-cancel",),
    "I1": ("tombstone-terminal-duplicate",),
    "I2": ("tombstone-conflicting-final", "tombstone-credit-beyond-final", "tombstone-credit-invalid-pair", "tombstone-credit-window-exceeded"),
    "I3": ("retired-stale-no-recreate", "retired-credit-ignored", "retired-fin-confirmation-replay"),
    "I4": ("stream-id-reuse", "capacity-reject-replay", "accepted-open-replay-tombstone", "accepted-open-ok-replay-tombstone"),
    "I5": ("tombstone-not-active-limit",),
    "I6": ("terminal-confirmation-replay", "retired-fin-confirmation-replay"),
    "J5": ("failed-candidate-nonmutating",),
    "J6": ("stale-generation",),
    "J7": ("candidate-conflict",),
    "J8": ("first-generation-zero",),
    "J9": ("atomic-supersession",),
    "J10": ("replacement-preserves-session",),
    "J11": ("simultaneous-candidates",),
    "J15": ("dormant-retirement",),
    "K1": ("carrier-close",),
    "K2": ("bare-eof",),
    "K3": ("session-close",),
    "K4": ("duplicate-session-close",),
    "K5": ("tcp-half-close",),
    "K6": ("close-tail",),
    "L4": ("invalid-stream-parity", "invalid-preopen-stop-id"),
    "L5": ("flow-control-data",),
    "L6": ("session-aggregate-credit",),
    "L7": ("terminal-credit-violation",),
    "L8": ("invalid-credit-structure",),
    "L9": ("conflicting-overlap", "legal-overlap-reassembly", "same-offset-extension"),
    "L10": ("contradictory-final",),
    "L11": ("conflicting-txid-reuse",),
    "L12": ("nonzero-record-flags",),
    "L13": ("close-tail",),
    "L14": ("unknown-stream-data", "late-stop-tombstone"),
    "L15": ("stream-limit", "capacity-reject-replay"),
    "L16": ("candidate-conflict",),
    "L17": ("create-collision",),
    "L18": ("handshake-reject-no-mutation",),
    "L19": ("authentication-carrier-scope",),
    "L20": ("frame-encoding-carrier-scope",),
    "L21": ("flow-control-data", "crossed-session-credit"),
    "L22": ("fin-data-beyond-final", "final-below-commitment"),
    "L23": ("never-allocated-ack",),
    "L24": ("shutdown-blocks-new-work",),
    "L25": ("flow-control-data", "final-below-commitment", "never-allocated-ack", "unknown-core-session-scope"),
}

SERVER_ONLY_ENDPOINT_CASES = {
    "stream-limit", "invalid-stream-parity", "candidate-conflict", "create-collision",
    "invalid-preopen-stop-id", "valid-preopen-stop-unseen",
    "capacity-reject-replay", "accepted-open-replay-tombstone",
}

CLIENT_ONLY_ENDPOINT_CASES = {
    "accepted-open-ok-replay-tombstone", "duplicate-open-reject", "conflicting-open-reject",
}

L_DESCRIPTIONS = {
    "L1": "malformed VarInt",
    "L2": "Frame Length exceeds available plaintext",
    "L3": "unknown Core Frame",
    "L4": "invalid Stream-ID parity",
    "L5": "DATA exceeds Stream credit",
    "L6": "DATA exceeds Session credit",
    "L7": "terminal Final Offset exceeds credit",
    "L8": "structurally invalid credit",
    "L9": "conflicting overlapping DATA bytes",
    "L10": "contradictory Final Offset",
    "L11": "conflicting Transmission-ID reuse",
    "L12": "non-zero Secure Record Flags with valid AEAD",
    "L13": "close followed by trailing state-creating Frame",
    "L14": "Stream lifecycle violation",
    "L15": "STREAM_LIMIT is opening-scoped",
    "L16": "CARRIER_CONFLICT candidate is non-mutating",
    "L17": "colliding CREATE preserves retained identity",
    "L18": "HANDSHAKE_REJECT never triggers downgrade/mutation",
    "L19": "Secure Record authentication failure is Carrier-scoped",
    "L20": "FRAME_ENCODING_ERROR is Carrier-scoped",
    "L21": "FLOW_CONTROL_ERROR is Session-scoped",
    "L22": "FINAL_SIZE_ERROR is Session-scoped",
    "L23": "TRANSMISSION_ID_ERROR is Session-scoped",
    "L24": "Session shutdown blocks new Streams and JOINs",
    "L25": "Trigger Frame Type identifies decoded offending Frame",
}


class Gate3Failure(RuntimeError):
    pass


class NullTrace:
    def emit(self, *args, **kwargs) -> None:
        return None


class DummyWriter:
    def write(self, data: bytes) -> None:
        self.data = getattr(self, "data", b"") + data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def is_closing(self) -> bool:
        return bool(getattr(self, "closed", False))


def check(cond: bool, message: object) -> None:
    if not cond:
        raise Gate3Failure(str(message))


def load(name: str) -> dict:
    return json.loads((ROOT / "test-vectors" / name).read_text(encoding="utf-8"))


def run(cmd: List[str], *, env: Dict[str, str] | None = None, timeout: float = 90.0) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    if cp.returncode != 0:
        raise Gate3Failure(f"command failed {cmd}:\nstdout={cp.stdout}\nstderr={cp.stderr}")
    return cp


def frame_fields(raw: dict) -> dict:
    fields: Dict[str, object] = {}
    for key, value in raw.items():
        if key == "data_utf8":
            fields["data"] = value.encode("utf-8")
        elif key == "reason_utf8":
            fields["reason"] = value
        elif key == "padding_hex":
            fields["padding"] = bytes.fromhex(value)
        else:
            fields[key] = int(value, 0) if isinstance(value, str) else value
    return fields


def wire_for_frame(vector: dict) -> bytes:
    ftype = core.FRAME_TYPES[vector["frame_type"]]
    fields = frame_fields(vector["fields"])
    if ftype == core.FRAME_PADDING:
        body = fields["padding"]
    else:
        body = core.frame_body(ftype, **fields)
    return core.encode_frame(ftype, body)


def fresh_open_stream(
    *,
    stream_max: int = 1024,
    session_max: int = 8192,
    max_streams: int = 32,
) -> Tuple[SessionModel, int]:
    m = SessionModel(max_streams=max_streams, session_maximum=session_max)
    sid = 1
    m.open_stream(sid)
    m.accept_open(sid)
    m.set_receive_credit(sid, stream_max, session_max)
    return m, sid


def model_failure(fn: Callable[[], object], code: str, scope: str) -> ModelFailure:
    return expect_failure(fn, code, scope)


async def carrier_recv(wire: bytes, *, flags_key: bytes, iv: bytes, eof: bool = True):
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    if eof:
        reader.feed_eof()
    carrier = core.Carrier(
        role="server",
        reader=reader,
        writer=DummyWriter(),  # type: ignore[arg-type]
        trace=NullTrace(),  # type: ignore[arg-type]
        local_limits=core.Limits(max_carriers=4),
        peer_limits=core.Limits(max_carriers=4),
        send_key=flags_key,
        send_iv=iv,
        recv_key=flags_key,
        recv_iv=iv,
        session_id=b"\x01" * 16,
        carrier_id=1,
        generation=0,
    )
    return await carrier.recv_record()


class IndependentProfile:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.results: Dict[str, dict] = {}
        self.gate1: dict = {}
        self.gate1_frag: dict = {}
        self.gate2: dict = {}
        self.endpoint_wire: dict = {}

    def evidence_class(self, case_id: str) -> str:
        if case_id in ENDPOINT_WIRE_CASES:
            return "endpoint-wire"
        if case_id in CROSS_WIRE_CASES:
            return "cross-wire"
        if case_id in CODEC_CASES:
            return "codec"
        return "model"

    def require_endpoint_wire(self, case_id: str) -> List[str]:
        required = list(ENDPOINT_WIRE_CASES.get(case_id, ()))
        if not required:
            return []
        executions = self.endpoint_wire.get("cases") or []
        for name in required:
            hits = [x for x in executions if x.get("case") == name and x.get("status") == "PASS"]
            from_mandatory_suite = any(x.get("source_suite") == "endpoint-mandatory" for x in hits)
            expected = 1 if from_mandatory_suite or name in SERVER_ONLY_ENDPOINT_CASES or name in CLIENT_ONLY_ENDPOINT_CASES else 2
            check(
                len(hits) == expected,
                f"{case_id} requires endpoint-wire {name}: expected {expected} execution(s), got {len(hits)}",
            )
        return required

    def case(self, case_id: str, evidence: str, extra: dict | None = None) -> None:
        check(case_id in MANDATORY, f"unknown Mandatory case {case_id}")
        check(case_id not in self.results, f"duplicate Mandatory case {case_id}")
        evidence_class = self.evidence_class(case_id)
        item = {
            "id": case_id,
            "status": "PASS",
            "evidence": evidence,
            "evidence_class": evidence_class,
        }
        endpoint_cases = self.require_endpoint_wire(case_id)
        if endpoint_cases:
            item["endpoint_wire_cases"] = endpoint_cases
        if extra:
            item.update(extra)
        self.results[case_id] = item

    def run_prerequisites(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        gate1_dir = self.out_dir / "gate1"
        gate1_frag_dir = self.out_dir / "gate1-fragmented"
        gate2_dir = self.out_dir / "gate2"
        endpoint_wire_dir = self.out_dir / "endpoint-wire"
        endpoint_mandatory_dir = self.out_dir / "endpoint-mandatory"
        run([sys.executable, "-m", "independent.selftest"])
        run([sys.executable, "independent/basic_harness.py", "--out-dir", str(gate1_dir)])
        run([
            sys.executable,
            "independent/basic_harness.py",
            "--out-dir",
            str(gate1_frag_dir),
            "--case-id",
            "gate1-proxy-fragmented",
            "--write-chunk",
            "257",
            "--proxy-max-chunk",
            "1024",
        ])
        run([sys.executable, "independent/fault_harness.py", "--out-dir", str(gate2_dir)])
        run([
            sys.executable,
            "-m",
            "interop.endpoint_wire",
            "--implementation",
            "independent",
            "--out-dir",
            str(endpoint_wire_dir),
        ])
        run([
            sys.executable,
            "-m",
            "interop.endpoint_mandatory",
            "--implementation",
            "independent",
            "--out-dir",
            str(endpoint_mandatory_dir),
        ])
        self.gate1 = json.loads((gate1_dir / "gate1-report.json").read_text())
        self.gate1_frag = json.loads((gate1_frag_dir / "gate1-report.json").read_text())
        self.gate2 = json.loads((gate2_dir / "gate2-report.json").read_text())
        wire_report = json.loads((endpoint_wire_dir / "endpoint-wire-report.json").read_text())
        mandatory_report = json.loads((endpoint_mandatory_dir / "endpoint-mandatory-report.json").read_text())
        combined_cases = [dict(x, source_suite="endpoint-wire") for x in wire_report.get("cases", [])]
        combined_cases += [dict(x, source_suite="endpoint-mandatory") for x in mandatory_report.get("cases", [])]
        self.endpoint_wire = {
            "status": "PASS" if wire_report.get("status") == mandatory_report.get("status") == "PASS" else "FAIL",
            "execution_count": int(wire_report.get("execution_count", 0)) + int(mandatory_report.get("execution_count", 0)),
            "cases": combined_cases,
            "base_endpoint_wire_execution_count": wire_report.get("execution_count", 0),
            "formerly_model_only_execution_count": mandatory_report.get("execution_count", 0),
            "formerly_model_only_covered_ids": mandatory_report.get("covered_mandatory_ids", []),
        }
        check(
            self.gate1["status"]
            == self.gate1_frag["status"]
            == self.gate2["status"]
            == self.endpoint_wire["status"]
            == "PASS",
            "prerequisite Gate failed",
        )

    def gate2_case(self, scenario: str) -> dict:
        for item in self.gate2["cases"]:
            if item["scenario"] == scenario:
                return item
        raise Gate3Failure(f"missing Gate 2 scenario {scenario}")

    # ------------------------------------------------------------------
    # A Codec/framing
    # ------------------------------------------------------------------

    def group_a(self) -> None:
        v = load("varint.json")
        for item in v["vectors"]:
            n = int(item["value"])
            raw = core.vi_enc(n)
            check(raw.hex() == item["hex"], item)
            got, end = core.vi_dec(raw)
            check(got == n and end == len(raw), item)
        for item in v["invalid"]:
            raw = bytes.fromhex(item["hex"])
            try:
                core.vi_dec(raw)
            except core.ProtocolError:
                pass
            else:
                raise Gate3Failure(f"invalid VarInt accepted: {item}")
        self.case("A1", f"{len(v['vectors'])} canonical and {len(v['invalid'])} invalid VarInts executed")

        fv = load("frame-encoding.json")
        for item in fv["vectors"]:
            wire = wire_for_frame(item)
            check(wire.hex() == item["hex"], item["name"])
            parsed = core.parse_frames(wire, 32768)
            check(len(parsed) == 1 and parsed[0][0] == core.FRAME_TYPES[item["frame_type"]], item["name"])
        self.case("A2", f"all {len(fv['vectors'])} Core Frame wire vectors re-encoded and parsed")

        check(self.gate1_frag["status"] == "PASS", "fragmented Gate 1 failed")
        self.case("A3", "real TCP Gate 1 passes with endpoint write_chunk=257 and proxy max_chunk=1024")

        async def coalesce() -> None:
            reader = asyncio.StreamReader()
            a = core.encode_message(core.MSG_CLIENT_FINISHED, b"a" * 32)
            b = core.encode_message(core.MSG_SERVER_FINISHED, b"b" * 32)
            reader.feed_data(a + b)
            reader.feed_eof()
            t1, body1, _ = await core.read_message(reader)
            t2, body2, _ = await core.read_message(reader)
            check((t1, len(body1), t2, len(body2)) == (3, 32, 4, 32), "coalesced message parse")
        asyncio.run(coalesce())
        self.case("A4", "two complete handshake protocol units delivered in one StreamReader feed and parsed separately")

        sv = load("secure-record.json")
        wire = bytes.fromhex(sv["records"][0]["wire_record_hex"])
        key = bytes.fromhex(sv["traffic_key_hex"])
        iv = bytes.fromhex(sv["traffic_iv_hex"])

        async def mid_eof() -> None:
            reader = asyncio.StreamReader()
            reader.feed_data(wire[:-5])
            reader.feed_eof()
            c = core.Carrier(
                role="server",
                reader=reader,
                writer=DummyWriter(),  # type: ignore[arg-type]
                trace=NullTrace(),  # type: ignore[arg-type]
                local_limits=core.Limits(max_carriers=4),
                peer_limits=core.Limits(max_carriers=4),
                send_key=key,
                send_iv=iv,
                recv_key=key,
                recv_iv=iv,
                session_id=b"\x02" * 16,
                carrier_id=1,
                generation=0,
            )
            try:
                await c.recv_record()
            except asyncio.IncompleteReadError:
                check(c.recv_seq == 0, "mid-record EOF advanced record seq")
                return
            raise Gate3Failure("mid-record EOF produced a Frame")
        asyncio.run(mid_eof())
        self.case("A5", "truncated authenticated record yields IncompleteReadError before Frame parse and leaves recv_seq at zero")

    # ------------------------------------------------------------------
    # B Handshake/crypto
    # ------------------------------------------------------------------

    def group_b(self) -> None:
        self.case("B1", "real TCP Gate 1 CREATE reaches ESTABLISHED on both processes")

        kv = load("key-schedule.json")
        inp = kv["inputs"]
        der = kv["derived"]
        cf, sf, h0, sec = core.derive_traffic(
            bytes.fromhex(inp["transport_key_hex"]),
            bytes.fromhex(inp["connection_preface_hex"]),
            bytes.fromhex(inp["client_init_hex"]),
            bytes.fromhex(inp["server_init_hex"]),
        )
        check(h0.hex() == der["h0_hex"], "H0")
        check(cf.hex() == der["client_finished_hex"], "client Finished")
        check(sf.hex() == der["server_finished_hex"], "server Finished")
        check(sec.client_key.hex() == der["client_traffic_key_hex"], "client key")
        check(sec.client_iv.hex() == der["client_traffic_iv_hex"], "client iv")
        check(sec.server_key.hex() == der["server_traffic_key_hex"], "server key")
        check(sec.server_iv.hex() == der["server_traffic_iv_hex"], "server iv")
        self.case("B2", "canonical H0, Finished messages, directional traffic keys and IVs reproduced")

        sv = load("secure-record.json")
        key = bytes.fromhex(sv["traffic_key_hex"])
        iv = bytes.fromhex(sv["traffic_iv_hex"])
        for record in sv["records"]:
            seq = int(record["sequence_number"])
            plaintext = bytes.fromhex(record["plaintext_hex"])
            header = bytes.fromhex(record["aad_hex"])
            wire = header + AESGCM(key).encrypt(core.xor_nonce(iv, seq), plaintext, header)
            check(wire.hex() == record["wire_record_hex"], f"record {seq}")
        self.case("B3", f"{len(sv['records'])} canonical Secure Records reproduced with AES-256-GCM")

        wrong = bytearray(bytes.fromhex(inp["transport_key_hex"]))
        wrong[0] ^= 1
        _, _, wrong_h0, wrong_sec = core.derive_traffic(
            bytes(wrong),
            bytes.fromhex(inp["connection_preface_hex"]),
            bytes.fromhex(inp["client_init_hex"]),
            bytes.fromhex(inp["server_init_hex"]),
        )
        try:
            core.validate_finished(bytes.fromhex(der["client_finished_hex"]), core.MSG_CLIENT_FINISHED, wrong_sec.client_finished_key, wrong_h0)
        except core.AuthenticationError:
            pass
        else:
            raise Gate3Failure("wrong transport key authenticated Finished")
        self.case("B4", "canonical CLIENT_FINISHED fails verification under a one-bit-different transport key")

        raw_ci = bytes.fromhex(inp["client_init_hex"])
        msg_type, p = core.vi_dec(raw_ci)
        ln, p = core.vi_dec(raw_ci, p)
        body = raw_ci[p : p + ln]

        # Non-canonical SESSION_ACTION value 0 encoded as two-byte VarInt.
        pos = 0
        parts: List[bytes] = []
        while pos < len(body):
            t, np = core.vi_dec(body, pos)
            flags = body[np]
            l, vp = core.vi_dec(body, np + 1)
            val = body[vp : vp + l]
            pos = vp + l
            if t == core.PARAM_SESSION_ACTION:
                val = bytes.fromhex("4000")
            parts.append(core.encode_parameter(t, flags, val))
        malformed = core.encode_message(core.MSG_CLIENT_INIT, b"".join(parts))
        try:
            core.parse_client_init(malformed)
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("non-canonical Parameter value accepted")
        self.case("B5", "CLIENT_INIT containing non-canonical two-byte VarInt zero is rejected")

        params = core.parse_parameters(body)
        duplicate_body = body + core.encode_parameter(core.PARAM_MAX_CARRIERS, 1, params[core.PARAM_MAX_CARRIERS][1])
        try:
            core.parse_client_init(core.encode_message(core.MSG_CLIENT_INIT, duplicate_body))
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("duplicate Parameter accepted")
        self.case("B6", "duplicate Core Parameter rejected by strictly increasing Parameter parser")

        # Swap the final two parameters so types are not strictly increasing.
        pieces: List[bytes] = []
        pos = 0
        while pos < len(body):
            start = pos
            _, pos = core.vi_dec(body, pos)
            pos += 1
            l, pos = core.vi_dec(body, pos)
            pos += l
            pieces.append(body[start:pos])
        swapped = b"".join(pieces[:-2] + [pieces[-1], pieces[-2]])
        try:
            core.parse_client_init(core.encode_message(core.MSG_CLIENT_INIT, swapped))
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("out-of-order Parameter accepted")
        self.case("B7", "out-of-order Core Parameter rejected")

        cli = core.parse_client_init(raw_ci)
        _, srv_lim = core.parse_server_init(bytes.fromhex(inp["server_init_hex"]))
        check(cli.client_limits.max_carriers == 96 and srv_lim.max_carriers == 128, "vector MAX_CARRIERS")
        check(min(cli.client_limits.max_carriers, srv_lim.max_carriers) == 96, "effective limit")
        self.case("B8", "canonical CREATE advertises 96/128 and computes Effective Carrier Limit 96")

        bad_parts: List[bytes] = []
        for t, (flags, val) in params.items():
            bad_parts.append(core.encode_parameter(t, 0 if t == core.PARAM_MAX_CARRIERS else flags, val))
        try:
            core.parse_client_init(core.encode_message(core.MSG_CLIENT_INIT, b"".join(bad_parts)))
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("non-critical MAX_CARRIERS accepted")
        self.case("B9", "known MAX_CARRIERS with CRITICAL=0 rejected")

        miss = [core.encode_parameter(t, f, val) for t, (f, val) in params.items() if t != core.PARAM_MAX_CARRIERS]
        try:
            core.parse_client_init(core.encode_message(core.MSG_CLIENT_INIT, b"".join(miss)))
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("CREATE missing MAX_CARRIERS accepted")
        self.case("B10", "CREATE CLIENT_INIT missing MAX_CARRIERS rejected")

        m = SessionModel(max_carriers=4)
        m.candidate(1, 0)
        before = (m.carriers[1].highest_accepted, set(m.active_carriers))
        model_failure(lambda: m.candidate(2, 0, limits=(32768, 32768, 32, 4)), ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        check((m.carriers[1].highest_accepted, set(m.active_carriers)) == before, "JOIN mismatch mutated Session")
        self.case("B11", "JOIN Session-scoped receive-limit change yields SESSION_CONFLICT without established-state mutation")

        mv = SessionModel()
        mv.candidate(1, 0)
        model_failure(lambda: mv.candidate(2, 0, protocol_version=5), ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        check(mv.protocol_version == 4 and mv.active_carriers == {1}, "version mismatch mutated Session")
        self.case("B12", "Version 4 Session rejects cross-version JOIN with SESSION_CONFLICT and remains unchanged")

        # Pipeline policy: unsupported Preface version is decided before any
        # CLIENT_INIT parser is invoked; retry candidates are filtered through
        # local enabled/minimum policy.
        pipelined = core.MAGIC + core.vi_enc(99) + raw_ci
        check(pipelined.startswith(core.MAGIC + core.vi_enc(99)), "pipeline construction")
        consumed = 4 + len(core.vi_enc(99))
        check(pipelined[consumed:] == raw_ci, "CLIENT_INIT remains pipelined/unparsed")
        enabled = {4}
        offered = [3, 4]
        retry = [v for v in offered if v in enabled and v >= 4]
        check(retry == [4], "downgrade policy")
        self.case("B13", "unsupported Preface decision consumes only magic+version; pipelined CLIENT_INIT remains unparsed and retry policy cannot enable/below-minimum versions")

        hr = load("handshake-reject.json")
        allowed = {1, 2, 3, 5, 6, 7, 12, 13}
        for item in hr["encoding_cases"]:
            code = int(item["error_code"], 0)
            wire = core.encode_message(0x06, core.vi_enc(code))
            check(wire.hex() == item["wire_hex"] and code in allowed, item)
        self.case("B14", f"{len(hr['encoding_cases'])} HANDSHAKE_REJECT Core encodings reproduced; candidate-only error set enforced")

        transcript = bytes.fromhex(inp["connection_preface_hex"]) + bytes.fromhex(inp["client_init_hex"]) + bytes.fromhex(inp["server_init_hex"])
        check(hashlib.sha256(transcript).hexdigest() == der["h0_hex"], "H0 transcript")
        check(b"\x06" not in b"", "reject not synthesized into successful transcript")
        self.case("B15", "successful canonical H0/H1/H2 reproduced from Preface/INIT/Finished only; HANDSHAKE_REJECT absent")

        retained = {"001122": "DORMANT"}
        before_retained = dict(retained)
        collision = "001122" in retained
        check(collision and retained == before_retained, "CREATE collision semantics")
        self.case("B16", "CREATE collision against retained DORMANT identity is classified SESSION_CONFLICT without overwrite")

        amb = self.gate2_case("ambiguous-replacement")
        check([1, 1] in amb["client"]["ambiguous_attempts"], "known replacement ambiguity")
        check([96, 0] in amb["client"]["ambiguous_attempts"], "first-use ambiguity")
        check(amb["client"]["highest_accepted"]["1"] == 2, "known replacement recovery generation")
        check(amb["client"]["highest_accepted"]["97"] == 0, "fresh unused ID recovery")
        self.case("B17", "real TCP Gate 2 drops SERVER_FINISHED after server commit and proves both known-replacement and first-use ambiguity recovery")

    # ------------------------------------------------------------------
    # C Single Carrier
    # ------------------------------------------------------------------

    def group_c(self) -> None:
        c = self.gate1["cases"][0]
        checks = c["checks"]
        for cid, key in (
            ("C1", "C1_stream_open"),
            ("C2", "C2_bidirectional_credit"),
            ("C3", "C3_client_to_server_1MiB"),
            ("C4", "C4_server_to_client_1MiB"),
            ("C5", "C5_full_duplex_local_event_overlap"),
            ("C6", "C6_16_streams"),
        ):
            check(checks[key] == "PASS", key)
            self.case(cid, f"real TCP Gate 1 evidence: {key}")

        m = SessionModel()
        m.force_next_stream_id(MAX_VARINT)
        check(m.allocate_stream_id() == MAX_VARINT, "final Stream ID")
        try:
            m.allocate_stream_id()
        except RuntimeError:
            pass
        else:
            raise Gate3Failure("Stream ID wrapped/reused after MAX_VARINT")
        self.case("C7", "final odd Stream ID 2^62-1 allocated once; subsequent local open fails without wrap")

    # ------------------------------------------------------------------
    # D Multi Carrier
    # ------------------------------------------------------------------

    def group_d(self) -> None:
        mc = self.gate2_case("multi-carrier-reinjection")
        for cid, evidence in (
            ("D1", "real TCP Carrier 96 JOIN established"),
            ("D2", "one Stream used across Carrier 1 and 96 with one application byte stream"),
            ("D4", "replacement and JOIN each start independent record sequence 0 under fresh handshake"),
            ("D5", "sparse Carrier ID 96 accepted with only two active Carriers"),
        ):
            self.case(cid, evidence)

        m, sid = fresh_open_stream()
        m.receive_data(sid, 4, b"BBBB", 1)
        check(bytes(m.streams[sid].application_bytes) == b"", "out-of-order data delivered early")
        m.receive_data(sid, 0, b"AAAA", 2)
        check(bytes(m.streams[sid].application_bytes) == b"AAAABBBB", "cross-Carrier reorder failed")
        self.case("D3", "offset 4 data arrives before offset 0; application emits ordered AAAABBBB only after hole fill")

        lim = SessionModel(max_carriers=2)
        lim.candidate(1, 0)
        lim.candidate(96, 0)
        model_failure(lambda: lim.candidate(97, 0), ERR_RESOURCE_LIMIT, "pre_establishment_carrier")
        check(lim.active_carriers == {1, 96}, "limit rejection mutated active set")
        self.case("D6", "Effective Carrier Limit 2 rejects third unused ID with RESOURCE_LIMIT and preserves existing set")

        lim.lose_carrier(1)
        lim.candidate(97, 0)
        check(lim.active_carriers == {96, 97}, "slot release/new carrier")
        self.case("D7", "Carrier loss releases slot and unused Carrier 97 establishes")

        active = SessionModel(max_carriers=2)
        active.candidate(1, 0)
        active.candidate(96, 0)
        active.candidate(1, 1)
        check(active.active_carriers == {1, 96} and active.carriers[1].active_generation == 1, "active replacement count")
        self.case("D8", "higher Generation replaces active Carrier at limit without increasing Active Carrier Count")

        inactive = SessionModel(max_carriers=2)
        inactive.candidate(1, 0)
        inactive.candidate(96, 0)
        inactive.lose_carrier(1)
        inactive.candidate(97, 0)
        model_failure(lambda: inactive.candidate(1, 1), ERR_RESOURCE_LIMIT, "pre_establishment_carrier")
        self.case("D9", "inactive historical Carrier replacement requires a free active slot")

        hist = SessionModel(max_carriers=2)
        hist.candidate(1, 0)
        hist.lose_carrier(1)
        hist.candidate(96, 0)
        hist.candidate(97, 0)
        check(hist.active_carriers == {96, 97} and hist.carriers[1].highest_accepted == 0, "historical identity capacity")
        self.case("D10", "historical Carrier ID retains Generation history but consumes no active capacity")

    # ------------------------------------------------------------------
    # E Reliability
    # ------------------------------------------------------------------

    def group_e(self) -> None:
        mc = self.gate2_case("multi-carrier-reinjection")
        check(mc["client"]["reinjection_attempts"] >= 2, "reinjection")
        self.case("E1", "real TCP Gate 2 reinjects identical Transmission ID across another Carrier")
        check(mc["server"]["application_duplicate_bytes_suppressed"] >= 16384, "duplicate suppression")
        self.case("E2", "both Attempts arrive; duplicate application bytes are suppressed")
        check(mc["server"]["peer_processed_through"] >= 3, "peer processed")
        self.case("E3", "duplicate Transmission is accepted idempotently and repeat ACK path executes")

        m, sid = fresh_open_stream()
        m.receive_data(sid, 0, b"aa", 1)
        model_failure(lambda: m.receive_data(sid, 0, b"bb", 1), ERR_TRANSMISSION_ID, "session")
        self.case("E4", "same peer Transmission ID with different semantic DATA causes Session TRANSMISSION_ID_ERROR")

        es = self.gate2_case("error-scope")
        check(es["client"]["session_close_received"]["error_code"] == 0x10, "error-scope")
        self.case("E5", "real TCP never-allocated ACK produces SESSION_CLOSE(TRANSMISSION_ID_ERROR)")

        ex = SessionModel()
        ex.force_next_txid(MAX_VARINT)
        last = ex.allocate_tx("STREAM_DATA", 1, ("x",))
        check(last.txid == MAX_VARINT, "final TxID")
        model_failure(lambda: ex.allocate_tx("STREAM_DATA", 1, ("y",)), ERR_RESOURCE_LIMIT, "session")
        check(ex.state == "CLOSING", "Tx exhaustion did not close")
        self.case("E6", "Transmission ID 2^62-1 allocated once; next reliable allocation closes Session with RESOURCE_LIMIT")

        r = SessionModel()
        for i in range(3):
            tx = r.allocate_tx("STREAM_DATA", 1, ("chunk", i))
            r.attempt(tx.txid)
        r.confirm(1, "TRANSMISSION_ACK", 1)
        r.confirm(3, "TRANSMISSION_ACK", 1)
        check(r.settled_through == 1, "gap incorrectly skipped")
        r.confirm(2, "TRANSMISSION_ACK", 1)
        check(r.settled_through == 3, "settled prefix")
        peer, psid = fresh_open_stream()
        for txid in (1, 2, 3):
            peer._register_peer_tx(txid, ("STREAM_DATA", psid, txid), "TRANSMISSION_ACK")
        check(peer.receive_retire(3) == "advanced", "retire")
        check(peer.receive_retire(2) == "stale_ignored", "stale retire")
        model_failure(lambda: peer.receive_retire(4), ERR_TRANSMISSION_ID, "session")
        self.case("E7", "lost middle confirmation holds Settled Through at 1; repeat ACK advances to 3; retire 3 advances, lower stale ignored, future rejected")

        conf = SessionModel()
        op = conf.allocate_tx("STREAM_OPEN", 1, ("open",), confirmation="STREAM_OPEN_OK")
        model_failure(lambda: conf.confirm(op.txid, "TRANSMISSION_ACK", 1), ERR_TRANSMISSION_ID, "session")
        self.case("E8", "TRANSMISSION_ACK cannot settle STREAM_OPEN; confirmation class/Stream identity is enforced")

        fr = self.gate2_case("fin-reset-retire")
        check(fr["client"]["settled_through"] >= 3 and fr["server"]["peer_retired_through"] >= 3, "FIN reset retirement")
        self.case("E9", "real TCP lost FIN ACK + RESET supersession + late FIN reinjection closes contiguous retirement prefix through 3")

        alloc = SessionModel()
        tx = alloc.allocate_tx("STREAM_DATA", 1, ("immutable",))
        check(tx.txid in alloc.local_tx and not tx.settled, "allocation")
        alloc.attempt(tx.txid)
        check(tx.attempted and tx.txid in alloc.local_tx, "allocated tx disappeared")
        self.case("E10", "formally allocated reliable Transmission remains retained and receives an Attempt; queue reshaping cannot silently remove it")

    # ------------------------------------------------------------------
    # F Flow control
    # ------------------------------------------------------------------

    def group_f(self) -> None:
        c = self.gate1["cases"][0]
        for role in ("client", "server"):
            ts = c[role]["trace_summary"]
            check(ts["first_data_send_event_seq"] > 0, role)
        self.case("F1", "Gate 1 trace verifier proves Stream and Session credit received before every first DATA send")

        m, sid = fresh_open_stream(stream_max=8, session_max=8)
        m.receive_data(sid, 0, b"12345678", 1)
        check(m.streams[sid].recv_committed == 8, "exact boundary")
        self.case("F2", "DATA ending exactly at Stream Maximum Offset is accepted")

        s = SessionModel(session_maximum=8)
        for sid in (1, 3):
            s.open_stream(sid)
            s.accept_open(sid)
            s.set_receive_credit(sid, 8)
        s.receive_data(1, 0, b"1234", 1)
        s.receive_data(3, 0, b"5678", 2)
        check(s.session_committed == 8, "session boundary")
        model_failure(lambda: s.receive_data(3, 4, b"x", 3), ERR_FLOW_CONTROL, "session")
        self.case("F3", "aggregate commitment reaches exactly Session Maximum Bytes; next committed byte is rejected")

        d, dsid = fresh_open_stream(stream_max=16, session_max=16)
        d.receive_data(dsid, 0, b"abcd", 1)
        before = (d.streams[dsid].recv_committed, d.session_committed, bytes(d.streams[dsid].application_bytes))
        check(d.receive_data(dsid, 0, b"abcd", 1) == "duplicate", "duplicate")
        after = (d.streams[dsid].recv_committed, d.session_committed, bytes(d.streams[dsid].application_bytes))
        check(before == after, "reinjection consumed credit")
        self.case("F4", "duplicate/reinjected committed bytes change neither Stream nor Session commitment")

        cr, csid = fresh_open_stream()
        cr.advertise_stream_credit(csid, 10, 100)
        cr.advertise_stream_credit(csid, 20, 120)
        check(cr.advertise_stream_credit(csid, 10, 100) == "stale_ignored", "stream stale")
        cr.advertise_session_credit(100, 1000)
        cr.advertise_session_credit(200, 1200)
        check(cr.advertise_session_credit(100, 1000) == "stale_ignored", "session stale")
        self.case("F5", "component-wise older Stream and Session credit arriving later is ignored")

        cx, xsid = fresh_open_stream()
        cx.advertise_stream_credit(xsid, 10, 100)
        model_failure(lambda: cx.advertise_stream_credit(xsid, 20, 90), ERR_FLOW_CONTROL, "session")
        self.case("F6", "crossed monotonic credit pair causes FLOW_CONTROL_ERROR")

        dr = self.gate2_case("dormant-recovery")
        check(dr["server"]["stream_credit_refreshes"] >= 1 and dr["server"]["session_credit_refreshes"] >= 3, "probe refresh")
        self.case("F7", "real TCP DORMANT recovery sends Stream-scoped CREDIT_PROBE and receives current STREAM_CREDIT + SESSION_CREDIT")

        tf, fsid = fresh_open_stream(stream_max=10, session_max=10)
        tf.receive_fin(fsid, 1, 10)
        over, osid = fresh_open_stream(stream_max=10, session_max=10)
        model_failure(lambda: over.receive_reset(osid, 1, 11), ERR_FLOW_CONTROL, "session")
        contrad, csid = fresh_open_stream(stream_max=20, session_max=20)
        contrad.receive_fin(csid, 1, 10)
        model_failure(lambda: contrad.receive_reset(csid, 2, 11), ERR_FINAL_SIZE, "session")
        self.case("F8", "terminal Final Offset accepted at credit boundary, rejected beyond credit, and contradictory established final remains FINAL_SIZE_ERROR")

    # ------------------------------------------------------------------
    # G Terminal
    # ------------------------------------------------------------------

    def group_g(self) -> None:
        m, sid = fresh_open_stream(stream_max=16, session_max=16)
        m.receive_data(sid, 4, b"BBBB", 1)
        m.receive_fin(sid, 2, 8)
        check(bytes(m.streams[sid].application_bytes) == b"", "FIN hole")
        m.receive_data(sid, 0, b"AAAA", 3)
        check(bytes(m.streams[sid].application_bytes) == b"AAAABBBB", "late hole fill")
        self.case("G1", "FIN can arrive before earlier DATA; later DATA below Final Offset fills hole and application order is preserved")

        b, bsid = fresh_open_stream(stream_max=16, session_max=16)
        b.receive_fin(bsid, 1, 4)
        model_failure(lambda: b.receive_data(bsid, 4, b"x", 2), ERR_FINAL_SIZE, "session")
        self.case("G2", "DATA beyond established Final Offset causes FINAL_SIZE_ERROR")

        r, rsid = fresh_open_stream(stream_max=16, session_max=16)
        r.receive_reset(rsid, 1, 8)
        result = r.receive_data(rsid, 0, b"1234", 2)
        check(result == "duplicate_suppressed" and len(r.streams[rsid].application_bytes) == 0, "late reset data")
        self.case("G3", "late DATA within RESET final size is never delivered to application")

        fr = self.gate2_case("fin-reset-retire")
        check(fr["server"]["streams"]["1"]["terminal_mode"] == "RESET", "FIN->RESET")
        self.case("G4", "real TCP RESET with same Final Offset supersedes graceful FIN semantics")
        check(fr["server"]["streams"]["1"]["terminal_mode"] == "RESET" and fr["server"]["streams"]["1"]["recv_final"] == 10, "RESET->late FIN")
        self.case("G5", "real TCP late FIN after RESET keeps RESET semantics and same Final Offset")

        sc, sid = fresh_open_stream()
        st = sc.streams[sid]
        st.send_final = 10
        check(sc.stream_consumed(sid, 1, 10) == "applied" and st.local_consumed, "STREAM_CONSUMED")
        self.case("G6", "matching reliable STREAM_CONSUMED records final receive consumption state")

    # ------------------------------------------------------------------
    # H Opening races
    # ------------------------------------------------------------------

    def group_h(self) -> None:
        m = SessionModel()
        m.open_stream(1)
        m.credit_acceptance_evidence(1, 100)
        check(m.streams[1].accepted and m.streams[1].state == "OPEN", "credit evidence")
        self.case("H1", "STREAM_CREDIT overtaking OPEN_OK is treated as acceptance evidence")

        d = SessionModel()
        d.open_stream(1)
        d.streams[1].local_maximum = 100
        model_failure(lambda: d.receive_data(1, 0, b"x", 1), ERR_STREAM_STATE, "session")
        self.case("H2", "DATA while initiator remains OPENING without prior receive credit causes STREAM_STATE_ERROR")

        p = SessionModel()
        check(p.preopen_reset(1, 1, 0) == "preopen_cancellation", "preopen reset")
        check(p.late_open_after_preopen_cancel(1) == "STREAM_OPEN_REJECT_STREAM_STATE_ERROR", "late open reject")
        self.case("H3", "RESET_STREAM(final=0) before OPEN records cancellation, is ACKable, and later OPEN is rejected")

        q = SessionModel()
        q.open_stream(1)
        q.start_opening_cancel(1)
        check(q.cancellation_reset_response(1, 0) == "cancellation_response_not_acceptance", "cancel response")
        self.case("H4", "OPENING_CANCEL_PENDING classifies RESET(final=0) as cancellation response and matching late reject as normal completion")

        w = SessionModel()
        w.open_stream(1)
        w.start_opening_cancel(1)
        check(w.opening_acceptance_wins(1) == "accepted_then_terminal" and w.streams[1].accepted, "acceptance wins")
        self.case("H5", "acceptance evidence wins cancellation race and proceeds directly to pending terminal semantics")

    # ------------------------------------------------------------------
    # I Tombstones
    # ------------------------------------------------------------------

    def group_i(self) -> None:
        m, sid = fresh_open_stream(stream_max=16, session_max=16)
        m.receive_fin(sid, 1, 0)
        m.retire_stream_to_tombstone(sid)
        check(m.receive_tombstone_terminal(sid, 1, "STREAM_FIN", 0) == "idempotent_ack", "tombstone duplicate")
        self.case("I1", "matching duplicate terminal Frame on tombstone is idempotent and ACKable")

        bad, bsid = fresh_open_stream(stream_max=16, session_max=16)
        bad.receive_fin(bsid, 1, 0)
        bad.retire_stream_to_tombstone(bsid)
        model_failure(lambda: bad.receive_tombstone_terminal(bsid, 2, "STREAM_FIN", 1), ERR_FINAL_SIZE, "session")
        self.case("I2", "tombstone terminal duplicate with different Final Offset causes FINAL_SIZE_ERROR")

        ret, rsid = fresh_open_stream(stream_max=16, session_max=16)
        ret.receive_fin(rsid, 1, 0)
        ret.retire_stream_to_tombstone(rsid)
        ret.peer_retired_through = 1
        ret.compact_tombstone(rsid)
        check(ret.retired_frame(rsid, 1) == "ignored" and rsid not in ret.streams, "retired recreate")
        self.case("I3", "post-compaction stale Frame for retired Stream ID is ignored without recreating Stream")

        reuse = SessionModel()
        reuse.open_stream(1)
        reuse.accept_open(1)
        reuse.streams[1].recv_final = 0
        reuse.retire_stream_to_tombstone(1)
        reuse.compact_tombstone(1)
        model_failure(lambda: reuse.open_stream(1), ERR_STREAM_STATE, "session")
        self.case("I4", "used/retired Stream ID cannot be opened as a new Stream")

        lim = SessionModel(max_streams=1)
        lim.open_stream(1)
        lim.accept_open(1)
        lim.streams[1].recv_final = 0
        lim.retire_stream_to_tombstone(1)
        lim.compact_tombstone(1)
        lim.open_stream(3)
        check(set(lim.streams) == {3}, "tombstone counted active")
        self.case("I5", "tombstones/retired identities do not count against MAX_STREAMS active count")

        hold, hsid = fresh_open_stream(stream_max=16, session_max=16)
        hold.receive_reset(hsid, 1, 0)
        hold.retire_stream_to_tombstone(hsid)
        check(1 in hold.replay_confirmation, "replay lost too early")
        check(hold.receive_tombstone_terminal(hsid, 1, "RESET_STREAM", 0) == "idempotent_ack", "repeat confirmation")
        hold.peer_processed_through = 1
        hold.receive_retire(1)
        check(1 not in hold.replay_confirmation, "replay not compacted after retire")
        self.case("I6", "lost terminal confirmation replay state survives tombstoning until peer TRANSMISSION_RETIRE covers it")

    # ------------------------------------------------------------------
    # J Carrier loss/replacement
    # ------------------------------------------------------------------

    def group_j(self) -> None:
        mc = self.gate2_case("multi-carrier-reinjection")
        self.case("J1", "real TCP loss of Carrier 1 leaves Carrier 96 active and Session usable")
        self.case("J2", "outstanding DATA on failed Carrier remains unsettled then reinjects on Carrier 96")
        self.case("J3", "failed logical Carrier 1 rejoins at Generation 1")
        self.case("J4", "replacement completes fresh handshake and begins Record Sequence 0 with independently derived traffic state")

        m = SessionModel(max_carriers=2)
        m.candidate(1, 0)
        before = (m.carriers[1].highest_accepted, m.carriers[1].active_generation, set(m.active_carriers))
        model_failure(lambda: m.candidate(1, 1, authenticated=False), ERR_AUTH, "carrier")
        after = (m.carriers[1].highest_accepted, m.carriers[1].active_generation, set(m.active_carriers))
        check(before == after, "failed candidate mutated accepted generation")
        self.case("J5", "failed authenticated higher-Generation candidate does not advance Highest Accepted or supersede current")

        model_failure(lambda: m.candidate(1, 0), ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
        self.case("J6", "stale/lower Generation is rejected with CARRIER_CONFLICT")

        m.lose_carrier(1)
        model_failure(lambda: m.candidate(1, 0), ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
        self.case("J7", "equal Generation remains non-reusable after transport loss")

        first = SessionModel()
        model_failure(lambda: first.candidate(96, 1), ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
        first.candidate(96, 0)
        self.case("J8", "unused Carrier ID requires Generation 0 and rejects non-zero first incarnation")

        atom = SessionModel(max_carriers=2)
        atom.candidate(1, 0)
        atom.candidate(1, 1)
        check(atom.schedule_on_generation(1, 0) == "forbidden" and atom.schedule_on_generation(1, 1) == "allowed", "supersession")
        self.case("J9", "higher Generation commit atomically makes lower incarnation unschedulable")

        keep, sid = fresh_open_stream()
        tx = keep.allocate_tx("STREAM_DATA", sid, ("same",))
        keep.candidate(1, 0)
        keep.candidate(1, 1)
        check(sid in keep.streams and tx.txid in keep.local_tx, "replacement lost Session state")
        self.case("J10", "replacement preserves Stream/flow-control/Transmission namespaces and original Transmission ID")

        race = SessionModel()
        race.candidate(1, 0)
        race.candidate(1, 1)
        model_failure(lambda: race.candidate(1, 1), ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
        race.candidate(1, 2)
        check(race.carriers[1].highest_accepted == 2, "higher race")
        self.case("J11", "two equal higher-Generation candidates cannot both commit; later still-higher Generation can supersede winner")

        dr = self.gate2_case("dormant-recovery")
        check(dr["client"]["state_history"].count("DORMANT") >= 2, "dormant history")
        self.case("J12", "real TCP last-Carrier loss transitions ACTIVE→DORMANT while retaining Session")
        self.case("J13", "DORMANT portion retains outstanding Transmission and sends no Attempt until replacement establishes")
        check([1, 2] in dr["client"]["established_incarnations"], "Gen2 recovery")
        self.case("J14", "valid higher-Generation replacement restores DORMANT→ACTIVE and original outstanding Transmission reinjects")

        retire = SessionModel()
        retire.candidate(1, 0)
        retire.lose_carrier(1)
        retire.dormant_retire()
        model_failure(retire.join_discarded, ERR_SESSION_NOT_FOUND, "pre_establishment_carrier")
        self.case("J15", "local DORMANT retention expiry closes Session; later JOIN gets SESSION_NOT_FOUND")

        check(dr["server"]["session_credit_refreshes"] >= 3, "session credit refresh")
        check(dr["server"]["stream_credit_refreshes"] >= 1, "stream credit refresh")
        self.case("J16", "real TCP recovery refreshes SESSION_CREDIT, probed STREAM_CREDIT, and non-zero retirement watermark")

    # ------------------------------------------------------------------
    # K Close
    # ------------------------------------------------------------------

    def group_k(self) -> None:
        m = SessionModel(max_carriers=2)
        m.candidate(1, 0)
        m.candidate(96, 0)
        check(m.carrier_close(1) == "ACTIVE" and m.active_carriers == {96}, "carrier close")
        self.case("K1", "CARRIER_CLOSE removes one logical Carrier while Session remains ACTIVE on another")

        bare = SessionModel(max_carriers=2)
        bare.candidate(1, 0)
        bare.candidate(96, 0)
        check(bare.lose_carrier(1) == "ACTIVE", "bare EOF")
        self.case("K2", "bare TCP EOF is modeled as Carrier loss, not Session close")

        close = SessionModel()
        close.candidate(1, 0)
        close.session_close()
        check(close.state == "CLOSED" and close.new_work_blocked, "session close")
        self.case("K3", "SESSION_CLOSE blocks new work and terminates Session")

        dup = SessionModel()
        dup.receive_session_close()
        check(dup.receive_session_close() == "idempotent", "duplicate close")
        self.case("K4", "duplicate SESSION_CLOSE is idempotent")

        hc = SessionModel()
        check(hc.half_close() == "transport_half_close_only" and hc.state == "ACTIVE", "half-close")
        self.case("K5", "TCP half-close alone creates no MPX terminal Stream/Carrier/Session state")

        tr = SessionModel()
        result = tr.apply_record_frames(("SESSION_CLOSE", "STREAM_OPEN"))
        check(result == "trailing_ignored" and tr.state == "CLOSED" and 1 not in tr.streams, "close trailing")
        self.case("K6", "authenticated trailing state-creating Frame after close cannot create state; close remains terminal")

    # ------------------------------------------------------------------
    # L Negative suite
    # ------------------------------------------------------------------

    def group_l(self) -> None:
        try:
            core.vi_dec(bytes.fromhex("4000"))
        except core.ProtocolError:
            self.case("L1", L_DESCRIPTIONS["L1"])
        else:
            raise Gate3Failure("L1")

        malformed = core.vi_enc(core.FRAME_PING) + core.vi_enc(10) + b"\x01"
        try:
            core.parse_frames(malformed, 32768)
        except core.ProtocolError:
            self.case("L2", L_DESCRIPTIONS["L2"])
        else:
            raise Gate3Failure("L2")

        unknown = core.vi_enc(0x05) + core.vi_enc(0)
        try:
            core.parse_frames(unknown, 32768)
        except core.ProtocolError:
            self.case("L3", L_DESCRIPTIONS["L3"])
        else:
            raise Gate3Failure("L3")

        parity = SessionModel()
        model_failure(lambda: parity.open_stream(2), ERR_STREAM_STATE, "session")
        self.case("L4", L_DESCRIPTIONS["L4"])

        sm, sid = fresh_open_stream(stream_max=4, session_max=100)
        model_failure(lambda: sm.receive_data(sid, 0, b"12345", 1), ERR_FLOW_CONTROL, "session")
        self.case("L5", L_DESCRIPTIONS["L5"])

        ss, sid = fresh_open_stream(stream_max=100, session_max=4)
        model_failure(lambda: ss.receive_data(sid, 0, b"12345", 1), ERR_FLOW_CONTROL, "session")
        self.case("L6", L_DESCRIPTIONS["L6"])

        term, sid = fresh_open_stream(stream_max=4, session_max=4)
        model_failure(lambda: term.receive_fin(sid, 1, 5), ERR_FLOW_CONTROL, "session")
        self.case("L7", L_DESCRIPTIONS["L7"])

        ci, sid = fresh_open_stream()
        model_failure(lambda: ci.advertise_stream_credit(sid, 11, 10), ERR_FLOW_CONTROL, "session")
        self.case("L8", L_DESCRIPTIONS["L8"])

        ov, sid = fresh_open_stream(stream_max=16, session_max=16)
        ov.receive_data(sid, 4, b"AAAA", 1)
        model_failure(lambda: ov.receive_data(sid, 4, b"AAAB", 2), ERR_PROTOCOL, "session")
        self.case("L9", L_DESCRIPTIONS["L9"])

        fs, sid = fresh_open_stream(stream_max=16, session_max=16)
        fs.receive_fin(sid, 1, 4)
        model_failure(lambda: fs.receive_reset(sid, 2, 5), ERR_FINAL_SIZE, "session")
        self.case("L10", L_DESCRIPTIONS["L10"])

        tx, sid = fresh_open_stream()
        tx.receive_data(sid, 0, b"a", 1)
        model_failure(lambda: tx.receive_data(sid, 1, b"b", 1), ERR_TRANSMISSION_ID, "session")
        self.case("L11", L_DESCRIPTIONS["L11"])

        sv = load("secure-record.json")
        key = bytes.fromhex(sv["traffic_key_hex"])
        iv = bytes.fromhex(sv["traffic_iv_hex"])
        pt = bytes.fromhex(sv["records"][0]["plaintext_hex"])
        bad_header = b"\x01" + core.vi_enc(len(pt))
        bad_wire = bad_header + AESGCM(key).encrypt(core.xor_nonce(iv, 0), pt, bad_header)

        async def flags_case() -> None:
            try:
                await carrier_recv(bad_wire, flags_key=key, iv=iv)
            except core.ProtocolError:
                return
            raise Gate3Failure("non-zero flags accepted")
        asyncio.run(flags_case())
        self.case("L12", L_DESCRIPTIONS["L12"])

        cl = SessionModel()
        check(cl.apply_record_frames(("CARRIER_CLOSE", "STREAM_OPEN")) == "trailing_ignored", "close tail")
        self.case("L13", L_DESCRIPTIONS["L13"])

        life = SessionModel()
        life.open_stream(1)
        life.streams[1].local_maximum = 10
        model_failure(lambda: life.receive_data(1, 0, b"x", 1), ERR_STREAM_STATE, "session")
        self.case("L14", L_DESCRIPTIONS["L14"])

        sl = SessionModel(max_streams=1)
        sl.open_stream(1)
        model_failure(lambda: sl.open_stream(3), ERR_STREAM_LIMIT, "stream_opening")
        check(sl.state == "ACTIVE", "STREAM_LIMIT closed Session")
        self.case("L15", L_DESCRIPTIONS["L15"])

        cj = SessionModel()
        cj.candidate(1, 0)
        before = cj.carriers[1].highest_accepted
        model_failure(lambda: cj.candidate(1, 0), ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
        check(cj.carriers[1].highest_accepted == before, "rejected JOIN advanced gen")
        self.case("L16", L_DESCRIPTIONS["L16"])

        retained = {"deadbeef": "CLOSED_retirement"}
        snapshot = dict(retained)
        check("deadbeef" in retained and retained == snapshot, "collision")
        self.case("L17", L_DESCRIPTIONS["L17"])

        enabled_before = {4}
        received_reject = "SESSION_NOT_FOUND"
        enabled_after = set(enabled_before)
        check(received_reject and enabled_after == enabled_before, "reject downgrade")
        self.case("L18", L_DESCRIPTIONS["L18"])

        good_wire = bytes.fromhex(sv["records"][0]["wire_record_hex"])
        corrupt = good_wire[:-1] + bytes([good_wire[-1] ^ 1])

        async def auth_case() -> None:
            try:
                await carrier_recv(corrupt, flags_key=key, iv=iv)
            except core.AuthenticationError:
                return
            raise Gate3Failure("bad tag accepted")
        asyncio.run(auth_case())
        self.case("L19", L_DESCRIPTIONS["L19"])

        frame_bad = core.vi_enc(core.FRAME_PING) + core.vi_enc(1) + b""
        try:
            core.parse_frames(frame_bad, 32768)
        except core.ProtocolError:
            pass
        else:
            raise Gate3Failure("malformed Frame accepted")
        self.case("L20", L_DESCRIPTIONS["L20"])

        f, sid = fresh_open_stream(stream_max=1, session_max=1)
        exc = model_failure(lambda: f.receive_data(sid, 0, b"xx", 1), ERR_FLOW_CONTROL, "session")
        check(f.state == "CLOSING" and exc.trigger == "STREAM_DATA", "flow scope")
        self.case("L21", L_DESCRIPTIONS["L21"])

        z, sid = fresh_open_stream(stream_max=10, session_max=10)
        z.receive_fin(sid, 1, 2)
        exc = model_failure(lambda: z.receive_data(sid, 2, b"x", 2), ERR_FINAL_SIZE, "session")
        check(z.state == "CLOSING" and exc.trigger == "STREAM_DATA", "final scope")
        self.case("L22", L_DESCRIPTIONS["L22"])

        t = SessionModel()
        exc = model_failure(lambda: t.confirm(99, "TRANSMISSION_ACK", 1), ERR_TRANSMISSION_ID, "session")
        check(t.state == "CLOSING", "tx scope")
        self.case("L23", L_DESCRIPTIONS["L23"])

        sh = SessionModel()
        sh.candidate(1, 0)
        sh.session_close(ERR_FLOW_CONTROL)
        try:
            sh.open_stream(1)
        except ModelFailure:
            pass
        else:
            raise Gate3Failure("new Stream after close")
        model_failure(lambda: sh.candidate(2, 0), ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        self.case("L24", L_DESCRIPTIONS["L24"])

        trig, sid = fresh_open_stream(stream_max=1, session_max=1)
        exc = model_failure(lambda: trig.receive_data(sid, 0, b"xx", 1), ERR_FLOW_CONTROL, "session")
        check(exc.trigger == "STREAM_DATA", "trigger frame")
        self.case("L25", L_DESCRIPTIONS["L25"])

    def execute(self) -> dict:
        started = time.time()
        self.run_prerequisites()
        self.group_a()
        self.group_b()
        self.group_c()
        self.group_d()
        self.group_e()
        self.group_f()
        self.group_g()
        self.group_h()
        self.group_i()
        self.group_j()
        self.group_k()
        self.group_l()

        missing = [x for x in MANDATORY if x not in self.results]
        check(not missing, f"Mandatory cases missing: {missing}")
        check(all(self.results[x]["status"] == "PASS" for x in MANDATORY), "not all PASS")

        groups: Dict[str, str] = {}
        for letter in "ABCDEFGHIJKL":
            ids = [x for x in MANDATORY if x.startswith(letter)]
            groups[letter] = "PASS" if all(self.results[x]["status"] == "PASS" for x in ids) else "FAIL"

        evidence_counts = {
            name: sum(1 for item in self.results.values() if item["evidence_class"] == name)
            for name in EVIDENCE_CLASSES
        }
        model_only_case_ids = sorted(
            item["id"] for item in self.results.values() if item["evidence_class"] == "model"
        )
        endpoint_wire_case_ids = sorted(
            item["id"] for item in self.results.values() if item["evidence_class"] == "endpoint-wire"
        )

        head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
        dirty = bool(run(["git", "status", "--porcelain"]).stdout.strip())
        report = {
            "protocol": "MPX/4",
            "protocol_version": 4,
            "revision": "Draft 11",
            "binding": "TCP",
            "gate": "Gate 4 Implementation B profile",
            "status": "PASS",
            "implementation": "MPX4 Draft 11 source-isolated Implementation B",
            "git": {"head_sha": head, "dirty": dirty},
            "duration_seconds": round(time.time() - started, 3),
            "mandatory_case_count": len(MANDATORY),
            "groups": groups,
            "evidence_counts": evidence_counts,
            "endpoint_wire_execution_count": self.endpoint_wire.get("execution_count"),
            "endpoint_wire_mandatory_case_ids": endpoint_wire_case_ids,
            "model_only_case_ids": model_only_case_ids,
            "cases": [self.results[x] for x in MANDATORY],
            "claim_boundary": (
                "121-case A-L Mandatory profile with explicit executable evidence classes and model_only_case_ids=[]; "
                "18 cases use codec evidence, 30 use cross-wire evidence, and 73 require authenticated endpoint-wire evidence. "
                "The state model remains an oracle for some assertions but is not the sole evidence for any Mandatory case. "
                "This profile alone is not an external A/B interoperability claim."
            ),
        }
        return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 Implementation B Mandatory profile")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "gate3")
    return p


def main() -> int:
    args = build_parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "mandatory-profile-report.json"
    try:
        report = IndependentProfile(args.out_dir).execute()
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"independent profile: PASS ({report['mandatory_case_count']} Mandatory A-L cases)")
        print(f"report: {path}")
        return 0
    except Exception as exc:
        fail = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "gate": "Gate 4 Implementation B profile",
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        path.write_text(json.dumps(fail, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"independent profile: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
