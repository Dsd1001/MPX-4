#!/usr/bin/env python3
"""Canonical-vector self-test for source-isolated Implementation B."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import core

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    return json.loads((ROOT / "test-vectors" / name).read_text(encoding="utf-8"))


def check(cond: bool, message: object) -> None:
    if not cond:
        raise RuntimeError(str(message))


def fields(raw: dict) -> dict:
    out = {}
    for k, v in raw.items():
        if k == "data_utf8":
            out["data"] = v.encode()
        elif k == "reason_utf8":
            out["reason"] = v
        elif k == "padding_hex":
            out["padding"] = bytes.fromhex(v)
        else:
            out[k] = int(v, 0) if isinstance(v, str) else v
    return out


def main() -> int:
    varints = load("varint.json")
    for item in varints["vectors"]:
        n = int(item["value"])
        raw = core.vi_enc(n)
        check(raw.hex() == item["hex"], item)
        got, end = core.vi_dec(raw)
        check((got, end) == (n, len(raw)), item)
    for item in varints["invalid"]:
        try:
            core.vi_dec(bytes.fromhex(item["hex"]))
        except core.ProtocolError:
            pass
        else:
            raise RuntimeError(f"invalid VarInt accepted: {item}")

    frames = load("frame-encoding.json")
    for item in frames["vectors"]:
        ft = core.FRAME_TYPES[item["frame_type"]]
        f = fields(item["fields"])
        body = core.frame_body(ft, **f)
        wire = core.encode_frame(ft, body)
        check(wire.hex() == item["hex"], item["name"])
        parsed = core.parse_frames(wire, 32768)
        check(len(parsed) == 1 and parsed[0][0] == ft, item["name"])

    kv = load("key-schedule.json")
    inp = kv["inputs"]
    d = kv["derived"]
    cf, sf, h0, sec = core.derive_traffic(
        bytes.fromhex(inp["transport_key_hex"]),
        bytes.fromhex(inp["connection_preface_hex"]),
        bytes.fromhex(inp["client_init_hex"]),
        bytes.fromhex(inp["server_init_hex"]),
    )
    check(h0.hex() == d["h0_hex"], "H0")
    check(cf.hex() == d["client_finished_hex"], "client Finished")
    check(sf.hex() == d["server_finished_hex"], "server Finished")
    check(sec.client_key.hex() == d["client_traffic_key_hex"], "client traffic key")
    check(sec.client_iv.hex() == d["client_traffic_iv_hex"], "client traffic IV")
    check(sec.server_key.hex() == d["server_traffic_key_hex"], "server traffic key")
    check(sec.server_iv.hex() == d["server_traffic_iv_hex"], "server traffic IV")
    h1 = hashlib.sha256(
        bytes.fromhex(inp["connection_preface_hex"])
        + bytes.fromhex(inp["client_init_hex"])
        + bytes.fromhex(inp["server_init_hex"])
        + cf
    ).digest()
    core.validate_finished(cf, core.MSG_CLIENT_FINISHED, sec.client_finished_key, h0)
    core.validate_finished(sf, core.MSG_SERVER_FINISHED, sec.server_finished_key, h1)

    records = load("secure-record.json")
    key = bytes.fromhex(records["traffic_key_hex"])
    iv = bytes.fromhex(records["traffic_iv_hex"])
    for item in records["records"]:
        seq = int(item["sequence_number"])
        pt = bytes.fromhex(item["plaintext_hex"])
        aad = bytes.fromhex(item["aad_hex"])
        wire = aad + AESGCM(key).encrypt(core.xor_nonce(iv, seq), pt, aad)
        check(wire.hex() == item["wire_record_hex"], f"Secure Record {seq}")
        check(AESGCM(key).decrypt(core.xor_nonce(iv, seq), wire[len(aad):], aad) == pt, f"decrypt {seq}")

    print(
        "independent selftest: PASS "
        f"({len(varints['vectors'])} VarInts, {len(frames['vectors'])} Frames, "
        f"canonical handshake/keys, {len(records['records'])} Secure Records)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
