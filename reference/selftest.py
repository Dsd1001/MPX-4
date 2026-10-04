#!/usr/bin/env python3
"""Anchor the executable reference core to the repository's canonical Draft 11 vectors.

This is not an independent implementation. It prevents the reference-to-reference
runtime from drifting away from the published wire/crypto fixtures.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from reference.mpx4_core import (
    MSG_CLIENT_FINISHED,
    MSG_SERVER_FINISHED,
    derive_traffic,
    encode_client_init,
    encode_server_init,
    parse_client_init,
    parse_frames,
    parse_server_init,
    validate_finished,
    vi_dec,
    xor_nonce,
)


ROOT = Path(__file__).resolve().parents[1]


def check(condition: bool, detail: object) -> None:
    if not condition:
        raise RuntimeError(str(detail))


def main() -> int:
    ks = json.loads((ROOT / "test-vectors/key-schedule.json").read_text(encoding="utf-8"))
    sr = json.loads((ROOT / "test-vectors/secure-record.json").read_text(encoding="utf-8"))

    transport_key = bytes.fromhex(ks["inputs"]["transport_key_hex"])
    preface = bytes.fromhex(ks["inputs"]["connection_preface_hex"])
    client_init = bytes.fromhex(ks["inputs"]["client_init_hex"])
    server_init = bytes.fromhex(ks["inputs"]["server_init_hex"])

    parsed_client = parse_client_init(client_init)
    server_nonce, parsed_server_limits = parse_server_init(server_init)

    rebuilt_client = encode_client_init(
        session_id=parsed_client.session_id,
        carrier_id=parsed_client.carrier_id,
        generation=parsed_client.generation,
        client_nonce=parsed_client.client_nonce,
        limits=parsed_client.client_limits,
        session_action=parsed_client.session_action,
    )
    rebuilt_server = encode_server_init(server_nonce, parsed_server_limits)
    check(rebuilt_client == client_init, "reference CLIENT_INIT codec differs from canonical vector")
    check(rebuilt_server == server_init, "reference SERVER_INIT codec differs from canonical vector")

    client_finished, server_finished, h0, traffic = derive_traffic(
        transport_key,
        preface,
        client_init,
        server_init,
    )
    derived = ks["derived"]
    check(h0.hex() == derived["h0_hex"], "H0 mismatch")
    check(client_finished.hex() == derived["client_finished_hex"], "CLIENT_FINISHED mismatch")
    check(server_finished.hex() == derived["server_finished_hex"], "SERVER_FINISHED mismatch")
    check(traffic.client_finished_key.hex() == derived["client_finished_key_hex"], "client Finished key mismatch")
    check(traffic.server_finished_key.hex() == derived["server_finished_key_hex"], "server Finished key mismatch")
    check(traffic.client_key.hex() == derived["client_traffic_key_hex"], "client traffic key mismatch")
    check(traffic.client_iv.hex() == derived["client_traffic_iv_hex"], "client traffic IV mismatch")
    check(traffic.server_key.hex() == derived["server_traffic_key_hex"], "server traffic key mismatch")
    check(traffic.server_iv.hex() == derived["server_traffic_iv_hex"], "server traffic IV mismatch")

    h1 = hashlib.sha256(preface + client_init + server_init + client_finished).digest()
    validate_finished(client_finished, MSG_CLIENT_FINISHED, traffic.client_finished_key, h0)
    validate_finished(server_finished, MSG_SERVER_FINISHED, traffic.server_finished_key, h1)

    direction = sr["direction"]
    if direction == "client_to_server":
        key, iv = traffic.client_key, traffic.client_iv
        peer_frame_limit = parsed_server_limits.max_frame_payload
    elif direction == "server_to_client":
        key, iv = traffic.server_key, traffic.server_iv
        peer_frame_limit = parsed_client.client_limits.max_frame_payload
    else:
        raise RuntimeError(f"unsupported secure-record vector direction: {direction}")

    check(sr["traffic_key_hex"] == key.hex(), "secure-record vector key differs from reference")
    check(sr["traffic_iv_hex"] == iv.hex(), "secure-record vector IV differs from reference")

    record_count = 0
    frame_count = 0
    for rec in sr["records"]:
        seq = int(rec["sequence_number"])
        wire = bytes.fromhex(rec["wire_record_hex"])
        check(wire[:1] == b"\x00", "non-zero vector Record Flags")
        ciphertext_length, header_end = vi_dec(wire, 1)
        check(header_end + ciphertext_length + 16 == len(wire), "secure-record vector length mismatch")
        nonce = xor_nonce(iv, seq)
        plaintext = AESGCM(key).decrypt(
            nonce,
            wire[header_end : header_end + ciphertext_length] + wire[-16:],
            wire[:header_end],
        )
        check(plaintext.hex() == rec["plaintext_hex"], "secure-record plaintext mismatch")
        frames = parse_frames(plaintext, peer_frame_limit)
        check(frames, "secure-record vector contains no Frame")
        record_count += 1
        frame_count += len(frames)

    print(
        "reference selftest: PASS "
        f"(canonical handshake/Finished/traffic keys, {record_count} Secure Records, {frame_count} Frames)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
