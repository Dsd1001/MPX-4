#!/usr/bin/env python3
"""Replay-resistant implementation probes for the MPX/4 Draft 11 review v2.

These cases turn the externally supplied review-v2 counterexamples into
repository-owned regression tests.  Every case executes against both source-
isolated runtimes over real loopback TCP unless the defect is specifically an
ordered-output cancellation invariant inside a live Carrier.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .endpoint_wire import Fixture, NullTrace, Peer, ProbeError, check, wait_until

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")

ERROR_RESOURCE_LIMIT = 0x05
ERROR_SESSION_CONFLICT = 0x07
ERROR_CARRIER_CONFLICT = 0x0C


@dataclass
class PendingCandidate:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    preface: bytes
    client_init: bytes
    server_init: bytes
    carrier_id: int
    generation: int
    session_id: bytes


def pending_count(session) -> int:
    pending = session.pending_candidates
    if isinstance(pending, dict):
        return sum(int(x) for x in pending.values())
    return len(pending)


async def start_candidate(
    f: Fixture,
    carrier_id: int,
    generation: int,
    *,
    action: int = 1,
    session_id: Optional[bytes] = None,
) -> PendingCandidate:
    core = f.core
    assert f.port is not None
    reader, writer = await asyncio.open_connection("127.0.0.1", f.port)
    preface = core.MAGIC + core.vi_enc(core.VERSION)
    sid = f.session_id if session_id is None else session_id
    client_init = core.encode_client_init(
        sid,
        carrier_id,
        generation,
        secrets.token_bytes(32),
        f.limits,
        action,
    )
    writer.write(preface + client_init)
    await writer.drain()
    msg, _, server_init = await asyncio.wait_for(core.read_message(reader), timeout=2)
    check(msg == core.MSG_SERVER_INIT, ("expected SERVER_INIT", msg))
    return PendingCandidate(
        reader,
        writer,
        preface,
        client_init,
        server_init,
        carrier_id,
        generation,
        sid,
    )


async def finish_candidate(f: Fixture, candidate: PendingCandidate) -> Dict[str, object]:
    core = f.core
    cf, expected_sf, _, prelim = core.derive_traffic(
        f.key,
        candidate.preface,
        candidate.client_init,
        candidate.server_init,
    )
    candidate.writer.write(cf)
    await candidate.writer.drain()
    msg, body, raw = await asyncio.wait_for(core.read_message(candidate.reader), timeout=2)
    if msg == core.MSG_HANDSHAKE_REJECT:
        code, pos = core.vi_dec(body)
        check(pos == len(body), "HANDSHAKE_REJECT trailing bytes")
        candidate.writer.close()
        return {"status": "rejected", "error_code": code}
    check(msg == core.MSG_SERVER_FINISHED, ("expected SERVER_FINISHED", msg))
    check(raw == expected_sf, "SERVER_FINISHED canonical mismatch")
    h1 = hashlib.sha256(
        candidate.preface
        + candidate.client_init
        + candidate.server_init
        + cf
    ).digest()
    core.validate_finished(raw, core.MSG_SERVER_FINISHED, prelim.server_finished_key, h1)
    _, server_limits = core.parse_server_init(candidate.server_init)
    _, _, _, traffic = core.derive_traffic(
        f.key,
        candidate.preface,
        candidate.client_init,
        candidate.server_init,
        client_finished=cf,
        server_finished=raw,
    )
    peer = Peer(
        core,
        core.Carrier(
            "client",
            candidate.reader,
            candidate.writer,
            NullTrace(),
            f.limits,
            server_limits,
            traffic.client_key,
            traffic.client_iv,
            traffic.server_key,
            traffic.server_iv,
            candidate.session_id,
            candidate.carrier_id,
            candidate.generation,
            0,
        ),
        [],
    )
    await wait_until(
        lambda: (
            candidate.carrier_id in f.session.carriers
            and f.session.carriers[candidate.carrier_id].generation
            == candidate.generation
        ),
        label="candidate activation",
    )
    await peer.recv_until(core.FRAME_SESSION_CREDIT)
    return {"status": "established", "peer": peer}


async def raw_record(peer: Peer):
    carrier = peer.carrier
    core = peer.core
    flags = await asyncio.wait_for(carrier.reader.readexactly(1), timeout=2)
    length, encoded = await core.read_varint(carrier.reader)
    sealed = await asyncio.wait_for(carrier.reader.readexactly(length + 16), timeout=2)
    return flags + encoded, sealed


async def case_cancelled_record_abandons_carrier(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        carrier = f.session.carriers[1]
        core = f.core

        before = carrier.send_seq
        await f.session.send_frame(carrier, core.FRAME_PING, token=7)
        ping = await peer.recv_until(core.FRAME_PING)
        check(int(ping["token"]) == 7 and carrier.send_seq == before + 1, ping)

        seq = carrier.send_seq
        original_drain = carrier.writer.drain
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked_drain():
            entered.set()
            await release.wait()
            await original_drain()

        carrier.writer.drain = blocked_drain
        task = asyncio.create_task(
            f.session.send_frame(carrier, core.FRAME_PING, token=11)
        )
        await asyncio.wait_for(entered.wait(), timeout=2)
        header, sealed = await raw_record(peer)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            release.set()
            carrier.writer.drain = original_drain

        check(carrier.send_seq == seq + 1, (seq, carrier.send_seq))
        check(not carrier.output_usable, "cancelled post-commit Carrier remained writable")
        plaintext = AESGCM(carrier.send_key).decrypt(
            core.xor_nonce(carrier.send_iv, seq),
            sealed,
            header,
        )
        frames = core.parse_frames(plaintext, 32768)
        check(frames[0][0] == core.FRAME_PING and int(frames[0][1]["token"]) == 11, frames)

        await wait_until(
            lambda: 1 not in f.session.active_logical_ids,
            label="cancelled output Carrier abandonment",
        )
        rejected = False
        try:
            await carrier.send_frame(core.FRAME_PING, token=12)
        except Exception:
            rejected = True
        check(rejected, "abandoned Carrier accepted another Secure Record")
        return {
            "sequence_before_cancelled_record": seq,
            "sequence_after_cancel": carrier.send_seq,
            "record_committed_before_cancel": True,
            "carrier_abandoned": True,
            "nonce_reuse_possible": False,
        }


async def case_unauthenticated_generation_does_not_reserve(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=1) as f:
        old = await f.establish()
        core = f.core
        attacker = await start_candidate(f, 1, core.MAX_VARINT - 1)
        check(pending_count(f.session) >= 1, f.session.pending_candidates)

        valid = await start_candidate(f, 1, 1)
        result = await finish_candidate(f, valid)
        check(result["status"] == "established", result)
        replacement = result["peer"]
        f.peers[1] = replacement
        check(f.session.highest_accepted[1] == 1, f.session.highest_accepted)
        await f.ping(replacement, 0xA401)

        attacker.writer.close()
        await attacker.writer.wait_closed()
        await wait_until(
            lambda: pending_count(f.session) == 0,
            label="stalled candidate release",
        )
        return {
            "attacker_authenticated": False,
            "valid_lower_generation_committed": 1,
            "highest_accepted": f.session.highest_accepted[1],
            "old_transport_superseded": old.carrier.writer.is_closing(),
        }


async def case_new_data_after_reset_rejected(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        core = f.core
        stream = await f.open_stream(peer)
        await peer.carrier.send_frame(
            core.FRAME_SESSION_CREDIT,
            consumed_bytes=0,
            maximum_bytes=4096,
        )
        await peer.carrier.send_frame(
            core.FRAME_STREAM_CREDIT,
            stream_id=1,
            consumed_offset=0,
            maximum_offset=4096,
        )
        await wait_until(
            lambda: (
                stream.peer_maximum
                if implementation == "reference"
                else stream.peer_credit.maximum
            )
            == 4096,
            label="sender credit",
        )
        tx = await f.session.send_data(stream, b"A", f.session.carriers[1])
        first = await peer.recv_until(core.FRAME_STREAM_DATA)
        check(int(first["offset"]) == 0 and bytes(first["data"]) == b"A", first)
        await peer.carrier.send_frame(
            core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx.txid,
            receiver_timestamp_us=0,
        )
        stop = f.next_peer_tx(1)
        await peer.carrier.send_frame(
            core.FRAME_STOP_SENDING,
            stream_id=1,
            transmission_id=stop,
            stream_error_code=5,
        )
        await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
        reset = await peer.recv_until(core.FRAME_RESET_STREAM)
        await peer.carrier.send_frame(
            core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(reset["transmission_id"]),
            receiver_timestamp_us=0,
        )
        await wait_until(
            lambda: stream.send_terminal_mode == "RESET",
            label="local RESET terminal",
        )
        before_txid = f.session.next_txid
        observed = None
        try:
            await f.session.send_data(stream, b"B", f.session.carriers[1])
        except Exception as exc:
            observed = type(exc).__name__
        check(observed == "StreamStateError", observed)
        check(f.session.next_txid == before_txid, (before_txid, f.session.next_txid))
        await peer.expect_no(core.FRAME_STREAM_DATA, timeout=0.15)
        return {
            "terminal_mode": stream.send_terminal_mode,
            "final_offset": stream.send_final,
            "exception": observed,
            "new_transmission_allocated": False,
        }


async def case_concurrent_join_limit_commit_recheck(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=2) as f:
        await f.establish()
        a = await start_candidate(f, 96, 0)
        b = await start_candidate(f, 98, 0)
        ra = await finish_candidate(f, a)
        check(ra["status"] == "established", ra)
        f.peers[96] = ra["peer"]
        rb = await finish_candidate(f, b)
        check(
            rb == {"status": "rejected", "error_code": ERROR_RESOURCE_LIMIT},
            rb,
        )
        check(len(f.session.active_logical_ids) == 2, f.session.active_logical_ids)
        check(set(f.session.active_logical_ids) == {1, 96}, f.session.active_logical_ids)
        return {
            "effective_limit": f.session.effective_carrier_limit,
            "active_ids": sorted(f.session.active_logical_ids),
            "late_candidate_reject": rb["error_code"],
        }


async def case_generation_commit_recheck(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        old = await f.establish()
        f.peers[1001] = old
        low = await start_candidate(f, 1, 1)
        high = await start_candidate(f, 1, 2)
        high_result = await finish_candidate(f, high)
        check(high_result["status"] == "established", high_result)
        f.peers[1] = high_result["peer"]
        check(f.session.highest_accepted[1] == 2, f.session.highest_accepted)

        low_result = await finish_candidate(f, low)
        check(
            low_result == {"status": "rejected", "error_code": ERROR_CARRIER_CONFLICT},
            low_result,
        )
        check(f.session.highest_accepted[1] == 2, f.session.highest_accepted)
        check(f.session.carriers[1].generation == 2, f.session.carriers[1].generation)
        await f.ping(high_result["peer"], 0xA402)
        return {
            "highest_after_high": 2,
            "late_lower_reject": low_result["error_code"],
            "highest_final": f.session.highest_accepted[1],
        }


async def case_pending_join_cannot_reopen_closed_session(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        pending = await start_candidate(f, 96, 0)
        await peer.carrier.send_frame(
            f.core.FRAME_SESSION_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="review-v2-close",
        )
        await wait_until(lambda: f.session.state == "CLOSED", label="Session CLOSED")
        result = await finish_candidate(f, pending)
        check(
            result == {"status": "rejected", "error_code": ERROR_SESSION_CONFLICT},
            result,
        )
        check(f.session.state == "CLOSED", f.session.state)
        check(not f.session.active_logical_ids, f.session.active_logical_ids)
        return {
            "late_join_reject": result["error_code"],
            "state": f.session.state,
            "reopened": False,
        }


async def case_concurrent_create_session_isolation(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        sid2 = secrets.token_bytes(16)
        while sid2 == f.session_id:
            sid2 = secrets.token_bytes(16)
        a = await start_candidate(f, 1, 0, action=0, session_id=f.session_id)
        b = await start_candidate(f, 2, 0, action=0, session_id=sid2)
        ra = await finish_candidate(f, a)
        check(ra["status"] == "established", ra)
        peer = ra["peer"]
        f.peers[1] = peer
        stream = await f.open_stream(peer)
        rb = await finish_candidate(f, b)
        check(
            rb == {"status": "rejected", "error_code": ERROR_SESSION_CONFLICT},
            rb,
        )
        check(f.session.session_id == f.session_id, f.session.session_id)
        check(f.session.carriers[1].session_id == f.session_id, f.session.carriers[1].session_id)
        check(f.session.streams[1] is stream, f.session.streams)
        await f.ping(peer, 0xA403)
        return {
            "accepted_session_id": f.session.session_id.hex(),
            "second_create_reject": rb["error_code"],
            "state_preserved": True,
        }


async def case_superseded_record_cannot_mutate_state(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        f.peers[1001] = peer
        stream = await f.open_stream(peer)
        old_endpoint = f.session.carriers[1]
        old_task = f.session.carrier_tasks[(1, 0)]
        old_task.cancel()
        await asyncio.gather(old_task, return_exceptions=True)

        original_recv = old_endpoint.recv_record
        entered = asyncio.Event()
        release = asyncio.Event()

        async def gated_recv_record():
            entered.set()
            await release.wait()
            return await original_recv()

        old_endpoint.recv_record = gated_recv_record
        replacement_task = asyncio.create_task(f.session.receive_loop(old_endpoint))
        f.session.carrier_tasks[(1, 0)] = replacement_task
        await asyncio.wait_for(entered.wait(), timeout=2)

        txid = f.next_peer_tx(1)
        await peer.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            transmission_id=txid,
            offset=0,
            data=b"superseded",
        )

        replacement = await start_candidate(f, 1, 1)
        result = await finish_candidate(f, replacement)
        check(result["status"] == "established", result)
        f.peers[1] = result["peer"]
        commit_seq = next(
            e["event_seq"]
            for e in f.trace.events
            if e.get("event") == "candidate_committed" and e.get("generation") == 1
        )
        release.set()
        await asyncio.sleep(0.05)
        check(bytes(stream.recv_data) == b"", stream.recv_data)
        check(f.session.highest_accepted[1] == 1, f.session.highest_accepted)
        late_records = [
            e for e in f.trace.events
            if e.get("event") == "record_recv"
            and e.get("carrier_id") == 1
            and e.get("generation") == 0
            and e.get("event_seq", 0) > commit_seq
        ]
        discard_events = [
            e for e in f.trace.events
            if e.get("event") in {"superseded_record_discarded", "stale_incarnation_record_discarded"}
        ]
        check(late_records or discard_events or old_endpoint.writer.is_closing(), f.trace.events[-20:])
        return {
            "generation_commit_event": commit_seq,
            "old_application_bytes_after_commit": len(stream.recv_data),
            "late_old_record_authenticated": bool(late_records),
            "explicit_discard_event": bool(discard_events),
        }


async def case_incomplete_candidate_deadline(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=1) as f:
        peer = await f.establish()
        runtime = f.runtime
        original_timeout = runtime.CANDIDATE_HANDSHAKE_TIMEOUT
        runtime.CANDIDATE_HANDSHAKE_TIMEOUT = 0.10
        try:
            pending = await start_candidate(f, 1, f.core.MAX_VARINT - 2)
            check(pending_count(f.session) >= 1, f.session.pending_candidates)
            await wait_until(
                lambda: pending_count(f.session) == 0,
                timeout=1.0,
                label="candidate handshake deadline release",
            )
            eof = await asyncio.wait_for(pending.reader.read(1), timeout=1.0)
            check(eof == b"", eof)
            check(f.session.highest_accepted[1] == 0, f.session.highest_accepted)
            check(f.session.state == "ACTIVE", f.session.state)
            await f.ping(peer, 0xA405)
            return {
                "configured_test_deadline_seconds": 0.10,
                "pending_released": True,
                "transport_closed": True,
                "session_preserved": True,
            }
        finally:
            runtime.CANDIDATE_HANDSHAKE_TIMEOUT = original_timeout


async def case_settlement_automatically_advertises_retire(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        await f.open_stream(peer)
        core = f.core
        stop = f.next_peer_tx(1)
        await peer.carrier.send_frame(
            core.FRAME_STOP_SENDING,
            stream_id=1,
            transmission_id=stop,
            stream_error_code=23,
        )
        await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
        reset = await peer.recv_until(core.FRAME_RESET_STREAM)
        await peer.carrier.send_frame(
            core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(reset["transmission_id"]),
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: f.session.settled_through >= 1, label="settled prefix")
        retired = await peer.recv_until(core.FRAME_TRANSMISSION_RETIRE, timeout=2)
        check(
            int(retired["retired_through"]) >= 1,
            retired,
        )
        await wait_until(
            lambda: f.session.last_retire_advertised >= 1,
            label="retire advertisement state",
        )
        await f.ping(peer, 0xA404)
        return {
            "settled_through": f.session.settled_through,
            "retired_through": retired["retired_through"],
            "last_retire_advertised": f.session.last_retire_advertised,
        }


CASES = (
    ("cancelled-record-abandons-carrier", case_cancelled_record_abandons_carrier),
    ("unauthenticated-generation-does-not-reserve", case_unauthenticated_generation_does_not_reserve),
    ("new-data-after-reset-rejected", case_new_data_after_reset_rejected),
    ("concurrent-join-limit-commit-recheck", case_concurrent_join_limit_commit_recheck),
    ("generation-commit-recheck", case_generation_commit_recheck),
    ("pending-join-cannot-reopen-closed-session", case_pending_join_cannot_reopen_closed_session),
    ("concurrent-create-session-isolation", case_concurrent_create_session_isolation),
    ("superseded-record-cannot-mutate-state", case_superseded_record_cannot_mutate_state),
    ("incomplete-candidate-deadline", case_incomplete_candidate_deadline),
    ("settlement-automatically-advertises-retire", case_settlement_automatically_advertises_retire),
)


async def execute() -> dict:
    started = time.time()
    results = []
    for implementation in IMPLEMENTATIONS:
        for name, case in CASES:
            details = await asyncio.wait_for(case(implementation), timeout=10)
            item = {
                "implementation": implementation,
                "case": name,
                "status": "PASS",
                "details": details,
            }
            results.append(item)
            print(f"review-v2 {implementation}/{name}: PASS", flush=True)
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "review-v2 counterexample regression",
        "status": "PASS",
        "case_count": len(CASES),
        "execution_count": len(results),
        "implementations": list(IMPLEMENTATIONS),
        "cases": results,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "All nine review-v2 counterexample classes plus the required finite candidate "
            "handshake deadline are closed on both source-isolated runtime implementations."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 review-v2 regression harness")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "review-v2")
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "review-v2-report.json"
    try:
        report = asyncio.run(execute())
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"review-v2 regression: PASS ({report['execution_count']} executions; "
            f"{report['case_count']} case classes)"
        )
        print(f"report: {path}")
        return 0
    except Exception as exc:
        path.write_text(
            json.dumps(
                {
                    "protocol": "MPX/4",
                    "revision": "Draft 11",
                    "suite": "review-v2 counterexample regression",
                    "status": "FAIL",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"review-v2 regression: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
