#!/usr/bin/env python3
"""MPX/4 Draft 11 independent follow-up review regression suite.

This suite turns the independent 77ed0e1 replay findings into fail-closed
regressions against both source-isolated runtimes. It covers terminal client
installation, pre-open STOP response persistence, cross-Carrier output-failure
attribution/recovery, and local DATA API commit atomicity.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Awaitable, Callable

from .endpoint_wire import Fixture, check, wait_until

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")


async def grant_send_credit(f: Fixture, peer, stream, maximum: int) -> None:
    await peer.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=0,
        maximum_bytes=maximum,
    )
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=stream.stream_id,
        consumed_offset=0,
        maximum_offset=maximum,
    )
    await wait_until(
        lambda: f.session_credit()[1] >= maximum
        and f.stream_credit(stream.stream_id)[1] >= maximum,
        label="sender credit",
    )


def carrier_losses(f: Fixture) -> list[dict]:
    return [
        event
        for event in f.trace.events
        if event.get("event") == "carrier_lost"
    ]


async def case_client_join_normal_control(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        old = await f.establish()
        joined = await f.establish(96, 0, 1)
        await f.ping(joined, 0x7501)
        check(f.session.state == "ACTIVE", f.session.state)
        check(96 in f.session.active_logical_ids, f.session.active_logical_ids)
        await old.carrier.send_frame(
            f.core.FRAME_SESSION_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="followup-normal-close",
        )
        await wait_until(lambda: f.session.state == "CLOSED", label="normal client close")
        return {
            "join_installed": True,
            "joined_ping": True,
            "final_state": f.session.state,
        }


async def case_client_late_join_cannot_revive_closed(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        old = await f.establish()
        original_read = f.runtime.read_message
        entered = asyncio.Event()
        release = asyncio.Event()

        async def gated_read(reader):
            result = await original_read(reader)
            if result[0] == f.core.MSG_SERVER_FINISHED and not entered.is_set():
                entered.set()
                await release.wait()
            return result

        f.runtime.read_message = gated_read
        join_task = asyncio.create_task(f.establish(96, 0, 1))
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            await old.carrier.send_frame(
                f.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="followup-close-before-client-install",
            )
            await wait_until(lambda: f.session.state == "CLOSED", label="client Session CLOSED")
            check(f.session.done_event.is_set(), "client completion event not retained")
            release.set()
            outcome = await asyncio.gather(join_task, return_exceptions=True)
            check(isinstance(outcome[0], RuntimeError), outcome)
            check(f.session.state == "CLOSED", f.session.state)
            check(96 not in f.session.carriers, f.session.carriers)
            check(96 not in f.session.active_logical_ids, f.session.active_logical_ids)
            check(96 not in f.session.highest_accepted, f.session.highest_accepted)
            discarded = [
                event
                for event in f.trace.events
                if event.get("event") == "local_carrier_install_discarded"
                and event.get("carrier_id") == 96
            ]
            check(discarded, "late client Carrier was not explicitly discarded")
            return {
                "state_after_release": f.session.state,
                "late_join_rejected": True,
                "active_ids": sorted(f.session.active_logical_ids),
                "done_event_still_set": f.session.done_event.is_set(),
            }
        finally:
            release.set()
            f.runtime.read_message = original_read
            if not join_task.done():
                join_task.cancel()
                await asyncio.gather(join_task, return_exceptions=True)


async def case_preopen_stop_normal_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        p2 = await f.establish(2, 0, 1)
        p3 = await f.establish(3, 0, 1)
        fields = {
            "stream_id": 1,
            "transmission_id": f.next_peer_tx(1),
            "stream_error_code": 23,
        }
        await p1.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
        ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        reset = await p1.recv_until(f.core.FRAME_RESET_STREAM)
        check(int(ack["transmission_id"]) == fields["transmission_id"], ack)
        check(int(reset["final_offset"]) == 0, reset)
        tombstone = f.session.opening_tombstones.get(1) or {}
        check(tombstone.get("decision") == "preopen-stop", tombstone)
        check(tombstone.get("reset_txid") == int(reset["transmission_id"]), tombstone)
        await f.ping(p1, 0x7511)
        await f.ping(p2, 0x7512)
        await f.ping(p3, 0x7513)
        return {
            "ack": True,
            "reset": True,
            "reset_txid": int(reset["transmission_id"]),
            "all_carriers_alive": True,
        }


async def case_preopen_stop_ack_failure_resumes_same_reset(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        p2 = await f.establish(2, 0, 1)
        p3 = await f.establish(3, 0, 1)
        c2 = f.session.carriers[2]
        original_drain = c2.writer.drain
        entered = asyncio.Event()
        release = asyncio.Event()

        async def broken_drain():
            entered.set()
            await release.wait()
            raise ConnectionResetError("controlled pre-open ACK output failure")

        c2.writer.drain = broken_drain
        fields = {
            "stream_id": 1,
            "transmission_id": f.next_peer_tx(1),
            "stream_error_code": 31,
        }
        try:
            await p1.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
            await asyncio.wait_for(entered.wait(), timeout=2)
            first_ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(first_ack["transmission_id"]) == fields["transmission_id"], first_ack)
            release.set()
            await wait_until(
                lambda: 2 not in f.session.active_logical_ids,
                label="failed ACK output Carrier retirement",
            )
            retry_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            first_reset = await p1.recv_until(f.core.FRAME_RESET_STREAM)
            check(int(retry_ack["transmission_id"]) == fields["transmission_id"], retry_ack)
            check(int(first_reset["final_offset"]) == 0, first_reset)
            reset_txid = int(first_reset["transmission_id"])
            tombstone = f.session.opening_tombstones.get(1) or {}
            check(tombstone.get("reset_txid") == reset_txid, tombstone)

            await p3.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
            replay_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            replay_reset = await p1.recv_until(f.core.FRAME_RESET_STREAM)
            check(int(replay_ack["transmission_id"]) == fields["transmission_id"], replay_ack)
            check(int(replay_reset["transmission_id"]) == reset_txid, replay_reset)
            check(int(replay_reset["final_offset"]) == 0, replay_reset)

            check(f.session.state == "ACTIVE", f.session.state)
            await f.ping(p1, 0x7521)
            await f.ping(p3, 0x7523)
            return {
                "failed_output_carrier": 2,
                "retry_ack": True,
                "reset_txid": reset_txid,
                "replay_same_reset_txid": True,
                "surviving_ids": sorted(f.session.active_logical_ids),
            }
        finally:
            release.set()
            c2.writer.drain = original_drain


async def setup_cross_carrier_data(f: Fixture):
    p1 = await f.establish()
    stream = await f.open_stream(p1)
    p2 = await f.establish(2, 0, 1)
    p3 = await f.establish(3, 0, 1)
    fields = {
        "stream_id": stream.stream_id,
        "offset": 0,
        "transmission_id": f.next_peer_tx(1),
        "data": b"A",
    }
    return p1, p2, p3, stream, fields


async def case_cross_carrier_ack_normal_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1, p2, p3, stream, fields = await setup_cross_carrier_data(f)
        await p1.carrier.send_frame(f.core.FRAME_STREAM_DATA, **fields)
        ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == fields["transmission_id"], ack)
        check(bytes(stream.recv_data) == b"A", stream.recv_data)
        check(f.session.active_logical_ids == {1, 2, 3}, f.session.active_logical_ids)
        await f.ping(p1, 0x7531)
        await f.ping(p2, 0x7532)
        await f.ping(p3, 0x7533)
        return {"ack_on_alternate": 2, "active_ids": [1, 2, 3]}


async def case_cross_carrier_connection_error_isolates_output(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1, p2, p3, stream, fields = await setup_cross_carrier_data(f)
        c2 = f.session.carriers[2]
        original_drain = c2.writer.drain
        entered = asyncio.Event()
        release = asyncio.Event()

        async def broken_drain():
            entered.set()
            await release.wait()
            raise ConnectionResetError("controlled alternate ACK output failure")

        c2.writer.drain = broken_drain
        try:
            await p1.carrier.send_frame(f.core.FRAME_STREAM_DATA, **fields)
            await asyncio.wait_for(entered.wait(), timeout=2)
            first_ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(first_ack["transmission_id"]) == fields["transmission_id"], first_ack)
            release.set()
            await wait_until(lambda: 2 not in f.session.active_logical_ids, label="Carrier 2 loss")
            retry_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(retry_ack["transmission_id"]) == fields["transmission_id"], retry_ack)
            check(bytes(stream.recv_data) == b"A", stream.recv_data)
            check(f.session.state == "ACTIVE", f.session.state)
            check(f.session.active_logical_ids == {1, 3}, f.session.active_logical_ids)
            losses = carrier_losses(f)
            check(any(e.get("carrier_id") == 2 for e in losses), losses)
            check(not any(e.get("carrier_id") == 1 for e in losses), losses)
            await p1.expect_no(f.core.FRAME_SESSION_CLOSE, timeout=0.10)
            await p3.expect_no(f.core.FRAME_SESSION_CLOSE, timeout=0.10)
            await f.ping(p1, 0x7541)
            await f.ping(p3, 0x7543)
            return {
                "input_carrier_survived": True,
                "failed_output_carrier": 2,
                "active_ids": sorted(f.session.active_logical_ids),
                "session_state": f.session.state,
            }
        finally:
            release.set()
            c2.writer.drain = original_drain


async def case_cross_carrier_key_exhaustion_isolates_output(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1, p2, p3, stream, fields = await setup_cross_carrier_data(f)
        c2 = f.session.carriers[2]
        c2.send_seq = f.core.MAX_KEY_RECORDS
        await p1.carrier.send_frame(f.core.FRAME_STREAM_DATA, **fields)
        retry_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(retry_ack["transmission_id"]) == fields["transmission_id"], retry_ack)
        await wait_until(lambda: 2 not in f.session.active_logical_ids, label="exhausted Carrier loss")
        check(bytes(stream.recv_data) == b"A", stream.recv_data)
        check(f.session.state == "ACTIVE", f.session.state)
        check(f.session.active_logical_ids == {1, 3}, f.session.active_logical_ids)
        losses = carrier_losses(f)
        check(any(e.get("carrier_id") == 2 for e in losses), losses)
        check(not any(e.get("carrier_id") == 1 for e in losses), losses)
        await p1.expect_no(f.core.FRAME_SESSION_CLOSE, timeout=0.10)
        await p3.expect_no(f.core.FRAME_SESSION_CLOSE, timeout=0.10)
        await f.ping(p1, 0x7551)
        await f.ping(p3, 0x7553)
        return {
            "input_carrier_survived": True,
            "exhausted_output_carrier": 2,
            "active_ids": sorted(f.session.active_logical_ids),
            "session_state": f.session.state,
            "protocol_violation_close": False,
        }


async def setup_local_send(f: Fixture, maximum: int):
    peer = await f.establish()
    stream = await f.open_stream(peer)
    await grant_send_credit(f, peer, stream, maximum)
    carrier = f.session.carriers[1]
    return peer, stream, carrier


async def case_immutable_payload_reinject_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer, stream, carrier = await setup_local_send(f, 1 << 20)
        tx = await f.session.send_data(stream, b"good", carrier)
        first = await peer.recv_until(f.core.FRAME_STREAM_DATA)
        await f.session.send_tx(tx, carrier, reinjection=True)
        second = await peer.recv_until(f.core.FRAME_STREAM_DATA)
        check(bytes(first["data"]) == b"good", first)
        check(bytes(second["data"]) == b"good", second)
        check(int(first["transmission_id"]) == int(second["transmission_id"]), (first, second))
        return {
            "same_txid": int(first["transmission_id"]),
            "first": "good",
            "reinject": "good",
        }


async def case_mutable_payload_rejected_atomically(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer, stream, carrier = await setup_local_send(f, 1 << 20)
        before = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        rejected = False
        try:
            await f.session.send_data(stream, bytearray(b"good"), carrier)
        except TypeError:
            rejected = True
        check(rejected, "mutable payload was accepted")
        after = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        check(after == before, (before, after))
        check(f.session.state == "ACTIVE", f.session.state)
        await f.ping(peer, 0x7561)
        return {"rejected": True, "state_unchanged": True, "session_state": f.session.state}


async def case_legal_payload_boundary_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        size = 32768
        peer, stream, carrier = await setup_local_send(f, size + 1024)
        payload = b"L" * size
        tx = await f.session.send_data(stream, payload, carrier)
        data = await peer.recv_until(f.core.FRAME_STREAM_DATA)
        check(bytes(data["data"]) == payload, len(data["data"]))
        check(int(data["transmission_id"]) == tx.txid, data)
        return {"payload_length": size, "sent": True}


async def case_oversized_payload_rejected_atomically(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        size = 32769
        peer, stream, carrier = await setup_local_send(f, size + 1024)
        before = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        rejected = False
        try:
            await f.session.send_data(stream, b"X" * size, carrier)
        except f.core.ProtocolError:
            rejected = True
        check(rejected, "oversized payload was not rejected")
        after = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        check(after == before, (before, after))
        check(f.session.state == "ACTIVE", f.session.state)
        await f.ping(peer, 0x7571)
        return {
            "payload_length": size,
            "rejected": True,
            "state_unchanged": True,
            "session_state": f.session.state,
        }


CASES: tuple[tuple[str, Callable[[str], Awaitable[dict]]], ...] = (
    ("client-join-normal-control", case_client_join_normal_control),
    ("client-late-join-cannot-revive-closed", case_client_late_join_cannot_revive_closed),
    ("preopen-stop-normal-control", case_preopen_stop_normal_control),
    ("preopen-stop-ack-failure-resumes-same-reset", case_preopen_stop_ack_failure_resumes_same_reset),
    ("cross-carrier-ack-normal-control", case_cross_carrier_ack_normal_control),
    ("cross-carrier-connection-error-isolates-output", case_cross_carrier_connection_error_isolates_output),
    ("cross-carrier-key-exhaustion-isolates-output", case_cross_carrier_key_exhaustion_isolates_output),
    ("immutable-payload-reinject-control", case_immutable_payload_reinject_control),
    ("mutable-payload-rejected-atomically", case_mutable_payload_rejected_atomically),
    ("legal-payload-boundary-control", case_legal_payload_boundary_control),
    ("oversized-payload-rejected-atomically", case_oversized_payload_rejected_atomically),
)


async def execute() -> dict:
    started = time.time()
    rows = []
    for implementation in IMPLEMENTATIONS:
        for name, case in CASES:
            details = await asyncio.wait_for(case(implementation), timeout=15)
            rows.append(
                {
                    "implementation": implementation,
                    "case": name,
                    "status": "PASS",
                    "details": details,
                }
            )
            print(f"review-followup {implementation}/{name}: PASS", flush=True)
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "independent follow-up lifecycle/output/API regression",
        "status": "PASS",
        "case_count": len(CASES),
        "execution_count": len(rows),
        "implementations": list(IMPLEMENTATIONS),
        "cases": rows,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "The six independent-review counterexample classes and five paired normal "
            "controls pass on both source-isolated runtimes."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 independent follow-up review regressions")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "review-followup")
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "review-followup-report.json"
    try:
        report = asyncio.run(execute())
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "suite": "independent follow-up lifecycle/output/API regression",
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"review-followup regression: FAIL: {type(exc).__name__}: {exc}")
        print(f"report: {path}")
        return 1
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"review-followup regression: PASS ({report['execution_count']} executions; "
        f"{report['case_count']} case classes)"
    )
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
