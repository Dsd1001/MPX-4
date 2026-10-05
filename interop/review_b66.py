#!/usr/bin/env python3
"""MPX/4 Draft 11 b66 independent-review follow-up regressions.

This suite turns the b66d899 adjacent review probes into positive closure
regressions against both source-isolated runtimes:
- CREDIT_PROBE response progress after output-actor loss, in both endpoint roles;
- bounded multi-Carrier ACK failover plus Session-owned RESET work;
- Transmission-ID exhaustion preserving RESOURCE_LIMIT lifecycle;
- local DATA lower-bound validation before reliability/accounting commit.
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


async def grant(f: Fixture, peer) -> None:
    await peer.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=0,
        maximum_bytes=4096,
    )
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=0,
        maximum_offset=4096,
    )
    await wait_until(
        lambda: f.stream_credit(1)[1] == 4096 and f.session_credit()[1] == 4096,
        label="local DATA credit",
    )


async def credit_probe_case(
    implementation: str,
    role: str,
    fault: bool,
) -> dict:
    async with Fixture(implementation, role) as f:
        p1 = await f.establish()
        await f.open_stream(p1)
        p96 = await f.establish(96, 0, 1)
        await f.ping(p1, 9301)
        p1.backlog.clear()
        before = (
            f.session.stream_credit_refreshes,
            f.session.session_credit_refreshes,
        )
        if fault:
            f.session.carriers[96].send_seq = f.core.MAX_KEY_RECORDS

        await p1.carrier.send_frame(f.core.FRAME_CREDIT_PROBE, stream_id=1)

        if fault:
            await wait_until(
                lambda: 96 not in f.session.active_logical_ids,
                label="exhausted credit-response Carrier retirement",
            )
            stream_credit = await p1.recv_until(f.core.FRAME_STREAM_CREDIT)
            await p1.recv_until(f.core.FRAME_SESSION_CREDIT)
            check(f.session.active_logical_ids == {1}, f.session.active_logical_ids)
        else:
            stream_credit = await p96.recv_until(f.core.FRAME_STREAM_CREDIT)
            await p96.recv_until(f.core.FRAME_SESSION_CREDIT)

        check(int(stream_credit["stream_id"]) == 1, stream_credit)
        after = (
            f.session.stream_credit_refreshes,
            f.session.session_credit_refreshes,
        )
        check(tuple(a - b for a, b in zip(after, before)) == (1, 1), (before, after))
        check(not f.session.pending_credit_stream_ids, f.session.pending_credit_stream_ids)
        check(f.session.state == "ACTIVE", f.session.state)
        await f.ping(p1, 9302 if not fault else 9303)
        return {
            "endpoint_role": role,
            "fault_injected": fault,
            "stream_and_session_credit_observed": True,
            "refresh_deltas": [1, 1],
            "active_ids": sorted(f.session.active_logical_ids),
            "pending_credit_obligations": 0,
        }


async def case_credit_client_normal(implementation: str) -> dict:
    return await credit_probe_case(implementation, "client", False)


async def case_credit_client_output_failover(implementation: str) -> dict:
    return await credit_probe_case(implementation, "client", True)


async def case_credit_server_normal(implementation: str) -> dict:
    return await credit_probe_case(implementation, "server", False)


async def case_credit_server_output_failover(implementation: str) -> dict:
    return await credit_probe_case(implementation, "server", True)


async def repeated_output_failure(implementation: str, double: bool) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        p2 = await f.establish(2, 0, 1)
        p3 = await f.establish(3, 0, 1)
        c1, c2 = f.session.carriers[1], f.session.carriers[2]
        original1, original2 = c1.writer.drain, c2.writer.drain
        e1, e2, r1, r2 = (asyncio.Event() for _ in range(4))

        async def fail1():
            e1.set()
            await r1.wait()
            raise ConnectionResetError("controlled fallback ACK drain error")

        async def fail2():
            e2.set()
            await r2.wait()
            raise ConnectionResetError("controlled first ACK drain error")

        c2.writer.drain = fail2
        if double:
            c1.writer.drain = fail1
        try:
            txid = f.next_peer_tx(1)
            await p1.carrier.send_frame(
                f.core.FRAME_STOP_SENDING,
                stream_id=1,
                transmission_id=txid,
                stream_error_code=37,
            )
            await asyncio.wait_for(e2.wait(), 2)
            first_ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(first_ack["transmission_id"]) == txid, first_ack)
            reset_id = int(f.session.opening_tombstones[1]["reset_txid"])
            reset = f.session.local_tx[reset_id]
            check(reset_id in f.session.pending_response_txids, f.session.pending_response_txids)

            r2.set()
            if double:
                await asyncio.wait_for(e1.wait(), 2)
                second_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
                check(int(second_ack["transmission_id"]) == txid, second_ack)
                r1.set()
                await wait_until(
                    lambda: f.session.active_logical_ids == {3},
                    label="two failed ACK output actors retired",
                )
                final_ack = await p3.recv_until(f.core.FRAME_TRANSMISSION_ACK)
                check(int(final_ack["transmission_id"]) == txid, final_ack)
                wire_reset = await p3.recv_until(f.core.FRAME_RESET_STREAM)
                check(int(wire_reset["transmission_id"]) == reset_id, wire_reset)
                check(reset.attempts >= 1, reset.attempts)
                check(reset_id not in f.session.pending_response_txids, f.session.pending_response_txids)
                check(txid not in f.session.pending_confirmation_txids, f.session.pending_confirmation_txids)
                check(f.session.state == "ACTIVE", f.session.state)
                await f.ping(p3, 9203)
                return {
                    "two_failed_ack_output_actors": [2, 1],
                    "surviving_ids": [3],
                    "ack_failover_reached_third_carrier": True,
                    "same_reset_txid": reset_id,
                    "reset_attempted_automatically": True,
                    "pending_response_work": 0,
                    "pending_confirmation_work": 0,
                }

            retry_ack = await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(retry_ack["transmission_id"]) == txid, retry_ack)
            wire_reset = await p1.recv_until(f.core.FRAME_RESET_STREAM)
            check(int(wire_reset["transmission_id"]) == reset_id, wire_reset)
            check(reset.attempts >= 1, reset.attempts)
            await f.ping(p1, 9201)
            await f.ping(p3, 9202)
            return {
                "single_failed_ack_output_actor": 2,
                "automatic_ack_failover": True,
                "same_reset_txid": reset_id,
                "reset_attempted_automatically": True,
            }
        finally:
            r1.set()
            r2.set()
            c1.writer.drain, c2.writer.drain = original1, original2


async def case_single_output_failure_control(implementation: str) -> dict:
    return await repeated_output_failure(implementation, False)


async def case_double_output_failure_progress(implementation: str) -> dict:
    return await repeated_output_failure(implementation, True)


async def case_direct_allocator_exhaustion_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        f.session.next_txid = f.core.MAX_VARINT + 1
        error = None
        try:
            f.session.alloc_tx(f.core.FRAME_STREAM_FIN, 1, final_offset=1)
        except Exception as exc:
            error = type(exc).__name__
        check(error == "RuntimeError", error)
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == f.runtime.ERROR_RESOURCE_LIMIT, close)
        await wait_until(lambda: f.session.state == "CLOSED", label="allocator RESOURCE_LIMIT close")
        return {"error": error, "resource_limit_close": True}


async def case_send_data_exhaustion_preserves_close(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        stream = await f.open_stream(p)
        await grant(f, p)
        carrier = f.session.carriers[1]

        f.session.next_txid = f.core.MAX_VARINT
        last = await f.session.send_data(stream, b"A", carrier)
        data = await p.recv_until(f.core.FRAME_STREAM_DATA)
        check(last.txid == int(data["transmission_id"]) == f.core.MAX_VARINT, data)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=last.txid,
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: last.settled, label="final namespace DATA settlement")

        before = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "local_tx": set(f.session.local_tx),
        }
        error = None
        try:
            await f.session.send_data(stream, b"B", carrier)
        except Exception as exc:
            error = type(exc).__name__
        check(error == "RuntimeError", error)
        after_call = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "local_tx": set(f.session.local_tx),
        }
        check(after_call == before, (before, after_call))
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == f.runtime.ERROR_RESOURCE_LIMIT, close)
        await wait_until(lambda: f.session.state == "CLOSED", label="send_data RESOURCE_LIMIT close")
        return {
            "final_txid_was_sent": True,
            "next_allocation_rejected": error,
            "precommit_state_unchanged": True,
            "resource_limit_close": True,
        }


async def case_one_byte_data_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        stream = await f.open_stream(p)
        await grant(f, p)
        carrier = f.session.carriers[1]
        tx = await f.session.send_data(stream, b"A", carrier)
        data = await p.recv_until(f.core.FRAME_STREAM_DATA)
        check(bytes(data["data"]) == b"A", data)
        check(int(data["transmission_id"]) == tx.txid, data)
        return {"wire_payload_size": 1, "sent": True}


async def case_empty_data_rejected_atomically(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        stream = await f.open_stream(p)
        await grant(f, p)
        carrier = f.session.carriers[1]
        before = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        error = None
        try:
            await f.session.send_data(stream, b"", carrier)
        except Exception as exc:
            error = type(exc).__name__
        check(error == "ValueError", error)
        after = {
            "next_txid": f.session.next_txid,
            "send_offset": stream.send_offset,
            "session_send_committed": f.session.session_send_committed,
            "send_seq": carrier.send_seq,
            "local_tx": set(f.session.local_tx),
        }
        check(after == before, (before, after))
        check(f.session.state == "ACTIVE", f.session.state)
        tx = await f.session.send_data(stream, b"A", carrier)
        data = await p.recv_until(f.core.FRAME_STREAM_DATA)
        check(int(data["transmission_id"]) == tx.txid and bytes(data["data"]) == b"A", data)
        return {
            "empty_error": error,
            "precommit_state_unchanged": True,
            "subsequent_one_byte_send": True,
        }


CASES: tuple[tuple[str, Callable[[str], Awaitable[dict]]], ...] = (
    ("credit-client-normal-control", case_credit_client_normal),
    ("credit-client-output-failover", case_credit_client_output_failover),
    ("credit-server-normal-control", case_credit_server_normal),
    ("credit-server-output-failover", case_credit_server_output_failover),
    ("single-output-failure-control", case_single_output_failure_control),
    ("double-output-failure-progress", case_double_output_failure_progress),
    ("direct-allocator-exhaustion-control", case_direct_allocator_exhaustion_control),
    ("send-data-exhaustion-preserves-close", case_send_data_exhaustion_preserves_close),
    ("one-byte-data-control", case_one_byte_data_control),
    ("empty-data-rejected-atomically", case_empty_data_rejected_atomically),
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
            print(f"review-b66 {implementation}/{name}: PASS", flush=True)
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "b66 independent-review adjacent progress/boundary regression",
        "status": "PASS",
        "case_count": len(CASES),
        "execution_count": len(rows),
        "implementations": list(IMPLEMENTATIONS),
        "cases": rows,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "The four b66 adjacent finding classes and paired controls pass on "
            "both source-isolated runtimes, including both endpoint roles for "
            "CREDIT_PROBE response recovery."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 b66 review regressions")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "review-b66")
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "review-b66-report.json"
    try:
        report = asyncio.run(execute())
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "suite": "b66 independent-review adjacent progress/boundary regression",
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"review-b66 regression: FAIL: {type(exc).__name__}: {exc}")
        print(f"report: {path}")
        return 1
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"review-b66 regression: PASS ({report['execution_count']} executions; "
        f"{report['case_count']} case classes)"
    )
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
