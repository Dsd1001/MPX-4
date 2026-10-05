#!/usr/bin/env python3
"""MPX/4 Draft 11 update-review concurrency/progress regressions.

This suite preserves the prior review-v2 suite and adds the five remaining
counterexample classes plus four normal controls from MPX4-update-review.
All cases run against both source-isolated runtimes over real loopback TCP;
only deterministic scheduling barriers or the valid MAX_KEY_RECORDS boundary
are injected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Dict

from .endpoint_wire import Fixture, check, wait_until
from .review_v2 import PendingCandidate, finish_candidate, start_candidate

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")


async def grant(f: Fixture, peer, stream) -> None:
    core = f.core
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
        lambda: f.stream_credit(1)[1] == 4096 and f.session_credit()[1] == 4096,
        label="sender credit",
    )


async def send_client_finished(f: Fixture, candidate: PendingCandidate) -> None:
    client_finished, _, _, _ = f.core.derive_traffic(
        f.key,
        candidate.preface,
        candidate.client_init,
        candidate.server_init,
    )
    candidate.writer.write(client_finished)
    await candidate.writer.drain()


async def recv_until_any(peers, frame_type: int, timeout: float = 2.0):
    tasks = [asyncio.create_task(peer.recv_until(frame_type, timeout=timeout)) for peer in peers]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if not done:
            raise TimeoutError(f"frame 0x{frame_type:x} not observed on any surviving Carrier")
        winner = next(iter(done))
        frame = await winner
        index = tasks.index(winner)
        return peers[index], frame
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def case_normal_output_barrier_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        await f.establish()
        pending = await start_candidate(f, 96, 0)
        original_write = f.runtime.write_raw
        entered = asyncio.Event()
        release = asyncio.Event()

        async def gated_write(writer, data, write_chunk=0):
            await original_write(writer, data, write_chunk)
            if data[0] == f.core.MSG_SERVER_FINISHED and not entered.is_set():
                entered.set()
                await release.wait()

        f.runtime.write_raw = gated_write
        task = asyncio.create_task(finish_candidate(f, pending))
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            release.set()
            result = await task
            check(result["status"] == "established", result)
            peer = result["peer"]
            f.peers[96] = peer
            await f.ping(peer, 0x7301)
            check(f.session.state == "ACTIVE", f.session.state)
            check(f.session.carriers[96].generation == 0, f.session.carriers[96].generation)
            await peer.carrier.send_frame(
                f.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="update-control-close",
            )
            await wait_until(lambda: f.session.state == "CLOSED", label="normal close")
            return {
                "normal_join_and_ping": True,
                "state_after_post_install_close": f.session.state,
            }
        finally:
            release.set()
            f.runtime.write_raw = original_write
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            pending.writer.close()


async def case_post_commit_close_install_guard(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        old = await f.establish()
        pending = await start_candidate(f, 96, 0)
        original_write = f.runtime.write_raw
        entered = asyncio.Event()
        release = asyncio.Event()

        async def gated_write(writer, data, write_chunk=0):
            await original_write(writer, data, write_chunk)
            if data[0] == f.core.MSG_SERVER_FINISHED and not entered.is_set():
                entered.set()
                await release.wait()

        f.runtime.write_raw = gated_write
        try:
            await send_client_finished(f, pending)
            await asyncio.wait_for(entered.wait(), timeout=2)
            check(f.session.highest_accepted.get(96) == 0, f.session.highest_accepted)
            await old.carrier.send_frame(
                f.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="update-close-during-finished",
            )
            await wait_until(lambda: f.session.state == "CLOSED", label="Session CLOSED")
            release.set()
            await asyncio.sleep(0.05)
            check(f.session.state == "CLOSED", f.session.state)
            check(96 not in f.session.carriers, f.session.carriers)
            check(not f.session.active_logical_ids, f.session.active_logical_ids)
            discarded = [
                e for e in f.trace.events
                if e.get("event") == "committed_carrier_install_discarded"
                and e.get("carrier_id") == 96
            ]
            check(discarded, f.trace.events[-20:])
            return {
                "state_after_release": f.session.state,
                "late_carrier_installed": False,
                "discard_event": True,
            }
        finally:
            release.set()
            f.runtime.write_raw = original_write
            pending.writer.close()


async def case_post_commit_generation_install_guard(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        old = await f.establish()
        f.peers[1001] = old
        low = await start_candidate(f, 1, 1)
        original_write = f.runtime.write_raw
        entered = asyncio.Event()
        release = asyncio.Event()

        async def gated_write(writer, data, write_chunk=0):
            await original_write(writer, data, write_chunk)
            if data[0] == f.core.MSG_SERVER_FINISHED and not entered.is_set():
                entered.set()
                await release.wait()

        f.runtime.write_raw = gated_write
        try:
            await send_client_finished(f, low)
            await asyncio.wait_for(entered.wait(), timeout=2)
            check(f.session.highest_accepted[1] == 1, f.session.highest_accepted)

            high = await start_candidate(f, 1, 2)
            result = await finish_candidate(f, high)
            check(result["status"] == "established", result)
            peer = result["peer"]
            f.peers[1] = peer
            await f.ping(peer, 0x7302)
            check(f.session.carriers[1].generation == 2, f.session.carriers[1].generation)

            release.set()
            await asyncio.sleep(0.05)
            check(f.session.highest_accepted[1] == 2, f.session.highest_accepted)
            check(f.session.carriers[1].generation == 2, f.session.carriers[1].generation)
            check(f.session.choose_carrier().generation == 2, "no writable winning Carrier")
            await f.ping(peer, 0x7303)
            return {
                "highest_accepted": 2,
                "installed_generation": 2,
                "stale_install_discarded": True,
            }
        finally:
            release.set()
            f.runtime.write_raw = original_write
            low.writer.close()


async def case_normal_stop_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        stream = await f.open_stream(p1)
        p2 = await f.establish(2, 0, 1)
        p3 = await f.establish(3, 0, 1)
        await grant(f, p3, stream)
        fields = {
            "stream_id": 1,
            "transmission_id": f.next_peer_tx(1),
            "stream_error_code": 23,
        }
        await p1.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
        await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        reset = await p2.recv_until(f.core.FRAME_RESET_STREAM)
        check(int(reset["stream_id"]) == 1, reset)
        check(stream.send_terminal_mode == "RESET", stream.send_terminal_mode)
        rejected = False
        try:
            await f.session.send_data(stream, b"B", f.session.carriers[3])
        except f.runtime.StreamStateError:
            rejected = True
        check(rejected, "new DATA accepted after normal STOP->RESET")
        return {
            "reset_observed": True,
            "terminal_mode": stream.send_terminal_mode,
            "new_data_rejected": True,
        }


async def case_stop_ack_failure_preserves_reset(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        stream = await f.open_stream(p1)
        p2 = await f.establish(2, 0, 1)
        p3 = await f.establish(3, 0, 1)
        await grant(f, p3, stream)

        c2 = f.session.carriers[2]
        original_drain = c2.writer.drain
        entered = asyncio.Event()
        release = asyncio.Event()

        async def broken_drain():
            entered.set()
            await release.wait()
            raise ConnectionResetError("controlled post-write ACK drain error")

        c2.writer.drain = broken_drain
        fields = {
            "stream_id": 1,
            "transmission_id": f.next_peer_tx(1),
            "stream_error_code": 23,
        }
        try:
            await p1.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
            await asyncio.wait_for(entered.wait(), timeout=2)
            ack = await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
            check(int(ack["transmission_id"]) == fields["transmission_id"], ack)
            check(stream.send_terminal_mode == "RESET", stream.send_terminal_mode)
            resets = [
                t for t in f.session.local_tx.values()
                if t.frame_type == f.core.FRAME_RESET_STREAM
            ]
            check(len(resets) == 1 and resets[0].attempts == 0, [(t.txid, t.attempts) for t in resets])

            release.set()
            await wait_until(
                lambda: 2 not in f.session.active_logical_ids,
                label="failed ACK Carrier removed",
            )

            await p3.carrier.send_frame(f.core.FRAME_STOP_SENDING, **fields)
            _, replay_ack = await recv_until_any((p1, p3), f.core.FRAME_TRANSMISSION_ACK)
            check(int(replay_ack["transmission_id"]) == fields["transmission_id"], replay_ack)
            _, replay_reset = await recv_until_any((p1, p3), f.core.FRAME_RESET_STREAM)
            check(int(replay_reset["transmission_id"]) == resets[0].txid, replay_reset)
            check(resets[0].attempts >= 1, resets[0].attempts)

            rejected = False
            try:
                await f.session.send_data(stream, b"B", f.session.carriers[3])
            except f.runtime.StreamStateError:
                rejected = True
            check(rejected, "default RESET obligation was lost after ACK failure")
            await f.ping(p3, 0x7304)
            return {
                "original_ack_observed": True,
                "replay_ack_observed": True,
                "reset_recovered": True,
                "reset_txid": resets[0].txid,
                "terminal_mode": stream.send_terminal_mode,
            }
        finally:
            release.set()
            c2.writer.drain = original_drain


async def case_normal_retire_advancement_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        stream = await f.open_stream(peer)
        await grant(f, peer, stream)
        carrier = f.session.carriers[1]

        tx1 = await f.session.send_data(stream, b"A", carrier)
        await peer.recv_until(f.core.FRAME_STREAM_DATA)
        tx2 = await f.session.send_data(stream, b"B", carrier)
        await peer.recv_until(f.core.FRAME_STREAM_DATA)

        await peer.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx1.txid,
            receiver_timestamp_us=0,
        )
        first = await peer.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
        await peer.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx2.txid,
            receiver_timestamp_us=0,
        )
        second = await peer.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
        check([int(first["retired_through"]), int(second["retired_through"])] == [1, 2], (first, second))
        return {
            "wire_retired_prefixes": [1, 2],
            "last_retire_advertised": f.session.last_retire_advertised,
        }


async def case_retire_prefix_snapshot_interleaving(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        stream = await f.open_stream(peer)
        await grant(f, peer, stream)
        carrier = f.session.carriers[1]

        tx1 = await f.session.send_data(stream, b"A", carrier)
        await peer.recv_until(f.core.FRAME_STREAM_DATA)
        tx2 = await f.session.send_data(stream, b"B", carrier)
        await peer.recv_until(f.core.FRAME_STREAM_DATA)

        original_drain = carrier.writer.drain
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked_drain():
            entered.set()
            await release.wait()
            await original_drain()

        carrier.writer.drain = blocked_drain
        try:
            await peer.carrier.send_frame(
                f.core.FRAME_TRANSMISSION_ACK,
                stream_id=1,
                transmission_id=tx1.txid,
                receiver_timestamp_us=0,
            )
            await asyncio.wait_for(entered.wait(), timeout=2)
            first = await peer.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
            check(int(first["retired_through"]) == 1, first)

            await peer.carrier.send_frame(
                f.core.FRAME_TRANSMISSION_ACK,
                stream_id=1,
                transmission_id=tx2.txid,
                receiver_timestamp_us=0,
            )
            await wait_until(lambda: f.session.settled_through == 2, label="second settlement")
            check(f.session.last_retire_advertised == 0, f.session.last_retire_advertised)
            release.set()

            second = await peer.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
            check(int(second["retired_through"]) == 2, second)
            await wait_until(
                lambda: f.session.last_retire_advertised == 2,
                label="retire watermark catches up",
            )
            return {
                "wire_retired_prefixes": [1, 2],
                "settled_through": f.session.settled_through,
                "last_retire_advertised": f.session.last_retire_advertised,
            }
        finally:
            release.set()
            carrier.writer.drain = original_drain


async def case_normal_retirement_retry_control(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        peer = await f.establish()
        stream = await f.open_stream(peer)
        await grant(f, peer, stream)
        carrier = f.session.carriers[1]
        tx = await f.session.send_data(stream, b"A", carrier)
        await peer.recv_until(f.core.FRAME_STREAM_DATA)
        await peer.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx.txid,
            receiver_timestamp_us=0,
        )
        retire = await peer.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
        check(int(retire["retired_through"]) == 1, retire)
        return {
            "retired_through": int(retire["retired_through"]),
            "primary_output_usable": carrier.output_usable,
        }


async def case_retirement_key_exhaustion_fails_over(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish()
        stream = await f.open_stream(p1)
        await grant(f, p1, stream)
        c1 = f.session.carriers[1]

        tx = await f.session.send_data(stream, b"A", c1)
        await p1.recv_until(f.core.FRAME_STREAM_DATA)

        p2 = await f.establish(2, 0, 1)
        c2 = f.session.carriers[2]
        before_alt = c2.send_seq

        c1.send_seq = f.core.MAX_KEY_RECORDS
        await p1.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx.txid,
            receiver_timestamp_us=0,
        )

        retire = await p2.recv_until(f.core.FRAME_TRANSMISSION_RETIRE)
        check(int(retire["retired_through"]) == 1, retire)
        await wait_until(
            lambda: f.session.last_retire_advertised >= 1,
            label="alternate Carrier retirement advertisement",
        )
        await wait_until(
            lambda: not c1.output_usable,
            label="exhausted Carrier output retired",
        )
        check(c2.send_seq > before_alt, (before_alt, c2.send_seq))
        await f.ping(p2, 0x7305)
        return {
            "exhausted_output_usable": c1.output_usable,
            "alternate_extra_records": c2.send_seq - before_alt,
            "retired_through": int(retire["retired_through"]),
            "alternate_ping": True,
        }


CASES = (
    ("normal-output-barrier-control", case_normal_output_barrier_control),
    ("post-commit-close-install-guard", case_post_commit_close_install_guard),
    ("post-commit-generation-install-guard", case_post_commit_generation_install_guard),
    ("normal-stop-control", case_normal_stop_control),
    ("stop-ack-failure-preserves-reset", case_stop_ack_failure_preserves_reset),
    ("normal-retire-advancement-control", case_normal_retire_advancement_control),
    ("retire-prefix-snapshot-interleaving", case_retire_prefix_snapshot_interleaving),
    ("normal-retirement-retry-control", case_normal_retirement_retry_control),
    ("retirement-key-exhaustion-fails-over", case_retirement_key_exhaustion_fails_over),
)


async def execute() -> dict:
    started = time.time()
    rows = []
    for implementation in IMPLEMENTATIONS:
        for name, case in CASES:
            details = await asyncio.wait_for(case(implementation), timeout=12)
            rows.append(
                {
                    "implementation": implementation,
                    "case": name,
                    "status": "PASS",
                    "details": details,
                }
            )
            print(f"review-update {implementation}/{name}: PASS", flush=True)
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "update-review concurrency/output/progress regression",
        "status": "PASS",
        "case_count": len(CASES),
        "execution_count": len(rows),
        "implementations": list(IMPLEMENTATIONS),
        "cases": rows,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "The five update-review counterexample classes and four paired normal controls "
            "pass on both source-isolated runtimes."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 update-review regression harness")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "review-update")
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "review-update-report.json"
    try:
        report = asyncio.run(execute())
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "suite": "update-review concurrency/output/progress regression",
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        }
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        raise
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"review-update regression: PASS ({report['execution_count']} executions; "
        f"{report['case_count']} case classes)"
    )
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
