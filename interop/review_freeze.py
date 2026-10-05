#!/usr/bin/env python3
"""Freeze-followup regression for authenticated Carrier output-failure scope.

The parent runner launches the real Gate runtime CLI in a subprocess. The child
mode adds a controlled transport-error seam without modifying the runtime:
- none: no fault;
- pre: a JOIN candidate raw handshake output fails before authentication;
- post-create: CREATE authenticates and installs, then initial-credit drain fails;
- post-join: a new JOIN Carrier authenticates and installs, then initial-credit drain fails;
- post-replacement: a higher-Generation replacement authenticates and installs, then initial-credit drain fails.

Every post-auth case passes only if the failed Carrier stays Carrier-scoped,
Session state remains recoverable/usable through another Carrier, and graceful
SESSION_CLOSE still exits 0.

Pre-write CREATE/JOIN/replacement/rejoin cases require autonomous current credit
without CREDIT_PROBE and never drop an already committed encrypted Record.
Record-transport cases additionally exercise both endpoint roles, cancellation,
newer snapshots, no-actor debt, independent retirement refresh, and cleanup.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from .endpoint_wire import Fixture, Peer, check, wait_until

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")
MODES = (
    "none", "pre", "post-create", "post-join", "post-replacement",
    "prewrite-create", "prewrite-join", "prewrite-replacement", "prewrite-rejoin",
)
OWNERSHIP_MODES = ("ownership-server", "ownership-client")
POST_TARGET_INDEX = {
    "post-create": 1, "post-join": 2, "post-replacement": 3,
    "prewrite-create": 1, "prewrite-join": 2, "prewrite-replacement": 3, "prewrite-rejoin": 2,
}


def fault_entry(argv: list[str]) -> int:
    if len(argv) < 3:
        raise SystemExit("fault-entry requires IMPLEMENTATION MODE and runtime argv")
    implementation, mode, *runtime_argv = argv
    if implementation not in IMPLEMENTATIONS or mode not in MODES:
        raise SystemExit("invalid fault-entry implementation/mode")

    core = importlib.import_module(
        "reference.mpx4_core" if implementation == "reference" else "independent.core"
    )
    runtime = importlib.import_module(
        "reference.gate2_runtime" if implementation == "reference" else "independent.gate_runtime"
    )
    original_write_raw = runtime.write_raw
    original_drain = asyncio.StreamWriter.drain
    original_write = asyncio.StreamWriter.write
    writer_indices: dict[asyncio.StreamWriter, int] = {}
    committed_writers: set[asyncio.StreamWriter] = set()
    faulted_writers: set[asyncio.StreamWriter] = set()
    next_writer_index = 0

    async def handshake_write(writer, data, *args, **kwargs):
        nonlocal next_writer_index
        if writer not in writer_indices:
            next_writer_index += 1
            writer_indices[writer] = next_writer_index
        writer_index = writer_indices[writer]
        if mode == "pre" and writer_index == 2:
            raise ConnectionResetError(
                "FREEZE CONTROL: candidate transport failure before authentication"
            )
        result = await original_write_raw(writer, data, *args, **kwargs)
        message_type, _ = core.vi_dec(data)
        if (
            message_type == core.MSG_SERVER_FINISHED
            and POST_TARGET_INDEX.get(mode) == writer_index
        ):
            committed_writers.add(writer)
        return result

    async def controlled_drain(writer):
        result = await original_drain(writer)
        if mode.startswith("post-") and writer in committed_writers and writer not in faulted_writers:
            faulted_writers.add(writer)
            raise ConnectionResetError(
                "FREEZE CONTROL: initial credit output failure after authenticated commit"
            )
        return result

    def controlled_write(writer, data):
        if mode.startswith("prewrite-") and writer in committed_writers and writer not in faulted_writers:
            faulted_writers.add(writer)
            trace_path = Path(runtime_argv[runtime_argv.index("--trace") + 1])
            (trace_path.parent / "prewrite-fault.json").write_text(json.dumps({
                "boundary": "before-first-encrypted-TCP-write",
                "encrypted_bytes_written": 0,
                "writer_index": writer_indices[writer],
            }) + "\n", encoding="utf-8")
            raise ConnectionResetError("FREEZE CONTROL: initial credit failed before any encrypted TCP write")
        return original_write(writer, data)

    runtime.write_raw = handshake_write
    asyncio.StreamWriter.drain = controlled_drain
    asyncio.StreamWriter.write = controlled_write
    sys.argv = [sys.argv[0], *runtime_argv]
    return runtime.main()


async def run_case(implementation: str, mode: str, out_dir: Path) -> dict:
    fixture = Fixture(implementation, "server")
    case_dir = out_dir / f"{implementation}-{mode}"
    case_dir.mkdir(parents=True, exist_ok=True)
    trace_path = case_dir / "trace.jsonl"
    result_path = case_dir / "result.json"
    env = dict(
        os.environ,
        MPX4_REF_PSK_HEX=fixture.key.hex(),
        PYTHONDONTWRITEBYTECODE="1",
    )
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-B",
        "-m",
        "interop.review_freeze",
        "fault-entry",
        implementation,
        mode,
        "server",
        "--scenario",
        "multi-carrier-reinjection",
        "--port",
        "0",
        "--timeout",
        "3",
        "--trace",
        str(trace_path),
        "--result",
        str(result_path),
        cwd=ROOT,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    peers: list[Peer] = []
    try:
        assert proc.stdout is not None
        ready_raw = await asyncio.wait_for(proc.stdout.readline(), timeout=3.0)
        ready = json.loads(ready_raw)
        fixture.port = int(ready["port"])

        first_carrier = await fixture._peer_client_handshake(0, 1, 0)
        first = Peer(fixture.core, first_carrier, [])
        peers.append(first)
        candidate_error = None
        survivor = first
        boundary = "join"

        if mode in {"post-create", "prewrite-create"}:
            boundary = "create"
            # SERVER_FINISHED already authenticated CREATE, but initial credit
            # fails on this first Carrier. The retained Session must recover via JOIN.
            try:
                await first.recv_until(fixture.core.FRAME_SESSION_CREDIT)
            except Exception as exc:
                candidate_error = type(exc).__name__
            if mode == "prewrite-create":
                check(candidate_error in {"IncompleteReadError", "ConnectionResetError"}, candidate_error)
            await asyncio.sleep(0.05)
            check(proc.returncode is None, f"CLI server exited after CREATE output failure: {proc.returncode}")
            recovery_carrier = await fixture._peer_client_handshake(1, 2, 0)
            recovery = Peer(fixture.core, recovery_carrier, [])
            peers.append(recovery)
            await recovery.recv_until(fixture.core.FRAME_SESSION_CREDIT)
            survivor = recovery
        else:
            await first.recv_until(fixture.core.FRAME_SESSION_CREDIT)
            await fixture.ping(first, 0xB001)
            if mode == "prewrite-rejoin":
                boundary = "dormant-recovery"
                first.carrier.writer.close()
                await asyncio.sleep(0.05)
                replacement_carrier = await fixture._peer_client_handshake(1, 1, 1)
                replacement = Peer(fixture.core, replacement_carrier, [])
                peers.append(replacement)
                try:
                    await replacement.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                except (asyncio.IncompleteReadError, ConnectionResetError) as exc:
                    candidate_error = type(exc).__name__
                check(candidate_error is not None, "failed recovery emitted initial credit")
                recovery_carrier = await fixture._peer_client_handshake(1, 2, 0)
                survivor = Peer(fixture.core, recovery_carrier, [])
                peers.append(survivor)
                credit = await survivor.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                check(credit["maximum_bytes"] == 8 * 1024 * 1024, credit)
            elif mode in {"post-replacement", "prewrite-replacement"}:
                boundary = "replacement"
                alternate_carrier = await fixture._peer_client_handshake(1, 96, 0)
                alternate = Peer(fixture.core, alternate_carrier, [])
                peers.append(alternate)
                await alternate.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                await fixture.ping(alternate, 0xB010)
                survivor = alternate
                try:
                    replacement_carrier = await fixture._peer_client_handshake(1, 1, 1)
                    replacement = Peer(fixture.core, replacement_carrier, [])
                    peers.append(replacement)
                    await replacement.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                except Exception as exc:
                    candidate_error = type(exc).__name__
                if mode == "prewrite-replacement":
                    check(candidate_error in {"IncompleteReadError", "ConnectionResetError"}, candidate_error)
                    credit = await survivor.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                    check(credit["consumed_bytes"] == 0 and credit["maximum_bytes"] == 8 * 1024 * 1024, credit)
            else:
                try:
                    second_carrier = await fixture._peer_client_handshake(1, 2, 0)
                    second = Peer(fixture.core, second_carrier, [])
                    peers.append(second)
                    if mode == "none":
                        await second.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                    elif mode == "post-join":
                        await second.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                    elif mode == "prewrite-join":
                        await second.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                except Exception as exc:
                    candidate_error = type(exc).__name__
                if mode == "prewrite-join":
                    check(candidate_error in {"IncompleteReadError", "ConnectionResetError"}, candidate_error)
                    credit = await survivor.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                    check(credit["maximum_bytes"] == 8 * 1024 * 1024, credit)

        if mode.startswith("prewrite-"):
            fault = json.loads((case_dir / "prewrite-fault.json").read_text(encoding="utf-8"))
            check(fault["encrypted_bytes_written"] == 0 and fault["writer_index"] == POST_TARGET_INDEX[mode], fault)

        # The surviving/recovery Carrier must remain usable after the scoped fault.
        await fixture.ping(survivor, 0xB002)
        await survivor.carrier.send_frame(
            fixture.core.FRAME_SESSION_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason=f"freeze-followup-{mode}",
        )
        await asyncio.wait_for(proc.wait(), timeout=3.0)

        assert proc.stderr is not None
        stderr = await proc.stderr.read()
        (case_dir / "stderr.log").write_bytes(stderr)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        trace = [
            json.loads(line)
            for line in trace_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        scoped_events = [
            event
            for event in trace
            if event.get("event")
            in {
                "authenticated_carrier_output_failed",
                "candidate_handshake_failed",
                "handshake_error",
                "endpoint_error",
            }
        ]

        check(proc.returncode == 0, {"returncode": proc.returncode, "events": scoped_events})
        check(result.get("status") == "PASS", result)
        check(not any(e.get("event") == "handshake_error" for e in scoped_events), scoped_events)
        if mode.startswith(("post-", "prewrite-")):
            post_events = [
                event
                for event in scoped_events
                if event.get("event") == "authenticated_carrier_output_failed"
            ]
            check(len(post_events) == 1, post_events)
            check(post_events[0].get("error_type") == "ConnectionResetError", post_events)
        if mode.startswith("prewrite-"):
            failed_id = 2 if mode == "prewrite-join" else 1
            failed_generation = 1 if mode in {"prewrite-replacement", "prewrite-rejoin"} else 0
            check(not any(event.get("event") == "record_send"
                          and event.get("carrier_id") == failed_id
                          and event.get("generation") == failed_generation for event in trace), trace)
            check(not any(event.get("event") == "frame_recv"
                          and event.get("frame_type") == "CREDIT_PROBE" for event in trace), trace)
            if mode in {"prewrite-create", "prewrite-rejoin"}:
                check(any(event.get("event") == "session_state" and event.get("state") == "DORMANT"
                          for event in trace), trace)

        return {
            "implementation": implementation,
            "mode": mode,
            "exit_code": proc.returncode,
            "result_status": result.get("status"),
            "candidate_error": candidate_error,
            "boundary": boundary,
            "surviving_carrier_healthy": True,
            "graceful_session_close": True,
            "scoped_events": scoped_events,
        }
    finally:
        for peer in peers:
            try:
                peer.carrier.writer.close()
            except Exception:
                pass
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()


class RecordWriter:
    def __init__(self, source: asyncio.StreamReader, destination: asyncio.StreamReader) -> None:
        self.source = source
        self.destination = destination
        self.data = bytearray()
        self.failure: OSError | None = None
        self.drain_failure: BaseException | None = None
        self.drain_started: asyncio.Event | None = None
        self.drain_release: asyncio.Event | None = None
        self.closed = False

    def write(self, data: bytes) -> None:
        if self.failure is not None:
            raise self.failure
        check(not self.closed, "write on closed Record transport")
        self.data.extend(data)
        self.destination.feed_data(data)

    async def drain(self) -> None:
        if self.drain_started is not None:
            self.drain_started.set()
        if self.drain_release is not None:
            await self.drain_release.wait()
        if self.drain_failure is not None:
            raise self.drain_failure
        await asyncio.sleep(0)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.source.feed_eof()
            self.destination.feed_eof()


async def run_ownership_case(implementation: str, role: str, out_dir: Path) -> dict:
    fixture = Fixture(implementation, role)
    session = fixture.session
    core = fixture.core
    peers = []

    def pair(carrier_id, generation):
        local_reader = asyncio.StreamReader()
        peer_reader = asyncio.StreamReader()
        local_writer = RecordWriter(local_reader, peer_reader)
        peer_writer = RecordWriter(peer_reader, local_reader)
        send_key, recv_key = os.urandom(32), os.urandom(32)
        send_iv, recv_iv = os.urandom(12), os.urandom(12)
        shared = dict(trace=fixture.trace, local_limits=fixture.limits, peer_limits=fixture.limits,
                      session_id=fixture.session_id, carrier_id=carrier_id, generation=generation)
        local = core.Carrier(role=role, reader=local_reader, writer=local_writer,
                             send_key=send_key, send_iv=send_iv, recv_key=recv_key, recv_iv=recv_iv, **shared)
        remote = core.Carrier(role="client" if role == "server" else "server",
                              reader=peer_reader, writer=peer_writer, send_key=recv_key, send_iv=recv_iv,
                              recv_key=send_key, recv_iv=send_iv, **shared)
        peer = Peer(core, remote, [])
        peers.append(peer)
        return local, peer

    async def install(carrier):
        if role == "server":
            session.commit_server_candidate(SimpleNamespace(
                session_id=fixture.session_id, carrier_id=carrier.carrier_id,
                generation=carrier.generation, client_limits=fixture.limits,
                session_action=0 if session.session_id is None else 1,
            ))
        return await session.add_carrier(carrier, accepted_locally=role == "client")

    try:
        old, old_peer = pair(1, 0)
        await install(old)
        await old_peer.recv_until(core.FRAME_SESSION_CREDIT)
        healthy, healthy_peer = pair(96, 0)
        await install(healthy)
        await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
        await wait_until(lambda: not session.pending_work_tasks, label="initial credit completion")

        # A local trace/storage OSError after an encrypted Record has already
        # reached the peer is not a Carrier transport failure. Keep the actor
        # current and writable while propagating the unrelated local error.
        original_emit = fixture.trace.emit
        trace_faulted = False

        def trace_storage_fault(event, **fields):
            nonlocal trace_faulted
            if event == "record_send" and not trace_faulted:
                trace_faulted = True
                raise OSError("trace persistence failed after network commit")
            return original_emit(event, **fields)

        fixture.trace.emit = trace_storage_fault
        try:
            try:
                await session.send_frame(healthy, core.FRAME_PING, token=0xB020)
            except OSError as exc:
                check("trace persistence failed" in str(exc), exc)
            else:
                raise RuntimeError("trace OSError negative control did not fire")
        finally:
            fixture.trace.emit = original_emit
        trace_ping = await healthy_peer.recv_until(core.FRAME_PING)
        check(trace_ping["token"] == 0xB020, trace_ping)
        check(healthy.output_usable, "trace OSError incorrectly poisoned Carrier output")
        check(session.choose_carrier(preferred=healthy.carrier_id) is healthy,
              "trace OSError incorrectly removed current Carrier")

        for stage in ("flush_pending_confirmations", "flush_pending_response_tx"):
            stage_started = asyncio.Event()
            stage_release = asyncio.Event()
            original_stage = getattr(session, stage)

            async def paused_stage(*args, **kwargs):
                stage_started.set()
                await stage_release.wait()
                await original_stage(*args, **kwargs)

            setattr(session, stage, paused_stage)
            try:
                await old_peer.carrier.send_frame(core.FRAME_CREDIT_PROBE, stream_id=0)
                await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
                await asyncio.wait_for(stage_started.wait(), 2)
                check(not session.pending_credit_stream_ids, "first credit flush has not completed")
                owned_task = session.pending_credit_flush_task
                check(owned_task is not None and not owned_task.done(), "credit worker left paused stage")
                generation_before = session.credit_refresh_generation
                await healthy_peer.carrier.send_frame(core.FRAME_CREDIT_PROBE, stream_id=0)
                await wait_until(lambda: session.credit_refresh_generation > generation_before,
                                 label=f"second actor probe during {stage}")
                check(session.pending_credit_flush_task is owned_task, "second probe did not coalesce")
                stage_release.set()
                await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
                await wait_until(lambda: not session.pending_credit_stream_ids and not session.pending_work_tasks,
                                 label=f"autonomous credit after {stage}")
            finally:
                stage_release.set()
                setattr(session, stage, original_stage)
        failed, _ = pair(1, 1)
        failed.writer.failure = OSError("initial credit failed before encrypted Record write")
        session.settled_through = 3
        session.last_retire_advertised = 3
        try:
            await install(failed)
        except fixture.runtime.CarrierOutputError as exc:
            check(exc.carrier is failed and exc.cause is failed.writer.failure, exc)
            failed.writer.close()
        check(not failed.writer.data and failed.send_seq == 0, "pre-write fault emitted Record bytes")
        credit = await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
        check(credit["maximum_bytes"] == session.session_local_maximum, credit)
        check(not failed.output_usable and session.choose_carrier() is healthy, "failed actor remains writable")
        retire = await healthy_peer.recv_until(core.FRAME_TRANSMISSION_RETIRE)
        check(retire["retired_through"] == 3, retire)
        await fixture.ping(healthy_peer, 0xB021)

        committed, committed_peer = pair(1, 2)
        committed.writer.drain_failure = ConnectionResetError("initial credit failed after encrypted Record commit")
        try:
            await install(committed)
        except fixture.runtime.CarrierOutputError as exc:
            check(exc.carrier is committed and exc.cause is committed.writer.drain_failure, exc)
        await committed_peer.recv_until(core.FRAME_SESSION_CREDIT)
        check(committed.send_seq == 1 and committed.writer.data and not committed.output_usable,
              "committed Record was removed or failed output reused")
        await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
        await healthy_peer.recv_until(core.FRAME_TRANSMISSION_RETIRE)
        await fixture.ping(healthy_peer, 0xB022)

        cancelled_actor, cancelled_peer = pair(1, 3)
        cancelled_actor.writer.drain_failure = asyncio.CancelledError()
        try:
            await install(cancelled_actor)
        except asyncio.CancelledError:
            pass
        await cancelled_peer.recv_until(core.FRAME_SESSION_CREDIT)
        check(cancelled_actor.send_seq == 1 and not cancelled_actor.output_usable,
              "post-commit cancellation reused a Record nonce or actor")
        await healthy_peer.recv_until(core.FRAME_SESSION_CREDIT)
        await healthy_peer.recv_until(core.FRAME_TRANSMISSION_RETIRE)
        await fixture.ping(healthy_peer, 0xB025)

        healthy.writer.close()
        await wait_until(lambda: session.state == "DORMANT", label="all Carrier loss")
        isolated, _ = pair(96, 1)
        isolated.writer.failure = ConnectionResetError("recovery initial credit has no healthy actor")
        try:
            await install(isolated)
        except fixture.runtime.CarrierOutputError:
            pass
        check(session.state == "DORMANT" and 0 in session.pending_credit_stream_ids
              and session.pending_retire_refresh, "no-actor refresh debt was lost")
        check(not isolated.writer.data and isolated.send_seq == 0 and not isolated.output_usable,
              "isolated pre-write failure did not fail closed")
        recovered, recovered_peer = pair(7, 0)
        await install(recovered)
        await recovered_peer.recv_until(core.FRAME_SESSION_CREDIT)
        await recovered_peer.recv_until(core.FRAME_TRANSMISSION_RETIRE)
        await fixture.ping(recovered_peer, 0xB023)
        await wait_until(lambda: not session.pending_work_tasks, label="credit worker completion")

        recovered.writer.drain_started = asyncio.Event()
        recovered.writer.drain_release = asyncio.Event()
        maximum_before = session.session_local_maximum
        first_refresh = asyncio.create_task(session.refresh_after_establish(recovered))
        await asyncio.wait_for(recovered.writer.drain_started.wait(), 2)
        first_refresh.cancel()
        cancelled = await asyncio.gather(first_refresh, return_exceptions=True)
        check(isinstance(cancelled[0], asyncio.CancelledError), cancelled)
        owned_task = session.pending_credit_flush_task
        check(owned_task is not None and not owned_task.done(), "caller cancellation cancelled credit owner")
        first_credit = await recovered_peer.recv_until(core.FRAME_SESSION_CREDIT)
        check(first_credit["maximum_bytes"] == maximum_before, first_credit)
        session.session_local_maximum += 4096
        generation_before = session.credit_refresh_generation
        second_refresh = asyncio.create_task(session.refresh_after_establish(recovered))
        await wait_until(lambda: session.credit_refresh_generation > generation_before,
                         label="newer refresh obligation")
        check(session.pending_credit_flush_task is owned_task, "concurrent credit flush did not coalesce")
        second_refresh.cancel()
        cancelled = await asyncio.gather(second_refresh, return_exceptions=True)
        check(isinstance(cancelled[0], asyncio.CancelledError), cancelled)
        recovered.writer.drain_release.set()
        newer_credit = await recovered_peer.recv_until(core.FRAME_SESSION_CREDIT)
        check(newer_credit["maximum_bytes"] == session.session_local_maximum, newer_credit)
        await wait_until(lambda: not session.pending_work_tasks and not session.pending_retire_refresh,
                         label="newer snapshot completion")
        await recovered_peer.recv_until(core.FRAME_TRANSMISSION_RETIRE)
        await fixture.ping(recovered_peer, 0xB024)

        recovered.writer.drain_started = None
        recovered.writer.drain_release = None
        output_lock = recovered.write_lock if hasattr(recovered, "write_lock") else recovered._lock
        await output_lock.acquire()
        terminal_refresh = asyncio.create_task(session.refresh_after_establish(recovered))
        await wait_until(lambda: 0 in session.pending_credit_stream_ids, label="terminal pending refresh")
        terminal_refresh.cancel()
        await asyncio.gather(terminal_refresh, return_exceptions=True)
        sequence_before_close = recovered.send_seq
        await recovered_peer.carrier.send_frame(core.FRAME_SESSION_CLOSE, error_code=0,
                                               trigger_frame_type=0, reason="owned-credit-complete")
        await asyncio.wait_for(session.done_event.wait(), 2)
        check(session.state == "CLOSED" and session.fatal_error is None, session.summary())
        await session.cleanup()
        output_lock.release()
        check(not session.pending_credit_stream_ids and not session.pending_retire_refresh
              and not session.pending_work_tasks and session.pending_credit_flush_task is None
              and session.retire_task is None and recovered.send_seq == sequence_before_close,
              "terminal cleanup leaked or emitted owned credit work")
        return {"implementation": implementation, "mode": f"ownership-{role}",
                "encrypted_records": True, "tcp": False, "autonomous_credit": True, "ping": True,
                "raw_oserror": True, "trace_oserror_not_transport": True,
                "committed_record_retained": True, "all_path_loss_rejoin": True,
                "cancelled_callers": 3, "newer_snapshot_retained": True,
                "credit_after_confirmation_await": True, "credit_after_response_await": True,
                "cancelled_output_handoff": True, "retire_refresh": True, "terminal_cleanup": True}
    finally:
        await session.cleanup()
        for peer in peers:
            peer.carrier.writer.close()
        case_dir = out_dir / f"{implementation}-ownership-{role}"
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "trace.jsonl").write_text("".join(json.dumps(event) + "\n" for event in fixture.trace.events))


async def execute(out_dir: Path, implementations=IMPLEMENTATIONS, modes=MODES + OWNERSHIP_MODES) -> dict:
    started = time.time()
    cases = []
    for implementation in implementations:
        for mode in modes:
            if mode in OWNERSHIP_MODES:
                detail = await run_ownership_case(implementation, mode.removeprefix("ownership-"), out_dir)
            else:
                detail = await run_case(implementation, mode, out_dir)
            cases.append({"status": "PASS", **detail})
            print(f"freeze-followup {implementation}/{mode}: PASS", flush=True)
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "freeze-followup authenticated Carrier output scope",
        "status": "PASS",
        "case_count": len(cases),
        "execution_count": len(cases),
        "cases": cases,
        "duration_seconds": round(time.time() - started, 3),
    }


def parent_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="MPX/4 freeze-followup regression")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--implementation", choices=IMPLEMENTATIONS)
    parser.add_argument("--mode", choices=MODES + OWNERSHIP_MODES)
    args = parser.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.out_dir / "review-freeze-report.json"
    try:
        report = asyncio.run(execute(
            args.out_dir,
            (args.implementation,) if args.implementation else IMPLEMENTATIONS,
            (args.mode,) if args.mode else MODES + OWNERSHIP_MODES,
        ))
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "suite": "freeze-followup authenticated Carrier output scope",
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"freeze-followup regression: FAIL: {type(exc).__name__}: {exc}")
        print(f"report: {report_path}")
        return 1
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"freeze-followup regression: PASS ({report['execution_count']} executions)")
    print(f"report: {report_path}")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "fault-entry":
        return fault_entry(sys.argv[2:])
    return parent_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
