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

from .endpoint_wire import Fixture, Peer, check

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")
MODES = ("none", "pre", "post-create", "post-join", "post-replacement")
POST_TARGET_INDEX = {"post-create": 1, "post-join": 2, "post-replacement": 3}


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
        if writer in committed_writers and writer not in faulted_writers:
            faulted_writers.add(writer)
            raise ConnectionResetError(
                "FREEZE CONTROL: initial credit output failure after authenticated commit"
            )
        return result

    runtime.write_raw = handshake_write
    asyncio.StreamWriter.drain = controlled_drain
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

        if mode == "post-create":
            boundary = "create"
            # SERVER_FINISHED already authenticated CREATE, but initial credit
            # fails on this first Carrier. The retained Session must recover via JOIN.
            try:
                await first.recv_until(fixture.core.FRAME_SESSION_CREDIT)
            except Exception as exc:
                candidate_error = type(exc).__name__
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
            if mode == "post-replacement":
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
            else:
                try:
                    second_carrier = await fixture._peer_client_handshake(1, 2, 0)
                    second = Peer(fixture.core, second_carrier, [])
                    peers.append(second)
                    if mode == "none":
                        await second.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                    elif mode == "post-join":
                        await second.recv_until(fixture.core.FRAME_SESSION_CREDIT)
                except Exception as exc:
                    candidate_error = type(exc).__name__

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
        if mode.startswith("post-"):
            post_events = [
                event
                for event in scoped_events
                if event.get("event") == "authenticated_carrier_output_failed"
            ]
            check(post_events, scoped_events)
            check(
                any(event.get("error_type") == "ConnectionResetError" for event in post_events),
                post_events,
            )

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


async def execute(out_dir: Path) -> dict:
    started = time.time()
    cases = []
    for implementation in IMPLEMENTATIONS:
        for mode in MODES:
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
    args = parser.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.out_dir / "review-freeze-report.json"
    try:
        report = asyncio.run(execute(args.out_dir))
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
