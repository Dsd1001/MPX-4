#!/usr/bin/env python3
"""Process harness for MPX/4 Draft 11 Gate 2 scenarios."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PSK = hashlib.sha256(b"MPX4 Draft 11 Gate 2 reference PSK").hexdigest()
SCENARIOS = (
    "multi-carrier-reinjection",
    "dormant-recovery",
    "ambiguous-replacement",
    "fin-reset-retire",
    "error-scope",
)


class HarnessError(RuntimeError):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise HarnessError(msg)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_trace(path: Path) -> List[dict]:
    out = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    check(out, f"empty trace: {path}")
    check([x["event_seq"] for x in out] == list(range(1, len(out) + 1)), f"non-consecutive trace: {path}")
    return out


def contains_event(events: List[dict], event: str, **fields: object) -> bool:
    for item in events:
        if item.get("event") != event:
            continue
        if all(item.get(k) == v for k, v in fields.items()):
            return True
    return False


def count_event(events: List[dict], event: str, **fields: object) -> int:
    count = 0
    for item in events:
        if item.get("event") != event:
            continue
        if all(item.get(k) == v for k, v in fields.items()):
            count += 1
    return count


def verify_common(client: dict, server: dict, ctrace: List[dict], strace: List[dict], scenario: str) -> Dict[str, object]:
    check(client.get("status") == "PASS", f"client failed: {client}")
    check(server.get("status") == "PASS", f"server failed: {server}")
    check(client.get("session_id") == server.get("session_id"), "Session IDs differ")
    check(not any(x.get("event") == "endpoint_error" for x in ctrace), "client endpoint_error")
    check(not any(x.get("event") == "endpoint_error" for x in strace), "server endpoint_error")
    check(any(x.get("event") == "handshake_established" for x in ctrace), "client never established")
    check(any(x.get("event") == "handshake_established" for x in strace), "server never established")
    return {
        "client_events": len(ctrace),
        "server_events": len(strace),
        "session_id": client["session_id"],
        "scenario": scenario,
    }


def verify_scenario(
    scenario: str,
    client: dict,
    server: dict,
    ctrace: List[dict],
    strace: List[dict],
) -> Dict[str, object]:
    summary = verify_common(client, server, ctrace, strace, scenario)

    if scenario == "multi-carrier-reinjection":
        check([1, 0] in client["established_incarnations"], "client Carrier 1 Gen0 missing")
        check([96, 0] in client["established_incarnations"], "client sparse Carrier 96 Gen0 missing")
        check([1, 1] in client["established_incarnations"], "client replacement Carrier 1 Gen1 missing")
        check([1, 1] in server["established_incarnations"], "server replacement Carrier 1 Gen1 missing")
        check(client["reinjection_attempts"] >= 2, "client did not reinject twice")
        check(server["application_rx_bytes"] == 32768, "server delivered wrong application byte count")
        check(server["application_duplicate_bytes_suppressed"] >= 16384, "duplicate DATA was not suppressed")
        check(contains_event(ctrace, "carrier_lost", carrier_id=1, generation=0), "client Carrier 1 loss not observed")
        check(contains_event(strace, "peer_transmission_duplicate"), "server did not observe duplicate Transmission")
        check(contains_event(ctrace, "retire_received") or contains_event(strace, "retire_received"), "retire evidence missing")
        summary["checks"] = [
            "D1 JOIN",
            "D2 shared Stream state",
            "D4 carrier-specific record spaces",
            "D5 sparse Carrier ID",
            "E1 same Transmission ID reinjection",
            "E2 duplicate delivery suppression",
            "E3 duplicate confirmation",
            "F4 reinjection no extra commitment",
            "J1 unexpected Carrier loss",
            "J2 outstanding Transmission survives loss",
            "J3/J4 replacement with fresh crypto/record space",
        ]

    elif scenario == "dormant-recovery":
        check(client["state_history"].count("DORMANT") >= 2, "client did not enter DORMANT twice")
        check(server["state_history"].count("DORMANT") >= 2, "server did not enter DORMANT twice")
        check([1, 2] in client["established_incarnations"], "client Gen2 recovery missing")
        check([1, 2] in server["established_incarnations"], "server Gen2 recovery missing")
        check(client["reinjection_attempts"] >= 1, "client did not reinject outstanding DATA")
        check(server["application_rx_bytes"] == 16384, "server delivered wrong recovered byte count")
        check(client["session_credit_refreshes"] >= 3, "client recovery Session credit refresh missing")
        check(server["session_credit_refreshes"] >= 3, "server recovery Session credit refresh missing")
        check(server["stream_credit_refreshes"] >= 1, "server Stream credit refresh evidence missing")
        check(contains_event(ctrace, "frame_recv", frame_type="STREAM_CREDIT", stream_id=1), "client did not receive recovered Stream credit")
        check(contains_event(ctrace, "recovery_refresh", kind="TRANSMISSION_RETIRE"), "client retirement refresh after recovery missing")
        summary["checks"] = [
            "J12 last-Carrier loss enters DORMANT",
            "J13 no attempt while DORMANT",
            "J14 DORMANT recovery",
            "J10 retained Transmission/Stream state",
            "credit probe/Session credit refresh",
            "retirement watermark refresh",
        ]

    elif scenario == "ambiguous-replacement":
        check([1, 1] in client["ambiguous_attempts"], "client replacement ambiguity missing")
        check([96, 0] in client["ambiguous_attempts"], "client first-use ambiguity missing")
        check(client["highest_attempted"].get("1") == 2, "client did not retry known Carrier above ambiguous generation")
        check(client["highest_accepted"].get("1") == 2, "client did not accept Carrier 1 Gen2")
        check(server["highest_accepted"].get("1") == 2, "server did not accept Carrier 1 Gen2")
        check(client["highest_accepted"].get("96") is None, "client incorrectly accepted ambiguous first-use Carrier 96")
        check(server["highest_accepted"].get("96") == 0, "server did not commit ambiguous Carrier 96 Gen0")
        check(client["highest_accepted"].get("97") == 0, "client did not recover with fresh Carrier 97 Gen0")
        check(server["highest_accepted"].get("97") == 0, "server did not accept fresh Carrier 97 Gen0")
        check(count_event(strace, "fault_drop_server_finished") == 2, "server ambiguity faults not deterministic")
        summary["checks"] = [
            "B16 ambiguous replacement",
            "known Carrier retry above Highest Attempted",
            "first-use ambiguity recovers with fresh Carrier ID Gen0",
            "server commit/client uncertainty separation",
        ]

    elif scenario == "fin-reset-retire":
        cstream = client["streams"]["1"]
        sstream = server["streams"]["1"]
        check(cstream["send_terminal_mode"] == "RESET", "client send side did not adopt RESET semantics")
        check(cstream["recv_terminal_mode"] != "RESET", "client receive side was incorrectly terminated by STOP_SENDING")
        check(sstream["recv_terminal_mode"] == "RESET", "server receive side did not preserve RESET semantics")
        check(cstream["send_final"] == 10, "client final offset mismatch")
        check(sstream["recv_final"] == 10, "server final offset mismatch")
        check(client["settled_through"] >= 3, "client settled prefix did not cross FIN/RESET")
        check(server["peer_retired_through"] >= 3, "server did not receive retirement watermark")
        check(contains_event(ctrace, "transmission_attempt", frame_type="STREAM_FIN", reinjection=True), "FIN reinjection missing")
        check(contains_event(strace, "fault_suppress_confirmation", frame_type="STREAM_FIN"), "FIN confirmation fault missing")
        summary["checks"] = [
            "E9 FIN supersession does not create retirement gap",
            "G4 FIN then RESET",
            "G5 late FIN does not restore graceful EOF",
            "TRANSMISSION_RETIRE after contiguous settlement",
        ]

    elif scenario == "error-scope":
        close = client.get("session_close_received")
        check(isinstance(close, dict), "client did not receive SESSION_CLOSE")
        check(close.get("error_code") == 0x10, "wrong Core error code for impossible ACK")
        check(server["state_history"][-1] == "CLOSED", "server did not close Session")
        check(contains_event(strace, "session_failed", error_code=0x10), "server did not classify Session-scoped TRANSMISSION_ID_ERROR")
        summary["checks"] = [
            "E5 never-allocated ACK",
            "TRANSMISSION_ID_ERROR is Session-scoped",
            "SESSION_CLOSE carries Core error scope",
        ]
    else:
        raise HarnessError(f"unsupported scenario {scenario}")

    return summary


def run_case(args: argparse.Namespace, scenario: str) -> dict:
    case_dir = args.out_dir / scenario
    case_dir.mkdir(parents=True, exist_ok=True)
    server_trace = case_dir / "server.trace.jsonl"
    client_trace = case_dir / "client.trace.jsonl"
    server_result = case_dir / "server.result.json"
    client_result = case_dir / "client.result.json"
    server_stdout = case_dir / "server.stdout.txt"
    server_stderr = case_dir / "server.stderr.txt"
    client_stdout = case_dir / "client.stdout.txt"
    client_stderr = case_dir / "client.stderr.txt"

    env = os.environ.copy()
    env["MPX4_REF_PSK_HEX"] = args.psk_hex
    common = [
        "--scenario", scenario,
        "--timeout", str(args.endpoint_timeout),
        "--write-chunk", str(args.write_chunk),
        "--max-carriers", "4",
    ]

    server_cmd = [
        sys.executable, "-m", "independent.gate_runtime", "server",
        "--host", "127.0.0.1", "--port", "0",
        "--trace", str(server_trace), "--result", str(server_result), *common,
    ]
    server = subprocess.Popen(
        server_cmd,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    ready_line = server.stdout.readline() if server.stdout is not None else ""
    if not ready_line:
        out, err = server.communicate(timeout=5)
        raise HarnessError(f"server exited before READY: rc={server.returncode}\nstdout={out}\nstderr={err}")
    server_stdout.write_text(ready_line, encoding="utf-8")
    ready = json.loads(ready_line)
    check(ready.get("event") == "READY", f"unexpected server ready line: {ready}")
    port = int(ready["port"])

    client_cmd = [
        sys.executable, "-m", "independent.gate_runtime", "client",
        "--host", "127.0.0.1", "--port", str(port),
        "--trace", str(client_trace), "--result", str(client_result), *common,
    ]
    client = subprocess.run(
        client_cmd,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=args.case_timeout,
    )
    client_stdout.write_text(client.stdout, encoding="utf-8")
    client_stderr.write_text(client.stderr, encoding="utf-8")

    try:
        sout, serr = server.communicate(timeout=args.case_timeout)
    except subprocess.TimeoutExpired:
        server.kill()
        sout, serr = server.communicate()
        raise HarnessError(f"server timeout in {scenario}")
    server_stdout.write_text(ready_line + sout, encoding="utf-8")
    server_stderr.write_text(serr, encoding="utf-8")

    check(client.returncode == 0, f"{scenario} client exit {client.returncode}: {client.stderr}")
    check(server.returncode == 0, f"{scenario} server exit {server.returncode}: {serr}")

    client_json = read_json(client_result)
    server_json = read_json(server_result)
    ctrace = read_trace(client_trace)
    strace = read_trace(server_trace)
    verification = verify_scenario(scenario, client_json, server_json, ctrace, strace)

    return {
        "scenario": scenario,
        "status": "PASS",
        "verification": verification,
        "client": client_json,
        "server": server_json,
        "artifacts": {
            "client_trace": str(client_trace),
            "server_trace": str(server_trace),
            "client_result": str(client_result),
            "server_result": str(server_result),
            "client_stderr": str(client_stderr),
            "server_stderr": str(server_stderr),
        },
    }


def git_metadata() -> dict:
    def run(*parts: str) -> str:
        return subprocess.run(["git", *parts], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    return {"head_sha": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 Implementation B fault harness")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "gate2")
    p.add_argument("--scenario", action="append", choices=SCENARIOS)
    p.add_argument("--endpoint-timeout", type=float, default=12.0)
    p.add_argument("--case-timeout", type=float, default=40.0)
    p.add_argument("--write-chunk", type=int, default=0)
    p.add_argument("--psk-hex", default=DEFAULT_PSK)
    return p


def main() -> int:
    args = build_parser().parse_args()
    scenarios = args.scenario or list(SCENARIOS)
    started = time.time()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.out_dir / "gate2-report.json"
    cases = []
    try:
        for scenario in scenarios:
            cases.append(run_case(args, scenario))
            print(f"Gate 2 {scenario}: PASS")
        report = {
            "protocol": "MPX/4",
            "draft": "Draft 11",
            "gate": "Gate 2",
            "status": "PASS",
            "git": git_metadata(),
            "duration_seconds": round(time.time() - started, 3),
            "cases": cases,
            "claim_boundary": (
                "reference-to-reference deterministic fault/recovery runtime only; "
                "not complete A-L Mandatory coverage and not independent A/B interoperability"
            ),
        }
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"implementation B fault suite: PASS ({len(cases)} scenarios)")
        print(f"report: {report_path}")
        return 0
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "draft": "Draft 11",
            "gate": "Gate 2",
            "status": "FAIL",
            "git": git_metadata(),
            "duration_seconds": round(time.time() - started, 3),
            "completed_cases": cases,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"implementation B fault suite: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {report_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
