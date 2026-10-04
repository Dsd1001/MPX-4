#!/usr/bin/env python3
"""Neutral cross-implementation harness for the five Draft 11 fault scenarios."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
PSK = hashlib.sha256(b"MPX4 Draft 11 Gate 2 reference PSK").hexdigest()
MODULE = {"reference": "reference.gate2_runtime", "independent": "independent.gate_runtime"}
SCENARIOS = (
    "multi-carrier-reinjection",
    "dormant-recovery",
    "ambiguous-replacement",
    "fin-reset-retire",
    "error-scope",
)


class FaultCrossError(RuntimeError):
    pass


def check(cond: bool, message: object) -> None:
    if not cond:
        raise FaultCrossError(str(message))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def events(path: Path) -> List[dict]:
    out = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    check(out, f"empty trace {path}")
    check([x["event_seq"] for x in out] == list(range(1, len(out)+1)), f"event sequence {path}")
    return out


def has(xs: List[dict], event: str, **fields: object) -> bool:
    return any(x.get("event") == event and all(x.get(k) == v for k,v in fields.items()) for x in xs)


def verify(scenario: str, client: dict, server: dict, ct: List[dict], st: List[dict]) -> List[str]:
    check(client.get("status") == server.get("status") == "PASS", (client, server))
    check(client.get("session_id") == server.get("session_id"), "Session ID mismatch")
    check(not has(ct, "endpoint_error") and not has(st, "endpoint_error"), "endpoint_error")
    if scenario == "multi-carrier-reinjection":
        check([1,0] in client["established_incarnations"], "Carrier1 Gen0")
        check([96,0] in client["established_incarnations"], "Carrier96 Gen0")
        check([1,1] in client["established_incarnations"], "Carrier1 Gen1")
        check(client["reinjection_attempts"] >= 2, "reinjection")
        check(server["application_rx_bytes"] == 32768, "app bytes")
        check(server["application_duplicate_bytes_suppressed"] >= 16384, "duplicate suppression")
        check(has(st, "peer_transmission_duplicate"), "peer duplicate")
        return ["JOIN","sparse Carrier ID","same-Tx reinjection","duplicate suppression","unexpected loss","higher-Generation replacement"]
    if scenario == "dormant-recovery":
        check(client["state_history"].count("DORMANT") >= 2, "client DORMANT")
        check(server["state_history"].count("DORMANT") >= 2, "server DORMANT")
        check([1,2] in client["established_incarnations"], "client Gen2")
        check([1,2] in server["established_incarnations"], "server Gen2")
        check(client["reinjection_attempts"] >= 1, "reinject")
        check(server["application_rx_bytes"] == 16384, "recovered bytes")
        check(server["stream_credit_refreshes"] >= 1, "Stream credit refresh")
        check(has(ct, "recovery_refresh", kind="TRANSMISSION_RETIRE"), "retire refresh")
        return ["last-Carrier DORMANT","retained outstanding Tx","credit probe refresh","reinjection","retirement refresh"]
    if scenario == "ambiguous-replacement":
        check([1,1] in client["ambiguous_attempts"], "known ambiguity")
        check([96,0] in client["ambiguous_attempts"], "first-use ambiguity")
        check(client["highest_attempted"]["1"] == 2, "highest attempted")
        check(client["highest_accepted"]["1"] == 2, "Gen2 recovery")
        check(client["highest_accepted"].get("96") is None, "ambiguous 96 accepted locally")
        check(client["highest_accepted"]["97"] == 0, "fresh Carrier97")
        check(server["highest_accepted"]["96"] == 0, "server commit 96")
        return ["SERVER_FINISHED-loss ambiguity","retry above Highest Attempted","fresh-ID Gen0 first-use recovery"]
    if scenario == "fin-reset-retire":
        cs = client["streams"]["1"]; ss = server["streams"]["1"]
        check(cs["terminal_mode"] == ss["terminal_mode"] == "RESET", "RESET semantics")
        check(cs["send_final"] == ss["recv_final"] == 10, "final size")
        check(client["settled_through"] >= 3 and server["peer_retired_through"] >= 3, "retire prefix")
        check(has(ct, "transmission_attempt", frame_type="STREAM_FIN", reinjection=True), "late FIN reinjection")
        return ["lost FIN confirmation","STOP_SENDING/RESET","late FIN same final","contiguous retirement prefix"]
    if scenario == "error-scope":
        close = client.get("session_close_received")
        check(isinstance(close, dict) and close.get("error_code") == 0x10, "TRANSMISSION_ID_ERROR close")
        check(has(st, "session_failed", error_code=0x10), "server Session failure")
        return ["never-allocated ACK","Session-scoped TRANSMISSION_ID_ERROR","SESSION_CLOSE"]
    raise FaultCrossError(scenario)


def run_case(args: argparse.Namespace, scenario: str) -> dict:
    d = args.out_dir / scenario
    d.mkdir(parents=True, exist_ok=True)
    st = d / "server.trace.jsonl"; ct = d / "client.trace.jsonl"
    sr = d / "server.result.json"; cr = d / "client.result.json"
    env = os.environ.copy()
    env["MPX4_REF_PSK_HEX"] = PSK
    env["MPX4_INTEROP_PSK_HEX"] = PSK
    common = [
        "--scenario", scenario,
        "--timeout", str(args.endpoint_timeout),
        "--write-chunk", str(args.write_chunk),
        "--max-carriers", "4",
    ]
    sp = subprocess.Popen(
        [sys.executable, "-m", MODULE[args.server], "server", "--host", "127.0.0.1", "--port", "0", "--trace", str(st), "--result", str(sr), *common],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    ready_line = sp.stdout.readline() if sp.stdout else ""
    if not ready_line:
        out, err = sp.communicate(timeout=5)
        raise FaultCrossError(f"server no READY: {out} {err}")
    ready = json.loads(ready_line)
    port = int(ready["port"])
    cp = subprocess.run(
        [sys.executable, "-m", MODULE[args.client], "client", "--host", "127.0.0.1", "--port", str(port), "--trace", str(ct), "--result", str(cr), *common],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=args.case_timeout,
    )
    try:
        sout, serr = sp.communicate(timeout=args.case_timeout)
    except subprocess.TimeoutExpired:
        sp.kill(); sout, serr = sp.communicate()
        raise FaultCrossError(f"server timeout {scenario}")
    (d/"server.stdout.txt").write_text(ready_line+sout)
    (d/"server.stderr.txt").write_text(serr)
    (d/"client.stdout.txt").write_text(cp.stdout)
    (d/"client.stderr.txt").write_text(cp.stderr)
    check(cp.returncode == 0, f"client {scenario} rc={cp.returncode}: {cp.stderr}")
    check(sp.returncode == 0, f"server {scenario} rc={sp.returncode}: {serr}")
    cj=load(cr); sj=load(sr); ce=events(ct); se=events(st)
    checks=verify(scenario,cj,sj,ce,se)
    return {
        "scenario":scenario,
        "status":"PASS",
        "client_implementation":args.client,
        "server_implementation":args.server,
        "write_chunk":args.write_chunk,
        "checks":checks,
        "client":cj,
        "server":sj,
    }


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="neutral MPX/4 cross fault harness")
    p.add_argument("--client",choices=MODULE,required=True)
    p.add_argument("--server",choices=MODULE,required=True)
    p.add_argument("--out-dir",type=Path,required=True)
    p.add_argument("--scenario",action="append",choices=SCENARIOS)
    p.add_argument("--write-chunk",type=int,default=0)
    p.add_argument("--endpoint-timeout",type=float,default=10)
    p.add_argument("--case-timeout",type=float,default=25)
    return p


def main() -> int:
    args=parser().parse_args()
    scenarios=args.scenario or list(SCENARIOS)
    args.out_dir.mkdir(parents=True,exist_ok=True)
    path=args.out_dir/"cross-fault-report.json"
    cases=[]
    try:
        for scenario in scenarios:
            cases.append(run_case(args,scenario))
            print(f"cross fault {scenario}: PASS ({args.client} client -> {args.server} server)")
        report={
            "protocol":"MPX/4","revision":"Draft 11","gate":"Gate 4 cross fault",
            "status":"PASS","client_implementation":args.client,"server_implementation":args.server,
            "write_chunk":args.write_chunk,"cases":cases,
        }
        path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        return 0
    except Exception as exc:
        path.write_text(json.dumps({"status":"FAIL","error_type":type(exc).__name__,"error":str(exc),"completed":cases},indent=2,sort_keys=True)+"\n")
        print(f"cross fault: FAIL: {type(exc).__name__}: {exc}",file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main())
