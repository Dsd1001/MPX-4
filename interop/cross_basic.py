#!/usr/bin/env python3
"""Neutral real-TCP A/B harness for MPX/4 Draft 11 basic full-duplex interop."""

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
PSK = hashlib.sha256(b"MPX4 Draft 11 Gate 1 reference PSK").hexdigest()
MODULE = {"reference": "reference.endpoint", "independent": "independent.endpoint"}


class CrossError(RuntimeError):
    pass


def check(cond: bool, message: object) -> None:
    if not cond:
        raise CrossError(str(message))


def payload_digest(sender_role: str, stream_id: int, length: int) -> str:
    seed = f"mpx4-ref:{sender_role}:{stream_id}:".encode()
    payload = (seed * ((length + len(seed) - 1) // len(seed)))[:length]
    return hashlib.sha256(payload).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def trace(path: Path) -> List[dict]:
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    check(events, f"empty trace {path}")
    check([x["event_seq"] for x in events] == list(range(1, len(events)+1)), f"trace sequence {path}")
    return events


def verify_result(result: dict, role: str, peer_role: str, streams: int, bytes_per_stream: int) -> None:
    check(result.get("status") == "PASS", result)
    check(result.get("streams") == streams, f"{role} stream count")
    total = streams * bytes_per_stream
    check(result.get("tx_application_bytes") == total, f"{role} tx bytes")
    check(result.get("rx_application_bytes") == total, f"{role} rx bytes")
    items = result.get("stream_results") or {}
    for i in range(streams):
        sid = 1 + 2*i
        item = items.get(str(sid))
        check(isinstance(item, dict), f"{role} missing Stream {sid}")
        check(item.get("recv_bytes") == bytes_per_stream, f"{role} Stream {sid} length")
        check(item.get("recv_sha256") == payload_digest(peer_role, sid, bytes_per_stream), f"{role} Stream {sid} digest")
        check(item.get("recv_final") == bytes_per_stream, f"{role} Stream {sid} recv final")
        check(item.get("send_final") == bytes_per_stream, f"{role} Stream {sid} send final")


def verify_trace(events: List[dict], role: str, streams: int) -> dict:
    check(any(x.get("event") == "handshake_established" for x in events), f"{role} handshake")
    check(not any(x.get("event") == "endpoint_error" for x in events), f"{role} endpoint_error")
    sends = [i for i,x in enumerate(events) if x.get("event") == "frame_send" and x.get("frame_type") == "STREAM_DATA"]
    recvs = [i for i,x in enumerate(events) if x.get("event") == "frame_recv" and x.get("frame_type") == "STREAM_DATA"]
    check(sends and recvs, f"{role} DATA")
    sc = [i for i,x in enumerate(events) if x.get("event") == "frame_recv" and x.get("frame_type") == "SESSION_CREDIT"]
    check(sc and sc[0] < sends[0], f"{role} Session credit before DATA")
    for n in range(streams):
        sid = 1 + 2*n
        credit = [i for i,x in enumerate(events) if x.get("event") == "frame_recv" and x.get("frame_type") == "STREAM_CREDIT" and x.get("stream_id") == sid]
        data = [i for i,x in enumerate(events) if x.get("event") == "frame_send" and x.get("frame_type") == "STREAM_DATA" and x.get("stream_id") == sid]
        check(credit and data and credit[0] < data[0], f"{role} Stream {sid} credit")
    check(sends[0] < recvs[-1] and recvs[0] < sends[-1], f"{role} full duplex")
    return {
        "events": len(events),
        "first_data_send": events[sends[0]]["event_seq"],
        "last_data_send": events[sends[-1]]["event_seq"],
        "first_data_recv": events[recvs[0]]["event_seq"],
        "last_data_recv": events[recvs[-1]]["event_seq"],
    }


def run_case(args: argparse.Namespace) -> dict:
    case = args.out_dir
    case.mkdir(parents=True, exist_ok=True)
    st = case / "server.trace.jsonl"
    ct = case / "client.trace.jsonl"
    sr = case / "server.result.json"
    cr = case / "client.result.json"

    env = os.environ.copy()
    env["MPX4_REF_PSK_HEX"] = PSK
    env["MPX4_INTEROP_PSK_HEX"] = PSK

    common = [
        "--streams", str(args.streams),
        "--bytes-per-stream", str(args.bytes_per_stream),
        "--timeout", str(args.endpoint_timeout),
        "--write-chunk", str(args.write_chunk),
        "--max-carriers", "4",
    ]
    server_cmd = [
        sys.executable, "-m", MODULE[args.server], "server",
        "--host", "127.0.0.1", "--port", "0",
        "--trace", str(st), "--result", str(sr), *common,
    ]
    server = subprocess.Popen(server_cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    ready_line = server.stdout.readline() if server.stdout else ""
    if not ready_line:
        out, err = server.communicate(timeout=5)
        raise CrossError(f"server no READY rc={server.returncode}: {out} {err}")
    ready = json.loads(ready_line)
    check(ready.get("event") == "READY", ready)
    port = int(ready["port"])

    client_cmd = [
        sys.executable, "-m", MODULE[args.client], "client",
        "--host", "127.0.0.1", "--port", str(port),
        "--trace", str(ct), "--result", str(cr), *common,
    ]
    client = subprocess.run(client_cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=args.case_timeout)
    try:
        sout, serr = server.communicate(timeout=args.case_timeout)
    except subprocess.TimeoutExpired:
        server.kill()
        sout, serr = server.communicate()
        raise CrossError("server timeout")
    (case / "server.stdout.txt").write_text(ready_line+sout)
    (case / "server.stderr.txt").write_text(serr)
    (case / "client.stdout.txt").write_text(client.stdout)
    (case / "client.stderr.txt").write_text(client.stderr)
    check(client.returncode == 0, f"client rc {client.returncode}: {client.stderr}")
    check(server.returncode == 0, f"server rc {server.returncode}: {serr}")

    cj = load(cr); sj = load(sr)
    check(cj.get("session_id") == sj.get("session_id"), "Session ID mismatch")
    verify_result(cj, "client", "server", args.streams, args.bytes_per_stream)
    verify_result(sj, "server", "client", args.streams, args.bytes_per_stream)
    ce = trace(ct); se = trace(st)
    cts = verify_trace(ce, "client", args.streams)
    sts = verify_trace(se, "server", args.streams)
    return {
        "status": "PASS",
        "client_implementation": args.client,
        "server_implementation": args.server,
        "role_reversal_pair": f"{args.client}-client__{args.server}-server",
        "streams": args.streams,
        "bytes_each_direction": args.streams*args.bytes_per_stream,
        "write_chunk": args.write_chunk,
        "session_id": cj["session_id"],
        "client_trace": cts,
        "server_trace": sts,
        "client_result": cj,
        "server_result": sj,
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="neutral MPX/4 A/B basic interop harness")
    p.add_argument("--client", choices=MODULE, required=True)
    p.add_argument("--server", choices=MODULE, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--streams", type=int, default=16)
    p.add_argument("--bytes-per-stream", type=int, default=65536)
    p.add_argument("--write-chunk", type=int, default=0)
    p.add_argument("--endpoint-timeout", type=float, default=20)
    p.add_argument("--case-timeout", type=float, default=50)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        result = run_case(args)
        (args.out_dir / "cross-basic-report.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
        print(f"cross basic: PASS ({args.client} client -> {args.server} server)")
        return 0
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "cross-basic-report.json").write_text(json.dumps({"status":"FAIL","error_type":type(exc).__name__,"error":str(exc)}, indent=2)+"\n")
        print(f"cross basic: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
