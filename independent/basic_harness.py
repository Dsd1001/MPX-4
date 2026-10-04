#!/usr/bin/env python3
"""Gate 1 real-TCP integration harness for the Draft 11 reference endpoint.

The harness launches Client and Server as separate processes. It does not import
reference.mpx4_core and independently checks application bytes, Stream identity,
credit-before-data ordering, and local-event evidence of full-duplex overlap.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PSK = hashlib.sha256(b"MPX4 Draft 11 Gate 1 reference PSK").hexdigest()


class HarnessError(RuntimeError):
    pass


def payload_digest(sender_role: str, stream_id: int, length: int) -> str:
    seed = f"mpx4-ref:{sender_role}:{stream_id}:".encode("ascii")
    copies = (length + len(seed) - 1) // len(seed)
    payload = (seed * copies)[:length]
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_trace(path: Path) -> List[dict]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    if not events:
        raise HarnessError(f"empty trace: {path}")
    expected = list(range(1, len(events) + 1))
    actual = [int(event["event_seq"]) for event in events]
    if actual != expected:
        raise HarnessError(f"non-consecutive event sequence in {path}")
    return events


def event_indices(events: List[dict], event: str, frame_type: str | None = None) -> List[int]:
    out = []
    for idx, item in enumerate(events):
        if item.get("event") != event:
            continue
        if frame_type is not None and item.get("frame_type") != frame_type:
            continue
        out.append(idx)
    return out


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessError(message)


def verify_application_result(result: dict, receiver_role: str, sender_role: str, streams: int, bytes_per_stream: int) -> None:
    assert_true(result.get("status") == "PASS", f"{receiver_role} endpoint did not PASS: {result}")
    total = streams * bytes_per_stream
    assert_true(result.get("streams") == streams, f"{receiver_role} stream count mismatch")
    assert_true(result.get("tx_application_bytes") == total, f"{receiver_role} tx byte count mismatch")
    assert_true(result.get("rx_application_bytes") == total, f"{receiver_role} rx byte count mismatch")

    stream_results = result.get("stream_results", {})
    assert_true(len(stream_results) == streams, f"{receiver_role} stream result count mismatch")
    for index in range(streams):
        stream_id = 1 + 2 * index
        item = stream_results.get(str(stream_id))
        assert_true(isinstance(item, dict), f"{receiver_role} missing Stream {stream_id}")
        expected_digest = payload_digest(sender_role, stream_id, bytes_per_stream)
        assert_true(item.get("recv_bytes") == bytes_per_stream, f"{receiver_role} Stream {stream_id} recv length mismatch")
        assert_true(item.get("recv_sha256") == expected_digest, f"{receiver_role} Stream {stream_id} content mismatch")
        assert_true(item.get("recv_final") == bytes_per_stream, f"{receiver_role} Stream {stream_id} recv final mismatch")
        assert_true(item.get("send_final") == bytes_per_stream, f"{receiver_role} Stream {stream_id} send final mismatch")


def verify_trace(role: str, events: List[dict], streams: int) -> Dict[str, object]:
    assert_true(any(e.get("event") == "handshake_established" for e in events), f"{role} never established handshake")
    assert_true(not any(e.get("event") == "endpoint_error" for e in events), f"{role} trace contains endpoint_error")

    data_send = event_indices(events, "frame_send", "STREAM_DATA")
    data_recv = event_indices(events, "frame_recv", "STREAM_DATA")
    assert_true(data_send, f"{role} never sent STREAM_DATA")
    assert_true(data_recv, f"{role} never received STREAM_DATA")

    session_credit_recv = event_indices(events, "frame_recv", "SESSION_CREDIT")
    assert_true(session_credit_recv, f"{role} never received SESSION_CREDIT")
    assert_true(session_credit_recv[0] < data_send[0], f"{role} sent DATA before receiving Session credit")

    for index in range(streams):
        stream_id = 1 + 2 * index
        stream_credit = [
            idx for idx, e in enumerate(events)
            if e.get("event") == "frame_recv"
            and e.get("frame_type") == "STREAM_CREDIT"
            and e.get("stream_id") == stream_id
        ]
        stream_data_send = [
            idx for idx, e in enumerate(events)
            if e.get("event") == "frame_send"
            and e.get("frame_type") == "STREAM_DATA"
            and e.get("stream_id") == stream_id
        ]
        assert_true(stream_credit, f"{role} Stream {stream_id} never received Stream credit")
        assert_true(stream_data_send, f"{role} Stream {stream_id} never sent DATA")
        assert_true(stream_credit[0] < stream_data_send[0], f"{role} Stream {stream_id} sent DATA before Stream credit")

    if role == "client":
        opens = event_indices(events, "frame_send", "STREAM_OPEN")
        open_ok = event_indices(events, "frame_recv", "STREAM_OPEN_OK")
        assert_true(len(opens) == streams, f"client STREAM_OPEN count {len(opens)} != {streams}")
        assert_true(len(open_ok) == streams, f"client STREAM_OPEN_OK count {len(open_ok)} != {streams}")
    else:
        opens = event_indices(events, "frame_recv", "STREAM_OPEN")
        open_ok = event_indices(events, "frame_send", "STREAM_OPEN_OK")
        assert_true(len(opens) == streams, f"server STREAM_OPEN count {len(opens)} != {streams}")
        assert_true(len(open_ok) == streams, f"server STREAM_OPEN_OK count {len(open_ok)} != {streams}")

    # Full-duplex proof uses only one endpoint's own event ordering. Each role
    # must begin sending before it finishes receiving and begin receiving before
    # it finishes sending. No cross-endpoint timestamp subtraction is used.
    assert_true(data_send[0] < data_recv[-1], f"{role} did not send before completing receive direction")
    assert_true(data_recv[0] < data_send[-1], f"{role} did not receive before completing send direction")

    closes = event_indices(events, "frame_send" if role == "client" else "frame_recv", "SESSION_CLOSE")
    assert_true(closes, f"{role} missing SESSION_CLOSE evidence")

    return {
        "event_count": len(events),
        "first_data_send_event_seq": events[data_send[0]]["event_seq"],
        "last_data_send_event_seq": events[data_send[-1]]["event_seq"],
        "first_data_recv_event_seq": events[data_recv[0]]["event_seq"],
        "last_data_recv_event_seq": events[data_recv[-1]]["event_seq"],
        "stream_open_count": len(opens),
        "stream_open_ok_count": len(open_ok),
    }


def git_metadata() -> dict:
    def run(*args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    return {
        "head_sha": run("rev-parse", "HEAD"),
        "dirty": bool(run("status", "--porcelain")),
    }


def run_case(args: argparse.Namespace, case_dir: Path) -> dict:
    case_dir.mkdir(parents=True, exist_ok=True)
    server_trace = case_dir / "server.trace.jsonl"
    client_trace = case_dir / "client.trace.jsonl"
    server_result = case_dir / "server.result.json"
    client_result = case_dir / "client.result.json"
    server_stdout = case_dir / "server.stdout.txt"
    server_stderr = case_dir / "server.stderr.txt"
    client_stdout = case_dir / "client.stdout.txt"
    client_stderr = case_dir / "client.stderr.txt"
    proxy_trace = case_dir / "proxy.trace.jsonl"
    proxy_stdout = case_dir / "proxy.stdout.txt"
    proxy_stderr = case_dir / "proxy.stderr.txt"

    env = os.environ.copy()
    env["MPX4_REF_PSK_HEX"] = args.psk_hex

    common = [
        "--streams", str(args.streams),
        "--bytes-per-stream", str(args.bytes_per_stream),
        "--timeout", str(args.endpoint_timeout),
        "--write-chunk", str(args.write_chunk),
    ]

    server_cmd = [
        sys.executable,
        "-m",
        "independent.endpoint",
        "server",
        "--host", "127.0.0.1",
        "--port", "0",
        "--trace", str(server_trace),
        "--result", str(server_result),
        *common,
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
        stdout, stderr = server.communicate(timeout=5)
        raise HarnessError(f"server exited before READY: rc={server.returncode}\nstdout={stdout}\nstderr={stderr}")
    server_stdout.write_text(ready_line, encoding="utf-8")
    try:
        ready = json.loads(ready_line)
    except json.JSONDecodeError as exc:
        server.kill()
        raise HarnessError(f"invalid server READY line: {ready_line!r}") from exc
    if ready.get("event") != "READY":
        server.kill()
        raise HarnessError(f"unexpected server startup event: {ready}")
    port = int(ready["port"])

    proxy = None
    proxy_ready_line = ""
    client_port = port
    proxy_enabled = any((
        args.proxy_max_chunk > 0,
        args.proxy_delay_ms > 0,
        args.proxy_abort_after_c2s > 0,
        args.proxy_abort_after_s2c > 0,
    ))
    if proxy_enabled:
        proxy_cmd = [
            sys.executable,
            "-m",
            "reference.fault_proxy",
            "--target-host", "127.0.0.1",
            "--target-port", str(port),
            "--max-chunk", str(args.proxy_max_chunk),
            "--delay-ms", str(args.proxy_delay_ms),
            "--abort-after-c2s", str(args.proxy_abort_after_c2s),
            "--abort-after-s2c", str(args.proxy_abort_after_s2c),
            "--timeout", str(args.case_timeout),
            "--trace", str(proxy_trace),
        ]
        proxy = subprocess.Popen(
            proxy_cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        proxy_ready_line = proxy.stdout.readline() if proxy.stdout is not None else ""
        if not proxy_ready_line:
            stdout, stderr = proxy.communicate(timeout=5)
            server.kill()
            raise HarnessError(f"proxy exited before READY: rc={proxy.returncode}\\nstdout={stdout}\\nstderr={stderr}")
        proxy_stdout.write_text(proxy_ready_line, encoding="utf-8")
        proxy_ready = json.loads(proxy_ready_line)
        if proxy_ready.get("event") != "READY":
            proxy.kill()
            server.kill()
            raise HarnessError(f"unexpected proxy startup event: {proxy_ready}")
        client_port = int(proxy_ready["port"])

    client_cmd = [
        sys.executable,
        "-m",
        "independent.endpoint",
        "client",
        "--host", "127.0.0.1",
        "--port", str(client_port),
        "--trace", str(client_trace),
        "--result", str(client_result),
        *common,
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
        server_out_tail, server_err = server.communicate(timeout=args.case_timeout)
    except subprocess.TimeoutExpired:
        server.kill()
        server_out_tail, server_err = server.communicate()
        raise HarnessError("server did not exit after client completed")
    server_stdout.write_text(ready_line + server_out_tail, encoding="utf-8")
    server_stderr.write_text(server_err, encoding="utf-8")

    proxy_rc = None
    if proxy is not None:
        try:
            proxy_out_tail, proxy_err = proxy.communicate(timeout=args.case_timeout)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy_out_tail, proxy_err = proxy.communicate()
            raise HarnessError("proxy did not exit after endpoints completed")
        proxy_stdout.write_text(proxy_ready_line + proxy_out_tail, encoding="utf-8")
        proxy_stderr.write_text(proxy_err, encoding="utf-8")
        proxy_rc = proxy.returncode

    assert_true(client.returncode == 0, f"client exit {client.returncode}: {client.stderr}")
    assert_true(server.returncode == 0, f"server exit {server.returncode}: {server_err}")
    if proxy is not None:
        assert_true(proxy_rc == 0, f"proxy exit {proxy_rc}: {proxy_stderr.read_text(encoding='utf-8')}")
    assert_true(client_result.exists(), "client result missing")
    assert_true(server_result.exists(), "server result missing")

    client_json = read_json(client_result)
    server_json = read_json(server_result)
    assert_true(client_json.get("session_id") == server_json.get("session_id"), "endpoint Session IDs differ")
    assert_true(client_json.get("carrier_id") == 1 and server_json.get("carrier_id") == 1, "unexpected Carrier ID")
    assert_true(client_json.get("generation") == 0 and server_json.get("generation") == 0, "unexpected Generation")

    verify_application_result(client_json, "client", "server", args.streams, args.bytes_per_stream)
    verify_application_result(server_json, "server", "client", args.streams, args.bytes_per_stream)

    client_events = read_trace(client_trace)
    server_events = read_trace(server_trace)
    client_trace_summary = verify_trace("client", client_events, args.streams)
    server_trace_summary = verify_trace("server", server_events, args.streams)

    total = args.streams * args.bytes_per_stream
    assert_true(total >= 1024 * 1024, "Gate 1 profile requires at least 1 MiB per direction")
    assert_true(args.streams >= 16, "Gate 1 profile requires at least 16 simultaneous Streams")

    return {
        "case_id": args.case_id,
        "status": "PASS",
        "profile": {
            "streams": args.streams,
            "bytes_per_stream": args.bytes_per_stream,
            "bytes_each_direction": total,
            "write_chunk": args.write_chunk,
            "proxy_max_chunk": args.proxy_max_chunk,
            "proxy_delay_ms": args.proxy_delay_ms,
            "proxy_abort_after_c2s": args.proxy_abort_after_c2s,
            "proxy_abort_after_s2c": args.proxy_abort_after_s2c,
        },
        "session_id": client_json["session_id"],
        "checks": {
            "B1_CREATE_handshake": "PASS",
            "B2_key_schedule_finished": "PASS",
            "B3_secure_record": "PASS",
            "C1_stream_open": "PASS",
            "C2_bidirectional_credit": "PASS",
            "C3_client_to_server_1MiB": "PASS",
            "C4_server_to_client_1MiB": "PASS",
            "C5_full_duplex_local_event_overlap": "PASS",
            "C6_16_streams": "PASS",
            "K3_session_close": "PASS",
        },
        "client": {
            "result": client_json,
            "trace_summary": client_trace_summary,
        },
        "server": {
            "result": server_json,
            "trace_summary": server_trace_summary,
        },
        "artifacts": {
            "client_trace": str(client_trace),
            "server_trace": str(server_trace),
            "client_result": str(client_result),
            "server_result": str(server_result),
            "client_stdout": str(client_stdout),
            "client_stderr": str(client_stderr),
            "server_stdout": str(server_stdout),
            "server_stderr": str(server_stderr),
            "proxy_trace": str(proxy_trace) if proxy is not None else None,
            "proxy_stdout": str(proxy_stdout) if proxy is not None else None,
            "proxy_stderr": str(proxy_stderr) if proxy is not None else None,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MPX/4 Draft 11 Gate 1 reference interop harness")
    parser.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts")
    parser.add_argument("--case-id", default="gate1-basic-full-duplex")
    parser.add_argument("--streams", type=int, default=16)
    parser.add_argument("--bytes-per-stream", type=int, default=65536)
    parser.add_argument("--write-chunk", type=int, default=0)
    parser.add_argument("--proxy-max-chunk", type=int, default=0)
    parser.add_argument("--proxy-delay-ms", type=float, default=0.0)
    parser.add_argument("--proxy-abort-after-c2s", type=int, default=0)
    parser.add_argument("--proxy-abort-after-s2c", type=int, default=0)
    parser.add_argument("--endpoint-timeout", type=float, default=20.0)
    parser.add_argument("--case-timeout", type=float, default=45.0)
    parser.add_argument("--psk-hex", default=DEFAULT_PSK)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    started = time.time()
    case_dir = args.out_dir / args.case_id
    report_path = args.out_dir / "gate1-report.json"
    try:
        case = run_case(args, case_dir)
        report = {
            "protocol": "MPX/4",
            "draft": "Draft 11",
            "gate": "Gate 1",
            "status": "PASS",
            "git": git_metadata(),
            "started_unix": started,
            "duration_seconds": round(time.time() - started, 3),
            "cases": [case],
            "claim_boundary": (
                "reference-to-reference real-TCP integration only; this is not independent A/B interoperability "
                "and does not establish Protocol Version 4 stability"
            ),
        }
        args.out_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"implementation B Gate 1: PASS ({args.streams} Streams, "
            f"{args.streams * args.bytes_per_stream} bytes each direction)"
        )
        print(f"report: {report_path}")
        return 0
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        report = {
            "protocol": "MPX/4",
            "draft": "Draft 11",
            "gate": "Gate 1",
            "status": "FAIL",
            "git": git_metadata(),
            "started_unix": started,
            "duration_seconds": round(time.time() - started, 3),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"implementation B Gate 1: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {report_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
