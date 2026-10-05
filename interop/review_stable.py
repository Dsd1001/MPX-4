#!/usr/bin/env python3
"""MPX/4 Draft 11 stable-audit closure regressions.

Covers the stable-audit closure findings:
- legal unknown non-critical CLIENT_INIT/SERVER_INIT Parameters over real TCP;
- Session-owned reliable DATA after caller cancellation post-commit;
- Generation semantic-oracle negative controls for input-sensitive state transitions;
- Gate 4 negative controls for exact Mandatory IDs and per-case evidence recomputation.
R1's unauthenticated candidate-RST CLI regression is bound into J5 in
interop.endpoint_mandatory so it remains part of the Mandatory endpoint suite.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import tempfile
import time
from pathlib import Path
from typing import Awaitable, Callable

from tools import semantic_validation

from . import gate4_harness
from .endpoint_wire import Fixture, check, wait_until

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS = ("reference", "independent")
UNKNOWN_OPTIONAL_PARAMETER = 0x40


def append_optional_parameter(core, raw: bytes, message_type: int) -> bytes:
    actual_type, pos = core.vi_dec(raw)
    length, pos = core.vi_dec(raw, pos)
    check(actual_type == message_type, (actual_type, message_type))
    check(pos + length == len(raw), "handshake message boundary")
    body = raw[pos : pos + length]
    optional = core.encode_parameter(UNKNOWN_OPTIONAL_PARAMETER, 0, b"\x01")
    return core.encode_message(message_type, body + optional)


async def optional_parameter_case(implementation: str, role: str) -> dict:
    async with Fixture(implementation, role) as f:
        core = f.core
        if role == "server":
            original = core.encode_client_init

            def encode_client_init_with_optional(*args, **kwargs):
                return append_optional_parameter(
                    core,
                    original(*args, **kwargs),
                    core.MSG_CLIENT_INIT,
                )

            core.encode_client_init = encode_client_init_with_optional
            try:
                peer = await f.establish()
            finally:
                core.encode_client_init = original
        else:
            original = core.encode_server_init

            def encode_server_init_with_optional(*args, **kwargs):
                return append_optional_parameter(
                    core,
                    original(*args, **kwargs),
                    core.MSG_SERVER_INIT,
                )

            core.encode_server_init = encode_server_init_with_optional
            try:
                peer = await f.establish()
            finally:
                core.encode_server_init = original

        await f.ping(peer, 0xA401 if role == "server" else 0xA402)
        check(f.session.state == "ACTIVE", f.session.state)
        return {
            "endpoint_role": role,
            "parameter_type": UNKNOWN_OPTIONAL_PARAMETER,
            "critical": False,
            "established": True,
            "ping": True,
        }


async def case_optional_parameter_server(implementation: str) -> dict:
    return await optional_parameter_case(implementation, "server")


async def case_optional_parameter_client(implementation: str) -> dict:
    return await optional_parameter_case(implementation, "client")


async def grant_local_send_credit(f: Fixture, peer) -> None:
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
        lambda: f.session_credit()[1] >= 4096 and f.stream_credit(1)[1] >= 4096,
        label="stable-audit local send credit",
    )


async def cancelled_data_handoff_case(implementation: str, role: str) -> dict:
    async with Fixture(implementation, role) as f:
        peer = await f.establish()
        stream = await f.open_stream(peer)
        await grant_local_send_credit(f, peer)
        carrier = f.session.carriers[peer.carrier.carrier_id]
        output_lock = carrier.write_lock if hasattr(carrier, "write_lock") else carrier._lock

        await output_lock.acquire()
        task = asyncio.create_task(f.session.send_data(stream, b"abcd", carrier))
        try:
            await wait_until(
                lambda: (
                    f.session.session_send_committed >= 4
                    and stream.send_offset >= 4
                    and any(
                        tx.frame_type == f.core.FRAME_STREAM_DATA
                        and tx.txid in f.session.pending_response_txids
                        for tx in f.session.local_tx.values()
                    )
                ),
                label="post-commit DATA pending handoff",
            )
            data_tx = next(
                tx
                for tx in f.session.local_tx.values()
                if tx.frame_type == f.core.FRAME_STREAM_DATA
                and tx.txid in f.session.pending_response_txids
            )
            committed_before_cancel = f.session.session_send_committed
            offset_before_cancel = stream.send_offset
            task.cancel()
            result = await asyncio.gather(task, return_exceptions=True)
            check(result and isinstance(result[0], asyncio.CancelledError), result)
            check(data_tx.txid in f.session.pending_response_txids, f.session.pending_response_txids)
            check(f.session.session_send_committed == committed_before_cancel, f.session.session_send_committed)
            check(stream.send_offset == offset_before_cancel, stream.send_offset)
        finally:
            output_lock.release()

        # No caller-side/manual flusher is invoked here. The Session-owned
        # task created before the cancelled await must finish the Attempt itself.
        wire = await peer.recv_until(f.core.FRAME_STREAM_DATA)
        check(int(wire["transmission_id"]) == data_tx.txid, wire)
        check(int(wire["offset"]) == 0 and wire["data"] == b"abcd", wire)
        await wait_until(
            lambda: data_tx.txid not in f.session.pending_response_txids,
            label="automatic cancelled DATA dequeue",
        )
        await wait_until(
            lambda: not f.session.pending_work_tasks,
            label="automatic cancelled DATA worker completion",
        )

        await peer.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=data_tx.txid,
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: data_tx.settled, label="cancelled DATA settlement")
        await f.ping(peer, 0xA403 if role == "server" else 0xA404)
        return {
            "endpoint_role": role,
            "same_transmission_id": data_tx.txid,
            "commitment_bytes": committed_before_cancel,
            "send_offset": offset_before_cancel,
            "session_owned_after_cancel": True,
            "eventual_attempt": True,
            "settled": True,
        }


async def case_cancelled_data_server(implementation: str) -> dict:
    return await cancelled_data_handoff_case(implementation, "server")


async def case_cancelled_data_client(implementation: str) -> dict:
    return await cancelled_data_handoff_case(implementation, "client")


CASES: tuple[tuple[str, Callable[[str], Awaitable[dict]]], ...] = (
    ("optional-parameter-server", case_optional_parameter_server),
    ("optional-parameter-client", case_optional_parameter_client),
    ("cancelled-data-server", case_cancelled_data_server),
    ("cancelled-data-client", case_cancelled_data_client),
)


def semantic_check(condition: bool, detail: object) -> None:
    if not condition:
        raise semantic_validation.SemanticValidationError(str(detail))


def generation_oracle_negative_controls() -> dict:
    count = semantic_validation.validate_carrier_generation(ROOT, semantic_check)
    check(count == 16, count)
    source = json.loads((ROOT / "test-vectors" / "carrier-generation.json").read_text(encoding="utf-8"))

    variants = []
    failed_handshake = copy.deepcopy(source)
    item = next(c for c in failed_handshake["cases"] if c["name"] == "failed-higher-generation-handshake")
    item["candidate_result"] = "established"
    item["highest_accepted_generation_after"] = 999
    item["current_generation_after"] = 999
    variants.append(("failed-higher-generation-input-sensitive", failed_handshake))

    simultaneous = copy.deepcopy(source)
    item = next(c for c in simultaneous["cases"] if c["name"] == "simultaneous-equal-generation-candidates")
    item["candidate_generations"] = [1, 1]
    variants.append(("simultaneous-generation-derived", simultaneous))

    rejected = []
    for name, data in variants:
        with tempfile.TemporaryDirectory(prefix="mpx4-generation-negative-") as td:
            root = Path(td)
            vectors = root / "test-vectors"
            vectors.mkdir()
            (vectors / "carrier-generation.json").write_text(
                json.dumps(data, indent=2) + "\n",
                encoding="utf-8",
            )
            try:
                semantic_validation.validate_carrier_generation(root, semantic_check)
            except semantic_validation.SemanticValidationError:
                rejected.append(name)
            else:
                raise RuntimeError(f"Generation oracle accepted forged variant: {name}")
    return {"baseline_case_count": count, "rejected_variants": rejected}


def valid_profile_fixture() -> dict:
    cases = [
        {
            "id": case_id,
            "status": "PASS",
            "evidence_class": gate4_harness.EXPECTED_EVIDENCE[case_id],
        }
        for case_id in gate4_harness.MANDATORY_IDS
    ]
    evidence_counts = {
        name: sum(1 for case in cases if case["evidence_class"] == name)
        for name in ("model", "codec", "endpoint-wire", "cross-wire")
    }
    return {
        "status": "PASS",
        "mandatory_case_count": len(cases),
        "groups": {group: "PASS" for group in gate4_harness.GROUPS},
        "cases": cases,
        "evidence_counts": evidence_counts,
        "model_only_case_ids": [],
        "endpoint_wire_mandatory_case_ids": sorted(
            case["id"] for case in cases if case["evidence_class"] == "endpoint-wire"
        ),
        "endpoint_wire_execution_count": 91,
        "implementation": "stable-audit-control",
    }


def gate4_profile_negative_controls() -> dict:
    baseline = valid_profile_fixture()
    gate4_harness.verify_profile(baseline, "stable-audit-valid-control")

    forged_ids = copy.deepcopy(baseline)
    for index, case in enumerate(forged_ids["cases"]):
        case["id"] = f"Z{index + 1}"
    forged_ids["endpoint_wire_mandatory_case_ids"] = [
        f"Z{index + 1}" for index in range(73)
    ]

    forged_evidence = copy.deepcopy(baseline)
    forged_evidence["cases"][0]["evidence_class"] = "model"

    rejected = []
    for name, report in (
        ("non-mandatory-unique-id-set", forged_ids),
        ("per-case-evidence-summary-mismatch", forged_evidence),
    ):
        try:
            gate4_harness.verify_profile(report, name)
        except gate4_harness.Gate4Error:
            rejected.append(name)
        else:
            raise RuntimeError(f"Gate 4 profile verifier accepted forged report: {name}")
    return {"valid_control": True, "rejected_variants": rejected}


async def execute() -> dict:
    started = time.time()
    results = []
    for name, func in CASES:
        for implementation in IMPLEMENTATIONS:
            detail = await func(implementation)
            results.append(
                {
                    "case": name,
                    "implementation": implementation,
                    "status": "PASS",
                    "detail": detail,
                }
            )
            print(f"stable-audit {implementation}/{name}: PASS", flush=True)

    validator_controls = (
        ("generation-oracle-negative-controls", generation_oracle_negative_controls),
        ("gate4-profile-negative-controls", gate4_profile_negative_controls),
    )
    for name, func in validator_controls:
        detail = func()
        results.append(
            {
                "case": name,
                "implementation": "validator",
                "status": "PASS",
                "detail": detail,
            }
        )
        print(f"stable-audit validator/{name}: PASS", flush=True)

    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "stable-audit closure regression",
        "status": "PASS",
        "case_count": len(CASES) + len(validator_controls),
        "execution_count": len(results),
        "cases": results,
        "duration_seconds": round(time.time() - started, 3),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 stable-audit closure regressions")
    p.add_argument("--out-dir", type=Path, required=True)
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "review-stable-report.json"
    try:
        report = asyncio.run(execute())
    except Exception as exc:
        report = {
            "protocol": "MPX/4",
            "revision": "Draft 11",
            "suite": "stable-audit closure regression",
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"stable-audit regression: FAIL: {type(exc).__name__}: {exc}")
        print(f"report: {path}")
        return 1
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"stable-audit regression: PASS ({report['execution_count']} executions; "
        f"{report['case_count']} case classes)"
    )
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
