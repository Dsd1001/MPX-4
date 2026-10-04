#!/usr/bin/env python3
"""Coverage-sensitivity controls for MPX/4 authenticated endpoint tests.

This suite deliberately breaks the real endpoint runtime in memory.  A
sensitivity control passes only when the corresponding endpoint-wire test then
fails.  It prevents a future Gate from remaining green while the handler it is
supposed to exercise has been bypassed.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import time
from pathlib import Path
from typing import Awaitable, Callable, Dict, List

from .endpoint_wire import run_one

IMPLEMENTATIONS = ("reference", "independent")


class SensitivityError(RuntimeError):
    pass


def runtime_module(name: str):
    return importlib.import_module(
        "reference.gate2_runtime" if name == "reference" else "independent.gate_runtime"
    )


def session_class(name: str):
    module = runtime_module(name)
    return module.Gate2Session if name == "reference" else module.IndependentSession


async def expect_case_failure(
    implementation: str,
    case_name: str,
    *,
    role: str = "server",
) -> str:
    try:
        await run_one(implementation, role, case_name)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    raise SensitivityError(
        f"{implementation}/{case_name} remained PASS after its runtime handler was deliberately broken"
    )


async def mutation_fail_session_noop(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.fail_session

    async def broken(self, *args, **kwargs):
        return None

    cls.fail_session = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "final-below-commitment",
        )
    finally:
        cls.fail_session = original
    return {
        "mutation": "fail_session_noop",
        "guard_case": "final-below-commitment",
        "observed_failure": observed,
    }


async def mutation_crossed_credit_accepted(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    if implementation == "reference":
        cls = session_class(implementation)
        original = cls.merge_credit_pair

        def broken(
            self,
            old_consumed,
            old_maximum,
            new_consumed,
            new_maximum,
            window_limit,
            label,
        ):
            return new_consumed, new_maximum, "mutated-accept"

        cls.merge_credit_pair = broken
        try:
            observed = await expect_case_failure(
                implementation,
                "crossed-session-credit",
            )
        finally:
            cls.merge_credit_pair = original
    else:
        credit_cls = runtime.CreditPair
        original = credit_cls.accept

        def broken(self, consumed, maximum, window_limit, label):
            self.consumed = consumed
            self.maximum = maximum
            return "mutated-accept"

        credit_cls.accept = broken
        try:
            observed = await expect_case_failure(
                implementation,
                "crossed-session-credit",
            )
        finally:
            credit_cls.accept = original
    return {
        "mutation": "crossed_credit_accepted",
        "guard_case": "crossed-session-credit",
        "observed_failure": observed,
    }


async def mutation_final_offset_bypassed(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.handle_stream_data

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        stream = self.streams.get(stream_id)
        saved = None if stream is None else stream.recv_final
        if stream is not None:
            stream.recv_final = None
        try:
            return await original(self, incoming, fields)
        finally:
            if stream is not None:
                stream.recv_final = saved

    cls.handle_stream_data = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "fin-data-beyond-final",
        )
    finally:
        cls.handle_stream_data = original
    return {
        "mutation": "final_offset_check_bypassed",
        "guard_case": "fin-data-beyond-final",
        "observed_failure": observed,
    }


async def mutation_reset_delivery_reenabled(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.handle_stream_data

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        stream = self.streams.get(stream_id)
        saved = None if stream is None else stream.terminal_mode
        if stream is not None and stream.terminal_mode == "RESET":
            stream.terminal_mode = "ACTIVE"
        try:
            return await original(self, incoming, fields)
        finally:
            if stream is not None:
                stream.terminal_mode = saved

    cls.handle_stream_data = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "reset-late-data-suppressed",
        )
    finally:
        cls.handle_stream_data = original
    return {
        "mutation": "reset_application_delivery_reenabled",
        "guard_case": "reset-late-data-suppressed",
        "observed_failure": observed,
    }


MUTATIONS: List[Callable[[str], Awaitable[dict]]] = [
    mutation_fail_session_noop,
    mutation_crossed_credit_accepted,
    mutation_final_offset_bypassed,
    mutation_reset_delivery_reenabled,
]


async def amain() -> dict:
    started = time.time()
    results = []
    for implementation in IMPLEMENTATIONS:
        for mutation in MUTATIONS:
            result = await mutation(implementation)
            result.update(
                {
                    "implementation": implementation,
                    "status": "PASS",
                    "meaning": "deliberate runtime defect made the guarded endpoint-wire case fail",
                }
            )
            results.append(result)
            print(
                f"sensitivity {implementation}/{result['mutation']}: PASS "
                f"(guard={result['guard_case']})",
                flush=True,
            )
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "endpoint coverage sensitivity",
        "status": "PASS",
        "control_count": len(results),
        "controls": results,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "Each listed real-runtime mutation is detected by a specific authenticated "
            "endpoint-wire case; a green model-only profile cannot mask these defects."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 endpoint coverage sensitivity controls")
    p.add_argument("--out-dir", type=Path, required=True)
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "endpoint-sensitivity-report.json"
    try:
        report = asyncio.run(amain())
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"endpoint sensitivity: PASS ({report['control_count']} deliberate defects detected)")
        print(f"report: {path}")
        return 0
    except Exception as exc:
        path.write_text(
            json.dumps(
                {
                    "protocol": "MPX/4",
                    "revision": "Draft 11",
                    "suite": "endpoint coverage sensitivity",
                    "status": "FAIL",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"endpoint sensitivity: FAIL: {type(exc).__name__}: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
