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
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from .endpoint_wire import run_one

IMPLEMENTATIONS = ("reference", "independent")


class SensitivityError(RuntimeError):
    pass


@dataclass
class MutationWitness:
    label: str
    hits: int = 0

    def mark(self) -> None:
        self.hits += 1


BASELINE_GUARDS: Tuple[Tuple[str, str], ...] = (
    ("server", "final-below-commitment"),
    ("server", "crossed-session-credit"),
    ("server", "fin-data-beyond-final"),
    ("server", "reset-late-data-suppressed"),
    ("server", "stop-sending-directionality"),
    ("server", "legal-overlap-reassembly"),
    ("server", "terminal-credit-beyond-final"),
    ("client", "tombstone-credit-beyond-final"),
    ("client", "tombstone-credit-invalid-pair"),
    ("client", "tombstone-credit-window-exceeded"),
    ("server", "tombstone-credit-beyond-final"),
    ("server", "tombstone-credit-invalid-pair"),
    ("server", "tombstone-credit-window-exceeded"),
    ("server", "padding-ignored"),
    ("server", "capacity-reject-replay"),
    ("server", "accepted-open-replay-tombstone"),
    ("client", "accepted-open-ok-replay-tombstone"),
    ("server", "unknown-core-session-scope"),
    ("client", "unknown-core-session-scope"),
    ("server", "invalid-preopen-stop-id"),
    ("client", "conflicting-open-reject"),
    ("server", "late-stop-tombstone"),
    ("server", "retired-fin-confirmation-replay"),
    ("server", "cross-carrier-reject-atomicity"),
    ("server", "retired-delayed-fin-recovery"),
    ("client", "retired-delayed-fin-recovery"),
)


def runtime_module(name: str):
    return importlib.import_module(
        "reference.gate2_runtime" if name == "reference" else "independent.gate_runtime"
    )


def session_class(name: str):
    module = runtime_module(name)
    return module.Gate2Session if name == "reference" else module.IndependentSession


def core_module(name: str):
    return importlib.import_module(
        "reference.mpx4_core" if name == "reference" else "independent.core"
    )


async def expect_case_failure(
    implementation: str,
    case_name: str,
    *,
    role: str = "server",
    witness: MutationWitness,
    runner: Optional[Callable[[str, str, str], Awaitable[dict]]] = None,
) -> dict:
    selected_runner = run_one if runner is None else runner
    hits_before = witness.hits
    try:
        await selected_runner(implementation, role, case_name)
    except Exception as exc:
        hits = witness.hits - hits_before
        if hits <= 0:
            raise SensitivityError(
                f"{implementation}/{case_name} failed before target mutation branch {witness.label} was reached: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return {
            "failure_type": type(exc).__name__,
            "failure": str(exc),
            "failure_stage": "post-target-guard",
            "target_hits": hits,
        }
    raise SensitivityError(
        f"{implementation}/{case_name} remained PASS after target mutation branch {witness.label} was reached"
    )


async def run_baseline_guards() -> List[dict]:
    results: List[dict] = []
    for implementation in IMPLEMENTATIONS:
        for role, case_name in BASELINE_GUARDS:
            await run_one(implementation, role, case_name)
            results.append(
                {
                    "implementation": implementation,
                    "role": role,
                    "case": case_name,
                    "status": "PASS",
                }
            )
    return results


async def run_oracle_negative_controls() -> List[dict]:
    results = []

    async def unrelated_setup_failure(*args, **kwargs):
        raise OSError("NEGATIVE CONTROL: unrelated fixture setup failed before any handler ran")

    for implementation in IMPLEMENTATIONS:
        witness = MutationWitness("negative-control-unreached")
        try:
            await expect_case_failure(
                implementation,
                "retired-fin-confirmation-replay",
                role="server",
                witness=witness,
                runner=unrelated_setup_failure,
            )
        except SensitivityError as exc:
            message = str(exc)
            if "failed before target mutation branch" not in message:
                raise
            results.append(
                {
                    "implementation": implementation,
                    "status": "PASS",
                    "handler_reached": False,
                    "classification": "ERROR/INCONCLUSIVE",
                    "reason": message,
                }
            )
        else:
            raise SensitivityError("unrelated setup failure was incorrectly accepted as mutation detection")
    return results


async def mutation_fail_session_noop(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.fail_session
    witness = MutationWitness("fail_session_noop")

    async def broken(self, *args, **kwargs):
        witness.mark()
        return None

    cls.fail_session = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "final-below-commitment",
            witness=witness,
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
    witness = MutationWitness("crossed_credit_accepted")
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
            if (new_consumed > old_consumed and new_maximum < old_maximum) or (
                new_consumed < old_consumed and new_maximum > old_maximum
            ):
                witness.mark()
            return new_consumed, new_maximum, "mutated-accept"

        cls.merge_credit_pair = broken
        try:
            observed = await expect_case_failure(
                implementation,
                "crossed-session-credit",
                witness=witness,
            )
        finally:
            cls.merge_credit_pair = original
    else:
        credit_cls = runtime.CreditPair
        original = credit_cls.accept

        def broken(self, consumed, maximum, window_limit, label):
            if (consumed > self.consumed and maximum < self.maximum) or (
                consumed < self.consumed and maximum > self.maximum
            ):
                witness.mark()
            self.consumed = consumed
            self.maximum = maximum
            return "mutated-accept"

        credit_cls.accept = broken
        try:
            observed = await expect_case_failure(
                implementation,
                "crossed-session-credit",
                witness=witness,
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
    witness = MutationWitness("final_offset_check_bypassed")

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        stream = self.streams.get(stream_id)
        saved = None if stream is None else stream.recv_final
        if stream is not None and saved is not None:
            end = int(fields["offset"]) + len(bytes(fields["data"]))
            if end > saved:
                witness.mark()
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
            witness=witness,
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
    witness = MutationWitness("reset_application_delivery_reenabled")

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        stream = self.streams.get(stream_id)
        saved = None if stream is None else stream.recv_terminal_mode
        if stream is not None and stream.recv_terminal_mode == "RESET":
            witness.mark()
            stream.recv_terminal_mode = "ACTIVE"
        try:
            return await original(self, incoming, fields)
        finally:
            if stream is not None:
                stream.recv_terminal_mode = saved

    cls.handle_stream_data = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "reset-late-data-suppressed",
            witness=witness,
        )
    finally:
        cls.handle_stream_data = original
    return {
        "mutation": "reset_application_delivery_reenabled",
        "guard_case": "reset-late-data-suppressed",
        "observed_failure": observed,
    }


async def mutation_stop_sending_conflates_receive_direction(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.handle_stop_sending
    witness = MutationWitness("stop_sending_conflates_receive_direction")

    async def broken(self, incoming, fields):
        await original(self, incoming, fields)
        stream = self.streams.get(int(fields["stream_id"]))
        if stream is not None:
            witness.mark()
            stream.recv_terminal_mode = "RESET"

    cls.handle_stop_sending = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "stop-sending-directionality",
            witness=witness,
        )
    finally:
        cls.handle_stop_sending = original
    return {
        "mutation": "stop_sending_conflates_receive_direction",
        "guard_case": "stop-sending-directionality",
        "observed_failure": observed,
    }


async def mutation_overlap_reassembly_exact_offset_only(implementation: str) -> dict:
    cls = session_class(implementation)
    witness = MutationWitness("overlap_reassembly_exact_offset_only")
    helper_name = "drain_contiguous_receive_data" if implementation == "reference" else "flush_contiguous_chunks"
    original = getattr(cls, helper_name)

    def broken(self, stream):
        witness.mark()
        while stream.recv_next in stream.recv_segments:
            chunk = stream.recv_segments.pop(stream.recv_next)
            stream.recv_data.extend(chunk)
            stream.recv_next += len(chunk)
            self.application_rx_bytes += len(chunk)

    setattr(cls, helper_name, broken)
    try:
        observed = await expect_case_failure(
            implementation,
            "legal-overlap-reassembly",
            witness=witness,
        )
    finally:
        setattr(cls, helper_name, original)
    return {
        "mutation": "overlap_reassembly_exact_offset_only",
        "guard_case": "legal-overlap-reassembly",
        "observed_failure": observed,
    }


async def mutation_terminal_credit_final_check_bypassed(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    cls = session_class(implementation)
    original = cls.handle_frame
    witness = MutationWitness("terminal_credit_final_check_bypassed")

    async def broken(self, incoming, frame_type, fields):
        stream = None
        saved = None
        if frame_type == runtime.FRAME_STREAM_CREDIT:
            stream = self.streams.get(int(fields["stream_id"]))
            if stream is not None:
                saved = stream.send_final
                if saved is not None and int(fields["consumed_offset"]) > saved:
                    witness.mark()
                stream.send_final = None
        try:
            return await original(self, incoming, frame_type, fields)
        finally:
            if stream is not None:
                stream.send_final = saved

    cls.handle_frame = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "terminal-credit-beyond-final",
            witness=witness,
        )
    finally:
        cls.handle_frame = original
    return {
        "mutation": "terminal_credit_final_check_bypassed",
        "guard_case": "terminal-credit-beyond-final",
        "observed_failure": observed,
    }


async def mutation_tombstone_credit_validation_bypassed(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    cls = session_class(implementation)
    original = cls.handle_frame
    witness = MutationWitness("tombstone_credit_validation_bypassed")

    async def broken(self, incoming, frame_type, fields):
        if frame_type == runtime.FRAME_STREAM_CREDIT:
            stream_id = int(fields["stream_id"])
            if stream_id not in self.streams and stream_id in self.tombstones:
                witness.mark()
                return
        return await original(self, incoming, frame_type, fields)

    guards = (
        "tombstone-credit-beyond-final",
        "tombstone-credit-invalid-pair",
        "tombstone-credit-window-exceeded",
    )
    observed = []
    cls.handle_frame = broken
    try:
        for role in ("client", "server"):
            for case_name in guards:
                failure = await expect_case_failure(
                    implementation,
                    case_name,
                    role=role,
                    witness=witness,
                )
                violation = case_name.removeprefix("tombstone-credit-")
                expected = (
                    f"retained tombstone STREAM_CREDIT {violation} did not close Session; "
                    "PING/PONG still succeeds"
                )
                if (
                    failure["failure_type"] != "ProbeError"
                    or not failure["failure"].startswith(expected)
                    or "all_local_tx_settled=True" not in failure["failure"]
                ):
                    raise SensitivityError(
                        f"tombstone mutation guard failed outside the credit check: {failure}"
                    )
                observed.append({"role": role, "case": case_name, "failure": failure})
    finally:
        cls.handle_frame = original
    return {
        "mutation": "tombstone_credit_validation_bypassed",
        "guard_case": guards[0],
        "guard_cases": list(guards),
        "observed_failures": observed,
    }


async def mutation_padding_not_ignored(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    cls = session_class(implementation)
    original = cls.handle_frame
    witness = MutationWitness("padding_not_ignored")

    async def broken(self, incoming, frame_type, fields):
        if frame_type == runtime.FRAME_PADDING:
            witness.mark()
            raise runtime.ProtocolError("mutated PADDING rejection")
        return await original(self, incoming, frame_type, fields)

    cls.handle_frame = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "padding-ignored",
            witness=witness,
        )
    finally:
        cls.handle_frame = original
    return {
        "mutation": "padding_not_ignored",
        "guard_case": "padding-ignored",
        "observed_failure": observed,
    }


async def mutation_capacity_reject_not_retained(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.handle_stream_open
    witness = MutationWitness("capacity_reject_not_retained")

    async def broken(self, incoming, fields):
        await original(self, incoming, fields)
        stream_id = int(fields["stream_id"])
        retained = self.opening_tombstones.get(stream_id)
        if retained is not None and int(retained.get("error_code", -1)) == 0x08:
            witness.mark()
            self.opening_tombstones.pop(stream_id, None)

    cls.handle_stream_open = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "capacity-reject-replay",
            role="server",
            witness=witness,
        )
    finally:
        cls.handle_stream_open = original
    return {
        "mutation": "capacity_reject_not_retained",
        "guard_case": "capacity-reject-replay",
        "observed_failure": observed,
    }


async def mutation_opening_decision_not_retained(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.retire_stream_to_tombstone
    witness = MutationWitness("opening_decision_not_retained")

    def broken(self, stream_id):
        tombstone = original(self, stream_id)
        witness.mark()
        tombstone["opening_txid"] = None
        tombstone["opening_decision"] = None
        return tombstone

    cls.retire_stream_to_tombstone = broken
    observed = []
    try:
        observed.append(
            await expect_case_failure(
                implementation,
                "accepted-open-replay-tombstone",
                role="server",
                witness=witness,
            )
        )
        observed.append(
            await expect_case_failure(
                implementation,
                "accepted-open-ok-replay-tombstone",
                role="client",
                witness=witness,
            )
        )
    finally:
        cls.retire_stream_to_tombstone = original
    return {
        "mutation": "opening_decision_not_retained",
        "guard_case": "accepted-open-replay-tombstone",
        "guard_cases": ["accepted-open-replay-tombstone", "accepted-open-ok-replay-tombstone"],
        "observed_failures": observed,
    }


async def mutation_unknown_core_not_session_scoped(implementation: str) -> dict:
    core = core_module(implementation)
    original = core.parse_frames
    witness = MutationWitness("unknown_core_not_session_scoped")

    def broken(plaintext, max_frame_payload):
        try:
            return original(plaintext, max_frame_payload)
        except core.FrameTypeProtocolError:
            witness.mark()
            return []

    core.parse_frames = broken
    observed = []
    try:
        for role in ("server", "client"):
            observed.append(
                await expect_case_failure(
                    implementation,
                    "unknown-core-session-scope",
                    role=role,
                    witness=witness,
                )
            )
    finally:
        core.parse_frames = original
    return {
        "mutation": "unknown_core_not_session_scoped",
        "guard_case": "unknown-core-session-scope",
        "observed_failures": observed,
    }


async def mutation_stream_id_parity_bypassed(implementation: str) -> dict:
    cls = session_class(implementation)
    helper_name = "validate_peer_stream_id" if implementation == "reference" else "require_peer_stream_id"
    original = getattr(cls, helper_name)
    witness = MutationWitness("stream_id_parity_bypassed")

    def broken(self, stream_id):
        if stream_id <= 0 or stream_id % 2 == 0:
            witness.mark()
        return None

    setattr(cls, helper_name, broken)
    try:
        observed = await expect_case_failure(
            implementation,
            "invalid-preopen-stop-id",
            role="server",
            witness=witness,
        )
    finally:
        setattr(cls, helper_name, original)
    return {
        "mutation": "stream_id_parity_bypassed",
        "guard_case": "invalid-preopen-stop-id",
        "observed_failure": observed,
    }


async def mutation_conflicting_open_reject_ignored(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    cls = session_class(implementation)
    original = cls.handle_frame
    witness = MutationWitness("conflicting_open_reject_ignored")

    async def broken(self, incoming, frame_type, fields):
        if frame_type == runtime.FRAME_STREAM_OPEN_REJECT:
            stream_id = int(fields["stream_id"])
            if stream_id not in self.streams and stream_id in self.opening_tombstones:
                witness.mark()
                return
        return await original(self, incoming, frame_type, fields)

    cls.handle_frame = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "conflicting-open-reject",
            role="client",
            witness=witness,
        )
    finally:
        cls.handle_frame = original
    return {
        "mutation": "conflicting_open_reject_ignored",
        "guard_case": "conflicting-open-reject",
        "observed_failure": observed,
    }


async def mutation_terminal_tombstone_stop_reopens(implementation: str) -> dict:
    cls = session_class(implementation)
    original = cls.handle_stop_sending
    witness = MutationWitness("terminal_tombstone_stop_reopens")

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        tombstone = self.tombstones.pop(stream_id, None)
        if tombstone is not None:
            witness.mark()
        try:
            return await original(self, incoming, fields)
        finally:
            if tombstone is not None:
                self.tombstones[stream_id] = tombstone

    cls.handle_stop_sending = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "late-stop-tombstone",
            role="server",
            witness=witness,
        )
    finally:
        cls.handle_stop_sending = original
    return {
        "mutation": "terminal_tombstone_stop_reopens",
        "guard_case": "late-stop-tombstone",
        "observed_failure": observed,
    }


async def mutation_retired_confirmation_replay_bypassed(implementation: str) -> dict:
    cls = session_class(implementation)
    helper_name = "replay_retired_reliable" if implementation == "reference" else "handle_retired_replay"
    original = getattr(cls, helper_name)
    witness = MutationWitness("retired_confirmation_replay_bypassed")

    async def broken(self, incoming, frame_type, fields):
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        if (
            stream_id in self.retired_stream_ids
            and txid > self.peer_retired_through
            and txid in self.peer_tx_semantics
        ):
            witness.mark()
            return False
        return await original(self, incoming, frame_type, fields)

    setattr(cls, helper_name, broken)
    try:
        observed = await expect_case_failure(
            implementation,
            "retired-fin-confirmation-replay",
            role="server",
            witness=witness,
        )
    finally:
        setattr(cls, helper_name, original)
    return {
        "mutation": "retired_confirmation_replay_bypassed",
        "guard_case": "retired-fin-confirmation-replay",
        "observed_failure": observed,
    }


async def mutation_opening_reject_commit_after_send(implementation: str) -> dict:
    runtime = runtime_module(implementation)
    cls = session_class(implementation)
    original = cls.handle_stream_open
    witness = MutationWitness("opening_reject_commit_after_send")

    async def broken(self, incoming, fields):
        stream_id = int(fields["stream_id"])
        if (
            self.role == "server"
            and stream_id not in self.streams
            and stream_id not in self.opening_tombstones
            and stream_id not in self.tombstones
            and stream_id not in self.retired_stream_ids
            and len(self.streams) >= self.local_limits.max_streams
        ):
            validator = (
                self.validate_peer_stream_id
                if implementation == "reference"
                else self.require_peer_stream_id
            )
            validator(stream_id)
            txid = int(fields["transmission_id"])
            self.register_peer_tx(runtime.FRAME_STREAM_OPEN, fields)
            response = {
                "stream_id": stream_id,
                "transmission_id": txid,
                "error_code": 0x08,
            }
            target = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            witness.mark()
            await self.send_frame(target, runtime.FRAME_STREAM_OPEN_REJECT, **response)
            self.peer_tx_confirmation[txid] = (runtime.FRAME_STREAM_OPEN_REJECT, response)
            self.opening_tombstones[stream_id] = {
                "opening_txid": txid,
                "decision": "rejected",
                "opening_decision": "rejected",
                "error_code": 0x08,
            }
            return
        return await original(self, incoming, fields)

    cls.handle_stream_open = broken
    try:
        observed = await expect_case_failure(
            implementation,
            "cross-carrier-reject-atomicity",
            role="server",
            witness=witness,
        )
    finally:
        cls.handle_stream_open = original
    return {
        "mutation": "opening_reject_commit_after_send",
        "guard_case": "cross-carrier-reject-atomicity",
        "observed_failure": observed,
    }


async def mutation_retired_first_arrival_recovery_bypassed(implementation: str) -> dict:
    cls = session_class(implementation)
    helper_name = "replay_retired_reliable" if implementation == "reference" else "handle_retired_replay"
    original = getattr(cls, helper_name)
    witness = MutationWitness("retired_first_arrival_recovery_bypassed")

    async def broken(self, incoming, frame_type, fields):
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        if (
            stream_id in self.retired_stream_ids
            and txid > self.peer_retired_through
            and txid not in self.peer_tx_semantics
        ):
            witness.mark()
            return False
        return await original(self, incoming, frame_type, fields)

    setattr(cls, helper_name, broken)
    observed = []
    try:
        for role in ("server", "client"):
            observed.append(
                await expect_case_failure(
                    implementation,
                    "retired-delayed-fin-recovery",
                    role=role,
                    witness=witness,
                )
            )
    finally:
        setattr(cls, helper_name, original)
    return {
        "mutation": "retired_first_arrival_recovery_bypassed",
        "guard_case": "retired-delayed-fin-recovery",
        "guard_roles": ["server", "client"],
        "observed_failures": observed,
    }


MUTATIONS: List[Callable[[str], Awaitable[dict]]] = [
    mutation_fail_session_noop,
    mutation_crossed_credit_accepted,
    mutation_final_offset_bypassed,
    mutation_reset_delivery_reenabled,
    mutation_stop_sending_conflates_receive_direction,
    mutation_overlap_reassembly_exact_offset_only,
    mutation_terminal_credit_final_check_bypassed,
    mutation_tombstone_credit_validation_bypassed,
    mutation_padding_not_ignored,
    mutation_capacity_reject_not_retained,
    mutation_opening_decision_not_retained,
    mutation_unknown_core_not_session_scoped,
    mutation_stream_id_parity_bypassed,
    mutation_conflicting_open_reject_ignored,
    mutation_terminal_tombstone_stop_reopens,
    mutation_retired_confirmation_replay_bypassed,
    mutation_opening_reject_commit_after_send,
    mutation_retired_first_arrival_recovery_bypassed,
]


async def amain() -> dict:
    started = time.time()
    baseline = await run_baseline_guards()
    negative_controls = await run_oracle_negative_controls()
    results = []
    for implementation in IMPLEMENTATIONS:
        for mutation in MUTATIONS:
            result = await mutation(implementation)
            result.update(
                {
                    "implementation": implementation,
                    "status": "PASS",
                    "meaning": (
                        "deliberate runtime defect reached its target mutation branch and "
                        "then made the guarded endpoint-wire case fail"
                    ),
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
        "baseline_status": "PASS",
        "baseline_control_count": len(baseline),
        "baseline_controls": baseline,
        "negative_control_status": "PASS",
        "negative_control_count": len(negative_controls),
        "negative_controls": negative_controls,
        "control_count": len(results),
        "controls": results,
        "duration_seconds": round(time.time() - started, 3),
        "claim": (
            "Unmutated guard scenarios pass first; every listed real-runtime mutation must "
            "reach its target branch before the guarded endpoint-wire case fails; unrelated "
            "pre-handler setup failures are classified ERROR/INCONCLUSIVE rather than mutation detection."
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
        print(
            f"endpoint sensitivity: PASS ({report['control_count']} deliberate defects detected; "
            f"{report['baseline_control_count']} baselines; "
            f"{report['negative_control_count']} oracle negative controls)"
        )
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
