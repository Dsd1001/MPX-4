#!/usr/bin/env python3
"""MPX/4 Draft 11 Gate 4 aggregate A/B interoperability harness.

Gate 4 requires:
- Implementation A (reference/) complete A-L Mandatory profile;
- source-isolated Implementation B (independent/) complete A-L Mandatory profile;
- no B runtime imports from reference/, tools/, or validator code;
- real TCP A->B and B->A basic full-duplex role reversal;
- real TCP A->B and B->A multi-Carrier/fault role reversal;
- the same cross-implementation runs with fragmented endpoint writes.

"Independent" here means separate runtime source/modules with no code import
dependency between A and B. Both implementations live in this repository and
were produced by the same project; this harness does not claim organizational
or third-party independence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
GROUPS = tuple("ABCDEFGHIJKL")
MANDATORY_COUNT = 121


class Gate4Error(RuntimeError):
    pass


def check(cond: bool, msg: object) -> None:
    if not cond:
        raise Gate4Error(str(msg))


def run(cmd: List[str], timeout: float = 240.0) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if cp.returncode != 0:
        raise Gate4Error(
            "command failed: "
            + " ".join(cmd)
            + f"\nstdout={cp.stdout}\nstderr={cp.stderr}"
        )
    return cp


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def implementation_b_dependency_audit() -> dict:
    forbidden_roots = {"reference", "tools"}
    violations = []
    python_files = sorted((ROOT / "independent").glob("*.py"))
    for path in python_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in forbidden_roots or root in {"semantic_validation", "validate"}:
                        violations.append({"file": path.name, "import": alias.name})
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    root = node.module.split(".", 1)[0]
                    if root in forbidden_roots or root in {"semantic_validation", "validate"}:
                        violations.append({"file": path.name, "import": node.module})
    check(not violations, f"Implementation B dependency isolation failed: {violations}")

    a_core = ROOT / "reference" / "mpx4_core.py"
    b_core = ROOT / "independent" / "core.py"
    a_endpoint = ROOT / "reference" / "endpoint.py"
    b_endpoint = ROOT / "independent" / "endpoint.py"
    hashes = {
        "reference_core_sha256": sha256(a_core),
        "independent_core_sha256": sha256(b_core),
        "reference_endpoint_sha256": sha256(a_endpoint),
        "independent_endpoint_sha256": sha256(b_endpoint),
    }
    check(hashes["reference_core_sha256"] != hashes["independent_core_sha256"], "A/B core source identical")
    check(hashes["reference_endpoint_sha256"] != hashes["independent_endpoint_sha256"], "A/B endpoint source identical")

    def function_asts(path: Path) -> Dict[str, str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return {
            node.name: ast.dump(node, include_attributes=False)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    critical = (
        "handle_frame",
        "handle_stream_data",
        "handle_stream_fin",
        "handle_reset_stream",
        "receive_loop",
    )
    a_runtime = function_asts(ROOT / "reference" / "gate2_runtime.py")
    b_runtime = function_asts(ROOT / "independent" / "gate_runtime.py")
    critical_ast = {
        name: {
            "present_in_a": name in a_runtime,
            "present_in_b": name in b_runtime,
            "ast_identical": a_runtime.get(name) == b_runtime.get(name),
        }
        for name in critical
    }
    check(
        all(v["present_in_a"] and v["present_in_b"] and not v["ast_identical"] for v in critical_ast.values()),
        f"A/B critical runtime handlers are not structurally isolated: {critical_ast}",
    )
    return {
        "status": "PASS",
        "python_files_checked": len(python_files),
        "forbidden_import_violations": [],
        "critical_runtime_ast_comparison": critical_ast,
        **hashes,
        "independence_scope": (
            "runtime source/module isolation only; both implementations are in the same "
            "repository/project and this does not claim external organizational independence"
        ),
    }


def verify_profile(report: dict, label: str) -> dict:
    check(report.get("status") == "PASS", f"{label} profile not PASS")
    check(report.get("mandatory_case_count") == MANDATORY_COUNT, f"{label} case count")
    groups = report.get("groups") or {}
    check(set(groups) == set(GROUPS), f"{label} group keys")
    check(all(groups[g] == "PASS" for g in GROUPS), f"{label} group failure")
    cases = report.get("cases") or []
    check(len(cases) == MANDATORY_COUNT, f"{label} report cases")
    check(all(c.get("status") == "PASS" for c in cases), f"{label} case failure")
    ids = [c.get("id") for c in cases]
    check(len(set(ids)) == MANDATORY_COUNT, f"{label} duplicate case ID")
    evidence_counts = report.get("evidence_counts") or {}
    check(set(evidence_counts) == {"model", "codec", "endpoint-wire", "cross-wire"}, f"{label} evidence classes")
    check(sum(int(v) for v in evidence_counts.values()) == MANDATORY_COUNT, f"{label} evidence count total")
    model_only = report.get("model_only_case_ids") or []
    endpoint_ids = report.get("endpoint_wire_mandatory_case_ids") or []
    check(len(model_only) == int(evidence_counts["model"]), f"{label} model-only count")
    check(not model_only and int(evidence_counts["model"]) == 0, f"{label} still has model-only Mandatory cases")
    check(len(endpoint_ids) == int(evidence_counts["endpoint-wire"]), f"{label} endpoint-wire count")
    check(int(evidence_counts["endpoint-wire"]) == 73, f"{label} endpoint-wire Mandatory count")
    check(int(report.get("endpoint_wire_execution_count") or 0) >= 91, f"{label} endpoint-wire executions")
    return {
        "status": "PASS",
        "mandatory_case_count": MANDATORY_COUNT,
        "groups": groups,
        "implementation": report.get("implementation"),
        "evidence_counts": evidence_counts,
        "endpoint_wire_execution_count": report.get("endpoint_wire_execution_count"),
        "endpoint_wire_mandatory_case_ids": endpoint_ids,
        "model_only_case_ids": model_only,
    }


def run_cross_basic(out: Path, client: str, server: str, chunk: int) -> dict:
    d = out / f"basic-{client}-client__{server}-server-chunk{chunk}"
    cmd = [
        sys.executable,
        "-m",
        "interop.cross_basic",
        "--client",
        client,
        "--server",
        server,
        "--out-dir",
        str(d),
    ]
    if chunk:
        cmd += ["--write-chunk", str(chunk)]
    run(cmd)
    r = read(d / "cross-basic-report.json")
    check(r.get("status") == "PASS", r)
    return {
        "status": "PASS",
        "client": client,
        "server": server,
        "write_chunk": chunk,
        "streams": r["streams"],
        "bytes_each_direction": r["bytes_each_direction"],
        "session_id": r["session_id"],
    }


def run_cross_fault(out: Path, client: str, server: str, chunk: int) -> dict:
    d = out / f"fault-{client}-client__{server}-server-chunk{chunk}"
    cmd = [
        sys.executable,
        "-m",
        "interop.cross_fault",
        "--client",
        client,
        "--server",
        server,
        "--out-dir",
        str(d),
    ]
    if chunk:
        cmd += ["--write-chunk", str(chunk)]
    run(cmd)
    r = read(d / "cross-fault-report.json")
    check(r.get("status") == "PASS", r)
    cases = r.get("cases") or []
    check(len(cases) == 5 and all(c.get("status") == "PASS" for c in cases), "fault scenario coverage")
    return {
        "status": "PASS",
        "client": client,
        "server": server,
        "write_chunk": chunk,
        "scenario_count": len(cases),
        "scenarios": [c["scenario"] for c in cases],
    }


def execute(out_dir: Path) -> dict:
    started = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    audit = implementation_b_dependency_audit()

    ref_dir = out_dir / "reference-mandatory-profile"
    b_dir = out_dir / "independent-mandatory-profile"
    run([sys.executable, "-m", "reference.gate3_harness", "--out-dir", str(ref_dir)])
    run([sys.executable, "-m", "independent.profile", "--out-dir", str(b_dir)])
    ref_profile = verify_profile(read(ref_dir / "gate3-report.json"), "reference")
    b_profile = verify_profile(read(b_dir / "mandatory-profile-report.json"), "independent")
    check(
        ref_profile["evidence_counts"] == b_profile["evidence_counts"],
        "A/B profile evidence classification differs",
    )

    endpoint_wire_dir = out_dir / "endpoint-wire-both"
    endpoint_mandatory_dir = out_dir / "endpoint-mandatory-both"
    sensitivity_dir = out_dir / "endpoint-sensitivity"
    review_v2_dir = out_dir / "review-v2"
    review_update_dir = out_dir / "review-update"
    run([
        sys.executable,
        "-m",
        "interop.endpoint_wire",
        "--out-dir",
        str(endpoint_wire_dir),
    ])
    endpoint_wire = read(endpoint_wire_dir / "endpoint-wire-report.json")
    check(endpoint_wire.get("status") == "PASS", "aggregate endpoint-wire suite failed")
    check(endpoint_wire.get("execution_count") == 200, "expected 200 baseline authenticated endpoint-wire executions")
    run([
        sys.executable,
        "-m",
        "interop.endpoint_mandatory",
        "--out-dir",
        str(endpoint_mandatory_dir),
    ])
    endpoint_mandatory = read(endpoint_mandatory_dir / "endpoint-mandatory-report.json")
    check(endpoint_mandatory.get("status") == "PASS", "formerly-model-only endpoint suite failed")
    check(endpoint_mandatory.get("execution_count") == 86, "expected 86 A/B formerly-model-only endpoint executions")
    check(len(endpoint_mandatory.get("covered_mandatory_ids") or []) == 42, "formerly-model-only suite ID coverage")
    run([
        sys.executable,
        "-m",
        "interop.endpoint_sensitivity",
        "--out-dir",
        str(sensitivity_dir),
    ])
    sensitivity = read(sensitivity_dir / "endpoint-sensitivity-report.json")
    check(sensitivity.get("status") == "PASS", "endpoint sensitivity suite failed")
    check(sensitivity.get("baseline_status") == "PASS", "endpoint sensitivity baseline controls failed")
    check(sensitivity.get("baseline_control_count") == 52, "expected 52 unmutated sensitivity baselines")
    check(sensitivity.get("negative_control_status") == "PASS", "endpoint sensitivity oracle negative controls failed")
    check(sensitivity.get("negative_control_count") == 2, "expected two sensitivity oracle negative controls")
    check(sensitivity.get("control_count") == 36, "expected thirty-six deliberate-defect sensitivity controls")

    run([
        sys.executable,
        "-m",
        "interop.review_v2",
        "--out-dir",
        str(review_v2_dir),
    ])
    review_v2 = read(review_v2_dir / "review-v2-report.json")
    check(review_v2.get("status") == "PASS", "review-v2 counterexample regression failed")
    check(review_v2.get("case_count") == 10, "expected ten review-v2 case classes")
    check(review_v2.get("execution_count") == 20, "expected twenty A/B review-v2 executions")

    run([
        sys.executable,
        "-m",
        "interop.review_update",
        "--out-dir",
        str(review_update_dir),
    ])
    review_update = read(review_update_dir / "review-update-report.json")
    check(review_update.get("status") == "PASS", "update-review regression failed")
    check(review_update.get("case_count") == 9, "expected nine update-review case classes")
    check(review_update.get("execution_count") == 18, "expected eighteen A/B update-review executions")

    basic = []
    faults = []
    for chunk in (0, 257):
        basic.append(run_cross_basic(out_dir, "reference", "independent", chunk))
        basic.append(run_cross_basic(out_dir, "independent", "reference", chunk))
        faults.append(run_cross_fault(out_dir, "reference", "independent", chunk))
        faults.append(run_cross_fault(out_dir, "independent", "reference", chunk))

    check(len(basic) == 4 and all(x["status"] == "PASS" for x in basic), "basic role reversal")
    check(len(faults) == 4 and all(x["status"] == "PASS" for x in faults), "fault role reversal")
    cross_fault_scenarios = sum(int(x["scenario_count"]) for x in faults)
    check(cross_fault_scenarios == 20, "expected 20 cross fault scenario executions")

    head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "status", "--porcelain"]).stdout.strip())
    return {
        "protocol": "MPX/4",
        "protocol_version": 4,
        "revision": "Draft 11",
        "binding": "TCP",
        "gate": "Gate 4",
        "status": "PASS",
        "git": {"head_sha": head, "dirty": dirty},
        "duration_seconds": round(time.time() - started, 3),
        "implementation_a": ref_profile,
        "implementation_b": b_profile,
        "implementation_b_dependency_audit": audit,
        "authenticated_endpoint_wire": {
            "status": endpoint_wire["status"],
            "baseline_execution_count": endpoint_wire["execution_count"],
            "formerly_model_only_execution_count": endpoint_mandatory["execution_count"],
            "total_execution_count": int(endpoint_wire["execution_count"]) + int(endpoint_mandatory["execution_count"]),
            "formerly_model_only_covered_ids": endpoint_mandatory.get("covered_mandatory_ids", []),
        },
        "endpoint_coverage_sensitivity": {
            "status": sensitivity["status"],
            "control_count": sensitivity["control_count"],
            "baseline_status": sensitivity["baseline_status"],
            "baseline_control_count": sensitivity["baseline_control_count"],
            "negative_control_status": sensitivity["negative_control_status"],
            "negative_control_count": sensitivity["negative_control_count"],
        },
        "review_v2_regression": {
            "status": review_v2["status"],
            "case_count": review_v2["case_count"],
            "execution_count": review_v2["execution_count"],
        },
        "review_update_regression": {
            "status": review_update["status"],
            "case_count": review_update["case_count"],
            "execution_count": review_update["execution_count"],
        },
        "cross_basic_role_reversal": basic,
        "cross_fault_role_reversal": faults,
        "cross_basic_run_count": len(basic),
        "cross_fault_scenario_execution_count": cross_fault_scenarios,
        "fragmented_write_chunk": 257,
        "mandatory_result": {
            "implementation_a_profile": "121/121 PASS",
            "implementation_b_profile": "121/121 PASS",
            "groups_a_through_l": "PASS for both executable-evidence profiles",
            "evidence_counts_per_implementation": ref_profile["evidence_counts"],
            "model_only_case_count": 0,
            "complete_executable_mandatory_profile": True,
            "all_121_cases_are_endpoint_wire": False,
            "evidence_boundary": "18 codec, 30 cross-wire, 73 endpoint-wire Mandatory case IDs per implementation",
        },
        "claim": (
            "Gate 4 aggregate PASS: both source-isolated runtimes pass all 121 A-L Mandatory case IDs with no model-only evidence; "
            "200 baseline authenticated endpoint-wire executions, 86 formerly-model-only endpoint executions, thirty-six target-witnessed "
            "sensitivity mutations after 52 unmutated baselines and two oracle negative controls, twenty A/B executions covering ten "
            "review-v2 regressions, and eighteen A/B executions covering nine update-review counterexample/control classes all pass; "
            "A/B real-TCP role reversal passes the basic and five fault profiles "
            "in direct and fragmented modes."
        ),
        "claim_boundary": (
            "No Mandatory case is model-only, but not every Mandatory case is classified endpoint-wire: codec and cross-wire evidence remain "
            "the appropriate executable evidence for 48 cases. Implementation B shares this repository, fixtures, and test design with "
            "Implementation A, so no external organizational independence is claimed."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 Gate 4 aggregate interoperability harness")
    p.add_argument("--out-dir", type=Path, default=ROOT / ".reference-artifacts" / "gate4")
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "gate4-report.json"
    try:
        report = execute(args.out_dir)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            "Gate 4 aggregate: PASS "
            "(A profile=121/121, B profile=121/121, "
            f"endpoint-wire={report['authenticated_endpoint_wire']['total_execution_count']}, "
            f"sensitivity={report['endpoint_coverage_sensitivity']['control_count']}, "
            f"review-v2={report['review_v2_regression']['execution_count']}, "
            f"review-update={report['review_update_regression']['execution_count']}, "
            f"{report['cross_basic_run_count']} cross-basic, "
            f"{report['cross_fault_scenario_execution_count']} cross-fault executions)"
        )
        print(f"report: {path}")
        return 0
    except Exception as exc:
        path.write_text(
            json.dumps(
                {
                    "protocol": "MPX/4",
                    "revision": "Draft 11",
                    "gate": "Gate 4",
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
        print(f"Gate 4: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
