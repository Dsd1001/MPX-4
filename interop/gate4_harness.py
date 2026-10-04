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
    return {
        "status": "PASS",
        "python_files_checked": len(python_files),
        "forbidden_import_violations": [],
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
    return {
        "status": "PASS",
        "mandatory_case_count": MANDATORY_COUNT,
        "groups": groups,
        "implementation": report.get("implementation"),
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
        "cross_basic_role_reversal": basic,
        "cross_fault_role_reversal": faults,
        "cross_basic_run_count": len(basic),
        "cross_fault_scenario_execution_count": cross_fault_scenarios,
        "fragmented_write_chunk": 257,
        "mandatory_result": {
            "implementation_a": "121/121 PASS",
            "implementation_b": "121/121 PASS",
            "groups_a_through_l": "PASS for both implementations",
        },
        "claim": (
            "Gate 4 PASS: two source-isolated MPX/4 implementations each pass the "
            "121-case A-L Mandatory profile and interoperate over real TCP in both "
            "client/server role directions for the basic full-duplex profile and the "
            "five deterministic multi-Carrier/fault scenarios, both direct and with "
            "257-byte endpoint write fragmentation."
        ),
        "claim_boundary": (
            "Implementation B shares this repository, protocol fixtures, and test scenario design "
            "with Implementation A. It imports no reference/tools/validator runtime source, but the "
            "result is not a claim of independent development by an external organization."
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
            "Gate 4: PASS "
            "(A=121/121, B=121/121, "
            f"{report['cross_basic_run_count']} cross-basic runs, "
            f"{report['cross_fault_scenario_execution_count']} cross-fault scenario executions)"
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
