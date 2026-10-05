# MPX/4 Draft 11 neutral interoperability harnesses

This directory orchestrates tests between the two executable implementations without importing either implementation's protocol runtime.

## Harnesses

- cross_basic.py — launches a selected Client and Server implementation as separate processes and verifies handshake establishment, explicit credit-before-DATA ordering, 16 concurrent Streams, full duplex, per-Stream byte counts/digests, FIN completion, and 1 MiB in each direction.
- cross_fault.py — launches the five deterministic multi-Carrier/fault scenarios across selected implementations and verifies JOIN/reinjection, duplicate suppression, DORMANT recovery, ambiguous SERVER_FINISHED recovery, FIN/RESET/retirement behavior, and Session-scoped TRANSMISSION_ID_ERROR.
- endpoint_wire.py — drives the real A/B Session runtimes over loopback TCP with full CREATE/Finished and authenticated Secure Records. In addition to flow-control, terminal, reassembly and error-scope checks, it covers legal PADDING and extension skipping, Session-scoped unknown Core Frames, pre-open Stream-ID validation, immutable STREAM_OPEN decisions/rejection reasons, terminal tombstone STOP_SENDING, and confirmation replay after retained state is compacted into a retired identity.
- endpoint_mandatory.py — executes the previously model-only Mandatory requirements against the real runtimes: version/reject handling, identifier exhaustion, Carrier capacity/replacement, reliable confirmation retirement, opening/cancellation races, tombstones, DORMANT retirement, candidate concurrency, and TCP/close behavior. It contributes 43 executions per implementation / 86 total and covers 42 unique Mandatory IDs.
- endpoint_sensitivity.py — deliberately breaks eighteen real handler contracts in each implementation. Every guard has an unmutated baseline, every mutation must hit its target branch before failure counts as detection, and four oracle negative controls prove unrelated infrastructure failures are ERROR/INCONCLUSIVE both before and after target witness. The controls cover the earlier flow-control/reassembly/tombstone/F1–F8 regressions plus cross-Carrier reject commit ordering and retired first-arrival recovery.
- review_v2.py — preserves the earlier 10-class / 20-execution review-v2 concurrency/output/progress evidence.
- review_update.py — adds 9 case classes / 18 A/B executions for the update review: post-Finished stale installation, STOP default-RESET persistence across ACK output failure, exact retirement-prefix accounting, key-exhaustion failover, and paired normal controls.
- review_followup.py — adds 11 case classes / 22 A/B executions from the independent replay: terminal Client late-JOIN installation, pre-open STOP response persistence, cross-Carrier output actor isolation/recovery, immutable DATA payload ownership, fail-atomic oversized DATA rejection, and paired normal controls.
- review_b66.py — adds 10 case classes / 20 A/B executions for the b66 follow-up: Client/Server CREDIT_PROBE response recovery, repeated ACK-output failover with retained RESET progress, Transmission-ID exhaustion closure, and empty/one-byte DATA boundaries.
- review_stable.py — adds 6 case classes / 10 executions for stable-audit closure: 8 A/B runtime executions cover legal unknown non-critical handshake Parameters and Session-owned reliable DATA after caller cancellation post-commit; 2 validator controls reject forged Generation inputs and forged Mandatory/evidence reports.
- gate4_harness.py — aggregate Gate 4 runner. It binds the exact 121 Mandatory IDs and recomputes evidence classes/counts/lists from individual cases rather than trusting report summaries.

## Gate 4 requirements enforced by the aggregate runner

Gate 4 aggregate is PASS only when:

1. Implementation A (reference/) reports 121/121 A–L case IDs PASS with `model_only_case_ids=[]`.
2. Implementation B (independent/) reports the same 121/121 result and evidence-class schema.
3. Each profile reports exactly **18 codec + 30 cross-wire + 73 endpoint-wire + 0 model** Mandatory IDs.
4. The baseline authenticated endpoint-wire suite passes **200 executions** across A/B and Client/Server roles (56 scenarios with explicit server-only/client-only applicability), including controlled cross-Carrier reject scheduling and post-compaction first-late reliable Frames.
5. The formerly-model-only endpoint suite passes **86 executions** across A/B and covers 42 unique former model-only IDs; E4, F3, J7 and K6 reuse existing endpoint-wire cases.
6. Thirty-six deliberate runtime defects are target-witnessed only after 52 unmutated baseline guards pass; four oracle negative controls prove unrelated infrastructure failures are not counted as mutation detection before or after target witness. J5 additionally verifies invalid candidate Finished and unauthenticated candidate-RST isolation through the real CLI Server process.
7. The review-v2 suite passes 20 A/B executions and the update-review suite passes 18 A/B executions covering five remaining counterexamples plus four normal controls.
8. The independent follow-up suite passes 22 A/B executions, the b66 follow-up passes 20 A/B executions, and the stable-audit closure suite passes 10 executions (8 A/B runtime + 2 validator negative controls).
9. Each Mandatory profile contains the exact A1–L25 ID set expected by Draft 11; Gate 4 recomputes each case's evidence class and aggregate lists/counts from the cases themselves.
10. Implementation B passes an AST import audit and critical-handler structural comparison proving no runtime dependency on reference/, tools/, or validator modules and no AST-identical critical receive handlers.
11. Reference Client → Independent Server and Independent Client → Reference Server pass the basic real-TCP profile.
12. Both role directions pass all five fault/recovery scenarios.
13. The cross-basic and cross-fault runs are repeated with endpoint writes fragmented to 257 bytes.

The aggregate therefore contains **286 authenticated endpoint executions**, thirty-six target-witnessed sensitivity controls after 52 unmutated baselines and four oracle negative controls, **20 review-v2 executions**, **18 update-review executions**, **22 independent follow-up executions**, **20 b66 follow-up executions**, **10 stable-audit closure executions**, four cross-basic executions, and twenty cross-fault scenario executions. No Mandatory case is model-only; codec and cross-wire remain the appropriate executable evidence for 48 of the 121 IDs.

## Independence boundary

The two protocol runtimes are source/module isolated, but they are maintained in the same repository and were produced within the same project. The Gate 4 report explicitly records this boundary and does not claim organizational or third-party independence.

Gate 4 provides the repository's current Draft 11 interoperability evidence with no model-only Mandatory case. A PASS means all 121 Mandatory IDs have executable evidence, not that all 121 are endpoint-wire tests. The source-isolation boundary above remains, and Gate 4 does not itself declare Protocol Version 4 stable.
