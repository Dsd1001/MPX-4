# MPX/4 Draft 11 neutral interoperability harnesses

This directory orchestrates tests between the two executable implementations without importing either implementation's protocol runtime.

## Harnesses

- cross_basic.py — launches a selected Client and Server implementation as separate processes and verifies handshake establishment, explicit credit-before-DATA ordering, 16 concurrent Streams, full duplex, per-Stream byte counts/digests, FIN completion, and 1 MiB in each direction.
- cross_fault.py — launches the five deterministic multi-Carrier/fault scenarios across selected implementations and verifies JOIN/reinjection, duplicate suppression, DORMANT recovery, ambiguous SERVER_FINISHED recovery, FIN/RESET/retirement behavior, and Session-scoped TRANSMISSION_ID_ERROR.
- endpoint_wire.py — drives the real A/B Session runtimes over loopback TCP with full CREATE/Finished and authenticated Secure Records. It contains paired positive/negative controls for Final Offset, RESET application termination, STOP_SENDING directionality, legal overlapping reassembly, credit pair merge, active/retained-tombstone terminal credit/final-size consistency, retired-identity ignore versus unknown-Stream errors, aggregate Session commitment, error scope, Record encoding, Stream lifecycle, candidate admission, and shutdown. The tombstone cases settle bidirectional RESET/ACK and STREAM_CONSUMED/ACK and retain Session confirmation replay before local-policy retirement; compaction follows a real TRANSMISSION_RETIRE.
- endpoint_mandatory.py — executes the previously model-only Mandatory requirements against the real runtimes: version/reject handling, identifier exhaustion, Carrier capacity/replacement, reliable confirmation retirement, opening/cancellation races, tombstones, DORMANT retirement, candidate concurrency, and TCP/close behavior. It contributes 43 executions per implementation / 86 total and covers 42 unique Mandatory IDs.
- endpoint_sensitivity.py — deliberately breaks eight real handler contracts in each implementation and requires the guarded endpoint-wire case to fail. The tombstone-only bypass checks all three credit violations in Client and Server roles and rejects setup failures as evidence.
- gate4_harness.py — aggregate Gate 4 runner.

## Gate 4 requirements enforced by the aggregate runner

Gate 4 aggregate is PASS only when:

1. Implementation A (reference/) reports 121/121 A–L case IDs PASS with `model_only_case_ids=[]`.
2. Implementation B (independent/) reports the same 121/121 result and evidence-class schema.
3. Each profile reports exactly **18 codec + 30 cross-wire + 73 endpoint-wire + 0 model** Mandatory IDs.
4. The baseline authenticated endpoint-wire suite passes **144 executions** across A/B and Client/Server roles (38 scenarios, four server-only).
5. The formerly-model-only endpoint suite passes **86 executions** across A/B and covers 42 unique former model-only IDs; E4, F3, J7 and K6 reuse existing endpoint-wire cases.
6. Sixteen deliberate runtime defects are each detected by the corresponding endpoint-wire control; J5 additionally verifies invalid candidate Finished isolation through the real CLI Server process.
7. Implementation B passes an AST import audit and critical-handler structural comparison proving no runtime dependency on reference/, tools/, or validator modules and no AST-identical critical receive handlers.
8. Reference Client → Independent Server and Independent Client → Reference Server pass the basic real-TCP profile.
9. Both role directions pass all five fault/recovery scenarios.
10. The cross-basic and cross-fault runs are repeated with endpoint writes fragmented to 257 bytes.

The aggregate therefore contains **230 authenticated endpoint executions**, sixteen sensitivity controls, four cross-basic executions, and twenty cross-fault scenario executions. No Mandatory case is model-only; codec and cross-wire remain the appropriate executable evidence for 48 of the 121 IDs.

## Independence boundary

The two protocol runtimes are source/module isolated, but they are maintained in the same repository and were produced within the same project. The Gate 4 report explicitly records this boundary and does not claim organizational or third-party independence.

Gate 4 provides the repository's current Draft 11 interoperability evidence with no model-only Mandatory case. A PASS means all 121 Mandatory IDs have executable evidence, not that all 121 are endpoint-wire tests. The source-isolation boundary above remains, and Gate 4 does not itself declare Protocol Version 4 stable.
