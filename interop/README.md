# MPX/4 Draft 11 neutral interoperability harnesses

This directory orchestrates tests between the two executable implementations without importing either implementation's protocol runtime.

## Harnesses

- cross_basic.py — launches a selected Client and Server implementation as separate processes and verifies handshake establishment, explicit credit-before-DATA ordering, 16 concurrent Streams, full duplex, per-Stream byte counts/digests, FIN completion, and 1 MiB in each direction.
- cross_fault.py — launches the five deterministic multi-Carrier/fault scenarios across selected implementations and verifies JOIN/reinjection, duplicate suppression, DORMANT recovery, ambiguous SERVER_FINISHED recovery, FIN/RESET/retirement behavior, and Session-scoped TRANSMISSION_ID_ERROR.
- endpoint_wire.py — drives the real A/B Session runtimes over loopback TCP with full CREATE/Finished and authenticated Secure Records. It contains paired positive/negative receiver controls for Final Offset, RESET application termination, credit pair merge, aggregate Session commitment, error scope, Record encoding, Stream lifecycle, candidate admission, and shutdown.
- endpoint_sensitivity.py — deliberately breaks four real handler contracts in each implementation and requires the guarded endpoint-wire case to fail.
- gate4_harness.py — aggregate Gate 4 runner.

## Gate 4 requirements enforced by the aggregate runner

Gate 4 aggregate is PASS only when:

1. Implementation A (reference/) reports 121/121 A–L profile case IDs PASS with explicit evidence classes.
2. Implementation B (independent/) reports the same 121/121 profile and evidence-class schema.
3. Both profiles explicitly list model-only case IDs instead of treating them as endpoint acceptance.
4. The combined authenticated endpoint-wire suite passes **96 executions** across A/B and Client/Server roles.
5. Eight deliberate runtime defects are each detected by the corresponding endpoint-wire control.
6. Implementation B passes an AST-based import audit proving no runtime dependency on reference/, tools/, or validator modules.
7. Reference Client → Independent Server and Independent Client → Reference Server pass the basic real-TCP profile.
8. Both role directions pass all five fault/recovery scenarios.
9. The cross-basic and cross-fault runs are repeated with endpoint writes fragmented to 257 bytes.

The aggregate therefore contains 96 endpoint-wire executions, eight sensitivity controls, four cross-basic executions, and twenty cross-fault scenario executions. The 121-case profiles currently remain mixed-evidence rather than 121 endpoint-wire executions.

## Independence boundary

The two protocol runtimes are source/module isolated, but they are maintained in the same repository and were produced within the same project. The Gate 4 report explicitly records this boundary and does not claim organizational or third-party independence.

Gate 4 provides the repository's current Draft 11 interoperability evidence under an explicit mixed-evidence boundary. A PASS must not be summarized as complete Mandatory Core endpoint interoperability while `model_only_case_ids` is non-empty. It does not itself declare Protocol Version 4 stable.
