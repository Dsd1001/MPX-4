# MPX/4 Draft 11 neutral interoperability harnesses

This directory orchestrates tests between the two executable implementations without importing either implementation's protocol runtime.

## Harnesses

- cross_basic.py — launches a selected Client and Server implementation as separate processes and verifies handshake establishment, explicit credit-before-DATA ordering, 16 concurrent Streams, full duplex, per-Stream byte counts/digests, FIN completion, and 1 MiB in each direction.
- cross_fault.py — launches the five deterministic multi-Carrier/fault scenarios across selected implementations and verifies JOIN/reinjection, duplicate suppression, DORMANT recovery, ambiguous SERVER_FINISHED recovery, FIN/RESET/retirement behavior, and Session-scoped TRANSMISSION_ID_ERROR.
- gate4_harness.py — aggregate Gate 4 runner.

## Gate 4 requirements enforced by the aggregate runner

Gate 4 is PASS only when:

1. Implementation A (reference/) reports 121/121 Mandatory A–L cases PASS.
2. Implementation B (independent/) reports 121/121 Mandatory A–L cases PASS.
3. Implementation B passes an AST-based import audit proving no runtime dependency on reference/, tools/, or validator modules.
4. Reference Client → Independent Server passes the basic real-TCP profile.
5. Independent Client → Reference Server passes the same profile.
6. Both role directions pass all five fault/recovery scenarios.
7. Items 4–6 are repeated with endpoint writes fragmented to 257 bytes.

The aggregate result therefore contains four cross-basic executions and twenty cross-fault scenario executions.

## Independence boundary

The two protocol runtimes are source/module isolated, but they are maintained in the same repository and were produced within the same project. The Gate 4 report explicitly records this boundary and does not claim organizational or third-party independence.

Gate 4 establishes the repository's Draft 11 Core interoperability evidence. It does not itself declare Protocol Version 4 stable.
