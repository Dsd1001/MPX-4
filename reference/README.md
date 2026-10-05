# MPX/4 Draft 11 executable reference

This directory contains a deliberately small executable MPX/4 Core-over-TCP reference and interoperability harness. Its purpose is to turn the Draft 11 specification and fixtures into real socket/runtime evidence.

It is **not** a production proxy, Relay, scheduler implementation, performance benchmark, or proof that Protocol Version 4 is stable.

## Current gate

The reference implementation completes Gate 1 and Gate 2 runtime scenarios. Gate 3 is now a **model-zero executable 121-case A–L profile**: every Mandatory case is backed by codec, endpoint-wire, or cross-wire execution. The current split is 18 codec, 30 cross-wire, 73 endpoint-wire, and 0 model-only. Gate 4 is driven by the neutral `interop/` harness against the source-isolated peer in `independent/`.

Implemented runtime subset:

- MPX/4 TCP Connection Preface and Protocol Version 4;
- CREATE with Carrier ID 1 / Generation 0;
- canonical CLIENT_INIT / SERVER_INIT Parameters and receive limits;
- PSK / HKDF-SHA256 / HMAC-SHA256 Finished exchange;
- AES-256-GCM Secure Records with independent directional sequence numbers;
- incremental real TCP reads and arbitrary write fragmentation;
- SESSION_CREDIT and STREAM_CREDIT before application DATA;
- client-initiated bidirectional STREAM_OPEN / STREAM_OPEN_OK;
- reliable STREAM_DATA and STREAM_FIN with TRANSMISSION_ACK;
- ordered reassembly and application byte/digest checking;
- 16 simultaneously active Streams;
- full-duplex application transfer;
- SESSION_CLOSE;
- JSONL endpoint traces with local monotonic timestamps and event sequence numbers.

The default Gate 1 profile transfers 16 × 65,536 bytes = **1 MiB in each direction**.

Gate 2 adds five real-TCP deterministic scenarios using separate Client and Server processes:

- `multi-carrier-reinjection` — Carrier JOIN with sparse Carrier ID 96, shared Stream state, same-Transmission reinjection across Carriers, duplicate delivery suppression, unexpected Carrier loss, and higher-Generation replacement with fresh Carrier crypto/Record sequence space;
- `dormant-recovery` — last-Carrier loss into DORMANT, retained outstanding Transmission state, Generation 1/2 recovery, CREDIT_PROBE-driven Stream/Session credit refresh, reinjection after recovery, and non-zero TRANSMISSION_RETIRE refresh after later recovery;
- `ambiguous-replacement` — deterministic loss after Server commit but before Client authentication of SERVER_FINISHED, known-Carrier recovery above Highest Attempted Generation, and first-use ambiguity recovery through a fresh Carrier ID at Generation 0;
- `fin-reset-retire` — lost FIN confirmation, STOP_SENDING/RESET_STREAM supersession semantics, late FIN reinjection with the same Final Offset, and contiguous Settled Through / TRANSMISSION_RETIRE recovery;
- `error-scope` — an impossible never-allocated TRANSMISSION_ACK is classified as Session-scoped TRANSMISSION_ID_ERROR and produces SESSION_CLOSE rather than Carrier-local failure.

The same Gate 2 suite is also run with deterministic endpoint TCP write fragmentation (`--write-chunk 257`).

Gate 3 executes **121 individually identified Mandatory cases** covering A1–A5, B1–B17, C1–C7, D1–D10, E1–E10, F1–F8, G1–G6, H1–H5, I1–I6, J1–J16, K1–K6, and L1–L25. The current reference profile reports **18 codec, 30 cross-wire, 73 endpoint-wire, and 0 model** case IDs. The former 46 model-only IDs now have real runtime evidence: 42 IDs are exercised by `interop/endpoint_mandatory.py`, while E4, F3, J7, and K6 reuse existing authenticated endpoint-wire cases.

`interop/endpoint_wire.py` runs the real Session runtimes over loopback TCP, completes CREATE/Finished, sends authenticated Secure Records, and verifies both endpoint roles where the rule is role-symmetric. It covers Final Offset versus DATA, RESET application-delivery suppression, STOP_SENDING send/receive direction separation, legal overlapping/out-of-order reassembly, Stream/Session credit pair merge and window structure, active/retained-tombstone terminal credit versus local Final Offset, retired-identity ignore versus unknown-Stream errors, Session aggregate commitment, byte identity, Transmission-ID conflicts, Record flags/encoding Carrier scope, Stream lifecycle/limit, candidate collision, error scope/Trigger Frame Type, shutdown blocking new work, cross-Carrier STREAM_OPEN decision atomicity, and first-late reliable Frames after retired-identity compaction. The baseline aggregate suite executes **200 cases across A/B and Client/Server roles**.

`interop/endpoint_mandatory.py` removes the remaining model-only Mandatory evidence. It executes real runtime behavior for JOIN consistency, Session Protocol Version, VERSION_NEGOTIATION and HANDSHAKE_REJECT, identifier exhaustion, Carrier slot/replacement rules, retirement/confirmation retention, opening races, tombstones, STREAM_CONSUMED, DORMANT retention, candidate concurrency, EOF/half-close, and Session/Carrier close behavior. It contributes **43 executions per implementation / 86 total** and covers 42 unique formerly-model-only Mandatory IDs.

`interop/endpoint_sensitivity.py` deliberately breaks eighteen real handler contracts in each runtime. In addition to the earlier flow-control/reassembly/terminal and F1–F8 guards, it reintroduces cross-Carrier rejection commit-after-send and retired first-arrival recovery loss. The suite first runs **52 unmutated baseline guards**, then requires every mutation to hit its target branch before the endpoint-wire case fails; **2 oracle negative controls** prove that unrelated pre-handler setup failures are rejected as ERROR/INCONCLUSIVE. There are **36 deliberate-defect controls**.

`interop/review_v2.py` owns the follow-up review-v2 scheduling/output/progress regressions. It executes **10 case classes against both runtimes / 20 total executions**: Secure Record cancellation after ordered-output commit, unauthenticated high-Generation non-reservation, finite candidate-handshake deadlines, commit-time revalidation of Generation/Session state/Effective Carrier Limit, concurrent CREATE isolation, superseded-incarnation receive isolation, rejection of new DATA after RESET, and automatic TRANSMISSION_RETIRE after Settled Through advances. The corrected J11 test also permits equal-Generation candidates to coexist in HANDSHAKING and makes the first authenticated commit the winner.

Gate 4 runs this reference implementation against `independent/`, a separate runtime source tree with its own VarInt, handshake, HKDF/Finished, AES-GCM Record, Frame codec, endpoint, and state implementation. The aggregate requires both model-zero 121-case profiles, **286 authenticated endpoint executions** (200 baseline + 86 formerly-model-only), thirty-six target-witnessed sensitivity mutations, 52 unmutated sensitivity baselines, two oracle negative controls, **20 review-v2 A/B executions**, A→B/B→A basic full-duplex tests, and all five deterministic fault scenarios in direct and fragmented modes. J5 exercises the actual CLI Server process: an invalid candidate Finished must close only that candidate while the established Carrier and listener remain usable.

The Gate 4 independence claim is deliberately scoped to **runtime source/module isolation**: `independent/` imports no `reference/`, `tools/`, or validator runtime code. Both implementations live in this repository and were produced within the same project, so the evidence does not claim third-party or organizationally independent development. No Mandatory case is model-only, but 18 codec and 30 cross-wire cases remain deliberately classified by their correct executable surface rather than being mislabeled endpoint-wire. Passing these gates also does not itself declare Protocol Version 4 stable.

## Files

- `mpx4_core.py` — executable codec, handshake/crypto, Carrier, Stream, credit, and reliability subset. It does not import the specification validator.
- `endpoint.py` — Client/Server CLI. Client and Server are run as separate processes with separate state and sockets.
- `interop_harness.py` — process orchestration plus an application/trace checker that does not import the endpoint state machine.
- `fault_proxy.py` — transport-layer test proxy for byte fragmentation, delay/backpressure, and connection abort.
- `gate2_runtime.py` — scenario-driven Session-level multi-Carrier/fault runtime with JOIN, Generation replacement, DORMANT state, reinjection, retirement, credit recovery, terminal races, and Core error scope.
- `gate2_harness.py` — launches Gate 2 Client/Server processes and independently verifies scenario-specific trace/state evidence.
- `mandatory_model.py` — executable state engine for Mandatory edge cases that require exhaustion, tombstones, opening races, candidate admission, or invalid peer behavior.
- `gate3_harness.py` — executes and reports every one of the 121 A–L Mandatory case IDs with explicit evidence class and endpoint-wire requirements for review-sensitive receiver/error cases.
- `selftest.py` — anchors the reference codec/crypto to the repository canonical handshake and Secure Record fixtures.

## Run

Install the same dependency used by repository validation:

    python -m pip install 'cryptography>=42,<47'

Anchor the reference implementation to canonical vectors:

    python -m reference.selftest

Run the default real-TCP Gate 1 profile:

    python reference/interop_harness.py --out-dir /tmp/mpx4-gate1

Run the same profile with deterministic endpoint write fragmentation and an intermediate TCP proxy that fragments forwarded byte streams:

    python reference/interop_harness.py \
      --out-dir /tmp/mpx4-gate1-fragmented \
      --case-id gate1-proxy-fragmented \
      --write-chunk 257 \
      --proxy-max-chunk 1024

Run all current Gate 2 deterministic fault/recovery scenarios:

    python reference/gate2_harness.py --out-dir /tmp/mpx4-gate2

Run the same Gate 2 scenarios while fragmenting endpoint TCP writes:

    python reference/gate2_harness.py \
      --out-dir /tmp/mpx4-gate2-fragmented \
      --write-chunk 257

Run authenticated endpoint conformance and sensitivity controls:

    python -m interop.endpoint_wire --out-dir /tmp/mpx4-endpoint-wire
    python -m interop.endpoint_mandatory --out-dir /tmp/mpx4-endpoint-mandatory
    python -m interop.endpoint_sensitivity --out-dir /tmp/mpx4-endpoint-sensitivity
    python -m interop.review_v2 --out-dir /tmp/mpx4-review-v2

Run the model-zero 121-case Mandatory profile:

    python -m reference.gate3_harness --out-dir /tmp/mpx4-gate3

Run the aggregate two-implementation Gate 4 suite:

    python -m interop.gate4_harness --out-dir /tmp/mpx4-gate4

The Gate 1 output directory contains:

- `gate1-report.json`;
- Client and Server result JSON;
- Client and Server JSONL traces;
- endpoint stdout/stderr;
- proxy trace/stdout/stderr when the proxy is enabled.

The harness reconstructs expected application payloads independently, verifies per-Stream byte counts and SHA-256 digests, checks Session/Stream credit appears before DATA, checks opening evidence, and uses each endpoint's own event ordering to prove send/receive overlap. It never subtracts timestamps from different endpoint clocks.

## Fault-injection boundary

`fault_proxy.py` injects only faults that are meaningful for a TCP byte stream:

- fragmentation/coalescing pressure;
- forwarding delay/backpressure;
- EOF/connection abort after a configured byte count.

It intentionally does **not** delete an already committed Secure Record and then continue forwarding later records. Doing that would corrupt the ordered byte stream and desynchronize the implicit Secure Record sequence/nonce; that is an authentication-failure test, not normal MPX reinjection.

Protocol-level Gate 2 faults such as delayed confirmation, FIN/RESET races, ambiguous SERVER_FINISHED commit points, DORMANT recovery, and cryptographically valid invalid peer Frames are injected inside `gate2_runtime.py` at authenticated protocol boundaries rather than by deleting arbitrary bytes from the TCP proxy. Additional Mandatory-profile cases can extend the same scenario mechanism.

## Evidence boundary

The harness reports the repository SHA and whether the working tree was dirty. Test artifacts are runtime evidence and are not committed.

Current gate status:

- **Gate 0: PASS** — codec/crypto/vector baseline and mutation validation;
- **Gate 1: PASS** — reference Client ↔ reference Server positive real-TCP integration, direct and fragmented;
- **Gate 2: PASS** — deterministic multi-Carrier/fault/recovery scenario suite, direct and fragmented;
- **Gate 3 profile: PASS** — 121/121 case IDs with **0 model-only**; evidence split is 18 codec + 30 cross-wire + 73 endpoint-wire;
- **Gate 4 aggregate: PASS** — source-isolated A/B role reversal plus 286 authenticated endpoint executions, thirty-six target-witnessed sensitivity controls with 52 baselines and two oracle negative controls, 20 review-v2 concurrency/output/progress executions, retained first-arrival/lifecycle replay validation, CLI candidate-isolation coverage, and direct/fragmented cross-fault evidence.

The repository now has executable evidence for every Draft 11 Mandatory case without a model-only fallback. This is still not a third-party independence claim, and it does not mean all 121 cases are endpoint-wire tests. Protocol Version 4 remains a development version until a separate Stability Declaration is made.
