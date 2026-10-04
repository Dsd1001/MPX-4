# MPX/4 Draft 11 executable reference

This directory contains a deliberately small executable MPX/4 Core-over-TCP reference and interoperability harness. Its purpose is to turn the Draft 11 specification and fixtures into real socket/runtime evidence.

It is **not** a production proxy, Relay, scheduler implementation, performance benchmark, or proof that Protocol Version 4 is stable.

## Current gate

The reference implementation now completes **Gate 1**, **Gate 2**, and the full **Gate 3 A–L Mandatory profile**. Gate 4 is driven by the neutral `interop/` harness against the source-isolated peer in `independent/`.

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

Gate 3 executes **121 individually identified Mandatory cases** covering A1–A5, B1–B17, C1–C7, D1–D10, E1–E10, F1–F8, G1–G6, H1–H5, I1–I6, J1–J16, K1–K6, and L1–L25. The runner combines real TCP Gate 1/2 evidence, canonical wire/crypto reproduction, and stateful edge execution for exhaustion, tombstones, opening races, candidate admission, credit ordering, and failure scope. A Gate 3 PASS requires every one of the 121 case IDs to be present and PASS.

Gate 4 then runs this reference implementation against `independent/`, a separate runtime source tree with its own VarInt, handshake, HKDF/Finished, AES-GCM Record, Frame codec, endpoint, and state implementation. The neutral harness verifies both implementations at 121/121 Mandatory cases and runs A→B and B→A over real TCP for the basic full-duplex profile and all five deterministic fault scenarios, both directly and with 257-byte endpoint write fragmentation.

The Gate 4 independence claim is deliberately scoped to **runtime source/module isolation**: `independent/` imports no `reference/`, `tools/`, or validator runtime code. Both implementations live in this repository and were produced within the same project, so the evidence does not claim third-party or organizationally independent development. Passing Gates 3 and 4 also does not by itself declare Protocol Version 4 stable.

## Files

- `mpx4_core.py` — executable codec, handshake/crypto, Carrier, Stream, credit, and reliability subset. It does not import the specification validator.
- `endpoint.py` — Client/Server CLI. Client and Server are run as separate processes with separate state and sockets.
- `interop_harness.py` — process orchestration plus an application/trace checker that does not import the endpoint state machine.
- `fault_proxy.py` — transport-layer test proxy for byte fragmentation, delay/backpressure, and connection abort.
- `gate2_runtime.py` — scenario-driven Session-level multi-Carrier/fault runtime with JOIN, Generation replacement, DORMANT state, reinjection, retirement, credit recovery, terminal races, and Core error scope.
- `gate2_harness.py` — launches Gate 2 Client/Server processes and independently verifies scenario-specific trace/state evidence.
- `mandatory_model.py` — executable state engine for Mandatory edge cases that require exhaustion, tombstones, opening races, candidate admission, or invalid peer behavior.
- `gate3_harness.py` — executes and reports every one of the 121 A–L Mandatory case IDs.
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

Run the complete 121-case Mandatory profile:

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
- **Gate 1: PASS** — reference Client ↔ reference Server over real TCP, direct and fragmented;
- **Gate 2: PASS** — deterministic multi-Carrier/fault/recovery scenario suite, direct and fragmented;
- **Gate 3: PASS** — all 121 A–L Mandatory case IDs;
- **Gate 4: PASS** — source-isolated A/B interoperability with role reversal for the basic and five fault profiles, direct and fragmented.

Gate 4 is the repository's basis for a Draft 11 Core interoperability claim under the independence boundary above. Protocol Version 4 remains a development version until a separate Stability Declaration is made.
