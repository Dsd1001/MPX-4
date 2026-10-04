# MPX/4 Draft 11 executable reference

This directory contains a deliberately small executable MPX/4 Core-over-TCP reference and interoperability harness. Its purpose is to turn the Draft 11 specification and fixtures into real socket/runtime evidence.

It is **not** a production proxy, Relay, scheduler implementation, performance benchmark, or proof that Protocol Version 4 is stable.

## Current gate

The current implementation includes **Gate 1 reference-to-reference integration** and a **Gate 2 deterministic fault/recovery runtime**.

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

Still not implemented as complete runtime interoperability coverage:

- the full A-L Mandatory profile, including all D/E/F/G/H/I/J/K/L cases and limits/exhaustion combinations;
- complete runtime coverage of STREAM_CONSUMED and every cancellation/tombstone/error-scope branch;
- all candidate rejection/resource-limit combinations and simultaneous-candidate races;
- an independently implemented peer.

Gate 1 and Gate 2 PASS results are reference-to-reference execution evidence only. They are not independent A/B interoperability claims and do not establish Version 4 stability.

## Files

- `mpx4_core.py` — executable codec, handshake/crypto, Carrier, Stream, credit, and reliability subset. It does not import the specification validator.
- `endpoint.py` — Client/Server CLI. Client and Server are run as separate processes with separate state and sockets.
- `interop_harness.py` — process orchestration plus an application/trace checker that does not import the endpoint state machine.
- `fault_proxy.py` — transport-layer test proxy for byte fragmentation, delay/backpressure, and connection abort.
- `gate2_runtime.py` — scenario-driven Session-level multi-Carrier/fault runtime with JOIN, Generation replacement, DORMANT state, reinjection, retirement, credit recovery, terminal races, and Core error scope.
- `gate2_harness.py` — launches Gate 2 Client/Server processes and independently verifies scenario-specific trace/state evidence.
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

Gate progression remains:

- **Gate 0:** codec/crypto/vector baseline and reference self-test;
- **Gate 1:** reference Client ↔ reference Server over real TCP;
- **Gate 2:** current deterministic multi-Carrier/fault/recovery scenario suite;
- **Gate 3:** complete A-L Mandatory profile;
- **Gate 4:** independent implementation A/B interoperability, with role reversal where supported.

Only Gate 4 provides the basis for an independent Core interoperability claim.
