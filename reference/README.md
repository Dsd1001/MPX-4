# MPX/4 Draft 11 executable reference

This directory contains a deliberately small executable MPX/4 Core-over-TCP reference and interoperability harness. Its purpose is to turn the Draft 11 specification and fixtures into real socket/runtime evidence.

It is **not** a production proxy, Relay, scheduler implementation, performance benchmark, or proof that Protocol Version 4 is stable.

## Current gate

The current implementation is **Gate 1 reference-to-reference integration**.

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

Not yet implemented as runtime interoperability coverage:

- JOIN, multiple active Carriers, replacement Generations, or DORMANT recovery;
- retransmission/reinjection and TRANSMISSION_RETIRE;
- RESET_STREAM / STOP_SENDING / STREAM_CONSUMED runtime behavior;
- CREDIT_PROBE recovery behavior;
- ambiguous SERVER_FINISHED recovery;
- complete error-scope/fault cases;
- the complete A-L Mandatory profile;
- an independently implemented peer.

Therefore a Gate 1 PASS means only that this reference Client and Server interoperate over real TCP for the implemented subset. It is not an independent A/B interoperability claim and does not establish Version 4 stability.

## Files

- `mpx4_core.py` — executable codec, handshake/crypto, Carrier, Stream, credit, and reliability subset. It does not import the specification validator.
- `endpoint.py` — Client/Server CLI. Client and Server are run as separate processes with separate state and sockets.
- `interop_harness.py` — process orchestration plus an application/trace checker that does not import the endpoint state machine.
- `fault_proxy.py` — transport-layer test proxy for byte fragmentation, delay/backpressure, and connection abort.
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

The output directory contains:

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

Later Gate 2 protocol faults such as delayed ACK generation, FIN/RESET races, ambiguous SERVER_FINISHED commit points, cross-Carrier reordering, and cryptographically valid invalid peer Frames require endpoint/test-peer hooks rather than UDP-style packet dropping.

## Evidence boundary

The harness reports the repository SHA and whether the working tree was dirty. Test artifacts are runtime evidence and are not committed.

Gate progression remains:

- **Gate 0:** codec/crypto/vector baseline and reference self-test;
- **Gate 1:** reference Client ↔ reference Server over real TCP;
- **Gate 2:** deterministic fault/recovery scenarios;
- **Gate 3:** complete A-L Mandatory profile;
- **Gate 4:** independent implementation A/B interoperability, with role reversal where supported.

Only Gate 4 provides the basis for an independent Core interoperability claim.
