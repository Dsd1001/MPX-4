# MPX/4 Draft 11 source-isolated Implementation B

This directory contains the second executable implementation used by Gate 4.

Its purpose is interoperability evidence, not production deployment. It independently implements the MPX/4 wire/crypto/runtime surface used by the profile: VarInt, Handshake Messages and Parameters, HKDF/HMAC Finished derivation, AES-256-GCM Secure Records, Core Frame codec, TCP endpoint behavior, Stream/Session credit, reliable Transmissions, Carrier replacement/recovery, and the stateful Mandatory edge cases.

## Source-isolation boundary

Implementation B has no runtime import dependency on reference/, tools/, tools/validate.py, or tools/semantic_validation.py.

interop/gate4_harness.py parses every Python import in this directory and fails Gate 4 if such a dependency appears. It also records separate SHA-256 hashes for the A/B core and endpoint sources.

The independence claim is intentionally limited to source/module isolation. Both implementations are maintained in this repository, use the same public specification and fixtures, and were built in the same project. Gate 4 therefore does not claim separate-company, separate-team, or third-party development.

The conformance/fault harnesses intentionally exercise the same published Mandatory cases and fault contracts on both implementations. Sharing a test corpus is not treated as sharing runtime protocol code.

## Files

- core.py — independent wire, handshake, crypto, Secure Record, Frame, Carrier, and basic Session runtime.
- endpoint.py — independent real-TCP Client/Server CLI used in A/B role reversal.
- gate_runtime.py — multi-Carrier/fault runtime using only independent.core.
- state.py — state engine for exhaustion, tombstones, opening races, credit ordering, candidate admission, and failure scope.
- selftest.py — canonical vector reproduction using Implementation B.
- basic_harness.py — B↔B basic real-TCP integration harness.
- fault_harness.py — B↔B five-scenario fault/recovery harness.
- profile.py — 121-case A–L executable-evidence profile for Implementation B; current classification is 18 codec, 30 cross-wire, 73 endpoint-wire, and 0 model-only.

## Run

Install the repository validation dependency:

    python -m pip install 'cryptography>=42,<47'

Run the canonical vector self-test:

    python -m independent.selftest

Run B↔B basic integration:

    python independent/basic_harness.py --out-dir /tmp/mpx4-b-basic

Run B↔B fault/recovery integration:

    python independent/fault_harness.py --out-dir /tmp/mpx4-b-fault

Run authenticated endpoint conformance for Implementation B:

    python -m interop.endpoint_wire --implementation independent --out-dir /tmp/mpx4-b-endpoint-wire
    python -m interop.endpoint_mandatory --implementation independent --out-dir /tmp/mpx4-b-endpoint-mandatory

Run the Implementation B model-zero Mandatory profile:

    python -m independent.profile --out-dir /tmp/mpx4-b-profile

Run aggregate Gate 4 A/B interoperability:

    python -m interop.gate4_harness --out-dir /tmp/mpx4-gate4

A successful Implementation B profile reports all 121/121 A–L case IDs PASS with `model_only_case_ids=[]` and evidence counts of 18 codec, 30 cross-wire, and 73 endpoint-wire. Aggregate Gate 4 additionally requires 182 authenticated endpoint executions across A/B, eight deliberate-defect sensitivity controls, and both role directions for the basic and five fault scenarios in direct and fragmented-write modes. This does not claim that all 121 Mandatory cases are endpoint-wire tests or that Implementation B was developed by an external organization.
