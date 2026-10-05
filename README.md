# MPX/4

**MPX/4** is an application-layer multipath transport protocol for combining multiple authenticated carrier connections into a single Session.

It provides:

- authenticated multi-Carrier Sessions;
- reliable ordered bidirectional Streams;
- Stream and Session flow control;
- independent per-endpoint Carrier selection;
- retransmission and cross-Carrier reinjection;
- extensible typed Frames and negotiated protocol Parameters.

## Current specification

**Protocol version:** 4  
**Specification revision:** Draft 11
**Status:** Working Draft

- [Core Protocol Specification](SPECIFICATION.md)
- [Normative State Machines and Frame Validity](STATE-MACHINES.md)
- [Normative Error Handling and Failure Scope](ERROR-HANDLING.md)
- [Normative Versioning and Compatibility](COMPATIBILITY.md)
- [MPX/4 over TCP](bindings/tcp.md)
- [Interoperability Profile](INTEROPERABILITY.md)
- [Protocol Registries](REGISTRIES.md)
- [Security Policy and Guidance](SECURITY.md)
- [Specification Changelog](CHANGELOG.md)

## Protocol model

    Application
        |
        v
    MPX Streams
        |
        v
    MPX Session
        |
        +-- Carrier 1
        +-- Carrier 2
        +-- Carrier 3
        '-- ...
        |
        v
    Secure Record Layer
        |
        v
    Transport Binding

The core protocol separates Stream semantics from Carrier transport semantics. A Stream remains one ordered byte stream even when an outstanding Transmission is retransmitted or reinjected across different Carriers.

Draft 11 keeps the ACTIVE / DORMANT Session model and immutable Session Protocol Version, while removing scheduler-mode negotiation from Core. Each endpoint selects Carriers for its own outbound Attempts using local policy subject to Core reliability, flow-control, identity, and Carrier-eligibility invariants.

Draft 11 is a freeze-preparation revision: it adds no scheduler or Relay topology to Core and no new successful-handshake wire element. It closes ambiguous-establishment recovery and reliable-state progress contracts and strengthens executable validation coverage.

## Interoperability material

### Examples

- [Handshake walkthrough](examples/handshake.md)
- [Frame encoding examples](examples/frames.md)
- [Retransmission and reinjection example](examples/reliability.md)
- [Terminal Stream lifecycle example](examples/terminal-lifecycle.md)
- [TCP Carrier example](examples/tcp-carrier.md)

### Test vectors

- [Test-vector overview](test-vectors/README.md)
- [VarInt vectors](test-vectors/varint.json)
- [Frame encoding vectors](test-vectors/frame-encoding.json)
- [Key schedule and Finished vector](test-vectors/key-schedule.json)
- [Secure Record vector](test-vectors/secure-record.json)
- [State validity cases](test-vectors/state-validity.json)
- [Carrier Generation cases](test-vectors/carrier-generation.json)
- [Error-scope cases](test-vectors/error-scope.json)
- [MAX_CARRIERS negotiation and active-count cases](test-vectors/max-carriers.json)
- [Session lifecycle and DORMANT cases](test-vectors/session-lifecycle.json)
- [Protocol Version compatibility cases](test-vectors/version-compatibility.json)
- [Handshake rejection cases](test-vectors/handshake-reject.json)
- [Identity lifecycle and exhaustion cases](test-vectors/identity-lifecycle.json)
- [Reordering, retirement, and record-size cases](test-vectors/reordering-reliability.json)
- [Confirmation-type validity cases](test-vectors/confirmation-validity.json)
- [Ambiguous establishment recovery cases](test-vectors/handshake-ambiguity.json)
- [Recovery credit / retirement progress cases](test-vectors/recovery-progress.json)
- [Reliable Transmission allocation cases](test-vectors/transmission-allocation.json)
- [Terminal flow-control cases](test-vectors/terminal-flow-control.json)
- [Close ordering and unknown-reason cases](test-vectors/close-ordering.json)
- [TCP binding framing cases](test-vectors/tcp-binding.json)

Test vectors and conformance cases are intended to let independent implementations verify identical wire encodings, authenticated handshake derivations, lifecycle behavior, Carrier Generation semantics, MAX_CARRIERS negotiation, active logical Carrier accounting, DORMANT recovery, Protocol Version isolation, handshake rejection, identifier exhaustion, local Carrier-selection invariants, and failure scope.

### Executable interoperability Gates 1–4

- [Draft 11 executable reference endpoint and harness](reference/README.md)

The `reference/` implementation runs a real TCP Client and Server as separate processes, uses fresh handshake randomness, and exchanges authenticated Secure Records. Gate 1 exercises 16 concurrent Streams and 1 MiB of application data in each direction. Gate 2 adds deterministic multi-Carrier/fault/recovery scenarios.

Gate 3 retains the 121 A–L case IDs and records the executable evidence class of every case as `codec`, `endpoint-wire`, or `cross-wire`. The former state-model-only coverage has been driven down to **zero**: each previously model-only Mandatory requirement is now bound to a real runtime execution, while codec-only and cross-wire cases retain those evidence classes where they are the appropriate executable test surface. Each implementation currently reports **18 codec + 30 cross-wire + 73 endpoint-wire + 0 model** case IDs.

Gate 4 adds `independent/`, a source-isolated second implementation with its own wire/crypto/endpoint runtime, plus neutral `interop/` harnesses. The aggregate requires both 121/121 executable-evidence profiles with `model=0`, **286 authenticated endpoint executions** (200 baseline receiver/error/scheduling probes plus 86 A/B executions for formerly model-only requirements), **36 target-witnessed deliberate-defect controls**, **52 unmutated sensitivity baselines**, **2 oracle negative controls**, the **20-execution review-v2 suite**, and a separate **18-execution update-review suite** covering 5 remaining counterexamples plus 4 paired normal controls across both runtimes, plus A→B/B→A basic full-duplex runs and all five cross-runtime fault scenarios in direct and fragmented modes. Update-review coverage closes post-Finished stale object installation, STOP default-RESET persistence across ACK output failure, exact TRANSMISSION_RETIRE watermark accounting during interleaving, and failover away from a key-exhausted Carrier. Sensitivity only counts a mutation when its target branch was reached; unrelated setup/handshake failures are classified ERROR/INCONCLUSIVE. J5 verifies failed candidate authentication against the actual CLI Server process. The B runtime is audited to import no `reference/`, `tools/`, or validator code and the critical A/B receive handlers are structurally compared.

This is a source/module-independence claim, not a claim that the two implementations were developed by separate organizations: both live in this repository and share public fixtures and test-scenario design. No Mandatory case is model-only, but this still does **not** mean all 121 cases are endpoint-wire tests: 18 are codec evidence and 30 are cross-wire evidence by design. Draft 11 still does **not** declare Protocol Version 4 stable.

## Extension points

- [Protocol extensions](extensions/README.md)
- [Carrier Receive Capacity Hint extension](extensions/capacity-hint.md)
- [Transport bindings](bindings/README.md)

Extensions are expected to define negotiation, scope, registry assignments, state transitions, error handling, interoperability behavior, and security considerations.

## Registries

MPX/4 maintains explicit registries for:

- Handshake Message Types;
- Handshake Parameter Types;
- Frame Types;
- Error Codes;
- published extension assignments.

Permanent assignments are maintained in [REGISTRIES.md](REGISTRIES.md).

## Repository validation

The repository includes fail-closed executable validation for JSON safety, links, registries, positive and negative VarInts, full Frame field/wire round-trips, handshake cryptography, wire-derived handshake limits, direction-bound Secure Record keys/IVs, Core Frame body legality, negotiated MAX_FRAME_PAYLOAD, close Reason length and close-last ordering, input-driven lifecycle/recovery/error-scope oracles, confirmation-type rules, complete Core Frame coverage, generated TCP fixtures, mutation checks under Python optimization, canonical-vector self-tests, real-TCP Gates 1–2, authenticated endpoint-wire negative/positive controls, formerly-model-only Mandatory endpoint execution, handler-sensitivity controls, the review-v2 and update-review concurrency/output/progress regression harnesses, model-zero 121-case Gate 3 profiles, and aggregate two-runtime Gate 4 evidence.

Validation tooling supports Python 3.11 and 3.12 and requires `cryptography>=42,<47`. GitHub Actions runs the full suite on both Python versions. `tools/validate.py` uses exit status 2 for conformance/vector validation failures; unexpected runtime or tooling failures use a different non-zero exit. `tools/mutation_test.py` first requires an unchanged baseline PASS in ordinary and optimized mode and accepts only the explicit validation-failure status for a mutation.

    python tools/generate_tcp_fixtures.py --check
    python tools/validate.py
    python -O tools/validate.py
    python tools/mutation_test.py
    python -m reference.selftest
    python reference/interop_harness.py --out-dir /tmp/mpx4-gate1
    python reference/interop_harness.py --out-dir /tmp/mpx4-gate1-fragmented --case-id gate1-proxy-fragmented --write-chunk 257 --proxy-max-chunk 1024
    python reference/gate2_harness.py --out-dir /tmp/mpx4-gate2
    python reference/gate2_harness.py --out-dir /tmp/mpx4-gate2-fragmented --write-chunk 257
    python -m interop.endpoint_wire --out-dir /tmp/mpx4-endpoint-wire
    python -m interop.endpoint_mandatory --out-dir /tmp/mpx4-endpoint-mandatory
    python -m interop.endpoint_sensitivity --out-dir /tmp/mpx4-endpoint-sensitivity
    python -m interop.review_v2 --out-dir /tmp/mpx4-review-v2
    python -m interop.review_update --out-dir /tmp/mpx4-review-update
    python -m reference.gate3_harness --out-dir /tmp/mpx4-gate3
    python -m independent.selftest
    python -m interop.gate4_harness --out-dir /tmp/mpx4-gate4

GitHub Actions runs the same checks on pushes and pull requests. Protocol integers beyond the JavaScript safe-integer range are represented as decimal strings in JSON vectors.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for specification-change requirements, registry-allocation rules, test-vector expectations, and extension guidance.

Protocol clarification, extension proposal, and interoperability issue forms are available through GitHub Issues.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md).

## Repository layout

    .
    ├── README.md
    ├── SPECIFICATION.md
    ├── STATE-MACHINES.md
    ├── ERROR-HANDLING.md
    ├── COMPATIBILITY.md
    ├── INTEROPERABILITY.md
    ├── REGISTRIES.md
    ├── SECURITY.md
    ├── CHANGELOG.md
    ├── CONTRIBUTING.md
    ├── LICENSE
    ├── bindings/
    │   ├── README.md
    │   └── tcp.md
    ├── extensions/
    │   ├── README.md
    │   ├── capacity-hint.md
    │   └── capacity-hint.json
    ├── examples/
    │   ├── handshake.md
    │   ├── frames.md
    │   ├── reliability.md
    │   ├── terminal-lifecycle.md
    │   └── tcp-carrier.md
    ├── test-vectors/
    │   ├── README.md
    │   ├── varint.json
    │   ├── frame-encoding.json
    │   ├── key-schedule.json
    │   ├── secure-record.json
    │   ├── state-validity.json
    │   ├── carrier-generation.json
    │   ├── error-scope.json
    │   ├── max-carriers.json
    │   ├── session-lifecycle.json
    │   ├── version-compatibility.json
    │   ├── handshake-reject.json
    │   ├── identity-lifecycle.json
    │   ├── reordering-reliability.json
    │   ├── confirmation-validity.json
    │   ├── handshake-ambiguity.json
    │   ├── recovery-progress.json
    │   ├── transmission-allocation.json
    │   ├── terminal-flow-control.json
    │   ├── close-ordering.json
    │   └── tcp-binding.json
    ├── tools/
    │   ├── generate_tcp_fixtures.py
    │   ├── validate.py
    │   ├── semantic_validation.py
    │   └── mutation_test.py
    ├── reference/
    │   ├── README.md
    │   ├── mpx4_core.py
    │   ├── endpoint.py
    │   ├── interop_harness.py
    │   ├── fault_proxy.py
    │   ├── gate2_runtime.py
    │   ├── gate2_harness.py
    │   ├── mandatory_model.py
    │   ├── gate3_harness.py
    │   └── selftest.py
    ├── independent/
    │   ├── README.md
    │   ├── core.py
    │   ├── endpoint.py
    │   ├── gate_runtime.py
    │   ├── state.py
    │   ├── profile.py
    │   └── selftest.py
    ├── interop/
    │   ├── README.md
    │   ├── cross_basic.py
    │   ├── cross_fault.py
    │   ├── endpoint_wire.py
    │   ├── endpoint_mandatory.py
    │   ├── endpoint_sensitivity.py
    │   └── gate4_harness.py
    └── .github/
        ├── workflows/
        │   └── validate.yml
        ├── ISSUE_TEMPLATE/
        └── pull_request_template.md

## Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described by RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## License

This repository is licensed under the [BSD 3-Clause License](LICENSE).
