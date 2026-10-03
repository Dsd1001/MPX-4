# Contributing to MPX/4

MPX/4 is maintained as an implementation-neutral protocol specification.

Contributions should improve interoperability, clarity, extensibility, security, or measurable transport behavior without depending on one specific codebase.

## Types of contribution

Contributions are welcome for:

- protocol clarifications;
- ambiguous or contradictory normative language;
- wire-format changes;
- new Frame or Parameter definitions;
- Carrier-selection metadata or policy-support extensions;
- security analysis;
- interoperability test vectors;
- transport-binding specifications;
- editorial improvements.

Implementation-specific bug reports should normally be filed in the implementation repository rather than this specification repository.

## Specification changes

A proposal that changes observable protocol behavior SHOULD include:

1. the problem being solved;
2. the affected protocol state;
3. the proposed wire representation;
4. endpoint behavior on success and failure;
5. backward-compatibility considerations;
6. security considerations;
7. at least one encoding or state-machine example.

Normative changes SHOULD use RFC-style requirements language consistently.

## Registry allocation

Do not select a permanent numeric value for a new Frame, Parameter, Error Code, or published extension assignment without updating [REGISTRIES.md](REGISTRIES.md).

New assignments SHOULD use the appropriate Extension range unless the change is part of the Core specification.

Private experiments SHOULD use the Private Use range.

Once a numeric value appears in a stable Protocol Version, it MUST NOT be reassigned inconsistently with [COMPATIBILITY.md](COMPATIBILITY.md).

## Extension design

An extension specification SHOULD state:

- whether it is Session-, Carrier-, Stream-, or Transmission-scoped;
- how support is negotiated;
- whether support is optional or required;
- which new registry values it consumes;
- the failure scope of every new Error Code it defines;
- whether each new Error Code is valid in STREAM_OPEN_REJECT, CARRIER_CLOSE, or SESSION_CLOSE;
- how an endpoint behaves when the extension is unsupported;
- interaction with flow control, retransmission, and connection closure;
- security and resource-consumption implications.

Extensions MUST NOT silently reinterpret existing Core fields and MUST follow the negotiation and stable-version rules in [COMPATIBILITY.md](COMPATIBILITY.md).

## Test vectors

Changes to wire encoding SHOULD include machine-readable test vectors when practical.

Changes to Stream, Carrier, Session, or Transmission lifecycle behavior SHOULD update [STATE-MACHINES.md](STATE-MACHINES.md) and the relevant lifecycle vectors. Stream validity changes belong in `test-vectors/state-validity.json`; Session ACTIVE/DORMANT/CLOSED changes belong in `test-vectors/session-lifecycle.json`.

Changes to Carrier Generation or replacement semantics SHOULD update `test-vectors/carrier-generation.json`.

Changes to CARRIER_ID range, MAX_CARRIERS negotiation, or active logical Carrier accounting SHOULD update `test-vectors/max-carriers.json`.

Changes to Protocol Version, VERSION_NEGOTIATION, stable-version compatibility, or extension negotiation SHOULD update [COMPATIBILITY.md](COMPATIBILITY.md) and `test-vectors/version-compatibility.json`.

Changes to published extension metadata semantics SHOULD update that extension's own machine-readable vectors.

Changes to Error Code scope or close behavior SHOULD update [ERROR-HANDLING.md](ERROR-HANDLING.md) and `test-vectors/error-scope.json`.

Changes to TCP transport mapping SHOULD update `bindings/tcp.md`, `test-vectors/tcp-binding.json`, and the relevant Mandatory group in [INTEROPERABILITY.md](INTEROPERABILITY.md).

Test vectors SHOULD include both:

- valid encodings that independent implementations can reproduce; and
- invalid encodings that conforming implementations are expected to reject.

## Draft revisions

Changes that alter the wire format or normative state machine should be recorded in [CHANGELOG.md](CHANGELOG.md).

During draft development, incompatible changes are permitted but SHOULD be explicitly documented. After a Protocol Version is declared stable, compatibility changes MUST follow [COMPATIBILITY.md](COMPATIBILITY.md).

## Pull requests

Keep protocol changes focused. Large independent changes are easier to review when submitted separately.

Editorial-only changes SHOULD avoid changing normative behavior.

When modifying normative text, identify whether the change is:

- clarification;
- compatible extension;
- incompatible draft change; or
- security correction.
