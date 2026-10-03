# MPX/4

**MPX/4** is an application-layer multipath transport protocol for combining multiple authenticated carrier connections into a single Session.

It provides:

- authenticated multi-Carrier Sessions;
- reliable ordered bidirectional Streams;
- Stream and Session flow control;
- Carrier-aware scheduling;
- retransmission and cross-Carrier reinjection;
- extensible typed Frames and negotiated protocol Parameters.

## Current specification

**Protocol version:** 4  
**Specification revision:** Draft 05
**Status:** Working Draft

- [Core Protocol Specification](SPECIFICATION.md)
- [Normative State Machines and Frame Validity](STATE-MACHINES.md)
- [Normative Error Handling and Failure Scope](ERROR-HANDLING.md)
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
- [TCP binding framing cases](test-vectors/tcp-binding.json)

Test vectors and conformance cases are intended to let independent implementations verify identical wire encodings, authenticated handshake derivations, lifecycle behavior, Carrier Generation semantics, MAX_CARRIERS negotiation, active logical Carrier accounting, and failure scope.

## Extension points

- [Protocol extensions](extensions/README.md)
- [Transport bindings](bindings/README.md)

Extensions are expected to define negotiation, scope, registry assignments, state transitions, error handling, interoperability behavior, and security considerations.

## Registries

MPX/4 maintains explicit registries for:

- Handshake Message Types;
- Handshake Parameter Types;
- Frame Types;
- Error Codes;
- Scheduler IDs.

Permanent assignments are maintained in [REGISTRIES.md](REGISTRIES.md).

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
    │   └── README.md
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
    │   └── tcp-binding.json
    └── .github/
        ├── ISSUE_TEMPLATE/
        └── pull_request_template.md

## Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described by RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## License

This repository is licensed under the [BSD 3-Clause License](LICENSE).
