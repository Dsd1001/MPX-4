# MPX/4

**MPX/4** is an application-layer multipath transport protocol for combining multiple authenticated carrier connections into a single session. It provides stream multiplexing, connection-level and stream-level flow control, carrier-aware scheduling, retransmission, and cross-carrier reinjection.

## Specification

- [MPX/4 Core Protocol Specification](SPECIFICATION.md)
- [MPX/4 Protocol Registries](REGISTRIES.md)

## Protocol model

- **Session** — the end-to-end MPX association.
- **Carrier** — one authenticated transport path belonging to a Session.
- **Stream** — a reliable ordered byte stream multiplexed within a Session.
- **Frame** — a typed protocol unit carried by the secure record layer.
- **Scheduler** — the policy that assigns transmissions to available Carriers.

## Scope

MPX/4 defines connection establishment and version negotiation, authenticated Session creation and Carrier joining, variable-length integer encoding, secure records, extensible typed Frames, Stream lifecycle, flow control, Carrier identity, path scheduling, retransmission, reinjection, error handling, and extension rules.

The initial transport binding is an ordered reliable byte stream such as TCP. Additional transport bindings can be specified independently.

## Status

This repository contains the working MPX/4 protocol specification. The wire format remains a draft until a stable protocol revision is declared.

## Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described by RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.