# MPX/4 Transport Bindings

MPX/4 separates the Core protocol from the transport used by each Carrier.

## Normative baseline

- [MPX/4 over TCP](tcp.md) — Draft 03 baseline transport binding.

The TCP binding defines connection establishment, byte-stream parsing, Secure Record mapping, transport loss, Carrier replacement, graceful close, TCP half-close behavior, and operational interaction with TCP.

## Future bindings

Additional bindings may be specified independently.

A transport-binding specification should define:

- connection establishment;
- ordering and reliability assumptions;
- mapping of Connection Preface, Handshake Messages, and Secure Records;
- parser behavior across transport fragmentation and coalescing;
- transport-specific failure and close semantics;
- Carrier identity and replacement;
- interaction with congestion control and flow control;
- maximum-record considerations;
- operational and security considerations;
- conformance and interoperability tests.

A new binding MUST preserve the Session, Stream, Transmission, and Frame semantics defined by the Core protocol.
