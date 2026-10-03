# MPX/4 Extensions

This directory is reserved for independently specified extensions to the MPX/4 Core Protocol.

An extension should define:

- negotiation and capability discovery;
- scope: Session, Carrier, Stream, or Transmission;
- new Frames or Parameters;
- registry allocations;
- endpoint state transitions;
- interaction with flow control, retransmission, and reinjection;
- error handling and the failure scope of every new Error Code;
- whether each new Error Code is valid in STREAM_OPEN_REJECT, CARRIER_CLOSE, or SESSION_CLOSE;
- security considerations;
- interoperability examples or test vectors.

Extensions MUST NOT silently reinterpret existing Core fields. Extension negotiation and same-version compatibility MUST follow [../COMPATIBILITY.md](../COMPATIBILITY.md).

Potential extension areas include datagrams, ephemeral key exchange, forward error correction, optional Carrier metadata, and path-management capabilities.

Core does not standardize scheduler modes. An extension may expose metadata useful to a local Carrier-selection policy, but SHOULD avoid requiring peers to run the same scheduling algorithm unless identical behavior is essential to interoperability.

Published extension in this repository:

- [Carrier Receive Capacity Hint](capacity-hint.md) — optional per-Carrier receive-capacity metadata; does not define a scheduler mode. Machine-readable cases: [capacity-hint.json](capacity-hint.json).
