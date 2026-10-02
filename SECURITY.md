# Security Policy

## Scope

This document describes security requirements and operational guidance for MPX/4 implementations.

Normative protocol behavior is defined in [SPECIFICATION.md](SPECIFICATION.md). This document supplements those requirements and describes the vulnerability-reporting process for this repository.

## Draft 01 security profile

The mandatory-to-implement Draft 01 profile uses:

- a 32-octet cryptographically random pre-shared transport key;
- fresh 32-octet Client and Server nonces for every Carrier handshake;
- HKDF-SHA256 for key derivation;
- HMAC-SHA256 for Finished authentication;
- independent Client-to-Server and Server-to-Client traffic keys;
- AES-256-GCM with a 16-octet authentication tag;
- a 12-octet per-direction traffic IV;
- a monotonically increasing per-direction Secure Record sequence number.

The exact key schedule, nonce construction, associated-data construction, and Finished calculations are normative in the Core specification.

## Trust model

MPX/4 assumes that Carrier transports can traverse networks that are fully observable and modifiable by an attacker.

A Carrier is not authenticated merely because it presents a valid Session ID or Carrier ID.

An endpoint MUST validate the peer's Finished authentication before attaching the Carrier to authenticated Session state.

## Transport key requirements

A transport key MUST contain 256 bits of cryptographically random material.

Human-memorable passwords MUST NOT be used directly as transport keys.

Keys SHOULD be provisioned through a confidential authenticated channel.

Different administrative trust domains SHOULD use independent transport keys.

A transport key SHOULD be replaced after suspected disclosure.

## Forward secrecy

The mandatory Draft 01 profile does not provide forward secrecy.

Knowledge of the long-term transport key together with recorded handshake and traffic data can permit retrospective derivation of Carrier traffic keys.

A future negotiated ephemeral key-exchange profile can add forward secrecy without changing the Session, Carrier, or Stream abstractions.

## Handshake transcript integrity

Finished authentication covers the exact encoded Connection Preface, CLIENT_INIT, and SERVER_INIT bytes, and SERVER_FINISHED additionally commits to CLIENT_FINISHED as specified by the transcript hashes.

Implementations MUST authenticate all Parameters that influence Session behavior, including:

- Session ID and action;
- Carrier ID and Generation;
- scheduler selection;
- configured path capacity;
- receive limits;
- fresh handshake nonces.

Parameter parsing MUST reject duplicate, out-of-order, malformed, and contradictory Core Parameters before accepting the handshake.

## Key separation

Client and Server Finished keys are independently derived.

Client-to-Server and Server-to-Client application traffic secrets are independently derived.

Each Carrier performs a fresh handshake containing fresh nonces and Carrier identity, producing independent traffic keys even when multiple Carriers belong to the same Session.

## Secure Record safety

Draft 01 uses a per-direction Record Sequence Number beginning at zero.

The sequence number is not transmitted. The underlying ordered byte-stream binding allows the receiver to advance the expected sequence deterministically.

The AES-GCM nonce is the direction-specific traffic IV XORed with the 96-bit representation of the sequence number.

Nonce reuse under one traffic key is forbidden.

Draft 01 permits at most 2^24 Secure Records in one direction under one application traffic key. Before exceeding this limit, the endpoint MUST establish a fresh Carrier handshake.

An AEAD authentication failure terminates the affected Carrier. Failed plaintext MUST NOT be processed.

## Replay and stale Carrier handling

A complete old Carrier handshake cannot validly replace a newer Carrier incarnation solely by replaying Session identifiers.

Implementations MUST enforce Carrier Generation rules:

- a lower Generation than an already accepted Generation is stale;
- a conflicting equal live Generation is rejected;
- a higher authenticated Generation supersedes older state for that Carrier ID.

Reliable Transmission IDs are Session-wide and are never reused.

Retransmission and reinjection repeat the same Transmission ID. If the same Transmission ID is observed with different semantic Frame contents, the Session is invalid.

## Stream-data integrity

AEAD authenticates Frame bytes in transit, but the protocol also defines semantic duplicate handling.

When data overlaps byte positions already accepted on a Stream, the overlapping octets MUST be identical.

Conflicting bytes at the same Stream offset are a Session-level protocol violation.

Final-size declarations are immutable once authenticated. Data beyond a known final size or a contradictory final size is invalid.

## Flow-control safety

Stream and Session credit are absolute, monotonic limits.

A retransmission or reinjection of already committed bytes consumes no additional logical credit.

Implementations MUST validate:

- offset addition for integer overflow;
- Maximum Offset against Stream commitment;
- Maximum Bytes against Session commitment;
- final sizes against previously authenticated data;
- monotonically increasing consumed and maximum values.

Flow-control accounting MUST remain valid when Carriers disconnect or are replaced.

## Parser robustness

All untrusted lengths and VarInts MUST be validated before allocation or indexing.

Implementations MUST reject non-canonical VarInts.

Implementations SHOULD impose explicit bounds on:

- unauthenticated handshake bytes;
- Parameters per handshake;
- Secure Record plaintext;
- Frame bodies;
- active Sessions;
- Carriers per Session;
- active Streams;
- pending reliable Transmissions;
- receive buffering;
- diagnostic reason strings.

Malformed input MUST NOT cause integer overflow, memory corruption, unbounded allocation, or process termination.

## Resource exhaustion

Authentication does not eliminate denial-of-service risk.

Implementations SHOULD:

- apply handshake deadlines;
- bound unauthenticated handshake state;
- release incomplete Session state promptly;
- rate-limit repeated expensive failures where operationally appropriate;
- avoid allocating large per-Stream buffers before authentication and limit checks complete;
- bound retransmission and reassembly state.

## Error handling

Protocol errors SHOULD fail closed.

Carrier-scoped failures SHOULD terminate only the affected Carrier when shared Session state remains valid.

Session-state contradictions, including flow-control violations and conflicting Stream data, require Session termination.

Diagnostic reason strings are non-normative and MUST NOT control protocol behavior.

Implementations SHOULD avoid logging transport keys, derived traffic secrets, authentication values, or plaintext application data.

## Test vectors

The repository provides machine-readable interoperability vectors for:

- MPX VarInt encoding;
- Frame encoding;
- Draft 01 key derivation and Finished authentication;
- Draft 01 Secure Record encryption.

Independent implementations SHOULD validate these vectors before interoperability testing.

## Reporting a vulnerability

Do not disclose suspected exploitable vulnerabilities in a public issue.

Use GitHub private vulnerability reporting / Security Advisories when available. A useful report includes:

- affected protocol revision or implementation;
- concise issue description;
- reproduction steps or a minimal proof of concept when appropriate;
- expected security impact;
- suggested mitigation if known.

Protocol-design questions that do not disclose an exploitable vulnerability can be discussed through normal repository issues.
