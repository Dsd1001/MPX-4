# Security Policy

## Scope

This document describes security requirements for MPX/4 protocol implementations and the process for reporting protocol or implementation vulnerabilities discovered through this repository.

The normative protocol security requirements are defined in [SPECIFICATION.md](SPECIFICATION.md). This document provides additional operational guidance.

## Security model

MPX/4 assumes that Carrier transports may traverse untrusted networks.

Endpoints therefore MUST authenticate a Carrier before attaching it to Session state, and established protocol records MUST provide confidentiality and integrity protection.

The Draft 00 mandatory-to-implement secure record profile uses:

- a 32-octet pre-shared transport key as the authentication root;
- HKDF-SHA256 for key derivation;
- independent traffic keys for each direction;
- AES-256-GCM for authenticated encryption;
- monotonically increasing per-direction record sequence numbers.

## Key requirements

Transport keys MUST contain 256 bits of cryptographically random material.

Human-memorable passwords MUST NOT be used directly as transport keys.

Transport keys SHOULD be provisioned through a confidential authenticated channel and SHOULD be rotated if compromise is suspected.

Different administrative trust domains SHOULD use independent transport keys.

## Nonce and sequence-number safety

AEAD nonce reuse under the same traffic key is forbidden.

Implementations MUST:

1. maintain independent sequence-number spaces for each traffic direction;
2. prevent sequence-number wraparound;
3. derive fresh application traffic keys for independent authenticated Carrier handshakes;
4. terminate the affected Carrier before any sequence number would be reused.

## Handshake integrity

Authentication MUST cover every negotiated value that can change Session behavior, including Session identity, Carrier identity, Carrier generation, scheduler selection, flow-control limits, and protocol limits.

Implementations MUST reject malformed, truncated, duplicated, or contradictory critical handshake Parameters.

Authentication values SHOULD be compared in constant time.

## Replay considerations

Implementations MUST NOT attach a Carrier to a live Session solely on the basis of unauthenticated Session or Carrier identifiers.

Fresh handshake nonces and authenticated handshake transcripts are REQUIRED.

Implementations SHOULD maintain sufficient state to prevent an older Carrier generation from replacing a newer accepted generation for the same logical Carrier ID.

## Parser robustness

All length fields, VarInts, counts, and resource allocations MUST be validated before allocation or indexing.

Implementations SHOULD enforce explicit limits on:

- handshake message size;
- Secure Record size;
- Frame size;
- Parameters per handshake;
- active Sessions;
- Carriers per Session;
- Streams per Session;
- pending retransmissions;
- pending application bytes.

Malformed input MUST NOT cause memory corruption, integer overflow, unbounded allocation, or process termination.

## Resource exhaustion

Authentication does not remove denial-of-service risk.

Implementations SHOULD:

- bound unauthenticated handshake state;
- apply handshake deadlines;
- release incomplete Session state promptly;
- rate-limit repeated failed authentication attempts when appropriate;
- avoid allocating large per-Stream structures before authentication and limit checks complete.

## Error handling

Protocol errors SHOULD fail closed.

Diagnostic reason strings are non-normative and MUST NOT control protocol behavior.

Implementations SHOULD avoid exposing secret key material, plaintext application data, or derived traffic keys in logs.

## Cryptographic agility

Draft 00 defines a mandatory-to-implement cryptographic profile so that independent implementations have a common interoperable baseline.

Future profiles MAY introduce additional key exchanges or AEAD algorithms through explicit protocol negotiation. A new profile MUST define downgrade behavior and MUST NOT silently reinterpret existing cryptographic Parameters.

## Reporting a vulnerability

Please do not disclose suspected security vulnerabilities in a public issue.

Use the repository's GitHub private vulnerability reporting / Security Advisory mechanism when available. Reports should include:

- affected protocol revision or implementation;
- a concise description of the issue;
- reproduction steps or a minimal proof of concept when appropriate;
- expected security impact;
- any suggested mitigation.

Protocol-design issues that do not disclose an exploitable vulnerability may be discussed through normal repository issues.
