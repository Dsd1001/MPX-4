# Security Policy

## Scope

This document describes security requirements and operational guidance for MPX/4 implementations.

Normative protocol behavior is defined in [SPECIFICATION.md](SPECIFICATION.md), [STATE-MACHINES.md](STATE-MACHINES.md), [ERROR-HANDLING.md](ERROR-HANDLING.md), and [COMPATIBILITY.md](COMPATIBILITY.md). This document supplements those requirements and describes the vulnerability-reporting process for this repository.

## Draft 11 security profile

The mandatory-to-implement Draft 11 profile uses:

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

Draft 11 defines no on-wire PSK identity or key selector. The deployment/service context MUST select the one transport key used to verify a candidate before Finished authentication is evaluated. A shared listener serving multiple transport keys therefore needs an external trusted demultiplexing context or a separately negotiated extension; Core does not standardize trial-decryption/verification across a key set. PSK selection is not itself peer authentication.

When CREATE is authenticated and accepted, the retained Session MUST be bound to the authentication principal or administrative trust domain represented by that deployment/service key context. Every later JOIN or replacement Carrier MUST authenticate under the same Session binding, or under a deployment-authorized key-rotation mapping that explicitly preserves that binding, before it can attach to the Session. Possession of a Session ID alone MUST NOT authorize JOIN. A listener that serves multiple trust domains MUST therefore preserve the CREATE-time binding across all endpoints that can accept JOIN for that Session; a candidate authenticated under a different unrelated key context is SESSION_CONFLICT even if its Session ID and other Core Parameters match.

This requirement does not add a mandatory on-wire key selector. Deployments can satisfy it with listener partitioning, trusted external demultiplexing, shared authenticated Session metadata, or an extension that defines authorized key rotation.

A transport key SHOULD be replaced after suspected disclosure.

## Forward secrecy

The mandatory Draft 11 profile does not provide forward secrecy.

Knowledge of the long-term transport key together with recorded handshake and traffic data can permit retrospective derivation of Carrier traffic keys.

A future negotiated ephemeral key-exchange profile can add forward secrecy without changing the Session, Carrier, or Stream abstractions.

## Handshake transcript integrity

Finished authentication covers the exact encoded Connection Preface, CLIENT_INIT, and SERVER_INIT bytes, and SERVER_FINISHED additionally commits to CLIENT_FINISHED as specified by the transcript hashes.

Implementations MUST authenticate all Parameters that influence Session behavior, including:

- Session ID and action;
- Carrier ID and Generation;
- receive limits;
- MAX_CARRIERS advertisements and therefore the Effective Carrier Limit;
- fresh handshake nonces.

Parameter parsing MUST reject duplicate, out-of-order, malformed, and contradictory Core Parameters before accepting the handshake.

HANDSHAKE_REJECT is deliberately outside the successful Finished transcript and is unauthenticated. Its Error Code is diagnostic only. A receiver MUST NOT treat HANDSHAKE_REJECT as peer authentication, mutate an existing Session because of it, or relax Protocol Version policy in response to it.

## Key separation

Client and Server Finished keys are independently derived.

Client-to-Server and Server-to-Client application traffic secrets are independently derived.

Each Carrier performs a fresh handshake containing fresh nonces and Carrier identity, producing independent traffic keys even when multiple Carriers belong to the same Session.

## Secure Record safety

Draft 11 uses a per-direction Record Sequence Number beginning at zero.

The sequence number is not transmitted. The underlying ordered byte-stream binding allows the receiver to advance the expected sequence deterministically.

The AES-GCM nonce is the direction-specific traffic IV XORed with the 96-bit representation of the sequence number.

Nonce reuse under one traffic key is forbidden.

Draft 11 permits at most 2^24 Secure Records in one direction under one application traffic key. Before exceeding this limit, the endpoint MUST establish a fresh Carrier handshake.

A sender that has assigned a sequence number to a complete serialized Record MUST emit that exact Record next or abandon the Carrier. Skipping a generated Record and continuing with a later sequence number would desynchronize the implicit nonce sequence; rolling the sequence number backward would risk nonce reuse.

An AEAD authentication failure terminates the affected Carrier. Failed plaintext MUST NOT be processed.

## Replay and stale Carrier handling

A complete old Carrier handshake cannot validly replace a newer Carrier incarnation solely by replaying Session identifiers.

Implementations MUST enforce Carrier Generation rules:

- the first accepted incarnation of an unused Carrier ID uses Generation 0;
- a lower Generation than Highest Accepted Generation is stale;
- an equal Generation is rejected even after the earlier transport is lost, because an accepted Carrier-incarnation tuple is never reusable;
- a higher Generation does not supersede anything until the candidate Carrier is fully authenticated and accepted;
- a higher accepted Generation supersedes all lower Generations for that Carrier ID;
- superseded Carriers are not eligible for new Attempts or path-measurement samples;
- Generation values never wrap.

Reliable Transmission IDs are Session-wide, allocated consecutively from 1, and are never skipped, reused, or wrapped. Stream IDs and Carrier Generations likewise never wrap within their defined spaces.

TRANSMISSION_RETIRE is authenticated Session state carried inside Secure Records. An endpoint may discard confirmation-replay detail only for peer Transmission IDs covered by the authenticated peer retirement watermark. A stale or lost retirement advertisement may delay reclamation but cannot settle an outstanding Transmission or authorize duplicate application delivery.

Retransmission and reinjection repeat the same Transmission ID. If the same Transmission ID is observed with different semantic Frame contents, the Session fails with TRANSMISSION_ID_ERROR.

## Stream-data integrity

Draft 11 state validation is normative in [STATE-MACHINES.md](STATE-MACHINES.md). State contradictions are treated as authenticated semantic protocol errors rather than parser errors.

AEAD authenticates Frame bytes in transit, but the protocol also defines semantic duplicate handling.

While byte-comparison evidence remains eligible under the Core state rules, data that overlaps byte positions already accepted on a Stream MUST contain identical overlapping octets. This includes active and active-terminal Stream state before valid TOMBSTONE entry. After valid TOMBSTONE entry, DATA wholly within the recorded peer Final Offset is stale and exact application-byte comparison evidence may be released; reliable Transmission-ID semantic consistency and any required confirmation replay remain independently enforced.

Conflicting bytes at the same Stream offset while byte-comparison evidence remains eligible are a Session-level protocol violation.

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
- simultaneous unauthenticated Carrier candidates;
- Secure Record plaintext;
- Frame bodies;
- active Sessions;
- active logical Carriers per Session, never above the Effective Carrier Limit;
- active Streams;
- pending reliable Transmissions;
- receive buffering;
- diagnostic reason strings.

Malformed input MUST NOT cause integer overflow, memory corruption, unbounded allocation, or process termination.

## Version downgrade resistance

VERSION_NEGOTIATION is unauthenticated and MUST NOT override local minimum-version or disabled-version policy.

An endpoint MUST NOT respond to an authentication failure, Secure Record failure, or other post-preface failure by automatically retrying a lower Protocol Version.

JOIN and replacement Carriers MUST use the immutable Session Protocol Version, preventing a lower-version Carrier from attaching to an already authenticated higher-version Session.

The unauthenticated VERSION_NEGOTIATION mechanism does not prove the highest mutually supported version. If both a higher and lower version are locally permitted, an active attacker able to suppress/forge the initial negotiation may be able to induce retry of the lower permitted version. Deployments that require strict downgrade resistance SHOULD pin the required version or minimum so that such fallback is not locally permitted until an authenticated compatible-version negotiation mechanism is available.

## DORMANT Session retention

A DORMANT Session intentionally retains authenticated Stream, flow-control, Generation, and reliable Transmission state while no Carrier is active.

Implementations SHOULD bound DORMANT Session count and retention duration to resist memory-exhaustion attacks. Retention duration is local policy and is not a peer-controlled availability guarantee.

Discarding a DORMANT Session MUST erase or retire its cryptographic and protocol state according to normal local teardown policy. A later JOIN for discarded state is rejected rather than reconstructing state from unauthenticated identifiers.

## Optional Carrier metadata trust

Core does not require or negotiate scheduling metadata. Published extensions may expose optional peer-supplied Carrier metadata.

Such metadata is authenticated only when its defining handshake completes; authentication proves who sent the value, not that the value is accurate.

Implementations MUST NOT use peer-advertised metadata to bypass congestion control, flow control, local resource policy, or Carrier usability checks.

The published [Carrier Receive Capacity Hint extension](extensions/capacity-hint.md) defines additional security considerations for optional capacity hints.

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

Failure scope is normative in [ERROR-HANDLING.md](ERROR-HANDLING.md).

Carrier-scoped authentication, integrity, or Frame-encoding failures terminate only the affected Carrier and MUST NOT invalidate other authenticated Carriers merely because they share the Session.

Session-scoped failures, including flow-control violations, final-size contradictions, and impossible Transmission identity, require a Session-wide transition to CLOSING and SESSION_CLOSE when an authenticated writable Carrier is available.

A candidate CREATE or JOIN failure MUST NOT mutate existing Session state, advance Carrier Generation, or supersede an authenticated Carrier. A safely reportable pre-establishment failure may use unauthenticated HANDSHAKE_REJECT, but the message does not widen failure scope.

Diagnostic reason strings are non-normative and MUST NOT control protocol behavior.

Implementations SHOULD avoid logging transport keys, derived traffic secrets, authentication values, or plaintext application data.

## Test vectors

The repository provides machine-readable interoperability vectors for:

- MPX VarInt encoding;
- Frame encoding;
- Draft 11 key derivation and Finished authentication;
- Draft 11 Secure Record encryption;
- Stream state validity;
- Carrier Generation replacement state;
- MAX_CARRIERS negotiation and active Carrier accounting;
- DORMANT Session lifecycle;
- Protocol Version compatibility and cross-version Session isolation;
- HANDSHAKE_REJECT encoding and unauthenticated candidate-only semantics;
- Session-ID collision and Stream/Transmission identifier exhaustion;
- ambiguous establishment and authenticated recovery boundaries;
- recovery-time credit and retirement progress;
- formal Transmission allocation and non-abandonment;
- terminal Final Offset flow-control;
- close ordering and unknown negotiated extension reasons;
- Error Code failure scope.

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


## Terminal state and tombstones

A terminal Stream can continue receiving stale authenticated duplicates from other Carriers after application-visible closure.

Implementations MUST retain enough terminal state to enforce final-size invariants, process required duplicate terminal Frames idempotently, and prevent Stream-ID reuse.

Detailed tombstones may be compacted only after the conditions in STATE-MACHINES.md are satisfied.

A compact retired identity MUST never be promoted back into a live Stream.

State compaction MUST NOT refund or recreate Session credit.


## TCP binding security

The Draft 11 TCP binding does not treat the TCP peer address, source port, destination port, route, or interface as an authenticated MPX identity.

Every TCP Carrier performs the full MPX authentication handshake.

A replacement TCP connection derives fresh traffic keys and starts new Secure Record sequence spaces. Partial Secure Records from a failed TCP connection are discarded and are never continued on the replacement connection.

Bare TCP EOF, reset, or half-close MUST NOT be interpreted as authenticated MPX Stream, Carrier, or Session terminal state.

Implementations SHOULD validate declared Secure Record length before allocating receive storage, particularly when input arrives incrementally over TCP.
