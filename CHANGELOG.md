# Changelog

All notable MPX/4 specification changes are recorded here.

MPX/4 remains in draft status. Draft revisions may make incompatible wire-format changes until a stable protocol revision is declared.

## Draft 05 — 2026-10-03

Draft 05 decouples Carrier identity space from active Carrier concurrency. It removes the fixed eight-Carrier Core limit and introduces bilateral MAX_CARRIERS negotiation.

### Added

- Core Handshake Parameter `MAX_CARRIERS` at Parameter Type `0x0a`.
- Mandatory CRITICAL=1 encoding for MAX_CARRIERS.
- Client Carrier Limit and Server Carrier Limit advertisements during CREATE.
- Session-wide `Effective Carrier Limit = min(Client Carrier Limit, Server Carrier Limit)`.
- Active logical Carrier counting rules independent of Carrier ID magnitude.
- Explicit slot accounting for new Carrier IDs, active replacement, inactive replacement, CARRIER_CLOSE, SESSION_CLOSE, and detected transport loss.
- Machine-readable [max-carriers.json](test-vectors/max-carriers.json) encoding and state-conformance cases.
- Mandatory interoperability tests for asymmetric negotiation, high/sparse Carrier IDs, limit enforcement, slot release, and replacement at the limit.

### Changed

- CARRIER_ID now uses the full non-zero MPX VarInt range `1 .. 2^62-1` instead of the fixed Draft 04 range `1 .. 8`.
- `Maximum Carriers per Session = 8` is removed from Core resource limits.
- Every CREATE and JOIN handshake now carries MAX_CARRIERS in both directions.
- JOIN MUST repeat each endpoint's original CREATE-time MAX_CARRIERS value; a change is SESSION_CONFLICT.
- A candidate that would increase Active Carrier Count beyond the Effective Carrier Limit is rejected with RESOURCE_LIMIT without modifying the established Session.
- A higher Generation replacing an already active logical Carrier does not consume an additional active Carrier slot.
- Replacing an inactive logical Carrier requires a free active Carrier slot at commit time.
- A closed or lost logical Carrier releases active capacity while retaining its historical Carrier ID and Highest Accepted Generation.
- Handshake transcript vectors, Finished values, application secrets, traffic keys, traffic IVs, and dependent Secure Record vectors are regenerated because MAX_CARRIERS is authenticated as part of CLIENT_INIT and SERVER_INIT.

### Clarified

- Carrier ID numeric magnitude is identity only and does not imply Carrier count.
- Sparse Carrier IDs are legal.
- HANDSHAKING candidates do not count against MAX_CARRIERS.
- Historical Carrier IDs, retained Generation state, and tombstones do not consume active Carrier slots.
- MAX_CARRIERS is an upper bound and does not guarantee admission when another valid resource or protocol rejection applies.
- Local active counts can temporarily differ because endpoints may detect transport loss at different times; the negotiated Effective Carrier Limit itself remains identical and immutable.

### Compatibility

Draft 05 preserves Draft 04 Frame encodings, Secure Record format, VarInt format, Scheduler IDs, Error Codes, and cryptographic algorithms.

Draft 05 is intentionally not CREATE/JOIN-handshake-compatible with Draft 04 because MAX_CARRIERS is a new mandatory critical Parameter. A Draft 04 endpoint that does not understand Parameter `0x0a` rejects it instead of silently assuming the obsolete fixed-eight rule.

Because MAX_CARRIERS changes the authenticated handshake transcript, Draft 04 Finished and traffic-key test vectors are not valid Draft 05 vectors even though the underlying HKDF/HMAC/AES-GCM algorithms are unchanged.

## Draft 04 — 2026-10-03

Draft 04 is a protocol-semantics and interoperability-precision revision. It preserves Draft 03 Core wire encodings, cryptographic derivations, Frame and Parameter assignments, and TCP binding framing.

### Added

- Normative [ERROR-HANDLING.md](ERROR-HANDLING.md) defining Stream-opening, Carrier, Session, and pre-establishment failure scopes.
- A complete Core Carrier Generation acceptance and replacement state machine.
- Highest Accepted Generation retention rules for each used Carrier ID.
- Atomic higher-Generation commit semantics after authenticated Carrier establishment.
- Explicit superseded-Carrier behavior.
- Generation exhaustion and no-wrap semantics.
- Protocol-level Scheduler contracts for AUTO, AGGREGATE, PROTECT, and WEIGHTED without standardizing implementation algorithms.
- Machine-readable [carrier-generation.json](test-vectors/carrier-generation.json) conformance cases.
- Machine-readable [error-scope.json](test-vectors/error-scope.json) conformance cases.

### Clarified

- The first accepted incarnation of an unused Carrier ID uses Generation 0.
- Equal Generation is always a Carrier-incarnation reuse conflict, even after the earlier transport is lost or closed.
- A failed replacement candidate does not advance Generation and does not mutate the existing Session.
- A higher Generation supersedes lower Generations only after the candidate reaches ESTABLISHED.
- Superseded Carriers receive no new Attempts, contribute no new path samples, and cannot create new protocol state after Generation commit.
- Replacement preserves Stream state, flow-control state, tombstones, retired identities, Scheduler ID, and the Session-wide Transmission-ID namespace.
- PONG is returned on the same Carrier as its PING when a response is sent; Core does not define probe cadence, timeout count, or path-quality thresholds.
- STREAM_OPEN_REJECT Core reasons and their failure scope.
- FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR, and TRANSMISSION_ID_ERROR are Session-scoped.
- FRAME_ENCODING_ERROR and authentication/integrity failure are Carrier-scoped.
- Candidate JOIN errors do not alter an existing Session.
- SESSION_CLOSE is required for Session-scoped errors when an authenticated writable Carrier is available.
- Scheduler algorithms, scoring functions, weight normalization, retry timers, probe intervals, queue models, and congestion policies remain implementation-defined.

### Interoperability

Draft 04 extends the Mandatory Carrier-replacement and negative-protocol test groups with:

- first-Generation validation;
- equal-Generation non-reuse after loss;
- failed-candidate non-mutation;
- superseded-Carrier rejection behavior;
- replacement preservation of Session state;
- exact Core error scopes and close actions;
- Session-error atomicity across multiple Carriers.

### Compatibility

Draft 04 is wire-compatible with Draft 03.

No new Core Frame Type, Handshake Parameter Type, Error Code, or Scheduler ID is allocated by this revision.

Implementations that already encode Draft 03 correctly can advance to Draft 04 without changing the MPX/4 wire codec or cryptographic vectors, but must implement the tightened Carrier Generation, error-scope, measurement, and Scheduler semantic rules.

## Draft 03 — 2026-10-03

Draft 03 adds the normative TCP transport binding and a common interoperability profile. It does not change the Draft 02 Core Frame layouts, Secure Record cryptography, Stream state semantics, or existing registry assignments.

### Added

- Normative [MPX/4 over TCP](bindings/tcp.md) transport binding.
- [INTEROPERABILITY.md](INTEROPERABILITY.md) with Mandatory Core interoperability test groups.
- TCP byte-stream parsing rules independent of TCP segment, write, and receive-call boundaries.
- Explicit handling for incomplete handshake messages and partial Secure Records.
- Carrier-loss and replacement behavior over TCP.
- TCP half-close rules.
- Graceful CARRIER_CLOSE and SESSION_CLOSE mapping to TCP teardown.
- TCP_NODELAY and TCP keepalive operational guidance.
- Lower-layer multipath interaction guidance.
- TCP Carrier example.
- Machine-readable TCP fragmentation, coalescing, and mid-record EOF vectors.

### Clarified

- One TCP connection maps to exactly one MPX Carrier.
- Carrier identity is CARRIER_ID plus CARRIER_GENERATION, not the TCP four-tuple.
- A replacement Carrier never resumes the failed Carrier's cryptographic record stream.
- Replacement begins with a new handshake, fresh keys, and Record Sequence Number 0.
- Bare TCP EOF is Carrier loss, not MPX graceful close.
- TCP half-close does not substitute for any MPX Stream or Session terminal Frame.
- MPX protocol size limits are independent of TCP MSS and path MTU.
- MPX flow control does not replace TCP congestion control.
- MPX/4 Draft 03 does not assign a well-known TCP port.

### Interoperability

Draft 03 defines Mandatory test groups for:

- codec and framing;
- handshake and cryptography;
- single-Carrier Streams;
- multi-Carrier Sessions;
- retransmission and reinjection;
- flow control;
- terminal behavior;
- opening reordering and cancellation;
- tombstones and retired identities;
- Carrier loss and replacement;
- close behavior;
- negative protocol tests.

### Compatibility

Draft 03 preserves Draft 02 Core wire encoding and state semantics.

A Draft 02 implementation can generally advance to Draft 03 without changing its Core encoder or cryptographic vectors, but must satisfy the normative TCP binding when claiming TCP interoperability.

## Draft 02 — 2026-10-02

Draft 02 is a state-machine and terminal-semantics revision. It does not change the Draft 01 cryptographic profile, Secure Record encoding, VarInt encoding, or Core Frame wire layouts.

### Added

- Normative [STATE-MACHINES.md](STATE-MACHINES.md).
- Explicit Session and Carrier lifecycle states.
- Separate Stream opening state and independent send/receive direction state machines.
- Frame-validity matrices for opening, active, terminal, tombstone, and retired states.
- Acceptance-evidence rules for cross-Carrier reordering around STREAM_OPEN_OK.
- Pre-open RESET_STREAM and STOP_SENDING cancellation rules.
- Explicit behavior for late DATA after FIN and RESET.
- TRANSMISSION_ACK validity rules for outstanding, settled, compacted, and never-allocated Transmission IDs.
- Tombstone entry conditions and minimum retained semantic state.
- Retired Stream identity rules that prevent Stream-ID reuse without requiring full Stream state forever.
- Deterministic state-error precedence.
- Machine-readable state-validity cases.
- Terminal Stream lifecycle example.

### Registry changes

- Added STREAM_STATE_ERROR at 0x0e.
- Added FINAL_SIZE_ERROR at 0x0f.
- Added TRANSMISSION_ID_ERROR at 0x10.

### Clarified

- A FIN establishes final size even when earlier DATA is still missing.
- DATA below a FIN final size can arrive later and fill holes.
- DATA arriving after RESET has no application delivery effect.
- Terminal reliable Frames are retransmitted with the same Transmission ID.
- A Stream ID remains permanently used after rejection or retirement.
- Detailed tombstones can be compacted only after terminal reliability and receive accounting are settled.
- Retired identities never recreate application Stream state.

### Compatibility

Draft 02 preserves the Draft 01 wire encodings for existing handshake messages, Secure Records, Parameters, and Frames.

Implementations that follow Draft 01 wire encoding but not Draft 02 state rules can still fail interoperability under cross-Carrier reordering or late terminal traffic.

## Draft 01 — 2026-10-02

Draft 01 is a precision and interoperability revision. It intentionally adds no new transport feature set.

### Changed

- Made shortest-width VarInt encoding mandatory and non-canonical encodings invalid.
- Defined canonical handshake Parameter ordering and duplicate-Parameter rejection.
- Defined directional semantics for MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS.
- Defined PATH_CAPACITY wire format and 0.1 Mbit/s capacity units.
- Replaced the conceptual key schedule with an exact HKDF-SHA256 derivation.
- Defined exact CLIENT_FINISHED and SERVER_FINISHED calculations.
- Defined application traffic key and IV derivation.
- Defined Secure Record Flags, length semantics, sequence-number origin, nonce construction, AAD, tag length, and per-key record limit.
- Clarified that one Transmission represents one reliable logical Frame and that retransmission/reinjection retain the same Transmission ID.
- Introduced the local Attempt concept for individual Carrier sends.
- Required Session-wide monotonically allocated, non-reused Transmission IDs.
- Added a reliable-control confirmation table.
- Defined Stream-ID allocation and out-of-order STREAM_OPEN handling across Carriers.
- Defined duplicate and overlapping STREAM_DATA semantics.
- Defined exact Stream and Session credit accounting.
- Defined CREDIT_PROBE behavior.
- Split CONNECTION_CLOSE into CARRIER_CLOSE and SESSION_CLOSE.
- Defined Carrier-scoped versus Session-scoped protocol errors.
- Expanded bidirectional Stream lifecycle and final-size rules.
- Defined same-Carrier acknowledgement guidance for unambiguous path measurement.
- Made registry allocation ranges explicit.

### Registry changes

- Added CARRIER_CLOSE at Frame Type 0x03.
- Added SESSION_CLOSE at Frame Type 0x04.
- Removed Draft 00 placeholder allocations for unspecified path-management Frames.
- Returned unspecified Datagram and KEY_SHARE Parameters to reserved space.
- Returned implicit initial-credit Parameters to reserved space; Draft 01 uses explicit credit Frames.

### Test material

- Updated VarInt and Frame vectors to Draft 01.
- Added a complete key-schedule / Finished test vector.
- Added an AES-256-GCM Secure Record test vector.

### Compatibility

Draft 01 is not wire-compatible with the Draft 00 document.

No stable MPX/4 wire-compatibility commitment existed for Draft 00.

## Draft 00 — 2026-10-02

Initial publication of the MPX/4 working specification.

### Added

- Session, Carrier, Stream, Transmission, Frame, and Secure Record abstractions.
- MPX/4 Connection Preface and version-negotiation model.
- 1/2/4/8-octet MPX VarInt encoding.
- CLIENT_INIT, SERVER_INIT, CLIENT_FINISHED, and SERVER_FINISHED handshake state machine.
- Extensible handshake Parameter format with a CRITICAL flag.
- Session creation and authenticated Carrier joining.
- Carrier ID and Carrier Generation model.
- Initial HKDF-SHA256 and AES-256-GCM security design.
- Secure Records capable of carrying multiple complete Frames.
- Typed Frame encoding using VarInt Type and Length fields.
- Reliable ordered Stream model.
- Stream and Session flow-control concepts.
- Carrier-aware scheduling, retransmission, and reinjection concepts.
- Initial protocol registries.
