# Changelog

All notable MPX/4 specification changes are recorded here.

MPX/4 remains in draft status. Draft revisions may make incompatible wire-format changes until a stable protocol revision is declared.

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
