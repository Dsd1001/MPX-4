# Changelog

All notable specification changes to MPX/4 are recorded here.

The protocol is currently in draft status. Draft revisions may make incompatible wire-format changes until a stable MPX/4 revision is declared.

## Draft 00 — 2026-10-02

Initial publication of the MPX/4 working specification.

### Added

- Session, Carrier, Stream, Transmission, Frame, and Secure Record abstractions.
- MPX/4 Connection Preface and version negotiation model.
- 1/2/4/8-octet MPX VarInt encoding.
- CLIENT_INIT, SERVER_INIT, CLIENT_FINISHED, and SERVER_FINISHED handshake state machine.
- Extensible handshake Parameter format with a CRITICAL flag.
- Session creation and authenticated Carrier joining.
- Carrier ID and Carrier Generation model.
- HKDF-SHA256 key schedule and AES-256-GCM mandatory-to-implement record profile.
- Secure Records capable of carrying multiple complete Frames.
- Typed Frame encoding using VarInt Type and Length fields.
- Reliable ordered Stream model.
- STREAM_OPEN, STREAM_DATA, TRANSMISSION_ACK, STREAM_CREDIT, SESSION_CREDIT, STREAM_FIN, RESET_STREAM, STOP_SENDING, and STREAM_CONSUMED semantics.
- Explicit distinction between Stream byte identity and Transmission identity.
- Cross-Carrier retransmission and reinjection semantics.
- Carrier path measurement model and scheduler registry.
- AUTO, AGGREGATE, PROTECT, and WEIGHTED scheduler identifiers.
- Initial protocol registries and error codes.
- Security considerations and resource-limit guidance.

### Compatibility

Draft 00 is the first MPX/4 wire-format draft and therefore defines no backward-compatibility guarantee with earlier MPX protocol versions.
