# MPX/4 Protocol Registries

**Protocol:** MPX/4  
**Registry Revision:** Draft 00

This document records numeric assignments used by the MPX/4 core protocol.

Values listed here are stable within a protocol version. Future specifications SHOULD allocate new values without changing existing assignments.

## 1. Handshake Message Types

| Value | Name | Status |
|---:|---|---|
| 0x00 | RESERVED | Reserved |
| 0x01 | CLIENT_INIT | Core |
| 0x02 | SERVER_INIT | Core |
| 0x03 | CLIENT_FINISHED | Core |
| 0x04 | SERVER_FINISHED | Core |
| 0x05 | VERSION_NEGOTIATION | Core |
| 0x06–0x3f | — | Reserved |
| 0x40–0x7f | — | Extension |
| 0x80+ | — | Private Use |

## 2. Handshake Parameter Types

| Value | Name | Value format | Status |
|---:|---|---|---|
| 0x00 | RESERVED | — | Reserved |
| 0x01 | SESSION_ID | 16 octets | Core |
| 0x02 | SESSION_ACTION | VarInt | Core |
| 0x03 | CARRIER_ID | VarInt | Core |
| 0x04 | CARRIER_GENERATION | VarInt | Core |
| 0x05 | CLIENT_NONCE | 32 octets | Core |
| 0x06 | SERVER_NONCE | 32 octets | Core |
| 0x07 | MAX_FRAME_PAYLOAD | VarInt | Core |
| 0x08 | MAX_RECORD_SIZE | VarInt | Core |
| 0x09 | MAX_STREAMS | VarInt | Core |
| 0x0a | INITIAL_STREAM_CREDIT | VarInt | Core |
| 0x0b | INITIAL_SESSION_CREDIT | VarInt | Core |
| 0x10 | SCHEDULER | VarInt | Core |
| 0x11 | PATH_CAPACITY | Structured | Core |
| 0x20 | DATAGRAM_SUPPORT | Empty / profile-defined | Extension |
| 0x21 | MAX_DATAGRAM_SIZE | VarInt | Extension |
| 0x22 | KEY_SHARE | Profile-defined | Extension |
| 0x23–0x3f | — | — | Reserved |
| 0x40–0x7f | — | — | Extension |
| 0x80+ | — | — | Private Use |

### 2.1. SESSION_ACTION values

| Value | Name |
|---:|---|
| 0x00 | CREATE |
| 0x01 | JOIN |

## 3. Frame Types

| Value | Name | Scope | Status |
|---:|---|---|---|
| 0x00 | PADDING | Record | Core |
| 0x01 | PING | Carrier | Core |
| 0x02 | PONG | Carrier | Core |
| 0x03 | CONNECTION_CLOSE | Connection | Core |
| 0x10 | STREAM_OPEN | Stream | Core |
| 0x11 | STREAM_OPEN_OK | Stream | Core |
| 0x12 | STREAM_OPEN_REJECT | Stream | Core |
| 0x13 | STREAM_DATA | Stream | Core |
| 0x14 | TRANSMISSION_ACK | Transmission | Core |
| 0x15 | STREAM_CREDIT | Stream | Core |
| 0x16 | STREAM_FIN | Stream | Core |
| 0x17 | RESET_STREAM | Stream | Core |
| 0x18 | STOP_SENDING | Stream | Core |
| 0x19 | STREAM_CONSUMED | Stream | Core |
| 0x20 | SESSION_CREDIT | Session | Core |
| 0x21 | CREDIT_PROBE | Stream / Session | Core |
| 0x30 | PATH_STATUS | Carrier | Extension |
| 0x31 | PATH_CHALLENGE | Carrier | Extension |
| 0x32 | PATH_RESPONSE | Carrier | Extension |
| 0x33 | PATH_RETIRE | Carrier | Extension |
| 0x34–0x3f | — | — | Reserved |
| 0x40–0x7f | — | — | Extension |
| 0x80+ | — | — | Private Use |

## 4. Error Codes

| Value | Name | Meaning |
|---:|---|---|
| 0x00 | NO_ERROR | Graceful closure |
| 0x01 | INTERNAL_ERROR | Local implementation failure |
| 0x02 | PROTOCOL_VIOLATION | Invalid protocol state or semantics |
| 0x03 | AUTHENTICATION_FAILED | Peer authentication failed |
| 0x04 | VERSION_UNSUPPORTED | Requested version unsupported |
| 0x05 | RESOURCE_LIMIT | Local resource bound reached |
| 0x06 | SESSION_NOT_FOUND | Requested Session does not exist |
| 0x07 | SESSION_CONFLICT | Session identity conflicts with existing state |
| 0x08 | STREAM_LIMIT | Maximum Stream count exceeded |
| 0x09 | FLOW_CONTROL_ERROR | Peer exceeded advertised credit |
| 0x0a | FRAME_ENCODING_ERROR | Malformed Frame encoding |
| 0x0b | SCHEDULER_MISMATCH | Scheduler policy incompatible |
| 0x0c | CARRIER_CONFLICT | Carrier ID or generation conflict |
| 0x0d | UNSUPPORTED_PARAMETER | Unknown critical Parameter |
| 0x0e–0x3f | — | Reserved |
| 0x40–0x7f | — | Extension |
| 0x80+ | — | Private Use |

## 5. Scheduler IDs

| Value | Name | Description |
|---:|---|---|
| 0x00 | AUTO | Implementation selects an operating policy based on observed path state |
| 0x01 | AGGREGATE | Concurrently uses eligible Carriers |
| 0x02 | PROTECT | Maintains a preferred Carrier with alternate Carrier protection |
| 0x03 | WEIGHTED | Uses configured capacity together with live path signals |
| 0x04–0x3f | — | Reserved |
| 0x40–0x7f | — | Extension |
| 0x80+ | — | Private Use |

## 6. Parameter Flags

| Bit | Name | Meaning |
|---:|---|---|
| 0 | CRITICAL | Unknown Parameter requires handshake rejection |
| 1–7 | RESERVED | MUST be zero in Draft 00 |

## 7. Allocation policy

Draft 00 uses the following policy:

- **Core:** defined by the MPX/4 core specification.
- **Reserved:** unavailable until assigned by a future protocol revision.
- **Extension:** available to a published compatible extension.
- **Private Use:** implementation-specific and not assumed interoperable.

Once assigned in a stable MPX/4 revision, a numeric value SHOULD NOT be reassigned to a different semantic meaning.
