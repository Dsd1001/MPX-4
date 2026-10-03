# MPX/4 Protocol Registries

**Protocol:** MPX/4  
**Registry Revision:** Draft 07

This document records numeric assignments used by the MPX/4 Core Protocol and published extensions maintained in this repository.

This file is the current registry snapshot for development Protocol Version 4. Draft revisions may still make explicitly documented incompatible changes. Once Protocol Version 4 is declared stable, assignments and incompatible semantic changes are governed by [COMPATIBILITY.md](COMPATIBILITY.md).

## 1. Allocation ranges

Unless a registry below defines a narrower rule, MPX/4 uses these numeric ranges:

| Range | Policy |
|---|---|
| 0x00–0x3f | Core and Core-reserved |
| 0x40–0x3fff | Published extensions |
| 0x4000–0x7fff | Private Use |
| 0x8000–2^62-1 | Reserved for future registry expansion |

Private Use values require an explicitly negotiated private profile and are not assumed interoperable.

## 2. Handshake Message Types

| Value | Name | Status |
|---:|---|---|
| 0x00 | RESERVED | Reserved |
| 0x01 | CLIENT_INIT | Core |
| 0x02 | SERVER_INIT | Core |
| 0x03 | CLIENT_FINISHED | Core |
| 0x04 | SERVER_FINISHED | Core |
| 0x05 | VERSION_NEGOTIATION | Core |
| 0x06–0x3f | — | Core-reserved |
| 0x40–0x3fff | — | Extension |
| 0x4000–0x7fff | — | Private Use |
| 0x8000–2^62-1 | — | Reserved |

## 3. Handshake Parameter Types

| Value | Name | Value format | Direction / scope | Status |
|---:|---|---|---|---|
| 0x00 | RESERVED | — | — | Reserved |
| 0x01 | SESSION_ID | 16 octets | Client | Core |
| 0x02 | SESSION_ACTION | VarInt | Client | Core |
| 0x03 | CARRIER_ID | VarInt | Client / Carrier | Core |
| 0x04 | CARRIER_GENERATION | VarInt | Client / Carrier | Core |
| 0x05 | CLIENT_NONCE | 32 octets | Client / Carrier | Core |
| 0x06 | SERVER_NONCE | 32 octets | Server / Carrier | Core |
| 0x07 | MAX_FRAME_PAYLOAD | VarInt | Both / receive limit | Core |
| 0x08 | MAX_RECORD_SIZE | VarInt | Both / receive limit | Core |
| 0x09 | MAX_STREAMS | VarInt | Both / receive limit | Core |
| 0x0a | MAX_CARRIERS | VarInt | Both / Session capability | Core |
| 0x0b–0x0f | — | — | — | Core-reserved |
| 0x10 | — | — | — | Reserved (retired Draft 06 SCHEDULER) |
| 0x11 | — | — | — | Reserved (retired Draft 06 PATH_CAPACITY) |
| 0x12–0x3f | — | — | — | Core-reserved |
| 0x40 | RECEIVE_CAPACITY_HINT | VarInt | Both / Carrier | Extension: Carrier Receive Capacity Hint |
| 0x41–0x3fff | — | Extension-defined | — | Extension |
| 0x4000–0x7fff | — | Private-profile-defined | — | Private Use |
| 0x8000–2^62-1 | — | — | — | Reserved |

### 3.1. SESSION_ACTION values

| Value | Name |
|---:|---|
| 0x00 | CREATE |
| 0x01 | JOIN |

## 4. Frame Types

| Value | Name | Scope | Status |
|---:|---|---|---|
| 0x00 | PADDING | Record | Core |
| 0x01 | PING | Carrier | Core |
| 0x02 | PONG | Carrier | Core |
| 0x03 | CARRIER_CLOSE | Carrier | Core |
| 0x04 | SESSION_CLOSE | Session | Core |
| 0x05–0x0f | — | — | Core-reserved |
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
| 0x1a–0x1f | — | — | Core-reserved |
| 0x20 | SESSION_CREDIT | Session | Core |
| 0x21 | CREDIT_PROBE | Stream / Session | Core |
| 0x22–0x3f | — | — | Core-reserved |
| 0x40–0x3fff | — | Extension-defined | Extension |
| 0x4000–0x7fff | — | Private-profile-defined | Private Use |
| 0x8000–2^62-1 | — | — | Reserved |

## 5. Error Codes

| Value | Name | Meaning | Core failure scope |
|---:|---|---|---|
| 0x00 | NO_ERROR | Graceful closure | Closure signal |
| 0x01 | INTERNAL_ERROR | Local implementation failure | Contextual |
| 0x02 | PROTOCOL_VIOLATION | Invalid protocol state or semantics | Carrier before ESTABLISHED; Session after ESTABLISHED |
| 0x03 | AUTHENTICATION_FAILED | Authentication failed | Carrier |
| 0x04 | VERSION_UNSUPPORTED | Requested version unsupported | Pre-establishment Carrier |
| 0x05 | RESOURCE_LIMIT | Local resource bound reached | Contextual |
| 0x06 | SESSION_NOT_FOUND | Requested Session does not exist | Pre-establishment Carrier |
| 0x07 | SESSION_CONFLICT | Session identity conflicts with existing state | Pre-establishment Carrier |
| 0x08 | STREAM_LIMIT | Maximum active Stream count exceeded | Stream opening |
| 0x09 | FLOW_CONTROL_ERROR | Peer exceeded advertised credit | Session |
| 0x0a | FRAME_ENCODING_ERROR | Malformed Frame encoding | Carrier |
| 0x0b | — | — | Reserved (retired Draft 06 SCHEDULER_MISMATCH) |
| 0x0c | CARRIER_CONFLICT | Carrier ID or Generation conflict | Pre-establishment Carrier |
| 0x0d | UNSUPPORTED_PARAMETER | Unknown critical Parameter | Pre-establishment Carrier |
| 0x0e | STREAM_STATE_ERROR | Frame is impossible in the current Stream lifecycle state | Session, except explicit STREAM_OPEN rejection cases |
| 0x0f | FINAL_SIZE_ERROR | Frame contradicts the established Stream final size | Session |
| 0x10 | TRANSMISSION_ID_ERROR | Transmission identity is conflicting or impossible | Session |
| 0x11–0x3f | — | Core-reserved | Defined on assignment |
| 0x40–0x3fff | — | Extension | Defined by extension |
| 0x4000–0x7fff | — | Private Use | Defined by private profile |
| 0x8000–2^62-1 | — | Reserved | — |

Failure scope is part of the Error Code semantics. The complete required actions are defined in [ERROR-HANDLING.md](ERROR-HANDLING.md).

AUTHENTICATION_FAILED is a registered semantic code, but an endpoint MAY close an unauthenticated Carrier without sending a wire error before ESTABLISHED.

## 6. Parameter Flags

| Bit | Name | Meaning |
|---:|---|---|
| 0 | CRITICAL | Unknown Parameter requires handshake rejection |
| 1–7 | RESERVED | MUST be zero in Draft 07 |

## 7. Registry stability

Within a stable MPX/4 Protocol Version, an assigned numeric value MUST NOT be reassigned to a different semantic meaning.

The normative versioning and registry-compatibility rules are defined in [COMPATIBILITY.md](COMPATIBILITY.md).

A Draft value removed before stability becomes Reserved unless the specification explicitly states otherwise.

Extensions SHOULD allocate from the Extension range rather than consuming Core-reserved values.
