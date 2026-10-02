# MPX/4 Core Protocol Specification

**Document:** MPX/4 Core Protocol  
**Revision:** Draft 00  
**Protocol Version:** 4  
**Status:** Working Draft

---

## Abstract

MPX/4 is an application-layer multipath transport protocol that combines multiple authenticated carrier connections into one logical Session. Applications communicate through reliable ordered Streams, while MPX independently schedules individual transmissions across available Carriers and may retransmit or reinject data on a different Carrier when delivery feedback indicates that doing so is beneficial.

The protocol separates Session semantics from carrier transport semantics. A Carrier is an authenticated path associated with an existing Session; multiple Carriers may be active concurrently. MPX therefore preserves a single ordered Stream abstraction while permitting individual portions of that Stream to traverse different paths.

This document defines the MPX/4 core protocol, including connection establishment, variable-length integer encoding, authentication, secure records, Frames, Streams, Carriers, flow control, delivery acknowledgements, retransmission, reinjection, path measurement, error handling, and extensibility.

## 1. Introduction

MPX/4 provides an end-to-end transport abstraction above one or more underlying carrier transports.

An MPX Session contains one or more Carriers. Each Carrier is an authenticated transport connection between the same pair of MPX endpoints. A Session multiplexes one or more Streams and maintains Stream state independently of any individual Carrier.

This separation permits:

1. concurrent use of multiple paths;
2. failover without terminating application Streams;
3. retransmission of outstanding data on an alternate Carrier;
4. scheduling based on observed latency, delivery rate, and outstanding work;
5. independent lifecycle management for Streams and Carriers.

MPX/4 does not require an underlying transport to expose message boundaries. The initial binding assumes a reliable ordered octet stream.

### 1.1. Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## 2. Terminology

**Endpoint** — An implementation participating in an MPX Session.

**Client** — The endpoint that creates a new Session.

**Server** — The endpoint that accepts a new Session.

**Session** — The logical end-to-end MPX association. Stream state, flow-control state, and scheduler policy belong to the Session.

**Carrier** — One authenticated underlying transport connection attached to a Session.

**Carrier ID** — A small integer identifying a logical Carrier within a Session.

**Carrier Generation** — A monotonically increasing value distinguishing successive transport connections for the same Carrier ID.

**Stream** — A reliable ordered byte stream carried by a Session.

**Transmission** — One schedulable and acknowledgeable MPX protocol unit. A retransmission or reinjection of the same Stream bytes uses a new Transmission ID.

**Reinjection** — Sending previously transmitted but unacknowledged Stream bytes on a different Carrier.

**Frame** — A typed protocol message contained within a Secure Record.

**Secure Record** — An authenticated encrypted container that carries one or more complete Frames.

**Credit** — An absolute transmission limit advertised by the receiver.

## 3. Architectural model

```text
Application
    |
    v
MPX Streams
    |
    v
MPX Session
    |
    +-- Carrier 1
    +-- Carrier 2
    +-- Carrier 3
    `-- ...
    |
    v
MPX Secure Record Layer
    |
    v
Transport Binding
```

Session state MUST survive the loss of an individual Carrier as long as at least one valid Carrier remains or the implementation permits a reconnection interval.

Stream byte ordering is defined by Stream offsets, not Carrier order.

## 4. Transport binding

The initial MPX/4 transport binding is a reliable ordered byte stream.

For a TCP binding:

- MPX MUST NOT depend on TCP segment boundaries.
- Multiple MPX Secure Records MAY be written in one transport write.
- One MPX Secure Record MAY require multiple transport reads.
- An implementation SHOULD avoid buffering policies that create avoidable latency for small control Frames.
- Path MTU and TCP MSS are properties of the underlying transport and are not MPX Frame-size limits.

The default maximum MPX Frame payload is 32768 bytes.

## 5. Connection preface and version negotiation

Each new Carrier begins with a Connection Preface:

```text
+-------------------------------+
| Magic              4 octets   |
+-------------------------------+
| Version             VarInt     |
+-------------------------------+
```

The Magic value is:

```text
4d 50 58 00
 M  P  X  \0
```

Version 4 is encoded as the VarInt value 4.

The Connection Preface identifies the protocol and the requested major version. The version is connection-scoped and MUST NOT be repeated in every Frame.

If a peer does not support the requested version, it MAY send VERSION_NEGOTIATION listing supported versions and then close the transport connection.

## 6. Variable-length integers

MPX/4 uses a 1-, 2-, 4-, or 8-octet variable-length integer representation.

The two most significant bits of the first octet encode the total integer width:

| Prefix | Width | Usable bits |
|---|---:|---:|
| 00 | 1 octet | 6 |
| 01 | 2 octets | 14 |
| 10 | 4 octets | 30 |
| 11 | 8 octets | 62 |

Values are encoded in network byte order. The maximum representable value is `2^62 - 1`.

Endpoints MUST reject non-conforming encodings. Encoders SHOULD use the shortest representation capable of holding the value.

## 7. Handshake

A newly connected Carrier progresses through the following states:

```text
TRANSPORT_CONNECTED
        |
        v
CONNECTION_PREFACE
        |
        v
CLIENT_INIT
        |
        v
SERVER_INIT
        |
        v
CLIENT_FINISHED
        |
        v
SERVER_FINISHED
        |
        v
ESTABLISHED
```

A Carrier MUST NOT carry application Frames before entering ESTABLISHED.

### 7.1. Handshake message format

```text
+-------------------------------+
| Message Type        VarInt     |
+-------------------------------+
| Message Length      VarInt     |
+-------------------------------+
| Message Body        ...        |
+-------------------------------+
```

### 7.2. Parameter format

CLIENT_INIT and SERVER_INIT contain Parameters:

```text
+-------------------------------+
| Parameter Type      VarInt     |
+-------------------------------+
| Flags               1 octet    |
+-------------------------------+
| Length              VarInt     |
+-------------------------------+
| Value               Length     |
+-------------------------------+
```

Parameter flag bit 0 is CRITICAL.

An endpoint receiving an unknown Parameter with CRITICAL=0 MUST ignore that Parameter.

An endpoint receiving an unknown Parameter with CRITICAL=1 MUST abort the handshake with UNSUPPORTED_PARAMETER.

All other flag bits are reserved and MUST be zero unless negotiated by a future specification.

## 8. Session establishment

The Client creates a Session by sending CLIENT_INIT with at least:

- SESSION_ID;
- SESSION_ACTION = CREATE;
- CARRIER_ID;
- CARRIER_GENERATION;
- CLIENT_NONCE;
- MAX_FRAME_PAYLOAD;
- MAX_STREAMS;
- SCHEDULER.

SESSION_ID is a 128-bit cryptographically random value.

The first Carrier of a new Session SHOULD use Carrier ID 1 and Generation 0.

The Server MUST reject creation when the supplied Session ID conflicts with an incompatible live Session.

### 8.1. Joining an existing Session

Additional Carriers use `SESSION_ACTION = JOIN` and provide the same SESSION_ID plus their own Carrier ID and Generation.

The Server MUST authenticate the Carrier before attaching it to Session state.

### 8.2. Carrier generations

A logical Carrier identity is the tuple `(Carrier ID, Generation)`.

If Carrier 2 disconnects and is re-established, a subsequent connection can use:

```text
Carrier ID = 2
Generation = previous generation + 1
```

A peer MUST reject stale generations once a higher generation has been accepted for the same Carrier ID.

## 9. Authentication and key schedule

MPX/4 Draft 00 uses a 32-octet pre-shared transport key as the authentication root.

CLIENT_INIT contains a fresh 32-octet CLIENT_NONCE.

SERVER_INIT contains a fresh 32-octet SERVER_NONCE.

The handshake transcript consists of the exact encoded bytes of:

```text
Connection Preface ||
CLIENT_INIT ||
SERVER_INIT
```

The key schedule uses HKDF-SHA256.

Conceptually:

```text
early_secret =
    HKDF-Extract(0, transport_key)

handshake_secret =
    HKDF-Expand(
        early_secret,
        "mpx4 handshake",
        SHA-256(transcript)
    )
```

Distinct labels MUST be used to derive:

- client finished key;
- server finished key;
- client application traffic key;
- server application traffic key.

CLIENT_FINISHED and SERVER_FINISHED contain transcript authentication values computed with the corresponding finished keys.

An implementation MUST use constant-time comparison for authentication values.

A future extension MAY introduce an ephemeral key exchange through a negotiated KEY_SHARE Parameter without changing the Session or Frame model.

## 10. Secure Record Layer

After the handshake reaches ESTABLISHED, all protocol Frames are transported in Secure Records.

```text
+--------------------------------+
| Record Flags        1 octet     |
+--------------------------------+
| Ciphertext Length   VarInt      |
+--------------------------------+
| Ciphertext          ...         |
+--------------------------------+
| Authentication Tag  AEAD-sized  |
+--------------------------------+
```

The Record header is authenticated as associated data.

Draft 00 uses AES-256-GCM as the mandatory-to-implement AEAD.

Each direction maintains an independent 64-bit monotonically increasing Record Sequence Number.

Sequence-number reuse with the same traffic key is forbidden.

A Secure Record MAY contain multiple complete Frames.

A Frame MUST NOT cross a Secure Record boundary.

This permits small control Frames to share one AEAD authentication tag with adjacent Frames.

## 11. Frame encoding

After record decryption, Frames are encoded as:

```text
+-------------------------------+
| Frame Type          VarInt     |
+-------------------------------+
| Frame Length        VarInt     |
+-------------------------------+
| Frame Body          Length     |
+-------------------------------+
```

Frame Length is the size of Frame Body only.

A receiver MUST NOT interpret transport-write boundaries as Frame boundaries.

Unknown extension Frames can be skipped because every Frame has an explicit length.

## 12. Stream model

MPX/4 Streams are reliable ordered byte streams.

Draft 00 uses odd positive Stream IDs for Client-initiated bidirectional Streams:

`1, 3, 5, 7, ...`

Even Stream IDs are reserved for future stream classes.

Stream data is identified by `(Stream ID, Offset)` and is independent of the Carrier used for transmission.

A receiver MUST deliver Stream bytes to the application in increasing Offset order.

Duplicate bytes already accepted at a Stream Offset MUST NOT be delivered twice.

## 13. STREAM_OPEN

Body:

```text
Stream ID   VarInt
Open ID     VarInt
```

Open ID is a Transmission identifier used to correlate acceptance or rejection.

A Stream MUST NOT carry STREAM_DATA until its open request is accepted.

## 14. STREAM_OPEN_OK

Body:

```text
Stream ID   VarInt
Open ID     VarInt
```

The Open ID MUST match an outstanding STREAM_OPEN for the same Stream.

## 15. STREAM_OPEN_REJECT

Body:

```text
Stream ID   VarInt
Open ID     VarInt
Error Code  VarInt
```

## 16. STREAM_DATA

Body:

```text
Stream ID        VarInt
Offset           VarInt
Transmission ID  VarInt
Data             remaining octets
```

Transmission ID MUST be non-zero and unique among simultaneously outstanding transmissions in the Session.

The same Stream bytes MAY be sent again using the same Stream ID and Offset but a different Transmission ID.

This property enables retransmission and cross-Carrier reinjection without changing Stream byte identity.

A receiver acknowledges a transmission using TRANSMISSION_ACK.

## 17. TRANSMISSION_ACK

Body:

```text
Stream ID              VarInt
Transmission ID        VarInt
Receiver Timestamp     VarInt
```

Receiver Timestamp is a monotonically increasing clock value relative to Session establishment.

Draft 00 uses microseconds as the timestamp unit.

Clock synchronization between endpoints is not required. Implementations MUST NOT compare the absolute value of local and remote clocks.

Timestamp differences on the same remote clock MAY be used for delivery-rate estimation.

## 18. STREAM_CREDIT

Body:

```text
Stream ID         VarInt
Consumed Offset   VarInt
Maximum Offset    VarInt
```

Consumed Offset identifies the highest contiguous Stream position consumed by the receiving application.

Maximum Offset is the absolute maximum Stream offset the peer is currently permitted to send.

Maximum Offset MUST NOT decrease.

A sender MUST NOT transmit data beyond Maximum Offset.

This is an absolute-credit model, not an incremental-grant model.

## 19. SESSION_CREDIT

Body:

```text
Consumed Bytes    VarInt
Maximum Bytes     VarInt
```

Session credit limits aggregate committed Stream data.

Maximum Bytes MUST NOT decrease.

The sender MUST satisfy both Stream credit and Session credit before transmitting new Stream data.

## 20. STREAM_FIN

Body:

```text
Stream ID        VarInt
Transmission ID  VarInt
Final Offset     VarInt
```

Final Offset identifies the end of the sending side of the Stream.

STREAM_FIN is reliable and is acknowledged through TRANSMISSION_ACK.

A receiver MUST treat inconsistent Final Offset values as a protocol violation.

## 21. RESET_STREAM

Body:

```text
Stream ID        VarInt
Transmission ID  VarInt
Final Offset     VarInt
Error Code       VarInt
```

RESET_STREAM terminates the sending direction of a Stream.

## 22. STOP_SENDING

Body:

```text
Stream ID        VarInt
Transmission ID  VarInt
Error Code       VarInt
```

STOP_SENDING requests that the peer cease future transmission on the Stream.

## 23. STREAM_CONSUMED

Body:

```text
Stream ID        VarInt
Transmission ID  VarInt
Final Offset     VarInt
```

STREAM_CONSUMED confirms final receive-side consumption and permits retirement of terminal Stream state when all other required conditions are satisfied.

## 24. PING and PONG

PING body:

```text
Token  VarInt
```

PONG body:

```text
Token  VarInt
```

A PONG MUST echo the Token from the corresponding PING.

PING/PONG is Carrier-scoped and MAY be used to estimate Carrier round-trip time.

## 25. Carrier state

Each Carrier maintains, at minimum:

- Carrier ID;
- Generation;
- active/inactive state;
- latest RTT estimate;
- minimum observed RTT;
- outstanding scheduled bytes;
- observed delivery rate;
- configured capacity, when applicable;
- scheduler role;
- failure and penalty state.

Carrier metrics are local implementation state unless explicitly exposed by a negotiated extension.

## 26. Scheduling

MPX/4 separates the scheduler from the Stream abstraction.

The Session Scheduler selects a Carrier for each newly schedulable Transmission.

Draft 00 defines four scheduler identifiers:

- AUTO;
- AGGREGATE;
- PROTECT;
- WEIGHTED.

The core protocol specifies identifiers and configuration exchange. The detailed decision algorithm is implementation-defined unless a scheduler-specific profile defines stronger requirements.

A scheduler MAY consider minimum RTT, smoothed RTT, estimated delivery rate, queued or outstanding bytes, configured link capacity, recent failures, penalty intervals, and path role.

A scheduler MUST NOT violate Session or Stream reliability semantics.

## 27. Retransmission and reinjection

An outstanding STREAM_DATA transmission is tracked by Transmission ID.

If the sender determines that retransmission is required, it MAY create a new Transmission for the same Stream ID, Offset, and Data.

The new transmission uses a new Transmission ID.

If the new transmission uses a different Carrier, the operation is a reinjection.

An acknowledgement of any valid transmission carrying the required Stream bytes allows the sender to retire redundant outstanding transmissions for those bytes according to implementation policy.

Reinjection MUST NOT cause duplicate application delivery.

## 28. Delivery measurement

TRANSMISSION_ACK can carry Receiver Timestamp information.

A sender MAY use local send time, local acknowledgement arrival time, remote monotonic acknowledgement timestamps, and acknowledged byte counts to estimate Carrier RTT and delivery rate.

Delivery-rate estimation SHOULD avoid treating application-limited traffic as path-capacity measurement.

A scheduler SHOULD distinguish transport congestion, queueing, and lack of offered load when updating path metrics.

## 29. Flow-control invariants

Implementations MUST enforce:

1. Stream credit is absolute and monotonic.
2. Session credit is absolute and monotonic.
3. New data MUST satisfy both limits.
4. Receiving data beyond advertised credit is a FLOW_CONTROL_ERROR.
5. Credit accounting MUST remain valid across Carrier failure and reinjection.
6. A retransmission of already committed bytes MUST NOT consume new logical Stream credit.

## 30. CONNECTION_CLOSE

Body:

```text
Error Code          VarInt
Trigger Frame Type  VarInt
Reason Length       VarInt
Reason              UTF-8 octets
```

Reason is diagnostic only.

Protocol behavior MUST NOT depend on Reason text.

## 31. Extensibility

MPX/4 provides extension points through:

- version negotiation;
- Parameters;
- Frame types;
- scheduler identifiers;
- error codes;
- reserved Stream-ID classes;
- future transport bindings.

Extension specifications MUST state whether new state is Session-scoped, Carrier-scoped, or Stream-scoped.

An extension MUST NOT silently reinterpret an existing registered field.

Unknown non-critical Parameters are ignored.

## 32. Protocol registries

The initial registries are maintained in [REGISTRIES.md](REGISTRIES.md).

Registries include Handshake Message Types, Parameter Types, Frame Types, Error Codes, and Scheduler IDs.

## 33. Security considerations

MPX carries application data and transport-control state across potentially untrusted networks.

An implementation MUST authenticate a Carrier before associating it with Session state.

Application traffic and control Frames MUST be integrity protected.

Traffic keys for opposite directions MUST be distinct.

Traffic keys for independent Carrier handshakes SHOULD be independently derived.

AEAD nonces MUST NOT repeat under the same key.

Handshake authentication MUST cover all Parameters that influence Session behavior, including Session identity, Session action, Carrier identity, scheduler selection, flow-control limits, and negotiated protocol limits.

Implementations SHOULD impose bounds on simultaneous Sessions, Carriers per Session, Streams per Session, pending Frames, pending bytes, reassembly state, and handshake duration.

Protocol errors SHOULD fail closed.

## 34. Resource limits

Recommended Draft 00 defaults:

| Limit | Default |
|---|---:|
| Maximum Carriers per Session | 8 |
| Maximum Frame payload | 32768 bytes |
| Maximum Secure Record plaintext | 65536 bytes |
| Maximum active Streams | 2048 |

Implementations MAY advertise lower compatible limits.

A peer MUST respect negotiated limits.

## 35. Operational considerations

A Session can remain operational while individual Carriers fail and reconnect.

Operators SHOULD provision at least one Carrier whose failure characteristics are independent of other Carriers when resilience is required.

Configured path capacity SHOULD represent usable transport capacity rather than nominal interface speed.

Scheduler telemetry SHOULD distinguish configured capacity from measured delivery rate.

## 36. Wire-size considerations

MPX/3 used a fixed 40-octet Frame header plus a 16-octet AEAD tag for each Frame.

MPX/4 uses VarInt Frame fields and permits multiple Frames to share one Secure Record authentication tag.

For a typical STREAM_DATA carrying 32768 bytes with small identifiers, the Frame metadata can be approximately 8–16 octets before record-layer overhead, depending on actual field values.

This is an encoding property, not an MTU. The underlying byte-stream transport remains responsible for segmentation.

## 37. State-machine summary

### 37.1. Carrier

```text
IDLE
 |
 v
CONNECTING
 |
 v
HANDSHAKING
 |
 v
ACTIVE
 |   \
 |    \ failure
 |     v
 |   INACTIVE
 |     |
 |     | reconnect with next Generation
 |     +------------------+
 |                        |
 +------------------------+
```

### 37.2. Stream

```text
IDLE
 |
 v
OPENING
 |
 +---- reject ----> CLOSED
 |
 v
OPEN
 |
 +---- FIN --------+
 |                 |
 +---- RESET ------+--> CLOSING --> RETIRED
```

## 38. Future work

The following items are intentionally outside Draft 00:

- ephemeral key exchange and forward-secrecy profile;
- datagram transport;
- server-initiated Streams;
- richer acknowledgement ranges;
- forward error correction;
- explicit Carrier migration;
- additional scheduler profiles;
- non-TCP transport bindings.

These features can be added without changing the core Session/Carrier/Stream architecture.

## Appendix A. Design invariants

An interoperable MPX/4 implementation preserves these invariants:

1. Stream identity is independent of Carrier identity.
2. Stream byte identity is defined by Stream ID and Offset.
3. Transmission identity is distinct from Stream byte identity.
4. Carrier failure does not itself terminate Streams.
5. Flow-control credit is Session state, not Carrier state.
6. Retransmission and reinjection do not consume new logical Stream credit.
7. A Carrier is authenticated before joining Session state.
8. Frame semantics do not depend on underlying packet boundaries.
9. Unknown optional handshake Parameters do not break extensibility.
10. Wire registries have stable numeric assignments.

## Appendix B. Initial conformance checklist

A conforming Draft 00 implementation:

- recognizes the MPX/4 Connection Preface;
- implements MPX VarInt;
- performs CLIENT_INIT / SERVER_INIT / FINISHED authentication;
- implements AES-256-GCM Secure Records;
- supports one or more authenticated Carriers per Session;
- implements STREAM_OPEN, STREAM_DATA, TRANSMISSION_ACK, STREAM_CREDIT, SESSION_CREDIT, STREAM_FIN, RESET_STREAM, and CONNECTION_CLOSE;
- enforces Stream and Session credit;
- preserves Stream ordering across Carriers;
- prevents duplicate application delivery under retransmission and reinjection;
- rejects malformed lengths and invalid state transitions.
