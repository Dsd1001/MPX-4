# MPX/4 Core Protocol Specification

**Document:** MPX/4 Core Protocol  
**Revision:** Draft 02  
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

**Transmission** — One reliable MPX protocol unit identified by a Session-wide Transmission ID. Retransmission and reinjection repeat the same Transmission and retain its Transmission ID.

**Attempt** — One concrete send of a Transmission on a Carrier. Attempts are local transport state and do not have a wire identifier.\n\n**Reinjection** — Sending another Attempt of an outstanding Transmission on a different Carrier.

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

    +-------------------------------+
    | Magic              4 octets   |
    +-------------------------------+
    | Version             VarInt     |
    +-------------------------------+

The Magic value is four octets:

    4d 50 58 00

Version 4 is encoded as the canonical VarInt value 4.

The Connection Preface identifies the protocol and requested major version. Version is connection-scoped and MUST NOT be repeated in Secure Records or Frames.

### 5.1. VERSION_NEGOTIATION

A Server that recognizes the MPX magic but does not support the requested version MAY send a VERSION_NEGOTIATION handshake message and then close the Carrier.

Its body is:

    Version Count        VarInt
    Supported Version    VarInt repeated Version Count times

Supported versions MUST be unique and encoded in descending numeric order.

VERSION_NEGOTIATION is unauthenticated. A Client MUST NOT treat it as proof of peer identity and MUST NOT enable a locally disabled protocol version solely because it appears in this message. If retry is permitted by local policy, the Client SHOULD select the highest mutually supported version.

## 6. Variable-length integers

MPX/4 uses a 1-, 2-, 4-, or 8-octet variable-length integer representation.

The two most significant bits of the first octet encode the total integer width:

| Prefix | Width | Usable bits |
|---|---:|---:|
| 00 | 1 octet | 6 |
| 01 | 2 octets | 14 |
| 10 | 4 octets | 30 |
| 11 | 8 octets | 62 |

Values are encoded in network byte order. The maximum representable value is 2^62 - 1.

Encoders MUST use the shortest representation capable of holding a value. Receivers MUST reject non-canonical encodings, truncated encodings, and values outside the 62-bit range.

## 7. Handshake framing and Parameter rules

A newly connected Carrier progresses through:

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

A Carrier MUST NOT carry Secure Records before entering ESTABLISHED.

### 7.1. Handshake message format

Each handshake message is:

    Message Type        VarInt
    Message Length      VarInt
    Message Body        Message Length octets

Message Length MUST use canonical VarInt encoding and MUST NOT exceed 4096 octets in Draft 02.

### 7.2. Parameter format

CLIENT_INIT and SERVER_INIT contain Parameters:

    Parameter Type      VarInt
    Flags               1 octet
    Length              VarInt
    Value               Length octets

Bit 0 of Flags is CRITICAL. Bits 1 through 7 are reserved and MUST be zero.

Parameters MUST appear in strictly increasing Parameter Type order. A Parameter Type MUST NOT occur more than once in one handshake message in Draft 02.

An endpoint receiving an unknown Parameter with CRITICAL=0 MUST ignore its value after validating its encoded length.

An endpoint receiving an unknown Parameter with CRITICAL=1 MUST abort the handshake.

Malformed, duplicate, out-of-order, or contradictory Core Parameters are protocol errors.

## 8. Core handshake Parameters

### 8.1. SESSION_ID

SESSION_ID is exactly 16 octets and identifies an MPX Session. A newly created Session ID MUST be generated from a cryptographically secure random source and MUST NOT be all zero.

### 8.2. SESSION_ACTION

SESSION_ACTION is a VarInt:

| Value | Meaning |
|---:|---|
| 0 | CREATE |
| 1 | JOIN |

CREATE establishes a new Session. JOIN attaches a new authenticated Carrier to an existing Session.

### 8.3. CARRIER_ID and CARRIER_GENERATION

CARRIER_ID is a VarInt in the range 1 through 8 in Draft 02.

CARRIER_GENERATION is a VarInt. The first transport instance of a Carrier ID uses Generation 0. A replacement transport for the same Carrier ID uses a strictly greater Generation.

The tuple (Carrier ID, Carrier Generation) identifies one Carrier incarnation.

### 8.4. CLIENT_NONCE and SERVER_NONCE

CLIENT_NONCE and SERVER_NONCE are each exactly 32 fresh random octets.

CLIENT_NONCE appears only in CLIENT_INIT.

SERVER_NONCE appears only in SERVER_INIT.

### 8.5. MAX_FRAME_PAYLOAD

MAX_FRAME_PAYLOAD is the maximum STREAM_DATA Data field, in octets, that the sender of the Parameter is willing to receive.

Valid Draft 02 values are 1 through 32768.

A peer MUST NOT send a larger STREAM_DATA Data field.

### 8.6. MAX_RECORD_SIZE

MAX_RECORD_SIZE is the maximum Secure Record plaintext length, in octets, that the sender of the Parameter is willing to receive.

Valid Draft 02 values are 1024 through 65536.

The record header and 16-octet AEAD tag are not included in this value.

A sender MUST ensure that each complete Frame fits within one Secure Record and MUST reduce STREAM_DATA chunk size when necessary.

### 8.7. MAX_STREAMS

MAX_STREAMS is the maximum number of simultaneously active peer-initiated Streams that the sender of the Parameter is willing to maintain.

Valid Draft 02 values are 1 through 2048.

Stream IDs are not bounded by MAX_STREAMS; the value limits concurrency.

### 8.8. SCHEDULER

SCHEDULER is a Session-wide Scheduler ID.

On CREATE, the Client requests one scheduler. The Server MUST either echo the same Scheduler ID in SERVER_INIT or abort the handshake with SCHEDULER_MISMATCH.

On JOIN, the Client MUST repeat the Session's existing Scheduler ID. A different value is a SCHEDULER_MISMATCH.

### 8.9. PATH_CAPACITY

PATH_CAPACITY is present only when SCHEDULER is WEIGHTED.

Its Value is:

    Downlink Capacity Units    VarInt
    Uplink Capacity Units      VarInt

One Capacity Unit equals 100,000 bits per second.

Downlink is Server-to-Client capacity. Uplink is Client-to-Server capacity.

Downlink Capacity Units MUST be in the range 1 through 65535.

Uplink Capacity Units MAY be zero, meaning no configured uplink value, or otherwise MUST be in the range 1 through 65535.

PATH_CAPACITY is Carrier-scoped and is supplied by the Client in each CLIENT_INIT. It MUST NOT appear for AUTO, AGGREGATE, or PROTECT.

### 8.10. Directional receive limits

The Client advertises receive limits in CLIENT_INIT and the Server advertises receive limits in SERVER_INIT. The two directions MAY use different values.

MAX_FRAME_PAYLOAD and MAX_STREAMS are Session-scoped directional receive limits. A JOIN handshake MUST repeat the values already established by that endpoint for the Session. A mismatch is a SESSION_CONFLICT.

MAX_RECORD_SIZE is a Carrier-scoped directional receive limit and MAY differ between Carriers in the same Session.

## 9. Session creation and Carrier joining

CLIENT_INIT for CREATE MUST contain, in canonical Parameter order:

- SESSION_ID;
- SESSION_ACTION;
- CARRIER_ID;
- CARRIER_GENERATION;
- CLIENT_NONCE;
- MAX_FRAME_PAYLOAD;
- MAX_RECORD_SIZE;
- MAX_STREAMS;
- SCHEDULER;
- PATH_CAPACITY when required by WEIGHTED.

SERVER_INIT MUST contain:

- SERVER_NONCE;
- MAX_FRAME_PAYLOAD;
- MAX_RECORD_SIZE;
- MAX_STREAMS;
- SCHEDULER.

The first Carrier of a new Session SHOULD use Carrier ID 1 and Generation 0.

The Server MUST NOT attach unauthenticated Carrier state to a live Session before validating CLIENT_FINISHED.

A JOIN uses the same SESSION_ID, SESSION_ACTION=JOIN, a Carrier ID, Generation, fresh CLIENT_NONCE, receive limits, and the existing Session Scheduler. Session-scoped receive limits MUST match the values already established for that endpoint; MAX_RECORD_SIZE MAY differ for the new Carrier.

A higher accepted Generation supersedes any lower Generation for the same Carrier ID. A lower Generation is stale and MUST be rejected. An equal Generation that conflicts with an already accepted live Carrier MUST be rejected with CARRIER_CONFLICT.

## 10. MPX/4 key schedule

Draft 02 uses a 32-octet pre-shared transport key as the authentication root, HKDF-SHA256 for key derivation, HMAC-SHA256 for Finished authentication, and AES-256-GCM for Secure Records.

### 10.1. MPX-Expand-Label

MPX-Expand-Label(Secret, Label, Context, Length) is HKDF-Expand using the following info structure:

    uint16_be(Length)
    uint8(label_length)
    ASCII("mpx4 " || Label)
    uint8(context_length)
    Context

Label does not contain a terminating zero octet.

Context length MUST fit in one octet.

### 10.2. Handshake secret

Let Z32 be 32 zero octets.

Let H0 be:

    SHA-256(
        Connection Preface ||
        encoded CLIENT_INIT ||
        encoded SERVER_INIT
    )

Then:

    early_secret =
        HKDF-Extract(Z32, transport_key)

    handshake_secret =
        MPX-Expand-Label(
            early_secret,
            "handshake",
            H0,
            32
        )

    client_finished_key =
        MPX-Expand-Label(
            handshake_secret,
            "client finished",
            empty_context,
            32
        )

    server_finished_key =
        MPX-Expand-Label(
            handshake_secret,
            "server finished",
            empty_context,
            32
        )

### 10.3. CLIENT_FINISHED

CLIENT_FINISHED has a 32-octet body:

    VerifyData =
        HMAC-SHA256(
            client_finished_key,
            H0
        )

The Server MUST validate VerifyData before attaching the Carrier to authenticated Session state.

Let H1 be:

    SHA-256(
        Connection Preface ||
        encoded CLIENT_INIT ||
        encoded SERVER_INIT ||
        encoded CLIENT_FINISHED
    )

### 10.4. SERVER_FINISHED

SERVER_FINISHED has a 32-octet body:

    VerifyData =
        HMAC-SHA256(
            server_finished_key,
            H1
        )

The Client MUST validate VerifyData before entering ESTABLISHED.

Let H2 be:

    SHA-256(
        Connection Preface ||
        encoded CLIENT_INIT ||
        encoded SERVER_INIT ||
        encoded CLIENT_FINISHED ||
        encoded SERVER_FINISHED
    )

### 10.5. Application traffic secrets

After Finished validation:

    client_application_secret =
        MPX-Expand-Label(
            handshake_secret,
            "client application",
            H2,
            32
        )

    server_application_secret =
        MPX-Expand-Label(
            handshake_secret,
            "server application",
            H2,
            32
        )

For each direction:

    traffic_key =
        MPX-Expand-Label(
            application_secret,
            "key",
            empty_context,
            32
        )

    traffic_iv =
        MPX-Expand-Label(
            application_secret,
            "iv",
            empty_context,
            12
        )

The Client uses the client traffic key for Client-to-Server records and the server traffic key for Server-to-Client records. The Server uses the inverse receive/send mapping.

Because the handshake transcript contains fresh nonces and Carrier identity Parameters, each authenticated Carrier derives independent application traffic keys.

## 11. Secure Record Layer

After SERVER_FINISHED has been generated and validated as required by the endpoint role, protocol Frames are carried in Secure Records.

Wire format:

    Record Flags        1 octet
    Ciphertext Length   VarInt
    Ciphertext          Ciphertext Length octets
    Authentication Tag  16 octets

### 11.1. Record Flags

Draft 02 defines no Record Flags.

Senders MUST transmit 0x00.

Receivers MUST reject a Secure Record whose Record Flags octet is non-zero.

### 11.2. Ciphertext Length

Ciphertext Length equals the Secure Record plaintext length because AES-GCM does not expand the encrypted plaintext apart from the authentication tag.

Ciphertext Length excludes the 16-octet authentication tag and excludes the record header.

It MUST be at least 1 and MUST NOT exceed the peer-advertised MAX_RECORD_SIZE.

### 11.3. Record sequence number

Each direction has an independent 64-bit Record Sequence Number.

The first Secure Record in each direction uses Sequence Number 0.

The sequence number increments by one after every successfully generated or authenticated record.

The sequence number is not transmitted.

Draft 02 limits one application traffic key to 2^24 Secure Records in one direction. An endpoint MUST establish a fresh Carrier handshake before sending another record under that traffic key.

### 11.4. Nonce construction

Let seq96 be:

    00000000 || uint64_be(Sequence Number)

The 12-octet AES-GCM nonce is:

    Nonce = traffic_iv XOR seq96

### 11.5. Associated data

The AEAD associated data is the exact encoded record header:

    Record Flags || canonical encoded Ciphertext Length

No decoded or reconstructed representation is used as AAD.

### 11.6. Authentication failure

If AES-GCM authentication fails, the receiver MUST discard the record and terminate that Carrier. No part of the failed plaintext may be processed.

A Secure Record MAY contain multiple complete Frames. A Frame MUST NOT cross a Secure Record boundary.

## 12. Frame encoding and extension handling

Secure Record plaintext is a sequence of one or more complete Frames:

    Frame Type          VarInt
    Frame Length        VarInt
    Frame Body          Frame Length octets

Frame Type and Frame Length MUST use canonical VarInt encoding.

An empty Secure Record is not permitted.

### 12.1. Unknown Frames

Unknown Frame handling is determined by the registered range:

- unknown values in the Core range 0x00 through 0x3f are a PROTOCOL_VIOLATION;
- unknown values in the Extension range 0x40 through 0x3fff MUST be skipped by Frame Length unless a negotiated extension specifies stronger behavior;
- values in the Private Use range 0x4000 through 0x7fff are valid only under an explicitly negotiated private profile;
- all higher values are reserved and MUST be rejected in Draft 02.

### 12.2. PADDING

PADDING is Frame Type 0x00.

Its body has no semantic meaning and is ignored. Senders SHOULD fill PADDING bodies with zero octets.

## 13. Transmission identity and reliable control

Transmission IDs are Session-wide positive VarInts.

A sender allocates Transmission IDs monotonically beginning at 1. A Transmission ID MUST NOT be reused within a Session after allocation.

Retransmission and reinjection of an outstanding Transmission MUST retain the same Transmission ID and the same logical Frame contents.

An Attempt is one concrete send of that Transmission on one Carrier. Attempt identity is local implementation state and is not encoded on the wire.

If a receiver observes the same Transmission ID with different semantic Frame contents, it MUST close the Session with PROTOCOL_VIOLATION.

A duplicate of an already processed reliable Transmission MUST be processed idempotently and its confirmation MUST be sent again.

| Frame | Reliability rule | Confirmation |
|---|---|---|
| STREAM_OPEN | reliable | STREAM_OPEN_OK or STREAM_OPEN_REJECT |
| STREAM_DATA | reliable | TRANSMISSION_ACK |
| STREAM_FIN | reliable | TRANSMISSION_ACK |
| RESET_STREAM | reliable | TRANSMISSION_ACK |
| STOP_SENDING | reliable | TRANSMISSION_ACK |
| STREAM_CONSUMED | reliable | TRANSMISSION_ACK |
| STREAM_CREDIT | idempotent state advertisement | none |
| SESSION_CREDIT | idempotent state advertisement | none |
| CREDIT_PROBE | repeatable probe | credit advertisement |
| PING | probe | PONG |
| PONG | response | none |
| CARRIER_CLOSE | terminal | none |
| SESSION_CLOSE | terminal | none |

## 14. Stream identifiers and opening

Draft 02 supports Client-initiated bidirectional Streams.

Client Stream IDs are positive odd integers allocated monotonically:

    1, 3, 5, 7, ...

A Stream ID MUST NOT be reused within a Session.

Because Frames can traverse different Carriers, a receiver MUST tolerate STREAM_OPEN arrival order that differs from numeric Stream-ID order.

MAX_STREAMS limits simultaneously active Streams, not the maximum numeric Stream ID.

### 14.1. STREAM_OPEN

Body:

    Stream ID        VarInt
    Transmission ID  VarInt

The Stream ID and Transmission ID MUST be non-zero.

The initiator retransmits an unanswered STREAM_OPEN using the same Transmission ID.

### 14.2. STREAM_OPEN_OK

Body:

    Stream ID        VarInt
    Transmission ID  VarInt

The Transmission ID echoes the STREAM_OPEN Transmission ID.

An endpoint accepting a Stream MUST make duplicate copies of the same STREAM_OPEN produce the same acceptance result.

### 14.3. STREAM_OPEN_REJECT

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Error Code       VarInt

The Transmission ID echoes the STREAM_OPEN Transmission ID.

A rejection is final for that Stream ID.

## 15. Stream data and reassembly

### 15.1. STREAM_DATA

Body:

    Stream ID        VarInt
    Offset           VarInt
    Transmission ID  VarInt
    Data             remaining octets

Data length MUST be between 1 and the peer-advertised MAX_FRAME_PAYLOAD.

Let End Offset be Offset + Data Length. Integer overflow is a protocol error.

A sender MUST NOT transmit bytes whose End Offset exceeds the latest Maximum Offset advertised by the receiver for that Stream.

Stream byte identity is defined by Stream ID and byte Offset, not by Transmission ID or Carrier.

If newly received data overlaps byte positions already accepted for the same Stream, every overlapping octet MUST be identical. Conflicting octets are a PROTOCOL_VIOLATION.

Duplicate data MUST NOT be delivered to the application more than once.

A receiver MUST buffer or otherwise account for out-of-order Stream data until lower offsets are available or the Stream is reset.

## 16. TRANSMISSION_ACK and delivery attribution

TRANSMISSION_ACK body:

    Stream ID              VarInt
    Transmission ID        VarInt
    Receiver Timestamp US  VarInt

Receiver Timestamp US is a monotonic timestamp measured in microseconds relative to a receiver-local Session epoch.

A value of 0 means that no delivery timestamp sample is supplied.

Clock synchronization between endpoints is not required. Absolute local and remote clock values MUST NOT be compared.

A receiver SHOULD send TRANSMISSION_ACK on the same Carrier on which the acknowledged Attempt was received while that Carrier remains usable.

If the original Carrier is unavailable, the acknowledgement MAY be sent on another Carrier.

Once a Transmission has been attempted more than once, or if its acknowledgement returns on a different Carrier, the sender MUST NOT treat that acknowledgement as an unambiguous first-attempt per-Carrier delivery-rate sample.

An acknowledgement settles the reliable Transmission independent of which Carrier carries the acknowledgement.

## 17. Flow control

MPX/4 uses independent Stream and Session flow control.

There is no implicit application-data credit.

A sender MUST possess both Stream credit and Session credit before committing new Stream bytes.

Retransmission and reinjection of already committed bytes consume no additional logical flow-control credit.

### 17.1. STREAM_CREDIT

Body:

    Stream ID         VarInt
    Consumed Offset   VarInt
    Maximum Offset    VarInt

Consumed Offset is the exclusive next byte position after the highest contiguous prefix released from receive-side accounting.

If bytes [0, N) have been consumed or otherwise validly released, Consumed Offset is N.

Maximum Offset is an exclusive upper bound. A sender may commit bytes only when End Offset <= Maximum Offset.

Consumed Offset and Maximum Offset MUST be monotonically non-decreasing.

Maximum Offset MUST be greater than or equal to Consumed Offset.

Draft 02 limits:

    Maximum Offset - Consumed Offset <= 16 MiB

A STREAM_OPEN acceptance does not itself grant Stream credit.

When a receiver accepts STREAM_OPEN, it MUST advertise an initial STREAM_CREDIT for its receive direction. The Stream initiator MUST likewise advertise receive credit before the peer sends application data in the reverse direction.

### 17.2. Session committed bytes

For each Stream, the receiver maintains a Committed Offset equal to the greatest authenticated End Offset or final size that has extended the Stream's logical commitment.

When a valid Frame increases a Stream's Committed Offset from A to B, the Session committed-byte counter increases by B - A.

Reordered data at a higher offset therefore commits the preceding range for Session-credit purposes even if some lower bytes have not yet arrived.

Duplicate or overlapping data that does not increase the Stream Committed Offset adds zero Session commitment.

### 17.3. SESSION_CREDIT

Body:

    Consumed Bytes    VarInt
    Maximum Bytes     VarInt

Consumed Bytes is the cumulative number of committed Stream bytes that the receiver has released from Session receive accounting.

Maximum Bytes is the absolute upper bound on the sender's cumulative Session committed-byte counter.

Both values MUST be monotonically non-decreasing.

Maximum Bytes MUST be greater than or equal to Consumed Bytes.

Draft 02 limits:

    Maximum Bytes - Consumed Bytes <= 128 MiB

The first authenticated Carrier of a Session MUST be followed by a SESSION_CREDIT advertisement in each direction before application data is sent in that direction.

Additional Carriers do not create additional Session credit. STREAM_CREDIT and SESSION_CREDIT are Session state and MAY be carried on any active Carrier; an endpoint MAY refresh the current values after Carrier replacement.

## 18. Stream final size and directional termination

Each bidirectional Stream has independent send and receive directions.

A Stream is retired only after both directions are terminal and all required reliable terminal control state has been confirmed.

### 18.1. STREAM_FIN

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Final Offset     VarInt

Final Offset is the exclusive end of the sending direction.

It MUST NOT be smaller than any previously authenticated End Offset for that Stream.

After a valid final size has been established, any Frame implying a different final size or data beyond that final size is a PROTOCOL_VIOLATION.

STREAM_FIN is reliable and is confirmed with TRANSMISSION_ACK.

### 18.2. RESET_STREAM

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Final Offset     VarInt
    Error Code       VarInt

RESET_STREAM terminates the sender's direction and declares its final size.

The final-size invariants for STREAM_FIN also apply to RESET_STREAM.

RESET_STREAM is reliable and is confirmed with TRANSMISSION_ACK.

### 18.3. STOP_SENDING

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Error Code       VarInt

STOP_SENDING requests that the peer cease transmission in the opposite direction.

A peer that has not already completed that sending direction SHOULD respond by issuing RESET_STREAM.

STOP_SENDING is reliable and is confirmed with TRANSMISSION_ACK.

### 18.4. STREAM_CONSUMED

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Final Offset     VarInt

A receiver sends STREAM_CONSUMED after it has released receive accounting through the terminal Final Offset and no longer requires tombstone state solely to preserve final-consumption credit.

Final Offset MUST match the established final size.

STREAM_CONSUMED is reliable and is confirmed with TRANSMISSION_ACK.

## 19. CREDIT_PROBE

CREDIT_PROBE body:

    Stream ID        VarInt

Stream ID 0 requests a current SESSION_CREDIT advertisement.

A non-zero Stream ID requests the current STREAM_CREDIT for that Stream and a current SESSION_CREDIT advertisement.

CREDIT_PROBE does not alter credit and MAY be repeated.

A receiver that still has relevant state SHOULD answer promptly. Absence of an answer is not itself a protocol violation.

## 20. PING and PONG

PING body:

    Token        VarInt

PONG body:

    Token        VarInt

A PONG MUST echo the PING Token.

A PONG SHOULD be returned on the same Carrier on which the PING was received.

PING/PONG is Carrier-scoped and MAY be used for Carrier RTT estimation. It has no Stream or Session flow-control effect.

## 21. Carrier and Session closure

### 21.1. CARRIER_CLOSE

Body:

    Error Code          VarInt
    Trigger Frame Type  VarInt
    Reason Length       VarInt
    Reason              Reason Length UTF-8 octets

CARRIER_CLOSE applies only to the Carrier on which it is sent.

Trigger Frame Type is 0 when no specific Frame triggered the closure.

Reason is diagnostic only and MUST NOT exceed 256 octets. Protocol behavior MUST NOT depend on Reason text.

After CARRIER_CLOSE, no new Secure Records are sent on that Carrier.

### 21.2. SESSION_CLOSE

SESSION_CLOSE uses the same body format as CARRIER_CLOSE but applies to the entire Session.

After SESSION_CLOSE is processed, no new Streams or Carriers may be created for that Session ID and all active Carriers are closed.

A sender MAY transmit SESSION_CLOSE on more than one active Carrier to improve delivery of the terminal state.

## 22. Error scope

Errors confined to one Carrier SHOULD terminate that Carrier without unnecessarily terminating the Session. Examples include:

- Secure Record authentication failure;
- stale or conflicting Carrier Generation during JOIN;
- transport framing failure limited to one Carrier.

Errors that invalidate shared Session or Stream state MUST terminate the Session. Examples include:

- FLOW_CONTROL_ERROR caused by exceeded shared credit;
- STREAM_STATE_ERROR caused by an impossible Stream lifecycle transition;
- FINAL_SIZE_ERROR caused by contradictory final-size semantics;
- TRANSMISSION_ID_ERROR caused by conflicting or impossible Transmission identity;
- conflicting Stream bytes at the same offset;
- invalid Session-wide scheduler state.

The detailed state-error precedence and Stream lifecycle rules are defined in STATE-MACHINES.md.

Before ESTABLISHED, authentication failure MAY be signaled only by transport closure.

## 23. Carrier state and scheduling

Each Carrier maintains, at minimum:

- Carrier ID and Generation;
- active/inactive state;
- latest and minimum RTT estimates;
- outstanding scheduled bytes;
- observed delivery rate;
- configured capacity when applicable;
- scheduler role;
- failure and penalty state.

Carrier metrics are local implementation state unless explicitly exposed by an extension.

The Session Scheduler selects a Carrier for each new Transmission and each later Attempt.

Draft 02 Scheduler IDs are AUTO, AGGREGATE, PROTECT, and WEIGHTED.

The exact selection algorithm is implementation-defined unless a scheduler profile defines stronger interoperability requirements.

A scheduler MUST NOT violate Stream ordering, Session reliability, flow control, or the reliability rules in this document.

## 24. Retransmission and reinjection

An outstanding reliable Frame is one Transmission.

If the sender determines that another Attempt is required, it retransmits the same semantic Frame with the same Transmission ID.

If the Attempt uses a different Carrier, the operation is reinjection.

The receiver MUST treat duplicate Attempts idempotently and MUST repeat the required confirmation.

A valid acknowledgement of the Transmission retires all remaining local Attempts of that Transmission.

Reinjection MUST NOT cause duplicate application delivery and MUST NOT consume additional Stream or Session credit.

## 25. Delivery measurement

A sender MAY use:

- local Attempt send time;
- local acknowledgement arrival time;
- Receiver Timestamp US;
- acknowledged byte counts;
- Carrier PING/PONG samples;

to estimate path behavior.

A first-attempt STREAM_DATA acknowledgement returned on the same Carrier can provide a path-specific delivery sample.

Once a Transmission has multiple Attempts, attribution is ambiguous unless an extension explicitly identifies Attempts. Draft 02 therefore prohibits treating such acknowledgements as unambiguous per-Carrier delivery-rate samples.

Delivery-rate estimation SHOULD avoid treating application-limited traffic as path capacity.

## 26. State validity and Stream lifecycle

The normative MPX/4 state machines, Frame-validity matrices, cross-Carrier reordering rules, terminal Stream rules, tombstone requirements, and retired-identity behavior are defined in [STATE-MACHINES.md](STATE-MACHINES.md).

That document is part of the MPX/4 Core specification for Draft 02.

In particular, conforming implementations MUST support:

- acceptance evidence that arrives before STREAM_OPEN_OK on another Carrier;
- valid RESET_STREAM or STOP_SENDING pre-open cancellation;
- late STREAM_DATA below an already established FIN Final Offset;
- idempotent processing of duplicate reliable Frames;
- immutable final-size semantics;
- tombstone retention sufficient to prevent Stream-ID reuse;
- compact retired identities after terminal reliability has been settled.

An implementation MAY use different internal state names or data structures, but its externally observable behavior MUST conform to the state supplement.

## 27. Resource limits

Draft 02 Core limits are:

| Limit | Value |
|---|---:|
| Maximum Carriers per Session | 8 |
| Maximum STREAM_DATA Data field | 32768 octets |
| Maximum Secure Record plaintext | 65536 octets |
| Maximum active Streams | 2048 |
| Maximum Stream credit window | 16 MiB |
| Maximum Session credit window | 128 MiB |
| Maximum handshake message | 4096 octets |
| Maximum close Reason | 256 octets |
| Maximum Secure Records per traffic key per direction | 2^24 |

An implementation MAY advertise lower receive limits where a Parameter exists.

## 28. Registry allocation and extensibility

Numeric assignments are maintained in REGISTRIES.md.

Extension specifications MUST state:

- negotiation mechanism;
- scope: Session, Carrier, Stream, Transmission, or transport binding;
- new registry assignments;
- behavior when unsupported;
- interaction with flow control and reliability;
- error scope;
- security and resource implications.

An extension MUST NOT silently reinterpret an existing registered value.

## 29. Security considerations

MPX/4 assumes Carrier transports can traverse untrusted networks.

Implementations MUST authenticate every Carrier before associating it with authenticated Session state.

Traffic keys for opposite directions are distinct.

Fresh CLIENT_NONCE and SERVER_NONCE values are required for each Carrier handshake.

The exact encoded handshake transcript is authenticated by Finished messages.

AEAD nonce reuse is forbidden.

Implementations MUST validate lengths and integer arithmetic before allocation, indexing, or offset addition.

Implementations SHOULD bound unauthenticated handshake state, pending reliable Transmissions, receive buffering, and failed authentication work.

Draft 02 does not provide forward secrecy because the mandatory key schedule is rooted only in the pre-shared transport key. A future negotiated key-exchange profile can add forward secrecy without changing the Session, Carrier, or Stream model.

## 30. Wire-size considerations

MPX/4 uses canonical VarInts and typed Frame bodies rather than a fixed per-Frame structure.

Small identifiers and offsets therefore occupy fewer octets.

Multiple Frames MAY share one Secure Record and one 16-octet AEAD tag.

MPX Frame and Secure Record sizes are protocol limits, not network MTUs. The underlying transport remains responsible for segmentation.

## 31. Conformance requirements

A conforming Draft 02 implementation MUST:

- recognize the MPX/4 Connection Preface;
- reject non-canonical VarInts;
- implement canonical Parameter ordering and duplicate rejection;
- implement the Draft 02 key schedule exactly;
- implement CLIENT_FINISHED and SERVER_FINISHED verification;
- implement AES-256-GCM Secure Records with the specified nonce and AAD construction;
- enforce peer receive limits;
- implement the Core Frame set in REGISTRIES.md;
- implement the normative state rules in STATE-MACHINES.md;
- preserve Transmission IDs across retransmission and reinjection;
- never reuse a Transmission ID within a Session;
- distinguish settled duplicate acknowledgements from never-allocated Transmission IDs;
- enforce Stream and Session flow-control rules;
- preserve Stream byte identity across Carriers;
- reject conflicting overlapping Stream bytes;
- preserve final-size invariants;
- tolerate the specified cross-Carrier reordering cases;
- retain terminal Stream state sufficient to prevent Stream-ID reuse;
- distinguish Carrier-scoped and Session-scoped closure.

## 32. Future work

The following remain outside Draft 02:

- ephemeral key exchange and forward secrecy;
- datagram transport;
- server-initiated Streams;
- explicit Attempt identifiers;
- acknowledgement ranges;
- forward error correction;
- explicit Carrier migration;
- additional scheduler profiles;
- non-byte-stream transport bindings.

## 33. Normative references

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels.
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function.
- RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- NIST FIPS 197 — Advanced Encryption Standard.
- NIST SP 800-38D — Galois/Counter Mode for authenticated encryption.

## Appendix A. Design invariants

An interoperable MPX/4 implementation preserves these invariants:

1. Stream identity is independent of Carrier identity.
2. Stream byte identity is defined by Stream ID and Offset.
3. Transmission identity is distinct from Attempt identity.
4. Retransmission and reinjection retain the Transmission ID.
5. Carrier failure does not itself terminate Streams.
6. Flow-control credit is Session and Stream state, not Carrier state.
7. Retransmission and reinjection consume no new logical data credit.
8. A Carrier is authenticated before joining authenticated Session state.
9. Frame semantics do not depend on underlying packet boundaries.
10. Wire registry values are stable within a protocol version.

## Appendix B. Draft 02 wire constants

    Protocol magic                     4d 50 58 00
    Protocol version                   4
    Mandatory AEAD                     AES-256-GCM
    AEAD key length                    32 octets
    AEAD IV length                     12 octets
    AEAD tag length                    16 octets
    Hash / HMAC                        SHA-256 / HMAC-SHA256
    Transport key length               32 octets
    Client nonce length                32 octets
    Server nonce length                32 octets
    Session ID length                  16 octets
    Capacity unit                      100,000 bit/s
