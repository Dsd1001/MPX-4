# MPX/4 Core Protocol Specification

**Document:** MPX/4 Core Protocol  
**Revision:** Draft 11
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

**Session** — The logical end-to-end MPX association. Stream state, flow-control state, reliable Transmission state, Carrier identity state, and Session Protocol Version belong to the Session. Local Carrier-selection policy does not become shared Session protocol state.

**Session Protocol Version** — The immutable on-wire Protocol Version established by the first Carrier that creates a Session.

**Carrier** — One authenticated underlying transport connection attached to a Session.

**Carrier ID** — A non-zero MPX VarInt identifying a logical Carrier within a Session. Its numeric value is an identity, not a concurrency limit.

**Carrier Generation** — A monotonically increasing value distinguishing successive transport connections for the same Carrier ID.

**Active logical Carrier** — A distinct Carrier ID whose current accepted incarnation is ESTABLISHED and eligible for Session use at an endpoint.

**Effective Carrier Limit** — The Session-wide maximum active logical Carrier count established as the minimum of the Client and Server MAX_CARRIERS advertisements during CREATE.

**Stream** — A reliable ordered byte stream carried by a Session.

**Transmission** — One reliable MPX protocol unit identified by a Session-wide Transmission ID. Retransmission and reinjection repeat the same Transmission and retain its Transmission ID.

**Attempt** — One concrete send of a Transmission on a Carrier. Attempts are local transport state and do not have a wire identifier.

**Reinjection** — Sending another Attempt of an outstanding Transmission on a different Carrier.

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

Loss of an individual Carrier does not by itself terminate the Session. If the last active Carrier is lost or closed without SESSION_CLOSE, an endpoint that retains the Session enters DORMANT state as defined in [STATE-MACHINES.md](STATE-MACHINES.md).

DORMANT retention duration is local implementation policy in Draft 11 and is not a negotiated availability guarantee.

Stream byte ordering is defined by Stream offsets, not Carrier order.

## 4. Transport bindings

MPX/4 Core is defined independently of transport packet boundaries.

A transport binding specifies how one MPX Carrier maps onto an underlying ordered transport, including connection establishment, byte-stream parsing, transport loss, replacement, and close behavior.

The normative baseline binding for Draft 11 is:

- [MPX/4 over TCP](bindings/tcp.md)

The TCP binding maps one TCP connection to one MPX Carrier and requires implementations to parse MPX independently of TCP segment, write, and receive-call boundaries.

Additional transport bindings can be defined without changing the Session, Stream, Transmission, or Frame abstractions.

The default maximum MPX Frame payload remains 32768 bytes.

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

The Connection Preface identifies the protocol and requested Protocol Version. Version is carried per connection but CREATE binds that value into immutable Session state as the Session Protocol Version.

Every JOIN and Carrier replacement for an existing Session MUST use the same Protocol Version as that Session. If an endpoint supports the candidate Protocol Version but the candidate identifies a Session created under another Protocol Version, the candidate MUST be rejected with SESSION_CONFLICT without modifying the existing Session.

Protocol Version evolution, draft-revision compatibility, downgrade rules, and stable-version extension requirements are defined normatively in [COMPATIBILITY.md](COMPATIBILITY.md).

### 5.1. VERSION_NEGOTIATION

A Server that recognizes the MPX magic but does not support the requested version MAY send a VERSION_NEGOTIATION handshake message immediately after parsing the Connection Preface and then close the Carrier. The Server does not need to wait for CLIENT_INIT. Octets already pipelined after the unsupported Preface MUST NOT be parsed as CLIENT_INIT under that unsupported version.

Its body is:

    Version Count        VarInt
    Supported Version    VarInt repeated Version Count times

Supported versions MUST be unique and encoded in descending numeric order.

VERSION_NEGOTIATION is unauthenticated. A Server sends it only before that Server has parsed or accepted CLIENT_INIT for the candidate. A Client MAY accept VERSION_NEGOTIATION even if it already transmitted a pipelined CLIENT_INIT, provided the Client has not yet accepted SERVER_INIT or any later handshake message on that candidate. After SERVER_INIT has been accepted, VERSION_NEGOTIATION is no longer valid for that candidate.

A Client MUST NOT treat VERSION_NEGOTIATION as proof of peer identity and MUST NOT enable a locally disabled protocol version solely because it appears in this message. If retry is permitted by local policy, the Client SHOULD select the highest mutually supported permitted version and MUST retry on a fresh underlying transport connection with fresh handshake state.

A post-preface authentication or protocol failure MUST NOT be interpreted as permission to downgrade automatically.

### 5.2. HANDSHAKE_REJECT

HANDSHAKE_REJECT is a pre-establishment diagnostic message for rejecting one candidate Carrier after the requested Protocol Version is understood.

Its body is:

    Error Code           VarInt

HANDSHAKE_REJECT is unauthenticated and is not included in the successful Finished transcript. Receipt of HANDSHAKE_REJECT MUST terminate only the current candidate Carrier handshake. It MUST NOT by itself:

- authenticate the peer;
- create, modify, or retire Session state;
- advance Carrier Generation;
- change flow-control, Stream, or reliable Transmission state;
- trigger Protocol Version downgrade or enable a disabled version.

An endpoint MAY send HANDSHAKE_REJECT only before SERVER_FINISHED has been sent or received on that candidate Carrier. After sending HANDSHAKE_REJECT, the sender MUST terminate the candidate transport. After receiving HANDSHAKE_REJECT, the receiver MUST terminate the candidate transport.

When a candidate can be rejected after a complete error classification and the endpoint can safely emit a handshake message, it SHOULD send HANDSHAKE_REJECT with the applicable Core Error Code. If framing is too malformed to determine a safe response boundary, or if failure occurs after SERVER_FINISHED, the endpoint MAY terminate the transport without sending HANDSHAKE_REJECT.

HANDSHAKE_REJECT MUST NOT be used to negotiate or signal an unsupported Connection Preface version. VERSION_NEGOTIATION or transport close is used for that case.

The Error Code carried by HANDSHAKE_REJECT classifies why this candidate was rejected. Core HANDSHAKE_REJECT permits these Error Codes:

- INTERNAL_ERROR;
- PROTOCOL_VIOLATION;
- AUTHENTICATION_FAILED;
- RESOURCE_LIMIT;
- SESSION_NOT_FOUND;
- SESSION_CONFLICT;
- CARRIER_CONFLICT;
- UNSUPPORTED_PARAMETER.

VERSION_UNSUPPORTED is not carried in HANDSHAKE_REJECT because version mismatch is handled before CLIENT_INIT by VERSION_NEGOTIATION or transport close. NO_ERROR and post-establishment/Stream-specific Error Codes are invalid in Core HANDSHAKE_REJECT.

An extension MAY define an extension Error Code as valid in HANDSHAKE_REJECT. A receiver that does not recognize the carried Error Code still terminates the candidate transport and treats the diagnostic reason as unknown; it MUST NOT send another HANDSHAKE_REJECT in response.

Because the message is unauthenticated, applications and retry logic MUST treat the code as advisory until a separately authenticated relationship exists.

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

A successful newly connected Carrier progresses through:

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

At any pre-establishment stage after the Protocol Version is understood, a classified candidate failure can instead terminate the handshake via HANDSHAKE_REJECT followed by transport close. A failure that cannot be safely reported terminates the candidate transport directly. Neither path reaches ESTABLISHED.

A Carrier MUST NOT carry Secure Records before entering ESTABLISHED.

### 7.1. Handshake message format

Each handshake message is:

    Message Type        VarInt
    Message Length      VarInt
    Message Body        Message Length octets

Message Length MUST use canonical VarInt encoding and MUST NOT exceed 4096 octets in Draft 11.

### 7.2. Parameter format

CLIENT_INIT and SERVER_INIT contain Parameters:

    Parameter Type      VarInt
    Flags               1 octet
    Length              VarInt
    Value               Length octets

Bit 0 of Flags is CRITICAL. Bits 1 through 7 are reserved and MUST be zero.

Parameters MUST appear in strictly increasing Parameter Type order. A Parameter Type MUST NOT occur more than once in one handshake message in Draft 11.

An endpoint receiving an unknown Parameter with CRITICAL=0 MUST ignore its value after validating its encoded length.

An endpoint receiving an unknown Parameter with CRITICAL=1 MUST reject the candidate handshake with UNSUPPORTED_PARAMETER and, when a safe response boundary is known, SHOULD send HANDSHAKE_REJECT(UNSUPPORTED_PARAMETER).

Malformed, duplicate, out-of-order, or contradictory Core Parameters are protocol errors.

## 8. Core handshake Parameters

### 8.1. SESSION_ID

SESSION_ID is exactly 16 octets and identifies an MPX Session. A newly created Session ID MUST be generated from a cryptographically secure random source and MUST NOT be all zero.

An initiating endpoint MUST NOT intentionally reuse a Session ID for which it still retains Session or retirement state.

On CREATE, a receiving endpoint MUST reject the candidate with SESSION_CONFLICT if the offered SESSION_ID already identifies a CREATING, ACTIVE, DORMANT, or CLOSING Session, or if retained CLOSED retirement state still reserves that Session ID. The candidate MUST NOT overwrite, merge with, or be reinterpreted as a JOIN to the existing or retired Session.

If the receiving endpoint no longer retains any state for a previously used random Session ID, the protocol cannot distinguish that historical value from a fresh collision; normal CREATE processing applies.

### 8.2. SESSION_ACTION

SESSION_ACTION is a VarInt:

| Value | Meaning |
|---:|---|
| 0 | CREATE |
| 1 | JOIN |

CREATE establishes a new Session. JOIN attaches a new authenticated Carrier to an existing Session.

A Session ID is an identifier, not an authorization credential. The authentication context under which CREATE is accepted becomes part of retained Session security state. A JOIN or replacement Carrier MUST authenticate under the same retained security binding, or under an explicitly authorized deployment key-rotation mapping, before it can attach to that Session. A candidate authenticated under an unrelated trust context is SESSION_CONFLICT even when SESSION_ID and the other immutable Core Parameters match. Draft 11 does not require an on-wire PSK selector; deployment context supplies this binding as specified in SECURITY.md.

### 8.3. CARRIER_ID and CARRIER_GENERATION

CARRIER_ID is a non-zero MPX VarInt in the range 1 through 2^62 - 1.

The numeric value of CARRIER_ID does not limit how many Carriers may be active. A Session may use sparse Carrier IDs and is not required to allocate them consecutively.

CARRIER_GENERATION is a VarInt. The first transport instance of a Carrier ID uses Generation 0. A replacement transport for the same Carrier ID uses a strictly greater Generation.

The tuple (Carrier ID, Carrier Generation) identifies one Carrier incarnation.

A Carrier ID that has previously been accepted remains the same logical Carrier identity for the lifetime of the Session. It MUST NOT later be reused as a new logical Carrier. A later incarnation of that Carrier ID is a replacement and therefore uses a higher Generation.

### 8.4. CLIENT_NONCE and SERVER_NONCE

CLIENT_NONCE and SERVER_NONCE are each exactly 32 fresh random octets.

CLIENT_NONCE appears only in CLIENT_INIT.

SERVER_NONCE appears only in SERVER_INIT.

### 8.5. MAX_FRAME_PAYLOAD

MAX_FRAME_PAYLOAD is the maximum STREAM_DATA Data field, in octets, that the sender of the Parameter is willing to receive.

Valid Draft 11 values are 1 through 32768.

A peer MUST NOT send a larger STREAM_DATA Data field.

### 8.6. MAX_RECORD_SIZE

MAX_RECORD_SIZE is the maximum Secure Record plaintext length, in octets, that the sender of the Parameter is willing to receive.

Valid Draft 11 values are 1024 through 65536.

The record header and 16-octet AEAD tag are not included in this value.

A sender MUST ensure that each complete Frame fits within one Secure Record and MUST reduce STREAM_DATA chunk size when necessary.

### 8.7. MAX_STREAMS

MAX_STREAMS is the maximum number of simultaneously active peer-initiated Streams that the sender of the Parameter is willing to maintain.

Valid Draft 11 values are 1 through 2048.

Stream IDs are not bounded by MAX_STREAMS; the value limits concurrency.

### 8.8. MAX_CARRIERS

MAX_CARRIERS is a Session capability advertised independently by both endpoints.

Its value is the maximum number of simultaneously active logical Carriers that the sender is willing to maintain in this Session. Valid values are 1 through 2^62 - 1.

MAX_CARRIERS MUST be encoded with the Parameter CRITICAL flag set to 1. A Draft 11 endpoint receiving MAX_CARRIERS with CRITICAL=0 MUST abort the handshake with PROTOCOL_VIOLATION.

During CREATE:

    Client Carrier Limit = MAX_CARRIERS in CLIENT_INIT
    Server Carrier Limit = MAX_CARRIERS in SERVER_INIT

The Session's Effective Carrier Limit is:

    Effective Carrier Limit = min(Client Carrier Limit, Server Carrier Limit)

The Effective Carrier Limit is Session-wide and immutable for the lifetime of the Session.

MAX_CARRIERS limits concurrency, not identifier values. In particular, a Session with Effective Carrier Limit 8 may legally use Carrier ID 96 as one of its active Carrier identities.

MAX_CARRIERS is an upper bound, not an admission guarantee. A candidate Carrier may still be rejected for another valid protocol or resource reason before the Effective Carrier Limit is reached.

On every JOIN, each endpoint MUST repeat exactly the MAX_CARRIERS value that it advertised during CREATE. A changed value is SESSION_CONFLICT.

The active logical Carrier count and replacement interaction are defined in Section 9.2 and in STATE-MACHINES.md.

### 8.9. Extension Parameters

Core does not negotiate or name a Session scheduler. Carrier selection for locally originated Transmission Attempts is endpoint-local policy subject to the invariants in Section 23.

Published extensions MAY define optional Carrier or Session metadata in the extension Parameter range. Such extensions MUST follow [COMPATIBILITY.md](COMPATIBILITY.md) and MUST remain safely ignorable when they use CRITICAL=0.

The Core handshake does not require capacity, weight, preference, topology, Relay, or path-role metadata.

### 8.10. Session-scoped and Carrier-scoped limits

The Client advertises receive limits in CLIENT_INIT and the Server advertises receive limits in SERVER_INIT. The two directions MAY use different values.

MAX_FRAME_PAYLOAD and MAX_STREAMS are Session-scoped directional receive limits. A JOIN handshake MUST repeat the values already established by that endpoint for the Session. A mismatch is a SESSION_CONFLICT.

MAX_CARRIERS is Session-scoped but is not directional. Each endpoint repeats its own CREATE-time advertisement on JOIN. The Effective Carrier Limit remains the minimum of the two original advertisements.

MAX_RECORD_SIZE is a Session-scoped directional receive limit. A JOIN handshake MUST repeat the value already established by that endpoint for the Session. A mismatch is a SESSION_CONFLICT.

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
- MAX_CARRIERS.

SERVER_INIT MUST contain:

- SERVER_NONCE;
- MAX_FRAME_PAYLOAD;
- MAX_RECORD_SIZE;
- MAX_STREAMS;
- MAX_CARRIERS.

Optional extension Parameters MAY additionally appear according to their defining specifications.

The first Carrier of a new Session SHOULD use Carrier ID 1 and Generation 0.

The Server MUST NOT attach unauthenticated Carrier state to a live Session before validating CLIENT_FINISHED. A candidate CREATE or JOIN rejected before establishment SHOULD use HANDSHAKE_REJECT when Section 5.2 permits a safe response.

A JOIN uses the same SESSION_ID, SESSION_ACTION=JOIN, a Carrier ID, Generation, fresh CLIENT_NONCE, Session-scoped limits, and the Session Protocol Version. MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, MAX_STREAMS, and MAX_CARRIERS MUST match the values already established for that endpoint.

Optional extension Parameters MAY differ between Carriers or Carrier Generations when their defining extension permits it.

### 9.1. Carrier Generation acceptance and replacement

For every Carrier ID that has ever reached ESTABLISHED in a Session, each endpoint MUST retain the Highest Accepted Generation for that Carrier ID for at least the lifetime of the Session.

For a Carrier ID with no previously accepted incarnation, the first accepted Generation MUST be 0. A candidate using a non-zero first Generation MUST be rejected with CARRIER_CONFLICT.

Let H be the Highest Accepted Generation for a Carrier ID and let G be the Generation carried by a candidate JOIN:

- if G < H, the candidate is stale and MUST be rejected with CARRIER_CONFLICT;
- if G = H, the candidate attempts to reuse an already accepted Carrier incarnation and MUST be rejected with CARRIER_CONFLICT, whether or not the earlier transport is still live;
- if G > H, the candidate is eligible to replace the current incarnation.

A candidate replacement MUST NOT advance H, supersede an existing Carrier, or alter Session state before that candidate completes authentication and all Session-scoped JOIN parameters are validated.

When a candidate with G > H reaches ESTABLISHED, the endpoint atomically sets H = G. Every lower Generation of the same Carrier ID becomes superseded at that endpoint.

A superseded Carrier:

- MUST NOT receive new Transmission Attempts;
- MUST NOT contribute new path-measurement samples;
- MUST NOT change the current Carrier Generation;
- SHOULD have its underlying transport closed promptly.

Frames already authenticated and completely processed before the Generation advance retain their normal effects. After the Generation advance is committed, an endpoint MUST NOT process subsequently received Secure Records from a lower Generation of that Carrier ID as new protocol state.

Failure of a candidate handshake MUST NOT advance H and MUST NOT supersede the current Carrier.

If H equals the maximum MPX VarInt value, that Carrier ID cannot be replaced again within the Session. Generation values MUST NOT wrap.

Replacement changes Carrier incarnation only. It MUST NOT reset or renumber:

- Stream IDs;
- Stream offsets;
- Stream or Session credit;
- Transmission IDs;
- settled or outstanding reliable Transmission state;

Outstanding reliable Transmissions MAY be retransmitted or reinjected over the replacement Carrier using their existing Transmission IDs.

The complete replacement state machine is defined in [STATE-MACHINES.md](STATE-MACHINES.md). Transport bindings define how a new underlying connection is established but MUST preserve these Core Generation rules.

### 9.2. Active logical Carrier count

The Effective Carrier Limit applies to simultaneously active logical Carriers, not to handshake candidates, historical Carrier IDs, or Carrier incarnations individually.

For limit accounting, an endpoint counts one active logical Carrier for each distinct Carrier ID whose current accepted incarnation is ESTABLISHED and eligible for Session use.

The following rules apply:

- the first established Carrier counts as one active logical Carrier;
- an unauthenticated or HANDSHAKING candidate does not count;
- multiple transport connections or Generations for the same Carrier ID never count as multiple logical Carriers;
- committing a higher Generation while the previous Generation of the same Carrier ID is still active leaves the active logical Carrier count unchanged;
- if no incarnation of that Carrier ID is active, establishing a replacement reactivates that logical Carrier and increases the active count by one;
- a Carrier ceases to count as active when the endpoint transitions its current incarnation out of ESTABLISHED because of CARRIER_CLOSE, SESSION_CLOSE, supersession, or detected transport loss;
- retained Highest Accepted Generation, tombstone, or historical identity state does not consume an active Carrier slot.

An endpoint MUST NOT commit a candidate Carrier if doing so would make its local active logical Carrier count exceed the Effective Carrier Limit.

A candidate for a previously unused Carrier ID consumes one active slot when committed. A replacement of an already active logical Carrier consumes no additional slot. A replacement of an inactive logical Carrier requires a free slot at commit time.

If a candidate would exceed the Effective Carrier Limit, the candidate MUST be rejected with RESOURCE_LIMIT and the existing Session MUST remain unchanged.

Because transport-loss detection can occur at different times at the two endpoints, their instantaneous local active counts may temporarily differ. The Effective Carrier Limit is nevertheless the same Session value at both endpoints; a candidate Carrier becomes usable only if its handshake completes successfully at both endpoints.

Closing or losing a Carrier releases active concurrency capacity but does not make its Carrier ID reusable as a new identity. A later use of that same Carrier ID remains a replacement and MUST use a higher Generation.

### 9.3. Ambiguous establishment recovery

A Client enters an **ambiguous establishment** condition when it has sent a valid CLIENT_FINISHED for a candidate Carrier but the candidate transport ends before the Client authenticates SERVER_FINISHED. In that condition the Server may or may not have committed the candidate.

The Client MUST NOT infer Server commit or non-commit from transport loss or from HANDSHAKE_REJECT. HANDSHAKE_REJECT is unauthenticated; SESSION_NOT_FOUND and other reject codes are advisory diagnostics, not authenticated Session-existence evidence.

Until recovery succeeds or local policy abandons the ambiguous state, the Client MUST retain enough information to avoid identity reuse, including the Session ID, CREATE/JOIN intent, candidate Carrier ID and Generation, the highest locally attempted ambiguous Generation for that Carrier ID, and the received SERVER_INIT/negotiated Session parameters needed to compare a later authenticated result.

For an already accepted logical Carrier ID, a replacement retry after ambiguous Generation G MUST use a Generation strictly greater than both the locally Highest Accepted Generation and every ambiguity-causing attempted Generation retained for that Carrier ID. A successful authenticated higher Generation resolves the ambiguity without claiming that an unverified earlier Generation was locally accepted.

For the ambiguous first use of a previously unused Carrier ID at Generation 0, the Client MUST NOT retry that same ID at a non-zero Generation unless it has authenticated evidence that Generation 0 was accepted. Recovery instead uses another previously unused Carrier ID at Generation 0, subject to normal Session existence, Effective Carrier Limit, and authentication rules.

After an ambiguous CREATE, the Client MAY attempt an authenticated JOIN to the same retained Session ID using a previously unused Carrier ID at Generation 0. A successfully authenticated JOIN proves that the Server retained compatible Session state. An unauthenticated rejection does not prove the opposite. Local policy MAY abandon the ambiguous Session; a subsequent independent CREATE then uses a fresh random Session ID rather than intentionally reusing the ambiguous ID.

Ambiguous recovery is a liveness mechanism, not an exception to authentication, Session-version, Generation, parameter-equality, or Carrier-limit rules.

## 10. MPX/4 key schedule

Draft 11 uses a 32-octet pre-shared transport key as the authentication root, HKDF-SHA256 for key derivation, HMAC-SHA256 for Finished authentication, and AES-256-GCM for Secure Records.

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

Draft 11 defines no Record Flags.

Senders MUST transmit 0x00.

Receivers MUST reject a Secure Record whose Record Flags octet is non-zero.

### 11.2. Ciphertext Length

Ciphertext Length equals the Secure Record plaintext length because AES-GCM does not expand the encrypted plaintext apart from the authentication tag.

Ciphertext Length excludes the 16-octet authentication tag and excludes the record header.

It MUST be at least 1 and MUST NOT exceed the peer-advertised MAX_RECORD_SIZE.

### 11.3. Record sequence number

Each direction has an independent 64-bit Record Sequence Number.

The first Secure Record in each direction uses Sequence Number 0.

The receive sequence number increments by one after every successfully authenticated record.

For sending, a sequence number is assigned when the complete serialized Secure Record is committed to the ordered Carrier output. Once assigned, that exact serialized Record MUST be the next Secure Record emitted in that direction. The sender MUST NOT discard that record, advance the sequence number, and continue emitting later records on the same Carrier. If ordered emission can no longer be guaranteed, the endpoint MUST abandon that Carrier rather than create a sequence gap or reuse a nonce.

The sequence number is not transmitted.

Draft 11 permits at most 2^24 Secure Records, numbered 0 through 2^24-1, in one direction under one application traffic key. An endpoint MUST establish a fresh Carrier handshake before sending any additional record under a fresh key. If replacement is not ready when the limit is reached, that direction stops generating records on the exhausted key; sequence numbers and nonces never wrap or reuse.

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
- all higher values are reserved and MUST be rejected in Draft 11.

### 12.2. PADDING

PADDING is Frame Type 0x00.

Its body has no semantic meaning and is ignored. Senders SHOULD fill PADDING bodies with zero octets.

## 13. Transmission identity and reliable control

Transmission IDs are Session-wide positive VarInts.

A sender allocates Transmission IDs as consecutive positive integers beginning at 1: 1, 2, 3, .... A Transmission ID MUST NOT be skipped, reused within a Session after allocation, or wrapped. The maximum allocatable Transmission ID is 2^62 - 1.

A Transmission ID becomes protocol-allocated only when the sender commits an immutable semantic reliable Frame into Session reliability state. An implementation MAY reserve queue slots or tentative local numbers before that point, but such local reservations are not allocated Transmission IDs and MUST NOT advance the protocol allocation sequence.

Once a reliable Transmission ID is allocated, the sender MUST NOT silently abandon or recycle it. While the Session remains usable, the Transmission remains outstanding until its required confirmation is received and MUST eventually receive an Attempt whenever an authenticated eligible Carrier and required flow-control/state preconditions exist. Local cancellation may change later application semantics only through the protocol rules for that operation; it does not erase an already allocated reliable Transmission. If a local resource failure makes this responsibility impossible to preserve safely, the endpoint MUST close the Session with RESOURCE_LIMIT when an authenticated writable Carrier is available.

After allocating Transmission ID 2^62 - 1, that endpoint's Transmission-ID namespace is exhausted for the Session. It MUST NOT allocate another reliable Transmission ID. Existing Transmissions and non-reliable/idempotent protocol state may continue to be processed. If further application or protocol work requires allocation of another reliable Transmission, the endpoint MUST transition the Session to CLOSING and SHOULD send SESSION_CLOSE with RESOURCE_LIMIT on an authenticated writable Carrier.

Retransmission and reinjection of an outstanding Transmission MUST retain the same Transmission ID and the same logical Frame contents.

An Attempt is one concrete send of that Transmission on one Carrier. Attempt identity is local implementation state and is not encoded on the wire.

If a receiver observes the same Transmission ID with different semantic Frame contents, it MUST close the Session with TRANSMISSION_ID_ERROR.

A duplicate of an already processed reliable Transmission MUST be processed idempotently and its confirmation MUST be sent again.

For every locally allocated reliable Transmission, the sender MUST retain the Transmission ID, Stream ID, original Frame type, and required confirmation class until that Transmission is settled or the retained state can be compacted safely. A confirmation settles a Transmission only when it matches the required confirmation class for that original Frame type. A confirmation naming the correct Transmission ID but the wrong confirmation class is TRANSMISSION_ID_ERROR.

| Frame | Reliability rule | Confirmation |
|---|---|---|
| STREAM_OPEN | reliable | STREAM_OPEN_OK or STREAM_OPEN_REJECT |
| STREAM_DATA | reliable | TRANSMISSION_ACK |
| STREAM_FIN | reliable | TRANSMISSION_ACK |
| RESET_STREAM | reliable | TRANSMISSION_ACK |
| STOP_SENDING | reliable | TRANSMISSION_ACK |
| STREAM_CONSUMED | reliable | TRANSMISSION_ACK |
| TRANSMISSION_RETIRE | idempotent cumulative state advertisement | none |
| STREAM_CREDIT | idempotent state advertisement | none |
| SESSION_CREDIT | idempotent state advertisement | none |
| CREDIT_PROBE | repeatable probe | credit advertisement |
| PING | probe | PONG |
| PONG | response | none |
| CARRIER_CLOSE | terminal | none |
| SESSION_CLOSE | terminal | none |

## 14. Stream identifiers and opening

Draft 11 supports Client-initiated bidirectional Streams.

Client Stream IDs are positive odd integers allocated monotonically:

    1, 3, 5, 7, ... , 2^62 - 1

A Stream ID MUST NOT be reused within a Session and MUST NOT wrap.

After Stream ID 2^62 - 1 has been allocated, the Client Stream-ID namespace is exhausted for that Session. The Client MUST NOT create another Stream in that Session. Existing Streams and the Session MAY remain active; a subsequent local application request to open another Stream MUST fail locally rather than reuse or wrap the Stream ID. An implementation MAY choose to close the Session with RESOURCE_LIMIT, but closure is not required solely because the Stream-ID namespace is exhausted.

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

The Transmission ID echoes the STREAM_OPEN Transmission ID. The referenced local Transmission MUST be a STREAM_OPEN for the same Stream ID. If the Transmission ID refers to another reliable Frame type, was never allocated, or belongs to another Stream, the receiver MUST close the Session with TRANSMISSION_ID_ERROR.

An endpoint accepting a Stream MUST make duplicate copies of the same STREAM_OPEN produce the same acceptance result.

### 14.3. STREAM_OPEN_REJECT

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Error Code       VarInt

The Transmission ID echoes the STREAM_OPEN Transmission ID. The referenced local Transmission MUST be a STREAM_OPEN for the same Stream ID. If the Transmission ID refers to another reliable Frame type, was never allocated, or belongs to another Stream, the receiver MUST close the Session with TRANSMISSION_ID_ERROR.

A rejection is final for that Stream ID.

Core rejection reasons and their scope are defined in [ERROR-HANDLING.md](ERROR-HANDLING.md). STREAM_LIMIT and Stream-specific RESOURCE_LIMIT are valid Core rejection reasons. STREAM_STATE_ERROR is valid when Core state rules explicitly require rejection of that Stream ID without closing the Session. NO_ERROR MUST NOT be used in STREAM_OPEN_REJECT.

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

Advancing a Stream's Consumed Offset releases receive-side flow-control accounting; by itself it does **not** release this byte-identity obligation. While later STREAM_DATA for an already accepted range remains eligible for Section 15.1 overlap processing, the receiver MUST retain the exact bytes or equivalent comparison evidence sufficient to detect conflicting octets. Equivalent evidence MAY be stored in a compact or external representation and need not keep application buffers resident.

For an accepted Stream, Section 15.1 overlap-comparison eligibility ends once the Stream validly enters TOMBSTONE under the state supplement: the receive direction is terminal, receive-side accounting has been fully released through the peer Final Offset, and the applicable FIN/RESET completion conditions have been met. From that point, a first-arriving or duplicate STREAM_DATA wholly within the recorded peer Final Offset is unambiguously stale and has no application or credit effect; it need not be byte-compared against released application data. This does **not** release any independent reliable-Transmission confirmation obligation for an unretired Transmission ID. Before TOMBSTONE entry, including an active terminal Stream, conflicting overlap remains PROTOCOL_VIOLATION.

An implementation that can no longer retain sufficient comparison evidence MUST NOT silently treat arbitrary low-offset STREAM_DATA as valid merely because the bytes are below Consumed Offset. It MUST either retain enough evidence until the Stream validly enters TOMBSTONE (or another protocol state makes such traffic unambiguously stale/without semantic effect), or apply a local resource policy that safely terminates the affected scope before the evidence is discarded. This is a receive-state/resource requirement and does not change flow-control credit accounting.

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

A TRANSMISSION_ACK settles the referenced reliable Transmission independent of which Carrier carries the acknowledgement only when the original Frame type requires TRANSMISSION_ACK. A TRANSMISSION_ACK that references a STREAM_OPEN Transmission is TRANSMISSION_ID_ERROR because STREAM_OPEN is settled only by STREAM_OPEN_OK or STREAM_OPEN_REJECT.

### 16.1. TRANSMISSION_RETIRE

TRANSMISSION_RETIRE allows the originator of reliable Transmissions to tell the peer when confirmation-replay state is no longer required.

Body:

    Retired Through     VarInt

Each endpoint maintains **Settled Through**, the largest N such that every locally allocated reliable Transmission ID from 1 through N has been settled by its required confirmation. Because Transmission IDs are consecutive, Settled Through advances only across a contiguous settled prefix.

When Settled Through advances above the last value advertised to the peer, the endpoint MUST eventually advertise a TRANSMISSION_RETIRE value at least that large whenever the Session has an authenticated writable Carrier. Multiple advances MAY be coalesced into one larger watermark, and the current value MAY be repeated on any active Carrier. After DORMANT recovery, Carrier establishment, or replacement, when the current watermark is non-zero and can release retained peer state, the endpoint MUST eventually refresh it while the Session remains active and an authenticated writable Carrier exists. Repeated refreshes MAY be coalesced and rate-limited.

A received TRANSMISSION_RETIRE value is monotonic Session state for the peer's Transmission namespace:

- a value greater than the stored peer Retired Through replaces it;
- an equal or lower value is stale or duplicate and is ignored;
- a value greater than the largest contiguous peer Transmission ID that this endpoint has already processed is TRANSMISSION_ID_ERROR.

Once peer Retired Through reaches N, the endpoint no longer needs to preserve confirmation-replay detail solely for peer reliable Transmission IDs <= N. A later duplicate Attempt carrying a Transmission ID <= peer Retired Through MUST NOT create new protocol or application effects and need not be confirmed again.

Before a processed peer reliable Transmission ID is covered by peer Retired Through, the endpoint MUST retain enough information to reproduce its required confirmation if that Transmission is received again.

TRANSMISSION_RETIRE itself has no Transmission ID, consumes no flow-control credit, and does not require acknowledgement. Loss of this advertisement can delay state reclamation but cannot cause an outstanding reliable Transmission to be treated as settled.

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

If bytes [0, N) have been consumed or otherwise validly released, Consumed Offset is N. Releasing those bytes from flow-control accounting does not by itself permit the receiver to forget byte-identity evidence required by Section 15.1 for later overlapping STREAM_DATA.

Maximum Offset is an exclusive upper bound. A sender may commit bytes only when End Offset <= Maximum Offset.

A receiver generating STREAM_CREDIT MUST make Consumed Offset and Maximum Offset monotonically non-decreasing across successive advertisements.

On receipt, each STREAM_CREDIT pair is first validated structurally. Maximum Offset MUST be greater than or equal to Consumed Offset, and the advertised window MUST satisfy the Draft 11 limit below. After structural validation, let `(C,M)` be the currently retained pair and `(C',M')` the received pair:

- if `C' >= C` and `M' >= M`, the advertisement is current or newer and the endpoint retains `(C',M')`;
- if `C' <= C` and `M' <= M`, the advertisement is stale or duplicate due to cross-Carrier reordering and is ignored;
- otherwise one component advanced while the other decreased, which cannot be produced by a conforming monotonic sender, and the Session fails with FLOW_CONTROL_ERROR.

This receive rule is component-wise; endpoints MUST NOT reject a fully stale credit advertisement merely because a newer advertisement arrived first on another Carrier.

Draft 11 limits:

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

Maximum Bytes is the absolute upper bound on the sender's cumulative Session committed-byte counter. Session committed and consumed counters are non-wrapping VarInts. Once no larger representable Maximum Bytes can be granted, the receiver MUST NOT authorize additional new commitment beyond 2^62 - 1; applications needing further data use a new Session.

A receiver generating SESSION_CREDIT MUST make Consumed Bytes and Maximum Bytes monotonically non-decreasing across successive advertisements.

On receipt, each SESSION_CREDIT pair is first validated structurally. Maximum Bytes MUST be greater than or equal to Consumed Bytes, and the advertised window MUST satisfy the Draft 11 limit below. Let `(C,M)` be the retained Session credit pair and `(C',M')` the received pair. The same component-wise merge rule as STREAM_CREDIT applies: component-wise newer values replace the retained pair, component-wise older/equal values are stale and ignored, and crossed values are a FLOW_CONTROL_ERROR.

Draft 11 limits:

    Maximum Bytes - Consumed Bytes <= 128 MiB

The first authenticated Carrier of a Session MUST be followed by a SESSION_CREDIT advertisement in each direction before application data is sent in that direction.

Additional Carriers do not create additional Session credit. STREAM_CREDIT and SESSION_CREDIT are Session state and MAY be carried on any active Carrier.

After DORMANT-to-ACTIVE recovery or Carrier replacement, each endpoint MUST eventually refresh its current SESSION_CREDIT while the Session remains active and an authenticated writable Carrier exists. A receiver need not proactively repeat every Stream advertisement, but when retained Stream state exists and the peer sends a valid non-zero CREDIT_PROBE, the receiver MUST eventually send the current STREAM_CREDIT for that Stream together with a current SESSION_CREDIT, unless the Stream or Session becomes terminal first. Implementations MAY coalesce and rate-limit refreshes without preventing eventual progress.

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

A STREAM_FIN Final Offset is a Stream commitment under Section 17.2. If it increases Committed Offset, the increase MUST satisfy the currently retained Stream Maximum Offset and the resulting cumulative Session committed-byte counter MUST NOT exceed retained Session Maximum Bytes. Exceeding either credit limit is FLOW_CONTROL_ERROR.

After a valid final size has been established, any Frame implying a different final size or data beyond that final size is a FINAL_SIZE_ERROR.

STREAM_FIN is reliable and is confirmed with TRANSMISSION_ACK.

### 18.2. RESET_STREAM

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Final Offset     VarInt
    Stream Error Code  VarInt

RESET_STREAM terminates the sender's direction and declares its final size.

The final-size and flow-control commitment invariants for STREAM_FIN also apply to RESET_STREAM.

Stream Error Code is an opaque VarInt termination reason carried for the Stream/application contract. It is not a Core Error Code report and does not inherit the failure scope assigned by the Core Error Code registry. Applications or profiles may define Stream Error Code meanings; an unknown value does not by itself change Session or Carrier failure scope.

RESET_STREAM is reliable and is confirmed with TRANSMISSION_ACK.

### 18.3. STOP_SENDING

Body:

    Stream ID        VarInt
    Transmission ID  VarInt
    Stream Error Code  VarInt

STOP_SENDING requests that the peer cease transmission in the opposite direction.

Its Stream Error Code has the same opaque Stream/application namespace as RESET_STREAM and MUST NOT be interpreted as a Core protocol-failure declaration.

A peer that has not already completed that sending direction SHOULD respond by issuing RESET_STREAM, normally carrying the same Stream Error Code unless the local application/profile selects another reason.

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

A receiver that still has the requested relevant state MUST eventually answer while the Session remains active and an authenticated writable Carrier exists. For Stream ID 0 it sends current SESSION_CREDIT. For a retained non-zero Stream it sends current STREAM_CREDIT and current SESSION_CREDIT. The response MAY be coalesced or rate-limited. If the requested state has already been retired or the Session/Stream becomes terminal first, no response is required.

## 20. PING and PONG

PING body:

    Token        VarInt

PONG body:

    Token        VarInt

A PONG MUST echo the PING Token.

A PONG, when sent, MUST be returned on the same Carrier on which the corresponding PING was received. Core implementations MUST NOT reroute that PONG onto another Carrier.

PING/PONG is Carrier-scoped and MAY be used for Carrier liveness and RTT estimation. For a PING/PONG exchange to be used as a path-specific RTT sample, the sender MUST be able to associate the echoed Token with exactly one outstanding PING on that Carrier.

PING/PONG has no Stream or Session flow-control effect.

Core does not define a probing interval, timeout count, smoothing algorithm, path-quality threshold, or background probe schedule. Those are local implementation policy and MUST NOT affect wire interoperability.

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

CARRIER_CLOSE MUST be the final Frame in the Secure Record containing it. After CARRIER_CLOSE, no new Secure Records are sent on that Carrier. A receiver MUST NOT allow any authenticated trailing Frame after CARRIER_CLOSE to create new protocol or application state.

An unrecognized Error Code from a valid negotiated extension or private-profile range is treated as an unknown diagnostic reason and does not cancel the Carrier terminal action.

### 21.2. SESSION_CLOSE

SESSION_CLOSE uses the same body format as CARRIER_CLOSE but applies to the entire Session.

After SESSION_CLOSE is processed, no new Streams or Carriers may be created for that Session ID and all active Carriers are closed.

SESSION_CLOSE MUST be the final Frame in each Secure Record containing it. A sender MAY transmit SESSION_CLOSE on more than one active Carrier to improve delivery of the terminal state. A receiver MUST NOT allow authenticated trailing Frames after SESSION_CLOSE to create new protocol or application state.

An unrecognized Error Code from a valid negotiated extension or private-profile range is treated as an unknown diagnostic reason and does not cancel the Session terminal action.

## 22. Error handling and failure scope

The normative Error Code scopes, required CARRIER_CLOSE / SESSION_CLOSE actions, pre-establishment rejection rules, Trigger Frame Type rules, and extension requirements are defined in [ERROR-HANDLING.md](ERROR-HANDLING.md).

That document is part of the MPX/4 Core specification.

In summary:

- a Stream-opening-scoped error rejects only that STREAM_OPEN;
- a Carrier-scoped error invalidates only the affected Carrier incarnation;
- a Session-scoped error MUST transition the Session to CLOSING and MUST cause SESSION_CLOSE when an authenticated writable Carrier is available;
- rejecting a candidate JOIN MUST NOT modify an existing Session;
- FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR, and TRANSMISSION_ID_ERROR are Session-scoped;
- FRAME_ENCODING_ERROR and authentication/integrity failure are Carrier-scoped;
- STREAM_STATE_ERROR is Session-scoped except where Core explicitly defines STREAM_OPEN_REJECT as the narrower action.

Error Code selection and failure scope are distinct. The deterministic error-code precedence remains defined in [STATE-MACHINES.md](STATE-MACHINES.md).

## 23. Carrier eligibility and local selection

Each endpoint independently selects an eligible Carrier for each locally originated Transmission Attempt. Core does not negotiate, name, or standardize scheduler modes.

An implementation MAY use any local policy, including round-robin, latency-aware, protection-oriented, capacity-aware, cost-aware, or adaptive selection. Different endpoints in the same Session MAY use unrelated policies for their respective sending directions.

A Carrier is eligible for a new Attempt only while it is authenticated, ESTABLISHED, not closing, not superseded by a higher Generation, and considered usable by the local endpoint.

Local Carrier-selection policy MUST NOT:

- change Stream byte identity;
- change a Transmission ID during retransmission or reinjection;
- create additional logical flow-control commitment for another Attempt;
- schedule new Attempts on a closing, superseded, DORMANT-only, or unusable Carrier;
- require the peer to make the same Carrier choice unless an explicitly negotiated extension says otherwise.

Carrier metrics such as RTT, outstanding bytes, measured delivery rate, configured capacity, monetary cost, interface class, or preference are local implementation state unless an extension explicitly exchanges them.

Core does not expose Relay topology or require a Relay to participate in MPX/4. A transport path containing one or more transparent forwarding hops is still one Carrier from the Core protocol's perspective.

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

Once a Transmission has multiple Attempts, attribution is ambiguous unless an extension explicitly identifies Attempts. Draft 11 therefore prohibits treating such acknowledgements as unambiguous per-Carrier delivery-rate samples.

Delivery-rate estimation SHOULD avoid treating application-limited traffic as path capacity.

## 26. State validity and Stream lifecycle

The normative MPX/4 state machines, Frame-validity matrices, cross-Carrier reordering rules, terminal Stream rules, tombstone requirements, and retired-identity behavior are defined in [STATE-MACHINES.md](STATE-MACHINES.md).

That document is part of the MPX/4 Core specification for Draft 11.

In particular, conforming implementations MUST support:

- acceptance evidence that arrives before STREAM_OPEN_OK on another Carrier;
- valid RESET_STREAM or STOP_SENDING pre-open cancellation;
- late STREAM_DATA below an already established FIN Final Offset;
- idempotent processing of duplicate reliable Frames;
- immutable final-size semantics;
- tombstone retention sufficient to prevent Stream-ID reuse;
- compact tombstones into retired identities only after each still-unretired peer reliable Transmission is either covered by peer TRANSMISSION_RETIRE or has equivalent confirmation-replay state retained at Session scope or elsewhere outside the compacted Stream state.

An implementation MAY use different internal state names or data structures, but its externally observable behavior MUST conform to the state supplement.

## 27. Resource limits

Draft 11 Core limits are:

| Limit | Value |
|---|---:|
| CARRIER_ID numeric range | 1 through 2^62 - 1 |
| MAX_CARRIERS advertised range | 1 through 2^62 - 1 |
| Maximum simultaneously active logical Carriers | Effective Carrier Limit negotiated by MAX_CARRIERS |
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

Draft 11 does not provide forward secrecy because the mandatory key schedule is rooted only in the pre-shared transport key. A future negotiated key-exchange profile can add forward secrecy without changing the Session, Carrier, or Stream model.

## 30. Wire-size considerations

MPX/4 uses canonical VarInts and typed Frame bodies rather than a fixed per-Frame structure.

Small identifiers and offsets therefore occupy fewer octets.

Multiple Frames MAY share one Secure Record and one 16-octet AEAD tag.

MPX Frame and Secure Record sizes are protocol limits, not network MTUs. The underlying transport remains responsible for segmentation.

## 31. Conformance requirements

A conforming Draft 11 implementation MUST:

- recognize the MPX/4 Connection Preface;
- reject non-canonical VarInts;
- implement canonical Parameter ordering and duplicate rejection;
- implement the Protocol Version and stable-compatibility rules in COMPATIBILITY.md;
- bind every Session to an immutable Session Protocol Version and require JOIN/replacement to use it;
- require MAX_CARRIERS with CRITICAL=1 in CREATE and JOIN handshakes;
- compute and retain the immutable Effective Carrier Limit as the minimum of the two CREATE-time MAX_CARRIERS advertisements;
- accept non-zero CARRIER_ID values across the full MPX VarInt range independently of Carrier concurrency;
- enforce Active Carrier Count against the Effective Carrier Limit;
- implement the Draft 11 key schedule exactly;
- implement CLIENT_FINISHED and SERVER_FINISHED verification;
- implement HANDSHAKE_REJECT as an unauthenticated candidate-only rejection signal without mutating existing Session state or triggering downgrade;
- implement AES-256-GCM Secure Records with the specified nonce and AAD construction;
- enforce peer receive limits;
- implement the Core Frame set in REGISTRIES.md;
- implement the normative state rules in STATE-MACHINES.md;
- implement the failure scopes and required close actions in ERROR-HANDLING.md;
- retain Highest Accepted Generation per used Carrier ID for the Session lifetime;
- reject stale, equal-reuse, and invalid first Carrier Generations with CARRIER_CONFLICT;
- commit a higher Carrier Generation only after successful Carrier establishment;
- prevent superseded Carriers from creating new protocol state or receiving new Attempts;
- preserve Transmission IDs across retransmission and reinjection;
- never reuse or wrap a Transmission ID within a Session and apply the defined exhaustion behavior;
- distinguish settled duplicate acknowledgements from never-allocated Transmission IDs;
- enforce Stream and Session flow-control rules;
- preserve Stream byte identity across Carriers;
- never reuse or wrap a Stream ID within a Session and apply the defined exhaustion behavior;
- reject conflicting overlapping Stream bytes;
- preserve final-size invariants;
- tolerate the specified cross-Carrier reordering cases;
- retain terminal Stream state sufficient to prevent Stream-ID reuse;
- distinguish Stream-opening-, Carrier-, and Session-scoped failures;
- send SESSION_CLOSE for Session-scoped errors when an authenticated writable Carrier is available;
- keep PING/PONG path measurement Carrier-specific;
- support ACTIVE-to-DORMANT Session transition when the last Carrier disappears without Session closure and retained Session state permits reconnection;
- preserve Session, Stream, flow-control, Generation, and reliable Transmission state while DORMANT;
- treat Carrier selection as local endpoint policy while obeying Core eligibility, reliability, identity, and flow-control invariants;
- ignore unsupported optional scheduling or path-metadata extensions safely when their defining extension permits it;
- implement at least one conforming transport binding;
- when claiming TCP interoperability, implement bindings/tcp.md;
- pass the Mandatory behavior groups in INTEROPERABILITY.md for a Draft 11 Core interoperability claim.

## 32. Future work

The following remain outside Draft 11:

- ephemeral key exchange and forward secrecy;
- datagram transport;
- server-initiated Streams;
- explicit Attempt identifiers;
- acknowledgement ranges;
- forward error correction;
- explicit Carrier migration;
- standardized scheduler algorithms or profiles;
- additional path-metadata extensions;
- additional transport bindings beyond the Draft 11 TCP baseline.

## 33. Normative references

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels.
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function.
- RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- RFC 9293 — Transmission Control Protocol (TCP).
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
10. Existing assigned wire registry values are not renumbered or repurposed within a stable Protocol Version.
11. Session Protocol Version is immutable after CREATE.
12. DORMANT preserves authenticated Session-owned state while Active Carrier Count is zero.
13. Carrier-selection policy is endpoint-local and does not alter Core Stream, Transmission, flow-control, or Carrier-eligibility semantics.
14. Transmission IDs, Stream IDs, and Carrier Generations never wrap; Session, Carrier, Stream, and Transmission identities are never reused contrary to their lifetime rules.
15. A rejected pre-establishment candidate cannot mutate an existing Session.

## Appendix B. Draft 11 wire constants

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
    HANDSHAKE_REJECT Message Type      0x06
    TRANSMISSION_RETIRE Frame Type     0x1a
    MAX_CARRIERS Parameter Type        0x0a
    CARRIER_ID range                   1 .. 2^62-1
    Transmission ID range              1 .. 2^62-1, consecutive
    Client Stream ID range             odd 1 .. 2^62-1
    MAX_CARRIERS value range           1 .. 2^62-1
