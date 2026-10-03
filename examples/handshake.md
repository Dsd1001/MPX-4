# MPX/4 Handshake Example

This document provides a non-normative walkthrough of an MPX/4 Draft 11 Session establishment.

The normative handshake requirements are defined in [../SPECIFICATION.md](../SPECIFICATION.md).

## 1. Initial Carrier

Assume a Client creates a new Session over a reliable ordered byte-stream Carrier.

    Client                                             Server
      |                                                   |
      |  Connection Preface                              |
      |  Magic = 4d 50 58 00                             |
      |  Version = 4                                     |
      |-------------------------------------------------->|
      |                                                   |
      |  CLIENT_INIT                                      |
      |-------------------------------------------------->|
      |                                                   |
      |  SERVER_INIT                                      |
      |<--------------------------------------------------|
      |                                                   |
      |  CLIENT_FINISHED                                  |
      |-------------------------------------------------->|
      |                                                   |
      |  SERVER_FINISHED                                  |
      |<--------------------------------------------------|
      |                                                   |
      |================ ESTABLISHED ======================|
      |                                                   |
      |  SESSION_CREDIT                                   |
      |<------------------------------------------------->|
      |                                                   |

No application-data credit is implicit. Each endpoint advertises Session credit explicitly after the first Carrier becomes established.

## 2. CLIENT_INIT

Illustrative logical Parameters, shown in mandatory increasing Parameter-Type order:

    SESSION_ID
      = 4a5f0c0a1fcb4d72a89a7a4f574d9d21

    SESSION_ACTION
      = CREATE

    CARRIER_ID
      = 1

    CARRIER_GENERATION
      = 0

    CLIENT_NONCE
      = 32 fresh random octets

    MAX_FRAME_PAYLOAD
      = 32768

    MAX_RECORD_SIZE
      = 65536

    MAX_STREAMS
      = 2048

    MAX_CARRIERS
      = 96
      CRITICAL = 1


MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS are Client receive limits. They constrain traffic sent by the Server.

MAX_CARRIERS is not a directional receive limit. It advertises that the Client is willing to maintain at most 96 simultaneously active logical Carriers in this Session.

Optional extension Parameters may follow the Core Parameters. Core does not require a scheduler identifier or capacity metadata.

## 3. SERVER_INIT

The Server validates the requested Session policy and returns its own receive limits and Carrier capability:

    SERVER_NONCE
      = 32 fresh random octets

    MAX_FRAME_PAYLOAD
      = 32768

    MAX_RECORD_SIZE
      = 65536

    MAX_STREAMS
      = 2048

    MAX_CARRIERS
      = 128
      CRITICAL = 1


The Server receive limits constrain traffic sent by the Client. The two endpoints are allowed to advertise different receive limits.

The Session establishes:

    Effective Carrier Limit = min(96, 128) = 96

The numeric Carrier ID space is independent of this concurrency limit. A later Carrier can legally use Carrier ID 4000000000 while the Session still contains only a small number of active logical Carriers.

## 4. Finished authentication

The exact encoded bytes of:

    Connection Preface
    CLIENT_INIT
    SERVER_INIT

produce transcript hash H0.

CLIENT_FINISHED contains the Draft 11 HMAC-SHA256 VerifyData over H0.

SERVER_FINISHED authenticates the transcript including CLIENT_FINISHED.

After both required Finished checks succeed, the endpoints derive the directional application traffic key and IV values used by Secure Records.

The exact Draft 11 derivation is defined in Section 10 of the Core specification.

Because MAX_CARRIERS is part of CLIENT_INIT and SERVER_INIT, changing either advertisement changes the authenticated transcript and therefore changes Finished values and application traffic secrets.

A complete machine-readable example is available in:

- [key-schedule.json](../test-vectors/key-schedule.json)

## 5. Opening a Stream

After Session establishment, the Client can send:

    STREAM_OPEN
      Stream ID        = 1
      Transmission ID  = 1

The Server either returns STREAM_OPEN_OK or STREAM_OPEN_REJECT with the same Stream ID and Transmission ID.

Application data in either direction still requires explicit Stream credit.

An accepting Server advertises STREAM_CREDIT for its receive direction.

After receiving STREAM_OPEN_OK, the Client advertises STREAM_CREDIT for its own receive direction before expecting Server application data.

## 6. Additional Carrier

A second Carrier joins the same Session with a fresh authenticated handshake:

    SESSION_ID
      = same Session ID

    SESSION_ACTION
      = JOIN

    CARRIER_ID
      = 96

    CARRIER_GENERATION
      = 0

    CLIENT_NONCE
      = new 32-octet random value

    MAX_CARRIERS
      = 96
      CRITICAL = 1


The Server repeats its original MAX_CARRIERS value of 128 in SERVER_INIT. The Effective Carrier Limit remains 96; JOIN does not renegotiate it.

Session-scoped receive-limit Parameters are also repeated for the new Carrier handshake.

Carrier ID 96 does not imply that 96 Carriers exist. It is only the identity of this logical Carrier.

The Carrier is not eligible for scheduling until CLIENT_FINISHED has authenticated the Client and the full handshake reaches ESTABLISHED.

## 7. Carrier reconnection

If Carrier 96 later disconnects and is re-established:

    CARRIER_ID
      = 96

    CARRIER_GENERATION
      = 1

The higher Generation distinguishes the new transport instance from stale state belonging to the previous Carrier incarnation.

A lower Generation is stale. An equal Generation is rejected even if the previous transport has already closed or been lost.

Replacement of an already active Carrier ID does not consume an additional active logical Carrier slot.

If Carrier 96 was already inactive, its replacement consumes one free active slot when it reaches ESTABLISHED. If the Session is already at the Effective Carrier Limit because another Carrier used the released capacity, the replacement candidate is rejected with RESOURCE_LIMIT until capacity becomes available.

## 8. Loss of the last Carrier

If the Session has one active Carrier and that Carrier is lost without SESSION_CLOSE, an endpoint that retains the Session enters DORMANT:

    Active Carrier Count = 0
    Session state         = DORMANT

Stream state, flow-control accounting, Carrier Generation history, and reliable Transmission state remain retained. No new Stream or DATA Transmission is created while DORMANT.

A later valid JOIN or replacement using Protocol Version 4 can return the Session to ACTIVE. A JOIN using another Protocol Version cannot attach to this Session even when that other version is locally supported.

If local retention policy discards the DORMANT Session before reconnection, a later JOIN receives SESSION_NOT_FOUND.

## 9. Rejected candidate Carrier

A failed CREATE, JOIN, or replacement can be rejected before establishment with HANDSHAKE_REJECT when the failure is safely reportable. For example, if a JOIN names a retained Carrier Generation conflict:

    Server -> Client

    HANDSHAKE_REJECT
      Error Code = CARRIER_CONFLICT

The candidate transport then closes. HANDSHAKE_REJECT is unauthenticated, does not enter the successful Finished transcript, and does not modify the existing Session.

A Client receiving such a rejection does not treat it as permission to retry a lower Protocol Version.

## Draft 11 notes

Handshake Parameters are encoded in strictly increasing Parameter-Type order.

MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS are directional receive limits.

MAX_CARRIERS is a required critical Session capability. It controls active logical Carrier concurrency and does not bound CARRIER_ID values.

The Session Protocol Version is fixed by CREATE and is repeated implicitly by the Connection Preface of every JOIN/replacement Carrier.

Carrier selection is local endpoint policy. An implementation may use optional published metadata extensions without making that local policy part of Core.

No application-data credit is implicit; Stream and Session credit are advertised explicitly with Frames after authentication.
