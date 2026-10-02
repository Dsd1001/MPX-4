# MPX/4 Handshake Example

This document provides a non-normative walkthrough of an MPX/4 Draft 02 Session establishment.

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

    SCHEDULER
      = AGGREGATE

MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS are Client receive limits. They constrain traffic sent by the Server.

If SCHEDULER were WEIGHTED, CLIENT_INIT would additionally contain PATH_CAPACITY for this Carrier.

## 3. SERVER_INIT

The Server validates the requested Session policy and returns its own receive limits:

    SERVER_NONCE
      = 32 fresh random octets

    MAX_FRAME_PAYLOAD
      = 32768

    MAX_RECORD_SIZE
      = 65536

    MAX_STREAMS
      = 2048

    SCHEDULER
      = AGGREGATE

The Server echoes the accepted Session Scheduler.

The Server receive limits constrain traffic sent by the Client. The two endpoints are allowed to advertise different receive limits.

## 4. Finished authentication

The exact encoded bytes of:

    Connection Preface
    CLIENT_INIT
    SERVER_INIT

produce transcript hash H0.

CLIENT_FINISHED contains the Draft 02 HMAC-SHA256 VerifyData over H0.

SERVER_FINISHED authenticates the transcript including CLIENT_FINISHED.

After both required Finished checks succeed, the endpoints derive the directional application traffic key and IV values used by Secure Records.

The exact Draft 02 derivation is defined in Section 10 of the Core specification.

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
      = 2

    CARRIER_GENERATION
      = 0

    CLIENT_NONCE
      = new 32-octet random value

    SCHEDULER
      = existing Session Scheduler

Receive-limit Parameters are also sent for the new Carrier handshake.

The Carrier is not eligible for scheduling until CLIENT_FINISHED has authenticated the Client and the full handshake reaches ESTABLISHED.

## 7. Carrier reconnection

If Carrier 2 later disconnects and is re-established:

    CARRIER_ID
      = 2

    CARRIER_GENERATION
      = 1

The higher Generation distinguishes the new transport instance from stale state belonging to the previous Carrier incarnation.

A lower Generation is stale. A conflicting equal live Generation is rejected.


## Draft 02 notes

Handshake Parameters are encoded in strictly increasing Parameter-Type order. MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS are directional receive limits. No application-data credit is implicit; Stream and Session credit are advertised explicitly with Frames after authentication.
