# MPX/4 Handshake Example

This document provides a non-normative example of an MPX/4 Session establishment.

The normative handshake requirements are defined in [../SPECIFICATION.md](../SPECIFICATION.md).

## 1. Initial Carrier

Assume a Client creates a new Session over a TCP Carrier.

The connection begins with:

```text
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
```

## 2. CLIENT_INIT

Illustrative logical Parameters:

```text
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

INITIAL_STREAM_CREDIT
  = implementation-selected value

INITIAL_SESSION_CREDIT
  = implementation-selected value

SCHEDULER
  = AGGREGATE
```

The Parameter order shown here is illustrative. An implementation MUST follow the ordering rules, if any, defined by the active protocol revision.

## 3. SERVER_INIT

The Server validates the requested Session creation and responds with Parameters including:

```text
SERVER_NONCE
  = 32 fresh random octets

MAX_FRAME_PAYLOAD
  = selected compatible value

MAX_RECORD_SIZE
  = selected compatible value

MAX_STREAMS
  = selected compatible value

SCHEDULER
  = selected compatible scheduler
```

The exact encoded CLIENT_INIT and SERVER_INIT bytes, together with the Connection Preface, form the authenticated handshake transcript.

## 4. Finished messages

The peers derive distinct finished keys and application traffic keys from the transport key and authenticated transcript.

CLIENT_FINISHED authenticates the Client view of the transcript.

SERVER_FINISHED authenticates the Server view of the transcript.

The Carrier enters ESTABLISHED only after the required Finished values validate.

## 5. Additional Carrier

A second Carrier joins the same Session with:

```text
SESSION_ID
  = 4a5f0c0a1fcb4d72a89a7a4f574d9d21

SESSION_ACTION
  = JOIN

CARRIER_ID
  = 2

CARRIER_GENERATION
  = 0

CLIENT_NONCE
  = new 32-octet random value
```

It performs a complete authenticated Carrier handshake before becoming eligible for scheduling.

## 6. Carrier reconnection

If Carrier 2 later disconnects and is re-established:

```text
CARRIER_ID
  = 2

CARRIER_GENERATION
  = 1
```

The higher Generation distinguishes the new transport connection from stale state belonging to the previous Carrier instance.
