# MPX/4 State Machines and Frame Validity

**Document:** MPX/4 State Machine Supplement  
**Revision:** Draft 03  
**Protocol Version:** 4  
**Status:** Normative Working Draft

This document is a normative companion to [SPECIFICATION.md](SPECIFICATION.md). It defines state transitions, Frame validity, duplicate handling, terminal Stream behavior, and retirement rules that are required for interoperable MPX/4 implementations.

## 1. Scope

MPX/4 multiplexes one Session across multiple independently ordered Carriers. Frames belonging to the same Stream can therefore arrive in an order that differs from the order in which an implementation emitted them on separate Carriers.

The state rules in this document are designed to preserve correctness under:

- cross-Carrier reordering;
- retransmission and reinjection;
- duplicate reliable Frames;
- Carrier failure and replacement;
- simultaneous directional shutdown;
- late delivery of terminal control Frames.

Implementations MAY use different internal state names. They MUST preserve the externally observable behavior defined here.

## 2. Error classes

This document uses three Stream-related error codes:

- **STREAM_STATE_ERROR** — a Frame is structurally valid but impossible in the current Stream lifecycle state.
- **FINAL_SIZE_ERROR** — a Frame contradicts an already established final size or carries bytes beyond it.
- **TRANSMISSION_ID_ERROR** — a Transmission ID is reused for different semantic contents or refers to an ID that the sender could not have allocated.

A malformed encoding remains FRAME_ENCODING_ERROR.

A flow-control violation remains FLOW_CONTROL_ERROR.

When a violation changes or contradicts shared Stream state, the error is Session-scoped unless this document explicitly says otherwise.

## 3. Session state

An MPX Session has the following abstract lifecycle:

    CREATING
       |
       v
    ACTIVE
       |
       v
    CLOSING
       |
       v
    CLOSED

### 3.1. CREATING

The Session exists provisionally while the first Carrier handshake is in progress.

Application Streams MUST NOT be created before the first Carrier reaches ESTABLISHED.

### 3.2. ACTIVE

At least one authenticated Carrier is or can become usable, and new Streams may be created subject to limits.

### 3.3. CLOSING

SESSION_CLOSE has been sent or received, or a Session-scoped protocol error has occurred.

No new Stream or Carrier may be created.

Existing protocol state MAY be processed only as required to complete local shutdown.

### 3.4. CLOSED

All Carrier transport state has been released.

A Session ID in CLOSED state MUST NOT be reused for a new Session while the implementation still retains retirement state for that Session ID.

## 4. Carrier state

Each Carrier has the following lifecycle:

    TRANSPORT_CONNECTED
            |
            v
       HANDSHAKING
            |
            v
        ESTABLISHED
            |
            v
         CLOSING
            |
            v
          CLOSED

Only handshake messages are valid in HANDSHAKING.

Only Secure Records are valid after ESTABLISHED.

After a Carrier enters CLOSING, no new application or control Frames may be scheduled onto it except the already-generated CARRIER_CLOSE record.

Carrier failure does not by itself change Stream lifecycle state.

## 5. Stream opening states

A Stream has an opening state independent of its two data directions.

For the Client initiator:

    IDLE
      |
      | send STREAM_OPEN
      v
    OPENING
      |       |   STREAM_OPEN_REJECT
      |   v
      | REJECTED
      |
      | STREAM_OPEN_OK
      v
    OPEN

For the Server responder:

    UNSEEN
      |
      | receive STREAM_OPEN
      v
    OPEN_PENDING
      |       |   reject
      |   v
      | REJECTED
      |
      | accept
      v
    OPEN

A Stream ID is never reusable, including after REJECTED or retirement.

## 6. Acceptance evidence during cross-Carrier reordering

After a Server accepts a Stream, STREAM_OPEN_OK, STREAM_CREDIT, STREAM_DATA, STREAM_FIN, RESET_STREAM, or STOP_SENDING may be emitted on different Carriers.

Therefore the Client can observe a Frame that could only have been sent after acceptance before it observes STREAM_OPEN_OK.

While in OPENING, the Client MUST tolerate the following inbound Frames as **acceptance evidence**:

- STREAM_CREDIT;
- STREAM_FIN with Final Offset 0;
- RESET_STREAM with Final Offset 0;
- STOP_SENDING.

Draft 03 has no implicit Stream data credit. Therefore STREAM_DATA cannot legally precede the first STREAM_OPEN_OK, because the Client has not yet advertised receive credit for the accepted Stream.

The Client processes valid acceptance-evidence Frames according to their normal semantics while remaining logically OPENING until STREAM_OPEN_OK is received.

After acceptance evidence has been observed, a later STREAM_OPEN_REJECT for that Stream is a STREAM_STATE_ERROR.

An implementation MAY internally transition to an equivalent "OPENING_WITH_ACCEPTANCE_EVIDENCE" state.

A rejected opening is terminal. Once STREAM_OPEN_REJECT is processed, the Stream ID MUST NOT be reused. Duplicate STREAM_OPEN_REJECT carrying the same Stream ID, original open Transmission ID, and Error Code is idempotent. A conflicting rejection is STREAM_STATE_ERROR. An implementation MAY represent the rejected Stream as a tombstone containing the original open Transmission ID, the rejection decision, and Error Code.

The Server MUST NOT send any acceptance-evidence Frame before it has accepted the Stream.

## 7. Pre-open cancellation

The reverse reordering case is also possible.

A Client can locally cancel a Stream while its STREAM_OPEN is still in flight. A RESET_STREAM or STOP_SENDING sent as part of that cancellation can arrive at the Server before STREAM_OPEN.

The Server MUST support the following pre-open cancellation cases for a previously unseen Client Stream ID that is valid under the Stream-ID allocation rules:

### 7.1. RESET_STREAM before STREAM_OPEN

RESET_STREAM is valid before STREAM_OPEN only when Final Offset is 0.

The Server:

1. records a cancellation tombstone for the Stream ID;
2. acknowledges the RESET_STREAM;
3. MUST NOT later create an application Stream if STREAM_OPEN for the same Stream ID arrives.

A later STREAM_OPEN for that ID is answered with STREAM_OPEN_REJECT using STREAM_STATE_ERROR.

A pre-open RESET_STREAM with non-zero Final Offset is a STREAM_STATE_ERROR because application data could not legally have been committed before Stream acceptance.

### 7.2. STOP_SENDING before STREAM_OPEN

STOP_SENDING MAY arrive before STREAM_OPEN.

The Server records the receive-direction cancellation for that Stream ID, acknowledges the STOP_SENDING, and sends RESET_STREAM with Final Offset 0 for its not-yet-started sending direction unless an equivalent RESET_STREAM is already pending.

If STREAM_OPEN later arrives, the Stream MUST NOT become an application Stream. The Server MUST answer with STREAM_OPEN_REJECT using STREAM_STATE_ERROR.

### 7.3. Other Frames before STREAM_OPEN

For an unseen Stream ID, STREAM_DATA, STREAM_FIN, STREAM_CREDIT, STREAM_CONSUMED, STREAM_OPEN_OK, and STREAM_OPEN_REJECT are STREAM_STATE_ERROR unless the endpoint can classify the Stream ID as an already retired identity.

## 8. Directional Stream states

After acceptance, each bidirectional Stream has independent send and receive direction states.

### 8.1. Send direction

    SEND_ACTIVE
        |
        +-- send STREAM_FIN ------> FIN_PENDING
        |                             |
        |                             | TRANSMISSION_ACK
        |                             v
        |                          SEND_CLOSED
        |
        +-- send RESET_STREAM ----> RESET_PENDING
                                      |
                                      | TRANSMISSION_ACK
                                      v
                                   SEND_CLOSED

After FIN_PENDING or RESET_PENDING begins, no new STREAM_DATA may be committed in that direction.

Retransmitted copies of the same terminal Frame retain the same Transmission ID.

If STOP_SENDING is received while FIN is pending, the sender MUST stop scheduling new Attempts of the FIN Transmission and create a new RESET_STREAM Transmission with the same Final Offset and the STOP_SENDING Error Code. The RESET_STREAM supersedes the FIN for application-visible termination. A later acknowledgement of the superseded FIN is treated as a stale settled acknowledgement and MUST NOT settle or cancel the RESET_STREAM Transmission.

### 8.2. Receive direction

    RECV_ACTIVE
        |
        +-- receive STREAM_FIN ----> FIN_RECEIVED
        |                              |
        |                              | all bytes [0, Final Offset)
        |                              | consumed
        |                              v
        |                           FIN_CONSUMED
        |
        +-- receive RESET_STREAM --> RESET_RECEIVED
                                       |
                                       | receive accounting released
                                       v
                                    RESET_CONSUMED

FIN_RECEIVED does not imply that all preceding bytes have arrived. STREAM_DATA with End Offset <= Final Offset remains valid and can fill earlier holes.

RESET_RECEIVED terminates application delivery for that direction. Later duplicate data within the established final size has no application effect but can still be acknowledged as stale reliable traffic.

## 9. Opening Frame validity

Legend:

- **A** — apply normally.
- **D** — duplicate/idempotent; repeat the previously required response when applicable.
- **B** — accept as cross-Carrier reordered acceptance evidence.
- **C** — valid pre-open cancellation.
- **I** — ignore as stale retired traffic; no application state is recreated.
- **E** — STREAM_STATE_ERROR.
- **T** — TRANSMISSION_ID_ERROR.

| Received Frame | UNSEEN responder | OPEN_PENDING responder | OPENING initiator | OPEN | TOMBSTONE | RETIRED_ID |
|---|---:|---:|---:|---:|---:|---:|
| STREAM_OPEN | A | D if same TxID; T otherwise | E | D if original TxID; T otherwise | D if decision retained; T if conflicting | I |
| STREAM_OPEN_OK | E | E | A | D if same open TxID | I | I |
| STREAM_OPEN_REJECT | E | E | A unless acceptance evidence exists | E after accepted | I | I |
| STREAM_CREDIT | E | E before accept | B | A | validate then ignore | I |
| STREAM_DATA | E | E before accept | E | A | stale handling | I |
| STREAM_FIN | E | E before accept | B only with Final Offset 0 | A | stale handling | I |
| RESET_STREAM | C only with Final Offset 0 | C | B only with Final Offset 0 | A | D/validate | I |
| STOP_SENDING | C | C | B | A | D/validate | I |
| STREAM_CONSUMED | E | E | E | state-dependent | D/validate | I |

The table expresses lifecycle validity. All ordinary encoding, final-size, Transmission-ID, and flow-control rules still apply.

## 10. Receive-direction Frame validity

For an accepted Stream:

| Received Frame | RECV_ACTIVE | FIN_RECEIVED | FIN_CONSUMED | RESET_RECEIVED / RESET_CONSUMED |
|---|---:|---:|---:|---:|
| STREAM_DATA within credit/final size | A | A; may fill holes | stale duplicate only | stale duplicate only |
| STREAM_DATA beyond final size | n/a until final known | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR |
| STREAM_FIN same Final Offset | A | D | D | D; reset semantics remain authoritative |
| STREAM_FIN different Final Offset | A if no final established | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR |
| RESET_STREAM same Final Offset | A | A; reset semantics become authoritative | A; reset semantics become authoritative | D if same terminal semantics |
| RESET_STREAM different Final Offset | A if no final established | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR | FINAL_SIZE_ERROR |
| CREDIT_PROBE for Stream | A | A | A | A while tombstone retained |
| STREAM_CONSUMED | pertains to opposite direction | pertains to opposite direction | pertains to opposite direction | pertains to opposite direction |

After RESET_RECEIVED, valid duplicate or late STREAM_DATA within Final Offset MUST NOT be delivered to the application.

## 11. Send-direction Frame validity

The following Frames describe peer state for the local sending direction:

| Received Frame | SEND_ACTIVE | FIN_PENDING | RESET_PENDING | SEND_CLOSED |
|---|---:|---:|---:|---:|
| STREAM_CREDIT | A | A if values do not contradict final size | A if values do not contradict final size | validate then ignore |
| STOP_SENDING | A; send RESET_STREAM using the STOP_SENDING Error Code | A; send RESET_STREAM with the same Final Offset and make reset semantics authoritative | D; repeat pending RESET_STREAM as needed | D |
| STREAM_CONSUMED | E before a final size is established | A only if Final Offset equals local final size | A only if Final Offset equals local final size | D if Final Offset matches |
| TRANSMISSION_ACK | settle referenced pending Tx | settle referenced pending Tx | settle referenced pending Tx | ignore duplicate settled ACK |

A STREAM_CONSUMED Final Offset that differs from the local established final size is FINAL_SIZE_ERROR.

## 12. TRANSMISSION_ACK validity

Transmission IDs are Session-wide and monotonically allocated.

On receiving TRANSMISSION_ACK:

1. if the Transmission ID identifies an outstanding local reliable Transmission, the acknowledgement settles it;
2. if it identifies a previously settled local Transmission, the acknowledgement is a harmless duplicate and is ignored;
3. if it is greater than or equal to the next Transmission ID the local endpoint has not yet allocated, it is TRANSMISSION_ID_ERROR;
4. if implementation state has compacted an older settled Transmission, the acknowledgement is treated as a stale duplicate.

The Stream ID carried by TRANSMISSION_ACK MUST match the Stream ID of the referenced Transmission. A mismatch is TRANSMISSION_ID_ERROR.

## 13. STREAM_CREDIT validity after terminal state

STREAM_CREDIT can legitimately arrive after a sending direction has become terminal because it may have been emitted earlier on another Carrier.

For a terminal sending direction:

- Consumed Offset MUST NOT exceed the local Final Offset;
- Maximum Offset MUST be greater than or equal to Consumed Offset;
- a credit update cannot authorize new data after local terminal state;
- a valid late update is otherwise ignored after accounting already released by terminal confirmation.

A value contradicting the local final size is FINAL_SIZE_ERROR.

## 14. Final-size invariants

A receive-direction final size is established by the first valid STREAM_FIN or RESET_STREAM.

After establishment:

1. the Final Offset never changes;
2. STREAM_DATA End Offset MUST NOT exceed Final Offset;
3. a repeated terminal Frame MUST use the same Final Offset;
4. STREAM_FIN followed by RESET_STREAM with the same Final Offset is valid; RESET_STREAM becomes authoritative for application-visible termination;
5. STREAM_FIN received after RESET_STREAM with the same Final Offset is acknowledged but MUST NOT replace reset semantics with graceful EOF;
6. any terminal Frame with a different Final Offset fails with FINAL_SIZE_ERROR;
7. Final Offset contributes to Session committed-byte accounting exactly once.

If RESET_STREAM establishes a Final Offset greater than the highest received DATA End Offset, the missing range still counts as committed for Session flow-control accounting.

## 15. Stream tombstones

An implementation MUST retain terminal Stream state long enough to make duplicate terminal traffic idempotent and to prevent Stream-ID reuse.

A **tombstone** is the minimal semantic record retained after application-visible Stream state is no longer required.

A tombstone SHOULD retain, when applicable:

- Stream ID;
- original STREAM_OPEN Transmission ID and acceptance/rejection decision;
- local terminal kind;
- local terminal Transmission ID;
- local Final Offset;
- local terminal Error Code for RESET_STREAM;
- peer terminal kind;
- peer terminal Transmission ID;
- peer Final Offset;
- peer terminal Error Code for RESET_STREAM;
- last receive-side Consumed Offset;
- last receive-side Maximum Offset.

An implementation MAY retain additional state.

## 16. Tombstone entry conditions

A rejected opening or pre-open cancellation can enter a lightweight opening tombstone without creating application Stream state. Such a tombstone retains the Stream ID, original open Transmission ID when known, the rejection/cancellation decision, and any terminal information needed to answer late duplicates.

For an accepted Stream, the Stream can leave active Stream state and enter TOMBSTONE only when:

1. its local sending direction has a final size and the local terminal Transmission has been acknowledged;
2. its receive direction has an established terminal state;
3. receive-side accounting has been fully released through the peer Final Offset;
4. for a normally FIN-terminated receive direction, the reliable STREAM_CONSUMED exchange has completed;
5. no locally pending reliable Transmission still requires full Stream state.

RESET_STREAM acknowledgement itself can settle sender-side data credit associated with the reset final size; an additional STREAM_CONSUMED is not required for the reset receive direction.

## 17. Tombstone Frame handling

While a tombstone is retained:

- duplicate STREAM_OPEN with the original open Transmission ID SHOULD receive the original OPEN_OK or OPEN_REJECT decision;
- duplicate STREAM_FIN or RESET_STREAM matching the recorded terminal state is acknowledged again;
- STREAM_DATA wholly within the recorded peer Final Offset has no application effect and MAY be acknowledged as stale traffic;
- STREAM_DATA extending beyond the recorded peer Final Offset is FINAL_SIZE_ERROR;
- STREAM_CREDIT is validated against the recorded local Final Offset and otherwise ignored;
- duplicate STREAM_CONSUMED matching the recorded local Final Offset is acknowledged again;
- a Frame that attempts to reopen or semantically alter the retired Stream is STREAM_STATE_ERROR, FINAL_SIZE_ERROR, or TRANSMISSION_ID_ERROR as appropriate.

## 18. Retired Stream identities

After all conditions in Section 16 are satisfied and the implementation no longer needs detailed tombstone information, it MAY compact a tombstone into a **retired identity**.

A retired identity records at least that the Stream ID has been used and MUST NOT be reused.

An implementation MAY represent retired identities as ranges, bitmaps, generation structures, or other compact data. Tombstones and retired identities do not count toward the peer's MAX_STREAMS active-Stream limit.

Frames received for a retired identity:

- MUST NOT recreate an application Stream;
- MUST NOT increase Stream or Session credit commitment;
- MUST NOT deliver application data;
- MAY be silently ignored when the detailed state required for a safe response has been compacted.

The endpoint MUST retain enough information for the Session lifetime to prevent a retired Stream ID from becoming a new Stream again.

## 19. Unknown Stream IDs

Because Stream Frames can reorder across Carriers, a Stream ID lower than the largest observed Stream ID is not automatically invalid.

A receiver MUST distinguish:

- an ID that is known active;
- an ID with retained tombstone or retired state;
- an ID that is plausibly allocated but whose STREAM_OPEN may still be in flight;
- an impossible ID under the Stream-ID parity or allocation rules.

Only STREAM_OPEN and the pre-open cancellation Frames defined in Section 7 can create protocol state for a previously unseen plausible Stream ID.

Other Frames for an unseen plausible ID are STREAM_STATE_ERROR.

Frames for an impossible Stream ID are STREAM_STATE_ERROR.

## 20. SESSION_CLOSE interaction

After SESSION_CLOSE is received:

- new STREAM_OPEN is not accepted;
- new Carrier JOIN is not accepted;
- application delivery MAY finish for plaintext already authenticated before closure according to local shutdown policy;
- no new application DATA Transmission is created;
- existing Carrier transports are closed.

A repeated SESSION_CLOSE is idempotent.

A CARRIER_CLOSE received on one Carrier does not change Stream state and does not close other Carriers.

## 21. State error precedence

When a Frame violates more than one rule, an implementation SHOULD report the most specific deterministic error available in this order:

1. FRAME_ENCODING_ERROR for malformed encoding;
2. TRANSMISSION_ID_ERROR for impossible or conflicting Transmission identity;
3. FINAL_SIZE_ERROR for final-size contradiction;
4. FLOW_CONTROL_ERROR for exceeded credit;
5. STREAM_STATE_ERROR for lifecycle impossibility;
6. PROTOCOL_VIOLATION for other semantic violations.

Error selection does not change whether the failure is Carrier-scoped or Session-scoped.

## 22. Conformance requirements

A conforming Draft 03 implementation MUST:

- tolerate cross-Carrier reordering permitted by this document;
- support acceptance evidence arriving before STREAM_OPEN_OK;
- support valid pre-open cancellation;
- process reliable duplicates idempotently;
- preserve one immutable final size per receive direction;
- distinguish Transmission from Attempt;
- retain enough terminal state to prevent Stream-ID reuse;
- never recreate application state for a tombstoned or retired Stream ID;
- allow late data below a FIN final size to fill earlier holes;
- never deliver post-reset duplicate data to the application;
- distinguish stale settled acknowledgements from never-allocated Transmission IDs.
