# MPX/4 State Machines and Frame Validity

**Document:** MPX/4 State Machine Supplement  
**Revision:** Draft 11
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

Failure scope and the required CARRIER_CLOSE / SESSION_CLOSE action are defined normatively in [ERROR-HANDLING.md](ERROR-HANDLING.md).

When a violation changes or contradicts shared Stream state, the error is Session-scoped unless this document explicitly defines a narrower STREAM_OPEN_REJECT action.

## 3. Session state

An MPX Session has the following abstract lifecycle:

    CREATING
       |
       v
    ACTIVE <------------------+
       |                       |
       | last Carrier gone     | Carrier established
       v                       |
    DORMANT -------------------+
       |
       | retention ends or local Session teardown
       v
    CLOSED

ACTIVE and DORMANT can also transition to CLOSING when SESSION_CLOSE is sent/received or a Session-scoped protocol error occurs. CLOSING transitions to CLOSED.

### 3.1. CREATING

The Session exists provisionally while the first Carrier handshake is in progress.

Application Streams MUST NOT be created before the first Carrier reaches ESTABLISHED.

### 3.2. ACTIVE

At least one authenticated logical Carrier is ESTABLISHED and eligible for Session use.

New Streams may be created subject to limits.

### 3.3. DORMANT

DORMANT means the endpoint retains a valid Session while its Active Carrier Count is zero.

An endpoint enters DORMANT when the last active logical Carrier leaves ESTABLISHED without SESSION_CLOSE and the endpoint chooses to retain the Session for reconnection.

While DORMANT:

- Session Protocol Version remains unchanged;
- Stream IDs, opening state, terminal state, tombstones, and retired identities are retained;
- Stream and Session flow-control accounting is retained;
- Highest Accepted Generation for every used Carrier ID is retained;
- outstanding and settled reliable Transmission state is retained;
- no new Stream is created;
- no new application DATA Transmission is created;
- no new Transmission Attempt can be sent because no Carrier is eligible;
- JOIN and valid Carrier replacement candidates MAY be accepted subject to normal handshake, Generation, and Effective Carrier Limit rules.

When a Carrier reaches ESTABLISHED, the endpoint transitions DORMANT to ACTIVE before scheduling new Attempts. Outstanding reliable Transmissions then become eligible for normal retransmission or reinjection without changing their Transmission IDs or logical flow-control commitment.

DORMANT retention duration is local policy. Draft 11 provides no negotiated minimum retention time. An endpoint MAY discard a DORMANT Session and transition directly to CLOSED. A later JOIN for discarded state is handled as SESSION_NOT_FOUND.

The two endpoints may enter or leave DORMANT at different times because transport-loss detection and retention policy are local.

After DORMANT-to-ACTIVE recovery, current Session credit and any required probed Stream credit are eventually refreshed according to SPECIFICATION.md. A non-zero TRANSMISSION_RETIRE watermark that can release peer replay state is likewise eventually refreshed while an authenticated writable Carrier exists.

### 3.4. CLOSING

SESSION_CLOSE has been sent or received, or a Session-scoped protocol error has occurred.

No new Stream or Carrier may be created.

Existing protocol state MAY be processed only as required to complete local shutdown.

### 3.5. CLOSED

All Carrier transport state has been released.

A Session ID in CLOSED state MUST NOT be reused for a new Session while the implementation still retains retirement state for that Session ID. A received CREATE using such a retained Session ID is rejected as SESSION_CONFLICT and MUST NOT recreate or overwrite the retired Session.

Once all state for that Session ID has been discarded, a future random collision cannot be distinguished from a new identifier and is processed normally. Implementations MUST NOT intentionally recycle retained Session IDs.

## 4. Carrier state

Each Carrier has the following lifecycle:

    TRANSPORT_CONNECTED
            |
            v
       HANDSHAKING ------------------> CLOSED
            |                 reject / failure
            v
        ESTABLISHED
            |
            v
         CLOSING
            |
            v
          CLOSED

Only handshake messages are valid in HANDSHAKING. HANDSHAKE_REJECT is terminal for the candidate handshake: after sending or receiving it, the candidate transitions directly to CLOSED after transport teardown and MUST NOT enter ESTABLISHED.

Only Secure Records are valid after ESTABLISHED.

After a Carrier enters CLOSING, no new application or control Frames may be scheduled onto it except the already-generated CARRIER_CLOSE record.

Carrier failure does not by itself change Stream lifecycle state.

### 4.1. Logical Carrier generation state

In addition to the transport lifecycle above, a Session maintains Generation state per Carrier ID.

For each Carrier ID, the abstract state is:

    UNUSED
      |
      | accept Generation 0
      v
    CURRENT(G)
      |
      | authenticate and accept G' > G
      v
    CURRENT(G')

Every previously accepted lower Generation is then SUPERSEDED.

A candidate handshake is not a Carrier incarnation accepted by the Session until it reaches ESTABLISHED.

### 4.2. First incarnation

When a Carrier ID is UNUSED, only Generation 0 can become the first accepted incarnation.

A candidate for an UNUSED Carrier ID with Generation greater than zero is rejected with CARRIER_CONFLICT.

A failed candidate does not change UNUSED state.

### 4.3. Replacement candidate

Let G be the Highest Accepted Generation and let G' be the Generation in a JOIN candidate for the same Carrier ID.

Before the candidate reaches ESTABLISHED:

- G remains current;
- the current Carrier remains eligible subject to its own liveness state;
- the candidate MUST NOT receive Session application Frames;
- the candidate MUST NOT change Stream, credit, local Carrier-selection eligibility, or reliable Transmission state.

If authentication or JOIN validation fails, the candidate is discarded and G remains unchanged. When the failure is classifiable and a safe pre-SERVER_FINISHED response can be emitted, HANDSHAKE_REJECT SHOULD carry the applicable Error Code; receipt or transmission of that message does not itself modify Session or Generation state.

### 4.4. Generation comparison

A JOIN candidate is evaluated as follows:

| Candidate Generation | Result |
|---|---|
| G' < G | reject CARRIER_CONFLICT as stale |
| G' = G | reject CARRIER_CONFLICT as Carrier-incarnation reuse |
| G' > G | eligible replacement; commit only after full Carrier establishment |

Equal Generation is a conflict even when the previously accepted transport is already closed or lost. A Carrier incarnation tuple MUST NOT be reused.

### 4.5. Replacement commit

When a candidate with G' > G is otherwise ready to reach ESTABLISHED, the endpoint first evaluates the Active Carrier Count rule in Section 4.9. If committing the candidate would exceed the Effective Carrier Limit, the candidate is rejected with RESOURCE_LIMIT and the Generation advance does not occur.

Otherwise, the Generation advance is committed at that endpoint as one Session-state transition:

1. Highest Accepted Generation becomes G';
2. the new incarnation becomes CURRENT(G');
3. every lower Generation of that Carrier ID becomes SUPERSEDED;
4. the Active Carrier Count is updated according to Section 4.9;
5. no new Transmission Attempt may be scheduled on a superseded incarnation;
6. no new path-measurement sample may be attributed to a superseded incarnation;
7. subsequently received Secure Records from a superseded incarnation MUST NOT create new protocol state;
8. the transport of a superseded incarnation SHOULD be closed promptly.

Frames from a lower Generation that were completely authenticated and processed before the commit keep their already-applied effects.

### 4.6. Simultaneous candidates

More than one candidate for the same Carrier ID may be handshaking concurrently.

Candidates do not reserve a Generation merely by connecting or sending CLIENT_INIT.

Each candidate is compared against the Highest Accepted Generation at its own establishment commit point.

Therefore:

- if two candidates use the same Generation, at most one can be accepted;
- after one is accepted, the other equal candidate is CARRIER_CONFLICT;
- a later candidate with a still-higher Generation may supersede a newly accepted lower Generation after it independently completes authentication.

An implementation MUST NOT select a winner solely from unauthenticated transport arrival order.

### 4.7. Ambiguous candidate outcome

After sending CLIENT_FINISHED, the Client may lose the candidate transport before authenticating SERVER_FINISHED. The Client then treats establishment as ambiguous rather than as either accepted or rejected.

An unauthenticated HANDSHAKE_REJECT or transport close does not resolve this ambiguity. Recovery follows SPECIFICATION.md Section 9.3. In particular, an already accepted Carrier replacement advances above every ambiguity-causing attempted Generation retained locally, whereas an ambiguous first use of an UNUSED Carrier ID recovers through another UNUSED Carrier ID at Generation 0 unless authenticated evidence establishes the earlier acceptance.

### 4.8. Replacement invariants

Replacement MUST preserve Session identity and all Session-owned state, including:

- Stream IDs and Stream offsets;
- Stream opening and terminal state;
- Stream and Session flow-control accounting;
- allocated, outstanding, settled, and retired Transmission IDs;
- local Settled Through and peer Retired Through Transmission watermarks;
- tombstones and retired Stream identities.

The replacement Carrier has new handshake nonces, new traffic secrets, new traffic keys, new IVs, and new per-direction Record Sequence Number spaces beginning at zero.

Outstanding reliable Transmissions remain eligible for normal retransmission or reinjection and retain their Transmission IDs.

Generation values never wrap. If the Highest Accepted Generation is 2^62 - 1, that Carrier ID has no further valid replacement Generation in the Session.

### 4.9. Active logical Carrier count

Each endpoint maintains a local Active Carrier Count for the Session.

The Session also stores:

    Client Carrier Limit
    Server Carrier Limit
    Effective Carrier Limit = min(Client Carrier Limit, Server Carrier Limit)

All three values are established during CREATE and are immutable for the Session lifetime.

The Active Carrier Count is the number of distinct Carrier IDs whose current accepted incarnation is ESTABLISHED and eligible for Session use at that endpoint.

The count changes as follows:

| Event | Active Carrier Count change |
|---|---:|
| first Session Carrier reaches ESTABLISHED | +1 |
| candidate for a previously unused Carrier ID reaches ESTABLISHED | +1 |
| higher Generation replaces an already active Carrier ID | 0 |
| higher Generation reactivates an inactive Carrier ID | +1 |
| CARRIER_CLOSE moves current incarnation out of ESTABLISHED | -1; if count reaches 0, Session becomes DORMANT when retained |
| detected transport loss moves current incarnation out of ESTABLISHED | -1; if count reaches 0, Session becomes DORMANT when retained |
| SESSION_CLOSE closes Session Carriers | each active logical Carrier is removed; Session goes through CLOSING, not DORMANT |
| candidate handshake starts or fails | 0 |
| lower Generation becomes SUPERSEDED during active replacement | no additional decrement |
| historical Generation/tombstone state is retained | 0 |

A decrement occurs at most once for one active logical Carrier transition. Superseding an active old Generation at the same commit that activates its replacement is one logical replacement and therefore has net count change 0.

Before committing any candidate that would add one active logical Carrier, the endpoint evaluates:

    Active Carrier Count + 1 <= Effective Carrier Limit

If false, the candidate is rejected with RESOURCE_LIMIT. Highest Accepted Generation, Stream state, flow-control state, and all other established Session state remain unchanged.

A candidate for the same Carrier ID as an already active logical Carrier does not require an additional slot when a higher Generation is committed.

A Carrier ID whose current incarnation has already closed or been declared lost does not reserve an active slot. If another Carrier ID consumes the freed capacity before that logical Carrier is replaced, its later replacement can be rejected with RESOURCE_LIMIT until capacity becomes available again.

HANDSHAKING candidates do not count toward MAX_CARRIERS. Implementations MAY apply separate local limits to simultaneous handshakes or transport resources; those limits are implementation policy and do not change the Effective Carrier Limit.

Carrier ID magnitude is irrelevant to this state machine. For example, Carrier IDs 1 and 4000000000 represent two logical Carriers, not four billion Carriers.

### 4.10. MAX_CARRIERS consistency on JOIN

Every JOIN carries both endpoints' original Session-scoped MAX_CARRIERS advertisements through CLIENT_INIT and SERVER_INIT.

If an endpoint receives a MAX_CARRIERS value different from the value that peer advertised during CREATE, the candidate JOIN fails with SESSION_CONFLICT and MUST NOT modify the existing Session.

The Effective Carrier Limit is never renegotiated by JOIN or replacement.

A JOIN accepted while the Session is DORMANT transitions the Session back to ACTIVE only when the candidate Carrier reaches ESTABLISHED. A failed candidate leaves the Session DORMANT.

### 4.11. Session Protocol Version on JOIN

CREATE records the Protocol Version of the first established Carrier as the immutable Session Protocol Version.

Every JOIN or replacement candidate MUST use that same Protocol Version.

If the candidate Protocol Version is unsupported, normal VERSION_NEGOTIATION applies before Session attachment. If the endpoint supports the candidate version but it differs from the identified Session Protocol Version, the candidate is rejected with SESSION_CONFLICT and the Session state is unchanged.

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

While in ordinary OPENING, the Client MUST tolerate the following inbound Frames as **acceptance evidence**:

- STREAM_CREDIT;
- STREAM_FIN with Final Offset 0;
- RESET_STREAM with Final Offset 0, except when Section 7 classifies it as a response to local pre-open cancellation;
- STOP_SENDING.

Draft 11 has no implicit Stream data credit. Therefore STREAM_DATA cannot legally precede the first STREAM_OPEN_OK, because the Client has not yet advertised receive credit for the accepted Stream.

The Client processes valid acceptance-evidence Frames according to their normal semantics while remaining logically OPENING until STREAM_OPEN_OK is received.

After acceptance evidence has been observed in ordinary OPENING, a later STREAM_OPEN_REJECT for that Stream is a STREAM_STATE_ERROR.

An implementation MAY internally transition to an equivalent "OPENING_WITH_ACCEPTANCE_EVIDENCE" state.

A rejected opening is terminal. Once STREAM_OPEN_REJECT is processed, the Stream ID MUST NOT be reused. Duplicate STREAM_OPEN_REJECT carrying the same Stream ID, original open Transmission ID, and Error Code is idempotent. A conflicting rejection is STREAM_STATE_ERROR. An implementation MAY represent the rejected Stream as a tombstone containing the original open Transmission ID, the rejection decision, and Error Code.

The Server MUST NOT send an acceptance-evidence Frame before it has accepted the Stream. The RESET_STREAM response explicitly permitted by Section 7.2 before STREAM_OPEN is a cancellation response and is not acceptance evidence.

## 7. Pre-open cancellation

A Client can locally cancel a Stream while its STREAM_OPEN is still in flight. The Client then enters a logical **OPENING_CANCEL_PENDING** state for that Stream ID. The implementation MAY use another internal name, but the externally visible behavior below is required.

A RESET_STREAM or STOP_SENDING sent as part of that cancellation can arrive at the Server before STREAM_OPEN.

### 7.1. RESET_STREAM before STREAM_OPEN

RESET_STREAM is valid before STREAM_OPEN only when Final Offset is 0.

The Server:

1. records a cancellation tombstone for the Stream ID;
2. acknowledges the RESET_STREAM;
3. MUST NOT later create an application Stream if STREAM_OPEN for the same Stream ID arrives.

A later STREAM_OPEN for that ID is answered with STREAM_OPEN_REJECT using STREAM_STATE_ERROR. For a Client in OPENING_CANCEL_PENDING, that matching rejection completes the cancelled opening and is not a Session error.

A pre-open RESET_STREAM with non-zero Final Offset is a STREAM_STATE_ERROR because application data could not legally have been committed before Stream acceptance.

### 7.2. STOP_SENDING before STREAM_OPEN

STOP_SENDING MAY arrive before STREAM_OPEN.

The Server records the receive-direction cancellation for that Stream ID, acknowledges the STOP_SENDING, and sends RESET_STREAM with Final Offset 0 for its not-yet-started sending direction unless an equivalent RESET_STREAM is already pending. This RESET_STREAM is a **pre-open cancellation response**; it is explicitly permitted before Stream acceptance and does not prove that the Stream was accepted.

A Client in OPENING_CANCEL_PENDING that has an outstanding pre-open STOP_SENDING treats a matching RESET_STREAM with Final Offset 0 as cancellation response rather than acceptance evidence.

If STREAM_OPEN later arrives at the Server without having been accepted earlier, the Stream MUST NOT become an application Stream. The Server MUST answer with STREAM_OPEN_REJECT using STREAM_STATE_ERROR. The cancelling Client treats this matching rejection as normal cancellation completion.

If the Server had already accepted STREAM_OPEN before processing the cancellation, STREAM_OPEN_OK or another unambiguous acceptance-evidence Frame remains authoritative when it arrives. The Stream is then treated as accepted and immediately subject to the already requested cancellation/terminal semantics; a later STREAM_OPEN_REJECT is not permitted for that accepted Stream.

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

If STOP_SENDING is received while FIN is pending, the sender MUST create a new RESET_STREAM Transmission with the same Final Offset and the STOP_SENDING Stream Error Code. The RESET_STREAM supersedes the FIN only for application-visible termination. The original FIN remains an outstanding reliable Transmission until its required TRANSMISSION_ACK is received. The sender MUST continue retransmission or reinjection Attempts of that same FIN Transmission as needed while an eligible Carrier exists, retaining the original Transmission ID and Frame contents.

If the peer has already processed the RESET_STREAM, a later STREAM_FIN with the same Final Offset is acknowledged normally but MUST NOT replace reset semantics with graceful EOF. The FIN acknowledgement settles only the FIN Transmission and MUST NOT settle or cancel the RESET_STREAM Transmission.

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
| STOP_SENDING | A; send RESET_STREAM using the STOP_SENDING Stream Error Code | A; send RESET_STREAM with the same Final Offset and make reset semantics authoritative | D; repeat pending RESET_STREAM as needed | D |
| STREAM_CONSUMED | E before a final size is established | A only if Final Offset equals local final size | A only if Final Offset equals local final size | D if Final Offset matches |
| TRANSMISSION_ACK | settle referenced pending Tx | settle referenced pending Tx | settle referenced pending Tx | ignore duplicate settled ACK |

A STREAM_CONSUMED Final Offset that differs from the local established final size is FINAL_SIZE_ERROR.

## 12. TRANSMISSION_ACK validity

Transmission IDs are Session-wide and allocated consecutively beginning at 1 without gaps, reuse, or wrap.

On receiving TRANSMISSION_ACK:

1. resolve the referenced local Transmission ID and its original Frame type;
2. if that Frame type does not use TRANSMISSION_ACK as its required confirmation, including STREAM_OPEN, the Session fails with TRANSMISSION_ID_ERROR;
3. the Stream ID carried by TRANSMISSION_ACK MUST match the Stream ID of the referenced Transmission, otherwise the Session fails with TRANSMISSION_ID_ERROR;
4. if the Transmission is outstanding, the acknowledgement settles it;
5. if it was previously settled, the acknowledgement is a harmless duplicate and is ignored;
6. if the Transmission ID is greater than or equal to the next ID the local endpoint has not yet allocated, it is TRANSMISSION_ID_ERROR;
7. if implementation state has safely compacted an older settled Transmission while retaining enough confirmation-class metadata to recognize stale ACKs, the acknowledgement is treated as a stale duplicate.

On receiving STREAM_OPEN_OK or STREAM_OPEN_REJECT, the referenced Transmission ID MUST identify a local STREAM_OPEN for the same Stream ID. A reference to another Frame type, another Stream, or a never-allocated Transmission ID is TRANSMISSION_ID_ERROR. A duplicate matching the already-recorded opening decision is idempotent; a conflicting opening decision is STREAM_STATE_ERROR.

### 12.1. Transmission-ID exhaustion

Transmission ID 2^62 - 1 is the final allocatable reliable Transmission ID in a Session. Allocation never wraps to 1 and no earlier ID becomes reusable.

After that ID is allocated, the endpoint may still settle, retransmit, reinject, or receive acknowledgements for existing Transmissions. It MUST NOT create a new reliable Transmission. If protocol or application progress requires a new reliable Transmission, the endpoint transitions the Session to CLOSING and SHOULD send SESSION_CLOSE with RESOURCE_LIMIT when an authenticated writable Carrier exists.

### 12.2. Transmission retirement watermarks

Each endpoint tracks:

- local Settled Through: the largest contiguous prefix of its own reliable Transmission IDs that are settled;
- peer Retired Through: the largest valid TRANSMISSION_RETIRE value received from the peer.

Local Settled Through advances only when every locally allocated Transmission ID up to the new value is settled. An advance above the last advertised value creates a pending Session-state advertisement that MUST eventually be emitted as TRANSMISSION_RETIRE while an authenticated writable Carrier exists. Peer Retired Through is monotonic and stale/lower advertisements are ignored. A peer retirement value that exceeds the largest contiguous peer Transmission ID already processed is TRANSMISSION_ID_ERROR.

For a peer reliable Transmission ID greater than peer Retired Through, enough response state MUST remain to reproduce the required confirmation on a duplicate Attempt. For an ID less than or equal to peer Retired Through, a later duplicate has no protocol or application effect and need not be confirmed again.

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
- local terminal Stream Error Code for RESET_STREAM;
- peer terminal kind;
- peer terminal Transmission ID;
- peer Final Offset;
- peer terminal Stream Error Code for RESET_STREAM;
- last receive-side Consumed Offset;
- last receive-side Maximum Offset;
- exact accepted Stream bytes or equivalent overlap-comparison evidence for any range that still remains subject to the Section 15.1 byte-identity rule.

An implementation MAY retain additional state. Flow-control release and application-buffer release do not by themselves release overlap-comparison evidence.

## 16. Tombstone entry conditions

A rejected opening or pre-open cancellation can enter a lightweight opening tombstone without creating application Stream state. Such a tombstone retains the Stream ID, original open Transmission ID when known, the rejection/cancellation decision, and any terminal information needed to answer late duplicates.

For an accepted Stream, the Stream can leave active Stream state and enter TOMBSTONE only when:

1. its local sending direction has a final size and the local terminal Transmission has been acknowledged;
2. its receive direction has an established terminal state;
3. receive-side accounting has been fully released through the peer Final Offset;
4. for a normally FIN-terminated receive direction, the reliable STREAM_CONSUMED exchange has completed;
5. no locally pending reliable Transmission still requires full Stream state;
6. every peer-originated reliable Transmission whose duplicate would require a Stream-specific confirmation is covered by peer Retired Through, or equivalent confirmation-replay state remains retained outside the Stream tombstone.

RESET_STREAM acknowledgement itself can settle sender-side data credit associated with the reset final size; an additional STREAM_CONSUMED is not required for the reset receive direction.

## 17. Tombstone Frame handling

While a tombstone is retained:

- duplicate STREAM_OPEN with the original open Transmission ID SHOULD receive the original OPEN_OK or OPEN_REJECT decision;
- duplicate STREAM_FIN or RESET_STREAM matching the recorded terminal state is acknowledged again;
- STREAM_DATA wholly within the recorded peer Final Offset has no application effect and MAY be acknowledged as stale traffic; if that traffic still falls under the Core overlap-comparison obligation, retained exact bytes or equivalent evidence MUST reject conflicting octets rather than silently accepting them;
- STREAM_DATA extending beyond the recorded peer Final Offset is FINAL_SIZE_ERROR;
- STREAM_CREDIT is validated against the recorded local Final Offset and otherwise ignored;
- duplicate STREAM_CONSUMED matching the recorded local Final Offset is acknowledged again;
- a Frame that attempts to reopen or semantically alter the retired Stream is STREAM_STATE_ERROR, FINAL_SIZE_ERROR, or TRANSMISSION_ID_ERROR as appropriate.

## 18. Retired Stream identities

After all conditions in Section 16 are satisfied, and every peer reliable Transmission that would require a Stream-specific confirmation has either been covered by peer Retired Through or has equivalent confirmation-replay state retained elsewhere, the implementation MAY compact a tombstone into a **retired identity**.

A retired identity records at least that the Stream ID has been used and MUST NOT be reused.

An implementation MAY represent retired identities as ranges, bitmaps, generation structures, or other compact data. Tombstones and retired identities do not count toward the peer's MAX_STREAMS active-Stream limit.

Frames received for a retired identity:

- MUST NOT recreate an application Stream;
- MUST NOT increase Stream or Session credit commitment;
- MUST NOT deliver application data;
- MAY be silently ignored only when any reliable Transmission carried by that Frame is already covered by peer Retired Through; otherwise the endpoint MUST retain or recover enough confirmation-replay state to send the required confirmation again.

The endpoint MUST retain enough information for the Session lifetime to prevent a retired Stream ID from becoming a new Stream again.

### 18.1. Stream-ID exhaustion

For the Draft 11 Client-initiated Stream space, 2^62 - 1 is the final allocatable odd Stream ID. Stream allocation never wraps and retired or closed Stream IDs never become reusable.

After the Client allocates Stream ID 2^62 - 1, no additional Stream can be created in that Session. Existing Streams and Session state remain valid. A later local request to create a Stream is rejected locally unless the implementation chooses to close the Session with RESOURCE_LIMIT.

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

A conforming Draft 11 implementation MUST:

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
- distinguish stale settled acknowledgements from never-allocated Transmission IDs;
- retain Highest Accepted Generation for every used Carrier ID;
- reject equal-Generation reuse even after transport loss;
- commit higher Generation only after candidate Carrier establishment;
- prevent superseded Carriers from receiving new Attempts or creating new protocol state;
- preserve Session-owned state across Carrier replacement;
- apply the Error Code failure scopes defined in ERROR-HANDLING.md;
- negotiate and retain the Effective Carrier Limit from MAX_CARRIERS;
- count active logical Carriers by distinct current Carrier ID rather than numeric ID magnitude or transport-connection count;
- reject a candidate with RESOURCE_LIMIT when committing it would exceed the Effective Carrier Limit;
- release active Carrier capacity when a current Carrier closes or is declared lost without making its Carrier ID reusable as a new identity;
- represent retained zero-Carrier Session state as DORMANT;
- prohibit new Stream creation and new DATA commitment while DORMANT;
- preserve reliable Transmission and flow-control state across DORMANT-to-ACTIVE recovery;
- enforce immutable Session Protocol Version across JOIN and replacement.
