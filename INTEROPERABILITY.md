# MPX/4 Interoperability Profile

**Document:** MPX/4 Interoperability Profile  
**Revision:** Draft 08
**Protocol Version:** 4  
**Status:** Working Interoperability Profile

This document defines a common interoperability test profile for independent MPX/4 implementations.

It does not require a specific implementation language, operating system, API shape, or scheduler algorithm.

## 1. Interoperability target

Two implementations satisfy the Draft 08 Core interoperability profile when they can complete all Mandatory test groups in this document using the MPX/4 Core Protocol, Draft 08 state rules, version-compatibility rules, error-scope rules, and the TCP binding.

The test endpoints are called Implementation A and Implementation B.

Unless a test states otherwise:

- A acts as Client;
- B acts as Server;
- the transport binding is TCP;
- MAX_FRAME_PAYLOAD is 32768;
- MAX_RECORD_SIZE is 65536;
- MAX_STREAMS is at least 32;
- both endpoints advertise MAX_CARRIERS of at least 4 unless a test specifies another value.

Tests SHOULD also be repeated with implementations swapped when both products support both endpoint roles.

## 2. Result classes

Each test produces one result:

- **PASS** — observed wire and endpoint behavior conforms.
- **FAIL** — behavior violates a normative requirement.
- **NOT APPLICABLE** — only for explicitly Optional test groups.
- **INCONCLUSIVE** — test environment failed before protocol behavior could be evaluated.

A Core interoperability claim MUST NOT treat an INCONCLUSIVE Mandatory test as PASS.

## 3. Required evidence

An interoperability run SHOULD retain:

- Protocol Version;
- specification revision;
- implementation names and versions;
- endpoint roles;
- negotiated Parameters;
- Carrier IDs and Generations;
- decoded Frame trace;
- error code and scope for negative tests;
- test result.

Secret transport keys and derived traffic secrets SHOULD NOT be retained in ordinary test logs.

## 4. Group A — Codec and framing

**Mandatory.**

### A1. Canonical VarInt

Both implementations reproduce all valid values in test-vectors/varint.json and reject every invalid vector.

### A2. Frame encoding

Both implementations reproduce test-vectors/frame-encoding.json.

### A3. TCP fragmentation

The receiver correctly parses the TCP-binding fragmentation cases in test-vectors/tcp-binding.json.

### A4. TCP coalescing

The receiver correctly parses multiple protocol units delivered in one TCP read.

### A5. Mid-record EOF

A TCP EOF in the middle of a Secure Record produces no Frame and terminates only that Carrier.

## 5. Group B — Handshake and cryptography

**Mandatory.**

### B1. CREATE handshake

A creates a Session and the first Carrier reaches ESTABLISHED on both endpoints.

### B2. Key schedule

Both implementations reproduce test-vectors/key-schedule.json.

### B3. Secure Record

Both implementations reproduce test-vectors/secure-record.json.

### B4. Wrong transport key

With different transport keys configured, the Carrier does not become authenticated Session state.

### B5. Non-canonical Parameter encoding

A malformed or non-canonical handshake encoding is rejected.

### B6. Duplicate Parameter

A duplicate Core Parameter is rejected.

### B7. Out-of-order Parameter

Core Parameters not in strictly increasing type order are rejected.

### B8. MAX_CARRIERS negotiation

A advertises MAX_CARRIERS=96 and B advertises MAX_CARRIERS=128. Both endpoints establish Effective Carrier Limit 96.

### B9. MAX_CARRIERS criticality

MAX_CARRIERS is encoded with CRITICAL=1. A peer sending the known MAX_CARRIERS Parameter with CRITICAL=0 is rejected with PROTOCOL_VIOLATION.

### B10. Missing MAX_CARRIERS

CREATE without MAX_CARRIERS in CLIENT_INIT or SERVER_INIT is rejected.

### B11. JOIN consistency

On JOIN, both endpoints repeat their original CREATE-time MAX_CARRIERS values. Changing either advertisement produces SESSION_CONFLICT and leaves the established Session unchanged.

### B12. Session Protocol Version

Both implementations reproduce the relevant cases in test-vectors/version-compatibility.json.

A Session created under Protocol Version 4 accepts only JOIN and replacement Carriers using Protocol Version 4. A candidate using another locally supported Protocol Version is rejected with SESSION_CONFLICT and the Session remains unchanged.

### B13. VERSION_NEGOTIATION downgrade safety

VERSION_NEGOTIATION is accepted only before CLIENT_INIT. A retry uses a fresh underlying connection and does not enable a locally disabled or below-minimum Protocol Version. Authentication failure is not interpreted as permission to retry with a lower version.

### B14. HANDSHAKE_REJECT encoding and scope

Both implementations reproduce test-vectors/handshake-reject.json. A candidate JOIN rejected with SESSION_NOT_FOUND, SESSION_CONFLICT, CARRIER_CONFLICT, or RESOURCE_LIMIT receives HANDSHAKE_REJECT with the classified Error Code when the failure is safely reportable before SERVER_FINISHED. The candidate transport then closes.

Receipt of HANDSHAKE_REJECT does not authenticate the sender, modify an existing Session, advance Carrier Generation, or trigger Protocol Version downgrade.

### B15. HANDSHAKE_REJECT is outside successful transcript

A successful Draft 08 CREATE reproduces the same CLIENT_INIT, SERVER_INIT, Finished, traffic-secret, key, IV, and Secure Record vector bytes as Draft 07. HANDSHAKE_REJECT appears only on a failed candidate and is never included in H0, H1, or H2 of a successful handshake.

### B16. CREATE Session-ID collision

A CREATE using a SESSION_ID already mapped to CREATING, ACTIVE, DORMANT, or CLOSING state, or to retained CLOSED retirement state, is rejected with SESSION_CONFLICT. The existing or retired Session is not overwritten, merged, reopened, or treated as the target of a JOIN.

## 6. Group C — Single-Carrier Stream

**Mandatory.**

### C1. Stream open

Client opens Stream 1 and receives STREAM_OPEN_OK.

### C2. Bidirectional credit

Both directions explicitly advertise Stream credit before peer application DATA is sent.

### C3. Client-to-Server data

At least 1 MiB is transferred without byte corruption, duplication, or reordering at the application interface.

### C4. Server-to-Client data

At least 1 MiB is transferred in the reverse direction.

### C5. Full duplex

Both directions transfer concurrently on one Stream.

### C6. Multiple Streams

At least 16 simultaneously active Streams carry independent data correctly.

### C7. Stream-ID exhaustion

The Client can allocate Stream ID 2^62 - 1 as the final odd Stream ID. A subsequent local Stream-open request does not wrap to 1 and does not reuse any retired Stream ID. Existing Streams and Session state may continue.

## 7. Group D — Multi-Carrier Session

**Mandatory.**

### D1. Carrier JOIN

A second Carrier joins the existing Session using a distinct Carrier ID and fresh handshake.

### D2. Shared Stream state

One Stream carries valid transmissions over both Carriers while preserving one application byte stream.

### D3. Cross-Carrier Frame ordering

A test intentionally delays one Carrier so that protocol Frames arrive in a different cross-Carrier order from send order.

Behavior follows STATE-MACHINES.md.

### D4. Carrier-specific record spaces

Each Carrier begins application Secure Record sequence numbering at zero under independently derived traffic keys.

### D5. Carrier ID space is independent of concurrency

With Effective Carrier Limit at least 2, the Session establishes two logical Carriers using IDs 1 and 96. Carrier ID 96 is accepted even though the Session contains only two active logical Carriers.

### D6. Effective Carrier Limit enforcement

A and B negotiate Effective Carrier Limit 2. After two distinct logical Carriers are active, a JOIN for a third previously unused Carrier ID is rejected with RESOURCE_LIMIT and the existing two-Carriers Session remains usable.

### D7. Slot release

With Effective Carrier Limit 2, one active Carrier closes or is declared lost. A new previously unused Carrier ID can then establish, returning the Active Carrier Count to 2.

### D8. Active replacement does not consume an additional slot

With Active Carrier Count equal to Effective Carrier Limit, a higher Generation for one already active Carrier ID can replace that current incarnation without requiring an additional Carrier slot. The Active Carrier Count remains unchanged.

### D9. Inactive replacement requires a free slot

A Carrier is lost and releases its active slot. Another previously unused Carrier ID consumes the freed capacity. A later replacement of the lost Carrier ID is rejected with RESOURCE_LIMIT until capacity becomes available again.

### D10. Historical Carrier IDs do not consume active capacity

A closed or lost Carrier retains Highest Accepted Generation and cannot be reused with the same Generation, but its historical identity does not count toward the Active Carrier Count.

## 8. Group E — Reliability and reinjection

**Mandatory.**

### E1. Same Transmission ID

A reliable STREAM_DATA Transmission is reinjected on a second Carrier with the same Transmission ID and identical semantic contents.

### E2. Duplicate delivery suppression

Both Attempts arrive. The application receives the Stream bytes exactly once.

### E3. Duplicate acknowledgement

The receiver can repeat TRANSMISSION_ACK for the duplicate Transmission without changing application state.

### E4. Conflicting Transmission reuse

A test peer reuses one Transmission ID with different semantic contents.

The receiving Session fails with TRANSMISSION_ID_ERROR.

### E5. Never-allocated ACK

A peer sends TRANSMISSION_ACK for a Transmission ID that the local endpoint has never allocated.

The Session fails with TRANSMISSION_ID_ERROR.

### E6. Transmission-ID exhaustion

Transmission ID 2^62 - 1 can be allocated once as the final reliable Transmission ID. A subsequent need for a new reliable Transmission does not wrap or reuse an ID; the endpoint transitions the Session to CLOSING and sends SESSION_CLOSE(RESOURCE_LIMIT) when possible. Existing outstanding Transmissions may still be settled before shutdown.

## 9. Group F — Flow control

**Mandatory.**

### F1. No implicit Stream credit

Application DATA is not sent before explicit Stream credit.

### F2. Stream boundary

A sender can transmit through exactly Maximum Offset and does not commit bytes beyond it.

### F3. Session boundary

Aggregate committed bytes across Streams do not exceed Maximum Bytes.

### F4. Reinjection accounting

Reinjecting already committed bytes consumes no additional Stream or Session credit.

### F5. Credit monotonicity

A decreasing STREAM_CREDIT or SESSION_CREDIT is rejected.

### F6. CREDIT_PROBE

A Stream-scoped CREDIT_PROBE produces current Stream and Session credit advertisement when state remains available.

## 10. Group G — Stream terminal behavior

**Mandatory.**

### G1. FIN with late hole fill

STREAM_FIN arrives before earlier DATA from another Carrier. Later DATA below Final Offset fills the hole successfully.

### G2. DATA beyond final size

DATA extending beyond established Final Offset fails with FINAL_SIZE_ERROR.

### G3. RESET with late duplicate DATA

Late DATA within reset Final Offset is not delivered to the application.

### G4. FIN then RESET

RESET_STREAM with the same Final Offset supersedes graceful FIN semantics.

### G5. RESET then FIN

A later FIN with the same Final Offset does not restore graceful EOF semantics.

### G6. STREAM_CONSUMED

Normal receive-side FIN completion produces the required reliable STREAM_CONSUMED behavior.

## 11. Group H — Opening reordering and cancellation

**Mandatory.**

### H1. Credit overtakes OPEN_OK

STREAM_CREDIT arrives on another Carrier before STREAM_OPEN_OK.

The Client treats it as acceptance evidence and does not fail the Session.

### H2. DATA before OPEN_OK

Without previously available receive credit, STREAM_DATA arriving while the Client is still OPENING is rejected with STREAM_STATE_ERROR.

### H3. Pre-open RESET

RESET_STREAM with Final Offset 0 arrives before STREAM_OPEN.

The Server records cancellation, acknowledges RESET_STREAM, and rejects the later STREAM_OPEN.

### H4. Pre-open STOP_SENDING

STOP_SENDING arrives before STREAM_OPEN.

The Server acknowledges it, sends RESET_STREAM with Final Offset 0, and rejects the later STREAM_OPEN.

## 12. Group I — Tombstones and retired identities

**Mandatory.**

### I1. Duplicate terminal Frame

After active Stream state is retired into a tombstone, a matching duplicate terminal Frame is processed idempotently.

### I2. Conflicting final size

A terminal duplicate carrying a different Final Offset fails with FINAL_SIZE_ERROR.

### I3. Retired Stream ID

After tombstone compaction, stale Frames for the retired Stream ID do not recreate application Stream state.

### I4. Stream-ID reuse

Attempting to open an already used Stream ID never creates a new Stream.

### I5. Active Stream limit

Tombstones and retired identities do not count as active Streams for MAX_STREAMS.

## 13. Group J — Carrier loss and replacement

**Mandatory.**

### J1. Unexpected Carrier loss

One of two active TCP Carriers is terminated without CARRIER_CLOSE.

The Session and active Streams remain usable over the other Carrier.

### J2. Outstanding Transmission

A reliable Transmission attempted on the failed Carrier remains unsettled and can be retransmitted or reinjected.

### J3. Replacement Generation

The failed logical Carrier rejoins on a new TCP connection using a higher Generation.

### J4. Fresh cryptographic state

The replacement Carrier performs a complete handshake, derives fresh traffic keys and IVs, and begins Record Sequence Number 0 in each direction.

### J5. Failed candidate is non-mutating

A higher-Generation candidate that fails authentication or JOIN validation does not advance Highest Accepted Generation and does not supersede the current Carrier.

### J6. Stale Generation

A lower Carrier Generation is rejected with CARRIER_CONFLICT.

### J7. Equal Generation is never reusable

An equal Generation is rejected with CARRIER_CONFLICT even after the previously accepted transport for that Generation has been lost or closed.

### J8. First incarnation uses Generation 0

An unused Carrier ID accepts Generation 0 as its first incarnation and rejects a non-zero first Generation with CARRIER_CONFLICT.

### J9. Atomic supersession

After a higher Generation reaches ESTABLISHED, lower Generations of that Carrier ID become superseded. New Attempts and path-measurement samples are not assigned to the superseded incarnation, and Secure Records received from it after the Generation commit do not create new protocol state.

### J10. Session-state preservation

Replacement preserves Stream state, flow-control state, tombstones, retired Stream IDs, and the Session-wide Transmission-ID namespace. Reinjection over the replacement Carrier retains the original Transmission ID.

### J11. Simultaneous candidates

Two concurrent candidates using the same higher Generation cannot both become accepted incarnations. A later still-higher authenticated Generation can supersede a newly accepted lower Generation.

### J12. Last-Carrier loss enters DORMANT

Both implementations reproduce the relevant cases in test-vectors/session-lifecycle.json.

A Session with one active Carrier and retained Session state loses that Carrier without SESSION_CLOSE. Active Carrier Count becomes zero and the endpoint enters DORMANT rather than destroying Stream, flow-control, Generation, or reliable Transmission state.

### J13. No new work while DORMANT

While DORMANT, the endpoint creates no new Stream and no new application DATA Transmission. Outstanding reliable Transmissions remain retained but no Attempt is sent because no Carrier is eligible.

### J14. DORMANT recovery

A valid JOIN or higher-Generation replacement reaches ESTABLISHED for a DORMANT Session. The endpoint transitions to ACTIVE and can retransmit or reinject previously outstanding Transmissions using their existing Transmission IDs and existing logical flow-control commitment.

### J15. DORMANT retirement

An endpoint discards a DORMANT Session according to local retention policy. A later JOIN for that Session is rejected as SESSION_NOT_FOUND. No negotiated minimum DORMANT retention time is assumed.

## 14. Group K — Close behavior

**Mandatory.**

### K1. CARRIER_CLOSE

One Carrier closes gracefully without terminating the Session or Streams.

### K2. Bare TCP EOF

A TCP EOF without authenticated CARRIER_CLOSE is treated as Carrier loss, not graceful MPX Session closure.

### K3. SESSION_CLOSE

A valid SESSION_CLOSE prevents new Streams and new Carrier JOINs.

### K4. Duplicate SESSION_CLOSE

A repeated SESSION_CLOSE is idempotent.

### K5. TCP half-close

TCP half-close is not interpreted as STREAM_FIN, RESET_STREAM, CARRIER_CLOSE, or SESSION_CLOSE.

## 15. Group L — Negative protocol tests

**Mandatory.**

At minimum, the receiver is tested with:

- malformed VarInt;
- Frame Length exceeding available record plaintext;
- unknown Core Frame;
- invalid Stream-ID parity;
- DATA exceeding Stream credit;
- DATA exceeding Session credit;
- conflicting overlapping DATA bytes;
- contradictory Final Offset;
- conflicting Transmission-ID reuse;
- Stream lifecycle violation.

The endpoint returns or internally records the error class required by the specification and applies the failure scope required by ERROR-HANDLING.md.

The Mandatory negative suite also verifies:

- STREAM_LIMIT on STREAM_OPEN produces STREAM_OPEN_REJECT and does not close the Session;
- a rejected JOIN with CARRIER_CONFLICT does not advance Generation or modify the existing Session and uses HANDSHAKE_REJECT(CARRIER_CONFLICT) when safely reportable;
- a colliding CREATE uses SESSION_CONFLICT and does not overwrite retained Session identity state;
- received HANDSHAKE_REJECT never triggers Protocol Version downgrade or existing-Session mutation;
- Secure Record authentication failure terminates only the affected Carrier;
- FRAME_ENCODING_ERROR terminates only the affected Carrier when the error is safely reportable after establishment;
- FLOW_CONTROL_ERROR produces Session-scoped shutdown;
- FINAL_SIZE_ERROR produces Session-scoped shutdown;
- TRANSMISSION_ID_ERROR produces Session-scoped shutdown;
- Session-scoped shutdown blocks new Streams and new Carrier JOINs across every Carrier;
- Trigger Frame Type identifies the offending decoded Frame when one is known.

## 16. Group M — Local Carrier-selection independence

**Recommended.**

Core interoperability does not require two implementations to expose, negotiate, or select the same scheduling mode.

When test harnesses permit local Carrier-choice control, implementations SHOULD verify that:

- A can prefer one eligible Carrier for its outbound Attempts while B independently prefers another;
- neither endpoint requires a peer scheduler identifier;
- a closing, superseded, or locally unusable Carrier is not selected for a new Attempt;
- retransmission or reinjection preserves the Transmission ID;
- local policy changes do not alter Stream identity or flow-control accounting;
- Carrier loss does not corrupt Stream semantics.

Published metadata extensions, including the Carrier Receive Capacity Hint extension, are tested separately from the Core interoperability claim.

## 17. Group N — Resource behavior

**Recommended.**

Implementations SHOULD be tested under:

- MAX_STREAMS saturation;
- maximum permitted Stream credit window;
- maximum permitted Session credit window;
- maximum Secure Record size;
- many terminal tombstones;
- repeated failed handshakes;
- slow or blocked Carrier writes.

Resource pressure must not create wire behavior that violates the Core protocol.

## 18. Minimum Core interoperability report

A published interoperability report SHOULD contain:

    Protocol: MPX/4
    Protocol Version: 4
    Revision: Draft 08
    Binding: TCP
    Implementation A: <name/version>
    Implementation B: <name/version>

    A Codec and framing: PASS
    B Handshake and cryptography: PASS
    C Single-Carrier Stream: PASS
    D Multi-Carrier Session: PASS
    E Reliability and reinjection: PASS
    F Flow control: PASS
    G Terminal behavior: PASS
    H Opening reordering: PASS
    I Tombstones: PASS
    J Carrier replacement: PASS
    K Close behavior: PASS
    L Negative protocol tests: PASS

Optional groups are reported separately.

## 19. Compatibility

Draft 08 keeps development Protocol Version 4 and preserves the successful Draft 07 Core handshake transcript, key schedule, Secure Record syntax, Frame encodings, and existing successful-path vectors.

Draft 08 adds Core Handshake Message Type 0x06 HANDSHAKE_REJECT for pre-establishment candidate rejection. The message is used only on failed candidate handshakes and is never included in a successful Finished transcript. A Draft 07 endpoint does not understand Message Type 0x06, so failed-candidate diagnostics are not interoperable across Draft 07/08 even though the successful Draft 08 baseline handshake bytes are unchanged.

Draft 08 also closes identifier-lifecycle semantics without changing identifier encodings: Transmission IDs and Stream IDs never wrap, and retained Session IDs cannot be reused by CREATE. Conflicting Transmission-ID reuse is consistently TRANSMISSION_ID_ERROR.

The normative long-term compatibility rules are defined in COMPATIBILITY.md. Draft 08 remains a development revision of Protocol Version 4 and does not yet declare Version 4 stable.
