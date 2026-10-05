# MPX/4 Interoperability Profile

**Document:** MPX/4 Interoperability Profile  
**Revision:** Draft 11
**Protocol Version:** 4  
**Status:** Working Interoperability Profile

This document defines a common interoperability test profile for independent MPX/4 implementations.

It does not require a specific implementation language, operating system, API shape, or scheduler algorithm.

## 1. Interoperability target

Two implementations satisfy the Draft 11 Core interoperability profile when they can complete all Mandatory test groups in this document using the MPX/4 Core Protocol, Draft 11 state rules, version-compatibility rules, error-scope rules, and the TCP binding.

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

On JOIN, both endpoints repeat their original CREATE-time MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, MAX_STREAMS, and MAX_CARRIERS values. Changing any Session-scoped receive limit or MAX_CARRIERS advertisement produces SESSION_CONFLICT and leaves the established Session unchanged.

This includes MAX_RECORD_SIZE: a later Carrier cannot join with a smaller or larger directional record limit than the value established for that endpoint during CREATE.

### B12. Session Protocol Version

Both implementations reproduce the relevant cases in test-vectors/version-compatibility.json.

A Session created under Protocol Version 4 accepts only JOIN and replacement Carriers using Protocol Version 4. A candidate using another locally supported Protocol Version is rejected with SESSION_CONFLICT and the Session remains unchanged.

### B13. VERSION_NEGOTIATION pipeline and downgrade safety

The Client sends Preface and CLIENT_INIT in one TCP write. The Server consumes only the Preface, determines that the requested version is unsupported, sends VERSION_NEGOTIATION, ignores the pipelined CLIENT_INIT bytes under that version, and closes. The Client accepts this unauthenticated response because it has not accepted SERVER_INIT, then retries only on a fresh underlying connection.

A retry does not enable a locally disabled or below-minimum Protocol Version. Authentication failure is not interpreted as permission to retry with a lower version. VERSION_NEGOTIATION received after SERVER_INIT has been accepted is rejected for that candidate.

### B14. HANDSHAKE_REJECT encoding and scope

Both implementations reproduce test-vectors/handshake-reject.json. A candidate JOIN rejected with SESSION_NOT_FOUND, SESSION_CONFLICT, CARRIER_CONFLICT, or RESOURCE_LIMIT receives HANDSHAKE_REJECT with the classified Error Code when the failure is safely reportable before SERVER_FINISHED. The candidate transport then closes.

Receipt of HANDSHAKE_REJECT does not authenticate the sender, modify an existing Session, advance Carrier Generation, or trigger Protocol Version downgrade.

### B15. HANDSHAKE_REJECT is outside successful transcript

A successful Draft 11 CREATE reproduces the same CLIENT_INIT, SERVER_INIT, Finished, traffic-secret, key, IV, and Secure Record baseline bytes as Draft 10. Draft 11 changes established-state reliability semantics but does not alter the successful handshake transcript.

### B16. CREATE Session-ID collision

A CREATE using a SESSION_ID already mapped to CREATING, ACTIVE, DORMANT, or CLOSING state, or to retained CLOSED retirement state, is rejected with SESSION_CONFLICT. The existing or retired Session is not overwritten, merged, reopened, or treated as the target of a JOIN.

### B17. Ambiguous establishment recovery

The harness drops the candidate transport after the Client sends CLIENT_FINISHED but before it authenticates SERVER_FINISHED. Tests cover an existing logical-Carrier replacement and an ambiguous CREATE/first-use Carrier ID.

The Client does not treat transport loss or an unauthenticated HANDSHAKE_REJECT as proof of Server commit/non-commit. A known replacement retries above every locally accepted or ambiguity-causing attempted Generation. An ambiguous first-use Carrier ID recovers through a different unused ID at Generation 0 unless authenticated evidence proves the first incarnation was accepted. An authenticated JOIN can establish retained Session existence; an unauthenticated SESSION_NOT_FOUND cannot.

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

### E7. Transmission retirement watermark

A sends reliable Transmissions 1 through 3. B processes all three, but the confirmation for Transmission 2 is initially lost. B retains enough response state to confirm Transmission 2 again. After A receives the repeated confirmation, A's Settled Through advances to 3 and A sends TRANSMISSION_RETIRE(3). Only then may B discard confirmation-replay detail for peer Transmissions through 3.

A stale lower TRANSMISSION_RETIRE is ignored. A value beyond B's largest contiguous processed peer Transmission ID is TRANSMISSION_ID_ERROR.

### E8. Confirmation type must match the original Transmission

A TRANSMISSION_ACK referring to an outstanding STREAM_OPEN Transmission is rejected with TRANSMISSION_ID_ERROR and does not settle the opening. STREAM_OPEN_OK and STREAM_OPEN_REJECT settle only a STREAM_OPEN with the same Stream ID and echoed Transmission ID. A confirmation referring to another Frame type, another Stream, or a never-allocated Transmission ID fails with TRANSMISSION_ID_ERROR.

### E9. FIN supersession does not create a retirement gap

Transmission 1 is settled. STREAM_FIN Transmission 2 is attempted on Carrier A, which fails before the peer processes it. The peer sends STOP_SENDING on Carrier B, causing the sender to allocate RESET_STREAM Transmission 3 with the same Final Offset. RESET_STREAM becomes authoritative for application-visible termination, but FIN Transmission 2 remains reliable.

After the peer processes and confirms RESET_STREAM 3, the sender reinjects FIN 2. The peer, already in reset semantics, acknowledges the late FIN with the same Final Offset without restoring graceful EOF. Once FIN 2 is confirmed, the sender's Settled Through advances from 1 to 3 and TRANSMISSION_RETIRE(3) is valid.

### E10. Allocated reliable Transmission cannot disappear

The harness distinguishes tentative local reservation from protocol allocation. After a reliable Transmission ID is formally allocated, local application cancellation or queue reshaping does not silently remove it from Session reliability state. While the Session remains usable and an eligible Carrier exists, the Transmission eventually receives an Attempt and can be settled by its required confirmation; an unrecoverable local resource failure closes the Session with RESOURCE_LIMIT when possible.

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

### F5. Stale credit after cross-Carrier reordering

For both STREAM_CREDIT and SESSION_CREDIT, a newer advertisement is delivered first on one Carrier and a fully older component-wise advertisement arrives later on another Carrier. The older advertisement is ignored and the Session remains usable.

### F6. Crossed credit is invalid

A structurally valid credit pair in which one monotonic component is greater than retained state while the other is lower is rejected with FLOW_CONTROL_ERROR.

### F7. CREDIT_PROBE

A Stream-scoped CREDIT_PROBE produces current Stream and Session credit advertisement when state remains available.

### F8. Terminal Final Offset obeys credit

STREAM_FIN and RESET_STREAM are tested at and beyond the current Stream Maximum Offset and aggregate Session Maximum Bytes. A terminal Final Offset that increases commitment within both limits is accepted. Exceeding either credit limit fails with FLOW_CONTROL_ERROR. Contradicting an already-established final size still fails with FINAL_SIZE_ERROR.

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

### H4. Pre-open STOP_SENDING cancellation response

The Client enters OPENING_CANCEL_PENDING and sends STOP_SENDING while STREAM_OPEN is still in flight. STOP_SENDING arrives first. The Server acknowledges it and sends RESET_STREAM with Final Offset 0. The Client classifies that RESET_STREAM as a cancellation response, not acceptance evidence.

The later STREAM_OPEN is rejected with STREAM_OPEN_REJECT(STREAM_STATE_ERROR), and the cancelling Client treats that matching rejection as normal cancellation completion rather than a Session error.

### H5. Acceptance wins the cancellation race

The Server accepts STREAM_OPEN before the pre-open cancellation reaches it, but STREAM_OPEN_OK is delayed on another Carrier. A RESET_STREAM generated in response to the later STOP_SENDING may arrive first. When STREAM_OPEN_OK or another unambiguous acceptance-evidence Frame arrives, acceptance is authoritative and the Stream proceeds directly into the requested terminal/cancellation semantics. The Server does not later send STREAM_OPEN_REJECT for the already accepted Stream.

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

### I6. Terminal confirmation loss blocks compaction

A peer terminal reliable Frame is processed and its confirmation is lost while another Carrier remains active. The receiving endpoint does not compact away the ability to repeat that confirmation merely because its own local terminal Transmission is settled. A duplicate/reinjected peer terminal Frame is confirmed again.

After the originator settles that Transmission and advances TRANSMISSION_RETIRE beyond it, the receiver may compact the confirmation-replay detail.

## 13. Group J — Carrier loss and replacement

**Mandatory.**

### J1. Unexpected Carrier loss

One of two active TCP Carriers is terminated without CARRIER_CLOSE.

The Session and active Streams remain usable over the other Carrier.

### J2. Outstanding Transmission

A reliable Transmission attempted on the failed Carrier remains unsettled and can be retransmitted or reinjected. Because MAX_RECORD_SIZE is Session-scoped, every established Carrier is capable of carrying a Frame that conformed to the Session record limit when the Transmission was created.

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

### J16. Recovery refresh progress

After DORMANT-to-ACTIVE recovery or Carrier replacement, current SESSION_CREDIT is eventually refreshed while an authenticated writable Carrier exists. A valid Stream-scoped CREDIT_PROBE for retained state eventually produces current STREAM_CREDIT plus SESSION_CREDIT. A non-zero TRANSMISSION_RETIRE watermark that can release peer replay state is eventually refreshed. Coalescing and rate limiting are permitted.

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

### K6. Close is terminal within its Secure Record

CARRIER_CLOSE and SESSION_CLOSE are emitted as the final Frame of their containing Secure Record. If a negative-test peer places an authenticated Frame after a close Frame, the trailing Frame does not create protocol or application state. A syntactically valid unknown reason from a negotiated extension/private range does not cancel the terminal close action.

## 15. Group L — Negative protocol tests

**Mandatory.**

At minimum, the receiver is tested with:

- malformed VarInt;
- Frame Length exceeding available record plaintext;
- unknown Core Frame;
- invalid Stream-ID parity;
- DATA exceeding Stream credit;
- DATA exceeding Session credit;
- FIN or RESET_STREAM Final Offset exceeding retained Stream or Session credit;
- structurally invalid credit (Consumed greater than Maximum), including when the pair would otherwise look stale;
- conflicting overlapping DATA bytes;
- contradictory Final Offset;
- conflicting Transmission-ID reuse;
- non-zero Secure Record Flags, including a cryptographically self-consistent re-encryption;
- a close Frame followed by a trailing state-creating Frame in the same authenticated Record;
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
    Revision: Draft 11
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

### 18.1. Repository executable evidence (non-normative)

The repository's executable Gate 3 runner maps the Mandatory profile above to 121 explicit case IDs and records the executable evidence class for every case. The current profile contains **18 codec, 30 cross-wire, 73 endpoint-wire, and zero model-only** case IDs. A state/oracle model may still supplement assertions, but it is not the sole evidence for any Mandatory case.

Authenticated `endpoint-wire` probes use real loopback TCP, complete CREATE/Finished where applicable, exchange authenticated Secure Records, and inspect both wire-visible responses and endpoint state. The paired controls include directional STOP_SENDING semantics, legal overlapping/out-of-order DATA reassembly, and terminal STREAM_CREDIT consistency with the local Final Offset in addition to final-size, credit, error-scope, and lifecycle checks. A dedicated formerly-model-only suite also exercises version/rejection handling, identifier exhaustion, Carrier capacity/replacement, reliable confirmation retirement, opening/cancellation races, tombstones, DORMANT retirement, candidate concurrency, and TCP/close behavior; failed-candidate J5 coverage includes the actual CLI Server process. Coverage-sensitivity controls deliberately break selected real handlers and require the corresponding endpoint-wire case to fail.

Retained-tombstone STREAM_CREDIT probes use bidirectional RESET/ACK and STREAM_CONSUMED/ACK, settled local reliable Transmissions, and Session-held confirmation replay before invoking the real local-policy retirement API. They test Consumed Offset at/beyond the recorded local Final Offset, Maximum Offset below Consumed Offset, and the Stream credit window at/above its limit. A valid Maximum Offset above the final size is accepted without recreating a Stream or expanding credit; legally compacted retired identities ignore stale credit, while unknown Streams cause STREAM_STATE_ERROR. F8/I2/I3 bind the relevant controls without changing Mandatory IDs or evidence classes.

For late STREAM_DATA, the executable contract distinguishes semantic byte evidence from reliable-confirmation state. Active Streams, including active terminal Streams, remain subject to Section 15.1 overlap byte identity. Once an accepted Stream validly enters TOMBSTONE, DATA wholly within the recorded peer Final Offset is unambiguously stale and cannot affect delivery or credit, so exact application-byte comparison evidence may be released; however, an unretired reliable Transmission ID still requires its retained ACK/terminal confirmation replay. Tombstone compaction may therefore proceed before peer TRANSMISSION_RETIRE only when equivalent confirmation-replay state remains outside the compacted Stream object.

Follow-up authenticated probes exercise the adjacent lifecycle/reliability rules: PADDING is ignored while unknown extensions remain skippable; unknown Core Frames are Session-scoped PROTOCOL_VIOLATION with the offending Trigger Frame Type; pre-open cancellation validates the client Stream-ID space before creating retained state; STREAM_OPEN acceptance/rejection decisions and rejection reasons remain immutable after active state is retired; late STOP_SENDING cannot replace an established terminal Final Offset; and compacted retired identities continue to replay confirmations for unretired reliable peer Transmissions when that replay state is retained at Session scope. Compaction itself now refuses to discard a Stream identity if a local reliable Transmission is unsettled or an unretired peer Transmission lacks equivalent confirmation replay.

Gate 4 adds a second source-isolated implementation and a neutral process harness. The aggregate requires both exact 121/121 model-zero profiles, 286 authenticated endpoint executions across the two runtimes (200 baseline plus 86 formerly-model-only), thirty-six target-witnessed sensitivity mutations after 52 unmutated baselines and eight oracle negative controls, 20 review-v2 executions, 18 update-review executions, 22 independent follow-up executions, 20 b66 follow-up executions, 18 stable-audit closure executions, 10 freeze-followup native-CLI executions covering no-fault/pre-auth controls and post-auth CREATE/JOIN/replacement output-failure scope, and real-TCP A→B/B→A role reversal for the baseline full-duplex and deterministic multi-Carrier/fault scenarios, both direct and under endpoint write fragmentation. The aggregate recomputes per-case evidence mappings and summary lists/counts from the exact Mandatory ID set and verifies endpoint probe references/execution counts against the raw endpoint reports. The update-review suite adds deterministic post-Finished installation barriers, STOP output-failure recovery, retirement-prefix interleaving, and MAX_KEY_RECORDS failover coverage without changing the wire format or Mandatory ID set.

The repository's second implementation is source/module isolated from the reference implementation and validator at runtime, but both implementations are maintained in the same repository and test project. This evidence supports an executable Mandatory-profile claim without asserting separate organizational or third-party development. The fact that model-only coverage is zero MUST NOT be restated as "all 121 cases are endpoint-wire" because codec and cross-wire evidence remain the appropriate executable surface for 48 case IDs.

These executable gates are evidence for Draft 11 interoperability only. They do not replace the separate requirements for a Protocol Version Stability Declaration.

## 19. Compatibility

Draft 11 keeps development Protocol Version 4 and preserves the Draft 10 wire format, registry assignments, successful CREATE/JOIN handshake transcript, key schedule, Secure Record syntax, and baseline encrypted records.

Draft 11 tightens recovery and progress semantics without adding a new Core numeric assignment: ambiguous establishment gets an authenticated recovery contract; reliable Transmission allocation cannot leave silently abandoned ID holes; recovery refresh obligations are explicit; RESET_STREAM/STOP_SENDING reason codes are separated semantically from Core failure-scope codes; and Secure Record send-sequence lifecycle is made explicit.

Draft 10 and Draft 11 are wire-compatible but are not guaranteed to make identical liveness/resource decisions in these edge cases. A Draft 10 implementation can still be interoperable on ordinary successful paths while lacking Draft 11 recovery/progress guarantees.

The normative long-term compatibility rules are defined in COMPATIBILITY.md. Draft 11 remains a development revision of Protocol Version 4 and does not yet declare Version 4 stable.
