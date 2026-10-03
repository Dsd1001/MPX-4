# MPX/4 Error Handling and Failure Scope

**Document:** MPX/4 Error Handling Supplement  
**Revision:** Draft 10
**Protocol Version:** 4  
**Status:** Normative Working Draft

This document is a normative companion to [SPECIFICATION.md](SPECIFICATION.md). It defines the scope of Core errors and the required protocol action after those errors are detected.

## 1. Scope

MPX/4 separates Stream, Carrier, and Session state. Error handling therefore MUST preserve the smallest protocol scope whose state can no longer be used safely.

An implementation MUST NOT terminate the entire Session for an error that this document defines as Carrier-scoped or Stream-opening-scoped.

An implementation MUST terminate the Session for an error that this document defines as Session-scoped.

Transport bindings MAY define additional transport-local failures, but they MUST map those failures onto the Core scopes defined here.

## 2. Failure scopes

MPX/4 defines the following failure scopes.

### 2.1. Stream-opening scope

A Stream-opening-scoped failure rejects one attempted Stream creation.

The receiver sends STREAM_OPEN_REJECT and leaves the Session and all Carriers usable.

Core STREAM_OPEN_REJECT reasons are:

- STREAM_LIMIT;
- RESOURCE_LIMIT when the exhausted resource is specific to accepting that Stream;
- STREAM_STATE_ERROR only where the Core state machine explicitly requires STREAM_OPEN_REJECT using that code, including a late STREAM_OPEN after valid pre-open cancellation.

NO_ERROR MUST NOT be used in STREAM_OPEN_REJECT.

Extension or Private Use error codes MAY be used in STREAM_OPEN_REJECT only when their defining specification declares Stream-opening scope.

### 2.2. Carrier scope

A Carrier-scoped failure invalidates one Carrier incarnation.

If the Carrier is already ESTABLISHED and it is safe to emit authenticated protocol traffic, the endpoint SHOULD send CARRIER_CLOSE with the applicable Error Code and then stop using that Carrier.

If authenticated reporting is not possible or not safe, closing the underlying transport is sufficient.

A Carrier-scoped failure MUST NOT by itself:

- change Stream byte identity;
- clear Session-wide reliable Transmission state;
- reset Stream or Session flow-control state;
- invalidate another authenticated Carrier;
- transition the Session to CLOSING.

If a Carrier-scoped failure removes the last active Carrier and the endpoint retains the Session, the Session enters DORMANT rather than CLOSING.

### 2.3. Session scope

A Session-scoped failure means shared Session state can no longer be trusted to continue interoperably.

The endpoint MUST:

1. transition the Session to CLOSING;
2. stop creating Streams and accepting Carrier JOINs;
3. stop creating new application DATA Transmissions;
4. send SESSION_CLOSE on at least one writable authenticated Carrier when possible;
5. use the detected Error Code in SESSION_CLOSE;
6. use the offending Frame Type as Trigger Frame Type when one is known, otherwise zero;
7. make all Carriers in the Session ineligible for new Transmission Attempts;
8. release the Session according to the transport binding and local shutdown policy.

A sender MAY send the same SESSION_CLOSE on more than one authenticated Carrier. One valid authenticated copy is sufficient for the peer to enter Session closing state.

### 2.4. Pre-establishment Carrier failure

Before a Carrier reaches ESTABLISHED, CARRIER_CLOSE and SESSION_CLOSE are not available because Secure Records are not yet active.

A handshake failure therefore terminates only the candidate Carrier connection unless the failure separately invalidates an already established Session.

When the requested Protocol Version is understood, the failure has a classified Core Error Code, and a safe response can be emitted before SERVER_FINISHED, the endpoint SHOULD send HANDSHAKE_REJECT carrying that Error Code and then terminate the candidate transport. If those conditions do not hold, terminating the candidate transport without HANDSHAKE_REJECT is valid.

HANDSHAKE_REJECT is unauthenticated. Its Error Code is diagnostic wire information, not authenticated proof of why the peer rejected the candidate. Receipt of the message MUST NOT mutate an existing Session or trigger Protocol Version downgrade.

Rejecting a candidate CREATE or JOIN MUST NOT modify any existing Session.

## 3. Core Error Code scope

The following table defines the Core scope of each registered Error Code.

| Error Code | Primary scope | Required Core action |
|---|---|---|
| NO_ERROR | Closure signal | Graceful CARRIER_CLOSE or SESSION_CLOSE; not a failure |
| INTERNAL_ERROR | Contextual | Use the smallest scope whose state cannot safely continue |
| PROTOCOL_VIOLATION | Carrier before ESTABLISHED; Session after ESTABLISHED | HANDSHAKE_REJECT when safely reportable before SERVER_FINISHED, otherwise terminate candidate; SESSION_CLOSE after establishment |
| AUTHENTICATION_FAILED | Carrier | HANDSHAKE_REJECT when safely reportable before SERVER_FINISHED; otherwise terminate the affected Carrier |
| VERSION_UNSUPPORTED | Pre-establishment Carrier | VERSION_NEGOTIATION when applicable, then terminate candidate Carrier |
| RESOURCE_LIMIT | Contextual | STREAM_OPEN_REJECT, HANDSHAKE_REJECT for a reportable candidate rejection, CARRIER_CLOSE, or SESSION_CLOSE according to the exhausted resource |
| SESSION_NOT_FOUND | Pre-establishment Carrier | HANDSHAKE_REJECT when safely reportable; reject JOIN candidate; existing Sessions are unaffected |
| SESSION_CONFLICT | Pre-establishment Carrier | HANDSHAKE_REJECT when safely reportable; reject CREATE/JOIN candidate; existing Session is unaffected |
| STREAM_LIMIT | Stream opening | STREAM_OPEN_REJECT |
| FLOW_CONTROL_ERROR | Session | SESSION_CLOSE |
| FRAME_ENCODING_ERROR | Carrier | CARRIER_CLOSE when safely reportable; otherwise terminate Carrier |
| CARRIER_CONFLICT | Pre-establishment Carrier | HANDSHAKE_REJECT when safely reportable; reject candidate Carrier |
| UNSUPPORTED_PARAMETER | Pre-establishment Carrier | HANDSHAKE_REJECT when safely reportable; reject candidate Carrier |
| STREAM_STATE_ERROR | Session, except explicit STREAM_OPEN rejection cases | SESSION_CLOSE, or STREAM_OPEN_REJECT where this specification explicitly permits rejection |
| FINAL_SIZE_ERROR | Session | SESSION_CLOSE |
| TRANSMISSION_ID_ERROR | Session | SESSION_CLOSE |

The scope in this table is normative.

A Core rule that explicitly assigns a narrower STREAM_OPEN_REJECT action takes precedence over the Session default for STREAM_STATE_ERROR. Retired Stream identities are governed by STATE-MACHINES.md and MAY be silently ignored when detailed response state has been compacted; retirement alone does not require STREAM_OPEN_REJECT.

## 4. Contextual Core errors

### 4.1. INTERNAL_ERROR

INTERNAL_ERROR represents a local implementation failure, not necessarily peer misconduct.

An endpoint MUST choose the smallest scope whose correctness can still be guaranteed:

- if only one candidate handshake cannot continue, terminate that candidate Carrier;
- if only one established Carrier can no longer continue safely and Session state remains valid, use Carrier scope;
- if shared Session state may be inconsistent, use Session scope.

An endpoint MUST NOT continue protocol processing in state it knows may be internally inconsistent.

### 4.2. RESOURCE_LIMIT

RESOURCE_LIMIT represents an exhausted local resource.

The protocol action depends on the resource being protected:

- inability to accept one additional Stream: STREAM_OPEN_REJECT;
- inability to complete one candidate Carrier handshake: reject that candidate and send HANDSHAKE_REJECT(RESOURCE_LIMIT) when safely reportable;
- a candidate whose establishment would exceed the negotiated Effective Carrier Limit: reject that candidate with RESOURCE_LIMIT;
- an established Carrier-specific resource limit: CARRIER_CLOSE;
- a Session-wide resource condition under which shared state cannot safely continue: SESSION_CLOSE.

General resource policy, memory sizing, queue sizing, handshake-admission policy, DORMANT retention duration, and eviction strategy remain local implementation choices. The explicit exception is active logical Carrier concurrency: MAX_CARRIERS is negotiated by Core and defines the immutable Effective Carrier Limit for the Session.

Exhaustion of the Session-wide Transmission-ID namespace is a Session resource condition when another reliable Transmission would be required and therefore leads to SESSION_CLOSE(RESOURCE_LIMIT). Exhaustion of the Client Stream-ID namespace prevents creation of additional Streams but does not by itself require Session closure.

## 5. Error selection precedence

When one received Frame violates more than one Core rule, the deterministic precedence in [STATE-MACHINES.md](STATE-MACHINES.md) applies.

Selecting the Error Code and selecting failure scope are separate operations.

For example:

- malformed Frame encoding is FRAME_ENCODING_ERROR and Carrier-scoped;
- a correctly encoded Frame that contradicts an established final size is FINAL_SIZE_ERROR and Session-scoped;
- a confirmation whose type does not match the referenced reliable Transmission, such as TRANSMISSION_ACK for STREAM_OPEN, is TRANSMISSION_ID_ERROR and Session-scoped;
- structurally valid credit that is fully stale due to cross-Carrier reordering is ignored, while a crossed credit pair in which one monotonic component rises and the other falls is FLOW_CONTROL_ERROR;
- TRANSMISSION_RETIRE beyond the largest contiguous peer Transmission prefix already processed is TRANSMISSION_ID_ERROR.

An implementation MUST NOT widen or narrow failure scope merely because a different Error Code would be operationally more convenient.

## 6. Trigger Frame Type

CARRIER_CLOSE and SESSION_CLOSE contain Trigger Frame Type.

When a specific decoded Frame caused the error, Trigger Frame Type MUST contain that Frame Type.

Trigger Frame Type is zero when:

- no specific Frame caused the close;
- the failure occurred before Frame decoding;
- the failure was local;
- the failure was caused by transport loss or another condition without a Core Frame Type.

Reason text is diagnostic only and MUST NOT change the scope or behavior defined by this document.

## 7. Authentication and integrity failures

Failure to authenticate CLIENT_FINISHED or SERVER_FINISHED is Carrier-scoped.

Failure to authenticate or decrypt a Secure Record is Carrier-scoped.

After Secure Record authentication failure, the endpoint MUST NOT process any plaintext from that record and MUST stop accepting further protocol state from that Carrier incarnation.

Because the peer identity or record integrity is not established for the failed input, an implementation MAY close the transport without sending CARRIER_CLOSE. For a pre-SERVER_FINISHED handshake authentication failure, HANDSHAKE_REJECT(AUTHENTICATION_FAILED) MAY be sent when a safe response can be emitted; it remains unauthenticated.

Other authenticated Carriers in the same Session remain valid unless a separate Session-scoped error occurs.

## 8. Candidate JOIN rejection

The following failures reject only the candidate Carrier:

- SESSION_NOT_FOUND;
- SESSION_CONFLICT, including JOIN using a Protocol Version different from the immutable Session Protocol Version and CREATE colliding with a retained Session ID;
- CARRIER_CONFLICT;
- UNSUPPORTED_PARAMETER;
- AUTHENTICATION_FAILED;
- candidate-Carrier RESOURCE_LIMIT;
- malformed or invalid handshake state.

A JOIN candidate that would make the endpoint's local Active Carrier Count exceed the Effective Carrier Limit is rejected with RESOURCE_LIMIT. The existing Session remains active.

When one of these failures is safely classifiable before SERVER_FINISHED, the rejecting endpoint SHOULD expose the same Error Code in HANDSHAKE_REJECT. The local error classification remains authoritative to the rejecting endpoint; the received unauthenticated code is advisory to the peer.

A failed CREATE or JOIN MUST NOT:

- change the Session Protocol Version;
- change either endpoint's stored MAX_CARRIERS advertisement or the Effective Carrier Limit;
- advance the accepted Carrier Generation;
- supersede an existing Carrier;
- reset cryptographic state of another Carrier;
- change Stream or flow-control state.

## 9. Session-error atomicity

When a Session-scoped error is detected, an endpoint MUST treat the transition to CLOSING as a Session-wide event.

After that transition, a Frame arriving on another Carrier MUST NOT create:

- a new Stream;
- a new Carrier;
- a new application DATA Transmission;
- new application-visible state inconsistent with Session closure.

Already authenticated plaintext MAY be validated or discarded according to the state-machine shutdown rules, but it MUST NOT reopen or extend the Session.

## 10. Extensions

Every extension that defines a new Error Code MUST declare:

- its failure scope;
- the protocol state in which it can occur;
- whether it is valid in STREAM_OPEN_REJECT;
- whether CARRIER_CLOSE or SESSION_CLOSE is required after ESTABLISHED;
- behavior before ESTABLISHED;
- interaction with duplicate or retransmitted Frames.

An extension MUST NOT rely on implementation-specific process, thread, socket, queue, or event-loop behavior to define error scope.
