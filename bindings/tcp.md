# MPX/4 over TCP

**Document:** MPX/4 TCP Transport Binding  
**Revision:** Draft 10
**Protocol Version:** 4  
**Status:** Normative Working Draft

This document defines the normative mapping of MPX/4 onto TCP.

It is a transport binding for the MPX/4 Core Protocol and is read together with [../SPECIFICATION.md](../SPECIFICATION.md), [../STATE-MACHINES.md](../STATE-MACHINES.md), and [../COMPATIBILITY.md](../COMPATIBILITY.md).

## 1. Scope

The TCP binding maps one MPX Carrier onto one reliable ordered TCP byte stream.

TCP provides:

- ordered byte delivery;
- reliable retransmission below MPX;
- congestion control for each TCP connection;
- connection failure indication.

MPX provides:

- Session identity;
- Carrier identity and Generation;
- authentication and Secure Records;
- Stream multiplexing;
- Session and Stream flow control;
- cross-Carrier scheduling;
- reliable Transmission acknowledgement;
- retransmission and reinjection across Carriers.

TCP segment boundaries, TCP write boundaries, and TCP receive-call boundaries have no MPX protocol meaning.

## 2. Normative reference

This binding assumes TCP semantics as specified by RFC 9293.

## 3. Carrier mapping

Each established TCP connection carries exactly one MPX Carrier.

A TCP connection MUST NOT carry two simultaneous MPX Carrier identities.

Carrier identity is defined by MPX CARRIER_ID and CARRIER_GENERATION, not by the TCP four-tuple.

A change in local or remote TCP address does not itself redefine an authenticated Carrier identity.

A replacement TCP connection for the same logical Carrier ID MUST perform a complete new MPX handshake using a strictly greater Carrier Generation.

## 4. Connection establishment

The Client opens a TCP connection to a Server endpoint selected by the deployment or application profile.

Immediately after TCP connection establishment, the Client sends the MPX Connection Preface followed by CLIENT_INIT. The Client MAY place both in one TCP write; TCP segmentation or coalescing does not alter handshake semantics.

No octets precede the MPX Connection Preface on a TCP Carrier defined by this binding.

The Server first parses the Connection Preface independently. If the Protocol Version is unsupported, it MAY send VERSION_NEGOTIATION immediately and MUST NOT parse any already-buffered following bytes as CLIENT_INIT under that unsupported version.

For a supported Protocol Version, the Server then reads and validates:

1. CLIENT_INIT;
2. subsequent handshake messages.

A Client that already transmitted pipelined CLIENT_INIT may still accept VERSION_NEGOTIATION until it has accepted SERVER_INIT or a later handshake message. Any retry occurs on a fresh TCP connection.

The Server MUST NOT treat a TCP connection as an authenticated Carrier until the MPX Finished exchange succeeds.

A TCP connection that is still performing the MPX handshake does not count toward the Session's Active Carrier Count. The negotiated MAX_CARRIERS limit applies only when a candidate would become an active logical Carrier at Core establishment commit.

## 5. Port selection

MPX/4 Draft 10 does not define or reserve a well-known TCP port.

TCP port selection is a deployment or application-profile concern.

A listener dedicated to MPX/4 expects the MPX Connection Preface as the first application octets.

A future port assignment or service-discovery profile can be defined independently of this binding.

## 6. Byte-stream parsing

An implementation MUST parse MPX messages from a continuous ordered byte stream.

It MUST support arbitrary fragmentation and coalescing.

For example, all of the following are equivalent from the MPX protocol perspective:

    write(preface)
    write(client_init)

and:

    write(preface || client_init)

and a sequence where the same bytes are delivered to the receiver one octet at a time.

An implementation MUST NOT assume that one TCP read returns one MPX message.

An implementation MUST NOT assume that one TCP write becomes one TCP segment.

## 7. Handshake mapping

Handshake messages use the Message Type and Message Length fields defined by the Core specification.

A receiver:

1. reads enough octets to decode the canonical Message Type VarInt;
2. reads enough octets to decode the canonical Message Length VarInt;
3. validates Message Length against protocol limits before allocation;
4. reads exactly Message Length body octets;
5. processes the complete message.

A TCP EOF, reset, or unrecoverable read error before a complete handshake message is received terminates the Carrier handshake.

Incomplete handshake bytes are discarded.

No partial handshake message changes authenticated Session state.

HANDSHAKE_REJECT, when used, is one complete handshake message followed by termination of the candidate TCP connection. The receiver MUST NOT interpret the subsequent TCP close as closing an already authenticated Session. A TCP implementation MAY close without HANDSHAKE_REJECT when the Core rules permit silent candidate termination.

## 8. Transition to Secure Records

The Client may send its first Secure Record only after validating SERVER_FINISHED.

The Server may send its first Secure Record only after generating SERVER_FINISHED and reaching the Server-side ESTABLISHED state defined by the Core handshake.

Handshake bytes and Secure Record bytes MAY be coalesced into the same TCP write when their protocol ordering remains valid.

The receiver still parses them as separate protocol units.

## 9. Secure Record mapping

After ESTABLISHED, the TCP byte stream contains a sequence of Secure Records.

For each record, the receiver:

1. reads the 1-octet Record Flags;
2. decodes the canonical Ciphertext Length VarInt;
3. validates Ciphertext Length before allocation;
4. reads exactly Ciphertext Length ciphertext octets;
5. reads exactly 16 authentication-tag octets;
6. authenticates and decrypts the complete record;
7. processes the contained complete Frames.

A receiver MUST NOT process partial plaintext from an incomplete record.

A receiver MUST NOT advance the receive Record Sequence Number until the complete record has been authenticated successfully.

Authentication failure terminates that Carrier as specified by the Core protocol.

## 10. Record fragmentation and coalescing

A Secure Record can be split across any number of TCP segments or receive calls.

Multiple Secure Records can be delivered in one TCP segment or receive call.

A conforming implementation therefore behaves identically for:

    TCP read #1: [record A]
    TCP read #2: [record B]

and:

    TCP read #1: [record A || record B]

and:

    TCP read #1: [first 3 bytes of record A]
    TCP read #2: [middle of record A]
    TCP read #3: [rest of record A || record B]

provided the resulting byte stream is identical.

## 11. Write batching

An implementation MAY batch:

- multiple Frames into one Secure Record; and
- multiple Secure Records into one TCP write.

Write batching MUST NOT change Frame ordering within one Carrier byte stream.

A Frame MUST NOT cross a Secure Record boundary.

Batching is an implementation decision and is not observable protocol state.

## 12. TCP congestion control

Each TCP Carrier is governed by the congestion-control behavior of its underlying TCP connection.

MPX flow control and scheduling do not replace TCP congestion control.

Core treats each authenticated Carrier as one eligible transport path. Local Carrier-selection policy may use transport-specific metrics but MUST preserve the Core Carrier identity and reliability rules.

MPX does not require a particular TCP congestion-control algorithm.

Two Carriers in one Session MAY use different TCP congestion-control algorithms or network paths.

## 13. Lower-layer multipath

The MPX protocol treats one TCP connection as one Carrier regardless of how the operating system internally implements that TCP connection.

If an underlying platform itself uses a multipath transport beneath the TCP API, MPX still observes that socket as one Carrier.

Deployments that require one MPX Carrier to correspond to one independently selected network path SHOULD configure the underlying transport accordingly.

Lower-layer path selection is outside the MPX wire protocol.

## 14. TCP_NODELAY and buffering

An implementation SHOULD avoid transport buffering that introduces unnecessary delay for small MPX control Frames.

On systems where TCP_NODELAY controls Nagle-style coalescing, enabling TCP_NODELAY is RECOMMENDED for MPX Carriers unless measured deployment behavior justifies another policy.

This recommendation does not change wire interoperability.

## 15. TCP keepalive and MPX PING

TCP keepalive MAY be enabled as a local operational mechanism.

TCP keepalive does not replace MPX PING/PONG.

MPX PING/PONG is authenticated protocol traffic and can contribute to Carrier-level path measurement.

TCP keepalive timing and failure policy are local implementation choices.

## 16. Handshake deadline

An implementation MUST impose a finite local deadline on an incomplete MPX Carrier handshake.

The exact deadline is local policy and is not negotiated by Draft 10.

Expiry of the handshake deadline closes only the incomplete Carrier attempt and does not alter authenticated state of an existing Session.

## 17. Established Carrier liveness

An implementation MAY use:

- MPX PING/PONG;
- TCP keepalive;
- application progress;
- write failure;
- read EOF or reset;
- local network-state signals;

to determine that a Carrier is no longer usable.

The exact liveness algorithm is implementation-defined.

A Carrier declared unusable MUST stop receiving new scheduling Attempts.

Outstanding reliable Transmissions remain Session state and can be retransmitted or reinjected on other Carriers.

## 18. Unexpected TCP loss

Any of the following without a previously processed matching MPX close condition is an unexpected Carrier loss:

- TCP EOF;
- TCP reset;
- unrecoverable socket error;
- local transport failure;
- timeout policy that closes the socket.

Unexpected TCP loss does not by itself close the MPX Session.

The endpoint:

1. marks the Carrier inactive;
2. discards incomplete handshake or Secure Record parser state belonging to that TCP connection;
3. preserves Session, Stream, flow-control, Generation, and reliable Transmission state;
4. updates Active Carrier Count;
5. if another Carrier remains active, makes outstanding Transmissions eligible for normal retransmission or reinjection policy;
6. if no Carrier remains active and the Session is retained, enters DORMANT;
7. MAY establish a replacement Carrier.

While DORMANT, no TCP Carrier exists on which MPX Frames can be sent. A newly established JOIN/replacement transitions the Session to ACTIVE before outstanding Transmissions become eligible for new Attempts.

## 19. Partial record on transport loss

If TCP terminates after only part of a Secure Record has arrived, the incomplete record is discarded.

No contained Frame is processed.

The receive Record Sequence Number is not advanced.

Because a replacement Carrier performs a new authenticated handshake with new traffic keys and sequence spaces, partial record bytes are never continued on another TCP connection.

## 20. Carrier replacement

Carrier Generation acceptance is a Core Session state machine defined in SPECIFICATION.md and STATE-MACHINES.md. The TCP binding supplies only the underlying replacement connection.

To attempt replacement of a failed or retired logical Carrier over TCP:

1. establish a new TCP connection;
2. send a new MPX Connection Preface using the Session Protocol Version;
3. perform a complete JOIN handshake;
4. use the same CARRIER_ID;
5. use a CARRIER_GENERATION strictly greater than the Highest Accepted Generation for that ID;
6. use fresh handshake nonces;
7. derive fresh traffic keys and IVs;
8. begin new per-direction Record Sequence Numbers at zero.

The candidate TCP connection does not become the current Carrier merely by connecting or sending CLIENT_INIT. The current Core Generation is unchanged until the candidate reaches ESTABLISHED.

The new TCP connection never resumes the old Carrier cryptographic record stream.

A failed replacement handshake is discarded without changing the Session Protocol Version, current Generation, Active Carrier Count, Effective Carrier Limit, or existing Session state.

If the candidate would reactivate an inactive logical Carrier while the Session is already at its Effective Carrier Limit, the candidate is rejected with RESOURCE_LIMIT before Generation commit.

If the candidate replaces an already active logical Carrier, it does not require an additional active Carrier slot.

After a higher Generation is accepted, lower-Generation TCP connections for the same Carrier ID are superseded according to the Core state machine and SHOULD be closed promptly.

Session-level reliable Transmission state continues across the replacement. Retransmission or reinjection on the replacement retains the original Transmission ID.

## 21. Simultaneous replacement attempts

Multiple TCP replacement candidates may exist concurrently, but TCP connection arrival order does not reserve or select a Carrier Generation.

Generation comparison occurs at the Core establishment commit point.

If more than one TCP connection attempts to JOIN using the same Carrier ID and Generation, at most one can become the accepted Carrier incarnation. Once one is accepted, another equal-Generation candidate is rejected with CARRIER_CONFLICT even if the accepted transport subsequently closes.

A separately authenticated candidate using a still-higher Generation may later supersede the current incarnation according to the Core state machine.

## 22. TCP half-close

TCP half-close has no MPX Stream semantic meaning.

An implementation MUST NOT use TCP FIN in one direction as a substitute for:

- STREAM_FIN;
- RESET_STREAM;
- CARRIER_CLOSE;
- SESSION_CLOSE.

If an endpoint receives TCP EOF for the read direction while the Carrier is otherwise expected to remain active, it treats the Carrier as lost or closing according to whether an authenticated MPX close Frame was already processed.

Applications requiring directional Stream shutdown use MPX Stream Frames, not TCP half-close.

## 23. Graceful Carrier close

To gracefully close one Carrier while preserving the Session, an endpoint sends CARRIER_CLOSE in an authenticated Secure Record.

After generating CARRIER_CLOSE:

- no new Transmission Attempt is scheduled on that Carrier;
- already batched octets preceding or containing CARRIER_CLOSE MAY be flushed;
- the endpoint MAY close the TCP connection after transmitting the record.

After receiving a valid CARRIER_CLOSE:

- the peer marks that Carrier closing;
- it stops scheduling new Attempts on that Carrier;
- it updates Active Carrier Count;
- if this was the last active Carrier and the Session is retained, it enters DORMANT;
- it MAY close the TCP connection immediately after processing already authenticated preceding bytes.

TCP FIN is transport cleanup, not the protocol-level Carrier-close signal.

## 24. Graceful Session close

SESSION_CLOSE is the protocol-level signal for graceful Session termination.

A sender SHOULD send SESSION_CLOSE on each currently writable authenticated Carrier when practical, but one valid authenticated copy is sufficient to close the Session.

After SESSION_CLOSE:

- no new Stream or Carrier is created;
- no new application DATA Transmission is created;
- each underlying TCP Carrier is closed according to local shutdown policy.

A later TCP EOF is expected transport cleanup.

## 25. TCP reset after protocol close

A TCP reset occurring after a valid CARRIER_CLOSE or SESSION_CLOSE does not change the already established MPX close semantics.

Implementations SHOULD base protocol state on authenticated MPX close Frames rather than on the particular TCP teardown sequence.

## 26. Address and interface selection

The protocol does not encode local interface names, source addresses, route identifiers, or network-interface indices.

Selecting a source address, destination address, interface, route, or network namespace for each TCP Carrier is a local implementation or deployment decision.

Different Carriers in one Session MAY use:

- different source addresses;
- different destination addresses;
- different IP versions;
- different network interfaces;
- different routes.

Carrier identity remains CARRIER_ID plus CARRIER_GENERATION.

## 27. DNS and endpoint discovery

DNS resolution and endpoint discovery are outside the MPX/4 Core and TCP binding.

A deployment profile MAY define one or more TCP endpoints for a Session.

Different Carriers MAY connect to different server addresses when those endpoints terminate the same logical MPX service and share the required Session authentication context.

## 28. Maximum sizes and TCP

MAX_FRAME_PAYLOAD and MAX_RECORD_SIZE are MPX protocol limits, not TCP MSS or path-MTU values. MAX_RECORD_SIZE is Session-scoped in Draft 10; every JOIN repeats the CREATE-time directional value, so any eligible Carrier in the Session can carry an already-created Frame that satisfied the Session limits.

An MPX Secure Record larger than one TCP segment is valid.

The TCP stack is responsible for segmentation and reassembly below MPX.

An implementation MUST NOT reduce MPX semantic correctness based on observed TCP segment size.

## 29. Backpressure

A blocked or slow TCP write makes that Carrier less suitable for additional scheduling work but does not change Session flow-control credit.

Implementations SHOULD account for local socket write backlog or outstanding bytes when selecting a Carrier.

MPX flow-control credit MUST NOT be refunded merely because bytes are still queued in a local TCP socket.

## 30. Security considerations

TCP does not provide the authentication, confidentiality, or integrity guarantees required by MPX.

All MPX security properties are provided by the MPX handshake and Secure Record Layer.

A TCP peer address is not an authenticated MPX identity.

Implementations MUST NOT skip MPX authentication based on:

- source IP address;
- source TCP port;
- local-interface selection;
- a previously used TCP four-tuple.

A replacement TCP connection always performs a fresh MPX Carrier handshake.

## 31. Conformance requirements

A conforming MPX/4 TCP binding implementation MUST:

- send the MPX Connection Preface as the first application octets;
- parse handshake messages independently of TCP read/write boundaries;
- parse Secure Records independently of TCP read/write boundaries;
- validate lengths before allocation;
- process no partial Secure Record plaintext;
- treat one TCP connection as one MPX Carrier;
- preserve Session state across unexpected loss of one Carrier;
- perform a fresh JOIN handshake for Carrier replacement;
- use a greater Carrier Generation for replacement;
- begin new Secure Record sequence spaces after replacement;
- never use TCP half-close as a substitute for MPX Stream or Session semantics;
- distinguish authenticated MPX close Frames from bare TCP teardown.

## 32. Interoperability tests

Machine-readable TCP byte-stream framing cases are provided in:

- [../test-vectors/tcp-binding.json](../test-vectors/tcp-binding.json)

End-to-end interoperability expectations are defined in:

- [../INTEROPERABILITY.md](../INTEROPERABILITY.md)
