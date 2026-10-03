# MPX/4 Carrier Receive Capacity Hint Extension

**Extension:** Carrier Receive Capacity Hint  
**Extension Revision:** 01  
**Applicable Core:** MPX/4 Draft 11 / Protocol Version 4 development line
**Status:** Published Optional Extension

This extension defines one optional authenticated per-Carrier capacity hint. It does not define a scheduler algorithm, scheduler mode, path topology model, Relay role, or shared scheduling policy.

## 1. Purpose

MPX/4 Core intentionally leaves Carrier selection to each sending endpoint.

Some implementations have provisioning knowledge about the approximate end-to-end capacity available for traffic arriving at one endpoint on one Carrier. This extension provides a small, safely ignorable way to communicate that receive-side estimate to the peer.

A local implementation may use the hint for a capacity-aware or weighted scheduling policy. Use of the hint does not make that local policy part of the MPX/4 protocol.

## 2. Extension Parameter

This extension allocates Handshake Parameter Type:

    0x40  RECEIVE_CAPACITY_HINT

Because 0x40 is encoded as an MPX VarInt, its canonical Parameter-Type encoding is `40 40`.

The Parameter format is:

    Parameter Type          0x40
    Flags                   0x00
    Length                  VarInt
    Receive Capacity Units  VarInt

The CRITICAL flag MUST be zero.

Receive Capacity Units MUST be in the range 1 through 65535.

One Capacity Unit equals 100,000 bits per second.

## 3. Semantics

RECEIVE_CAPACITY_HINT is expressed from the perspective of the endpoint sending the Parameter.

It means:

> the sender's configured estimate of the end-to-end capacity available for traffic that the peer sends to this endpoint over this Carrier.

Examples:

- a Client advertisement is a hint that may be useful to the Server when scheduling Server-to-Client traffic;
- a Server advertisement is a hint that may be useful to the Client when scheduling Client-to-Server traffic.

The value describes the Carrier as observed or provisioned end to end. Core and this extension do not decompose the Carrier into Client-to-Relay, Relay-to-Server, proxy, tunnel, interface, or other topology segments.

A Relay or transparent forwarding hop does not participate in this extension.

## 4. Handshake use

RECEIVE_CAPACITY_HINT MAY appear in CLIENT_INIT and MAY appear in SERVER_INIT for CREATE or JOIN.

It is Carrier-scoped.

The value MAY differ:

- between Carriers;
- between the two endpoints;
- between Generations of the same Carrier ID.

An endpoint that has no configured estimate simply omits the Parameter.

The Parameter is optional and unilateral:

- the peer is not required to echo it;
- the peer is not required to send its own hint;
- receipt of one hint does not activate a Session-wide mode;
- absence of the Parameter does not cause handshake failure.

An endpoint that does not implement this extension ignores the Parameter under the Core unknown-optional-Parameter rule because CRITICAL=0.

## 5. Authentication

When the Carrier handshake completes, RECEIVE_CAPACITY_HINT is authenticated because it is part of CLIENT_INIT or SERVER_INIT and therefore part of the Finished transcript.

Authentication means only that the peer sent the value. It does not prove that the capacity estimate is accurate.

## 6. Local use

A receiving endpoint MAY use the hint as one local input when selecting a Carrier for its own outbound Transmission Attempts.

It MAY combine the hint with:

- local configured capacity;
- RTT;
- measured delivery rate;
- loss or retransmission history;
- outstanding bytes;
- interface or monetary cost;
- any other local metric.

This extension does not define:

- a weight formula;
- a distribution ratio;
- a path score;
- a failover threshold;
- a probing interval;
- a congestion-control algorithm;
- a requirement that both endpoints make the same Carrier choices.

A local policy commonly described by an implementation as “Weighted” is therefore an implementation mode, not an MPX/4 wire-level scheduler.

## 7. Protocol invariants

Use of RECEIVE_CAPACITY_HINT MUST NOT:

- change Stream byte identity;
- change a Transmission ID during retransmission or reinjection;
- create additional logical flow-control commitment;
- make a closing, superseded, or unusable Carrier eligible;
- override Core flow control;
- be interpreted as reserved bandwidth or guaranteed throughput.

## 8. Error handling

A known implementation of this extension receiving:

- CRITICAL=1;
- a non-canonical VarInt;
- a value of zero;
- a value greater than 65535;
- a malformed Parameter length;

MUST reject the candidate handshake with PROTOCOL_VIOLATION.

An implementation that does not know the extension follows the Core unknown optional Parameter rule and safely ignores the value.

## 9. Security considerations

The hint is peer-supplied scheduling metadata and may be inaccurate, stale, or deliberately misleading.

Implementations SHOULD bound the influence of peer-provided hints and MAY prefer live path measurements over configured hints.

The hint MUST NOT be treated as:

- flow-control credit;
- congestion-control permission;
- a bandwidth reservation;
- proof of Relay or path topology;
- proof of available capacity.

## 10. Interoperability

Implementations claiming support for this extension SHOULD verify:

1. canonical Parameter Type 0x40 encoding;
2. CRITICAL=0;
3. values 1 and 65535 are accepted;
4. values 0 and 65536 are rejected by implementations that understand the extension;
5. a Client-only advertisement is accepted;
6. a Server-only advertisement is accepted;
7. different hints in the two directions are accepted;
8. omission by either endpoint does not fail the Core handshake;
9. a peer that does not implement the extension can ignore it and still interoperate at Core;
10. the hint can change on a higher-Generation replacement Carrier without changing Session identity.

Machine-readable cases are provided in [capacity-hint.json](capacity-hint.json).
