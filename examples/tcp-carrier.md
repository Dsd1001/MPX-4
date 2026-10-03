# MPX/4 TCP Carrier Example

This example illustrates the MPX/4 Draft 10 TCP binding.

## 1. TCP connect

The Client establishes one ordinary TCP connection.

The first application octets are:

```text
4d 50 58 00 04
```

which encode:

```text
Magic   = MPX\0
Version = 4
```

No transport-length prefix is added around the Connection Preface.

## 2. Handshake fragmentation

A TCP stack is free to deliver those bytes as:

```text
read #1: 4d
read #2: 50 58
read #3: 00 04
```

or all at once.

The MPX parser produces the same Connection Preface in both cases.

The same rule applies to CLIENT_INIT, SERVER_INIT, Finished messages, and Secure Records.

## 3. Secure Record fragmentation

The first Client-to-Server Secure Record from the repository test vector is:

```text
00 0d
d4 8c a4 d8 84 24 c8 13 ba a4 ae ff bc
78 67 96 65 96 e1 17 81 36 57 23 a7 bb b2 48 e9
```

TCP may deliver it in fragments such as:

```text
read #1: 00
read #2: 0d d4 8c a4
read #3: d8 84 24 c8 13 ba a4
read #4: ae ff bc 78 67 96 65 96 e1 17 81 36 57 23 a7 bb b2 48 e9
```

No Frame is exposed to the MPX state machine until the complete Record authenticates successfully.

## 4. Multiple Records in one read

Two consecutive Secure Records can arrive in one TCP read:

```text
[Record sequence 0][Record sequence 1]
```

The receiver parses the first Record from its encoded length and 16-octet tag, advances the receive sequence after successful authentication, and then parses the second Record.

TCP message boundaries are never consulted.

## 5. Carrier failure

Assume Carrier 2 is carrying an incomplete Secure Record when the TCP connection fails.

The incomplete record is discarded.

Session state remains:

```text
Session
├── Stream 1
├── outstanding Transmissions
└── Carrier 1 still active
```

Outstanding Transmissions that were attempted on Carrier 2 remain eligible for retransmission or reinjection.

## 6. Replacement

The replacement TCP connection performs a fresh JOIN:

```text
Carrier ID         = 2
Carrier Generation = previous Generation + 1
```

It sends a new Connection Preface, completes a new authenticated handshake, derives fresh traffic keys, and starts new Record Sequence Numbers at zero.

No partial byte stream or record sequence is resumed from the failed TCP connection.

## 7. Generation acceptance

Assume Carrier ID 2 has Highest Accepted Generation 4.

A replacement candidate with Generation 4 is rejected even if the Generation-4 TCP connection has already failed:

```text
Highest Accepted Generation = 4
Candidate Generation        = 4
Result                      = CARRIER_CONFLICT
```

The accepted incarnation tuple is never reused.

A candidate with Generation 5 does not supersede Generation 4 merely by opening TCP or sending CLIENT_INIT. If authentication fails, Generation 4 remains the Highest Accepted Generation.

Only after the Generation-5 Carrier reaches ESTABLISHED does the Session commit:

```text
Highest Accepted Generation = 5
Generation 5                = current
Generation 4                = superseded
```

Any outstanding Session Transmission keeps its existing Transmission ID if it is reinjected onto Generation 5.
