# MPX/4 Frame Encoding Examples

This document contains non-normative encoding examples for the MPX/4 Draft 03 Frame format.

All hexadecimal examples use network byte order.

## 1. STREAM_DATA

Logical Frame:

```text
Type             = STREAM_DATA (0x13)
Stream ID        = 1
Offset           = 32768
Transmission ID  = 7
Data             = "hello"
```

Relevant VarInt encodings:

```text
Stream ID 1       -> 01
Offset 32768      -> 80 00 80 00
Transmission ID 7 -> 07
```

The typed body is therefore 11 octets:

```text
01 80 00 80 00 07 68 65 6c 6c 6f
```

Frame Type and Frame Length are each one octet:

```text
13 0b
```

Complete decoded Frame representation:

```text
13 0b 01 80 00 80 00 07 68 65 6c 6c 6f
```

This byte sequence is the plaintext Frame representation before placement into a Secure Record. Retransmission or reinjection of this Transmission keeps Transmission ID 7 and identical logical Frame contents.

## 2. TRANSMISSION_ACK

Logical Frame:

```text
Type                = TRANSMISSION_ACK (0x14)
Stream ID           = 1
Transmission ID     = 7
Receiver Timestamp  = 1234567 microseconds
```

Encodings:

```text
1        -> 01
7        -> 07
1234567  -> 80 12 d6 87
```

The body length is 6 octets.

Complete Frame:

```text
14 06 01 07 80 12 d6 87
```

## 3. STREAM_CREDIT

Logical Frame:

```text
Type             = STREAM_CREDIT (0x15)
Stream ID        = 1
Consumed Offset  = 65536
Maximum Offset   = 131072
```

Encodings:

```text
1       -> 01
65536   -> 80 01 00 00
131072  -> 80 02 00 00
```

The body length is 9 octets.

Complete Frame:

```text
15 09 01 80 01 00 00 80 02 00 00
```

## 4. SESSION_CREDIT

Logical Frame:

```text
Type            = SESSION_CREDIT (0x20)
Consumed Bytes  = 1048576
Maximum Bytes   = 8388608
```

Encodings:

```text
1048576 -> 80 10 00 00
8388608 -> 80 80 00 00
```

Complete Frame:

```text
20 08 80 10 00 00 80 80 00 00
```

## 5. Frame boundaries and Secure Records

Multiple complete Frames can share one Secure Record.

For example, the plaintext of one Secure Record might contain:

```text
[TRANSMISSION_ACK]
[STREAM_CREDIT]
[STREAM_DATA]
```

Frame boundaries are recovered from each Frame's Type and Length fields.

A Frame does not span Secure Record boundaries.


## 6. CREDIT_PROBE

A Session-only credit probe is encoded as:

```text
21 01 00
```

The Frame Type is 0x21, Frame Length is 1, and Stream ID is 0. A non-zero Stream ID requests current Stream credit for that Stream together with current Session credit.

The Draft 03 Secure Record test vector encrypts the STREAM_DATA example above as the first Client-to-Server record.
