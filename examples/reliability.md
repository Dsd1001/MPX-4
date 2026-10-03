# MPX/4 Retransmission and Reinjection Example

This document illustrates the distinction between a Transmission and an Attempt in MPX/4 Draft 09.

## 1. One logical Transmission

Assume Stream 1 has the following outstanding Frame:

    STREAM_DATA
      Stream ID        = 1
      Offset           = 32768
      Transmission ID  = 7
      Data Length      = 32768

Transmission ID 7 identifies this reliable logical protocol unit for its entire lifetime.

## 2. First Attempt

The sender's local Carrier-selection policy initially selects Carrier 1:

    Transmission 7
        |
        +-- Attempt 1 --> Carrier 1

The sender records the local send time and the selected Carrier.

Attempt 1 has no separate wire identifier.

## 3. Reinjection

Suppose Carrier 1 stops making progress before Transmission 7 is acknowledged.

The sender can create another Attempt on Carrier 2 according to its local Carrier-selection policy:

    Transmission 7
        |
        +-- Attempt 1 --> Carrier 1
        |
        '-- Attempt 2 --> Carrier 2

The second copy remains:

    Stream ID        = 1
    Offset           = 32768
    Transmission ID  = 7
    Data             = identical bytes

A reinjection does not allocate a new Transmission ID and does not consume additional Stream or Session credit.

## 4. Receiver behavior

If Attempt 2 arrives first, the receiver accepts the Stream bytes and sends:

    TRANSMISSION_ACK
      Stream ID        = 1
      Transmission ID  = 7

If Attempt 1 later arrives, it is a duplicate of the same Transmission.

The receiver does not deliver the Stream bytes twice and sends the acknowledgement again.

If a repeated Transmission ID arrives with different semantic Frame contents, the Session is invalid.

## 5. Sender behavior

The first valid acknowledgement of Transmission 7 settles the logical Transmission.

Any remaining local Attempts can be retired.

The sender never reuses Transmission ID 7 for a different reliable Frame later in the Session.

## 6. Path measurement

An acknowledgement is most useful for path measurement when:

- the Transmission has only one Attempt; and
- the acknowledgement returns on the same Carrier.

Once a Transmission has multiple Attempts, the acknowledgement still settles reliability but Draft 09 does not treat it as an unambiguous per-Carrier delivery-rate sample.

## 7. Retirement watermark

After the sender has received confirmations for every locally allocated reliable Transmission from 1 through 7, its contiguous Settled Through value is 7. It may advertise:

    TRANSMISSION_RETIRE
      Retired Through = 7

The peer may then discard confirmation-replay detail for those Transmission IDs. Before receiving that watermark, a duplicate Transmission 7 must still receive its required confirmation again. A lost retirement advertisement delays reclamation but does not change reliability state.
