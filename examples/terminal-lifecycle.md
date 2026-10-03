# MPX/4 Terminal Stream Lifecycle Example

This non-normative example illustrates Draft 08 terminal state, late Frame handling, tombstones, and retired identities.

## 1. Normal FIN with reordered DATA

Assume Stream 1 has receive credit through offset 65536.

The sender transmits:

```text
Transmission 40
  STREAM_DATA
  Offset = 0
  Length = 32768

Transmission 41
  STREAM_DATA
  Offset = 32768
  Length = 32768

Transmission 42
  STREAM_FIN
  Final Offset = 65536
```

Because different Attempts can use different Carriers, the receiver can observe:

```text
STREAM_DATA 0..32768
STREAM_FIN Final Offset 65536
STREAM_DATA 32768..65536
```

Receiving STREAM_FIN establishes the immutable Final Offset but does not imply that all earlier bytes have arrived.

The later STREAM_DATA is valid because its End Offset does not exceed 65536. It fills the missing range and is delivered exactly once.

## 2. Data beyond final size

After Final Offset 65536 is established:

```text
STREAM_DATA
Offset = 65536
Length = 1
```

has End Offset 65537 and is invalid.

The Session fails with FINAL_SIZE_ERROR.

## 3. RESET and late duplicate DATA

Assume RESET_STREAM establishes:

```text
Final Offset = 49152
```

The receive direction is terminated immediately for application delivery.

A delayed duplicate STREAM_DATA covering bytes below 49152 may still arrive from another Carrier.

The receiver does not deliver those bytes to the application. The duplicate can be acknowledged as stale reliable traffic.

A Frame extending beyond 49152 is FINAL_SIZE_ERROR.

## 4. Terminal reliability

The local sending direction becomes terminal only after its STREAM_FIN or RESET_STREAM Transmission is acknowledged.

For normal FIN receive completion, the receiver later sends reliable STREAM_CONSUMED after application receive accounting has been released through Final Offset.

Once both directions have reached their terminal conditions and no reliable Stream Transmission still needs full Stream state, the implementation can replace the active Stream with a tombstone.

## 5. Tombstone

A tombstone retains only terminal semantic information needed to handle late duplicates safely.

For example:

```text
Stream ID:                  1
Open Transmission ID:      12
Open result:                accepted
Local terminal kind:        FIN
Local terminal TxID:        42
Local Final Offset:         65536
Peer terminal kind:         FIN
Peer terminal TxID:         81
Peer Final Offset:          98304
Last receive credit:        consumed=98304 max=98304
```

A duplicate peer STREAM_FIN matching TxID 81 and Final Offset 98304 is acknowledged again.

A peer STREAM_FIN with a different Final Offset fails with FINAL_SIZE_ERROR.

No application object is recreated.

## 6. Retired identity

After terminal reliability is fully settled, detailed tombstone state can be compacted.

The implementation must still remember that Stream ID 1 has already been used.

A later Frame for that retired identity cannot create a Stream, consume new credit, or deliver application data.

When detailed state has been discarded, such stale traffic may be ignored.
