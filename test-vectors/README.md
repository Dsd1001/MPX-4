# MPX/4 Test Vectors

This directory contains machine-readable interoperability vectors for MPX/4.

The vectors allow independent implementations to verify that they produce identical canonical encodings and cryptographic derivations.

Current sets:

- [varint.json](varint.json) — canonical MPX variable-length integer encodings and invalid inputs.
- [frame-encoding.json](frame-encoding.json) — plaintext Frame encodings before Secure Record encryption.
- [key-schedule.json](key-schedule.json) — Draft 10 handshake transcript, Finished values, application secrets, traffic keys, and traffic IVs.
- [secure-record.json](secure-record.json) — Draft 10 AES-256-GCM nonce, AAD, ciphertext, tag, and complete wire Record.
- [state-validity.json](state-validity.json) — Stream lifecycle and late-Frame conformance cases from the Draft 10 state-machine supplement.
- [carrier-generation.json](carrier-generation.json) — Carrier Generation acceptance, replacement, supersession, and non-reuse cases.
- [error-scope.json](error-scope.json) — Core Error Code scope and required STREAM_OPEN_REJECT / Carrier / Session actions.
- [max-carriers.json](max-carriers.json) — MAX_CARRIERS Parameter encoding, bilateral negotiation, active logical Carrier accounting, slot release, and replacement-at-limit cases.
- [session-lifecycle.json](session-lifecycle.json) — ACTIVE / DORMANT / CLOSED transitions and zero-Carrier recovery invariants.
- [version-compatibility.json](version-compatibility.json) — Session Protocol Version, VERSION_NEGOTIATION, downgrade, and stable-version evolution cases.
- [handshake-reject.json](handshake-reject.json) — HANDSHAKE_REJECT encoding, allowed Core Error Codes, unauthenticated scope, and candidate-only rejection behavior.
- [identity-lifecycle.json](identity-lifecycle.json) — Session-ID collision handling plus Stream-ID and Transmission-ID allocation/exhaustion rules.
- [reordering-reliability.json](reordering-reliability.json) — cross-Carrier credit reordering, pre-open cancellation, FIN/RESET retirement convergence, Transmission retirement, and Session-scoped record-size cases.
- [confirmation-validity.json](confirmation-validity.json) — required-confirmation-class, Stream/Transmission association, and wrong-confirmation negative cases.
- [tcp-binding.json](tcp-binding.json) — generated from the canonical handshake and Secure Record fixtures; TCP fragmentation, coalescing, and mid-record transport-loss cases. — TCP fragmentation, coalescing, and mid-record transport-loss cases.

Unless explicitly stated otherwise, test vectors are subordinate to the normative protocol specification. If a vector conflicts with the current specification, the specification controls and the vector must be corrected.

## Validation order

An implementation can validate interoperability in this order:

1. VarInt parsing and canonical encoding.
2. Frame encode/decode.
3. Handshake message and Parameter encoding, including MAX_CARRIERS.
4. Draft 10 key schedule and Finished authentication using the Draft 10 Core handshake transcript.
5. Secure Record encryption and decryption under Draft 10 derived traffic keys.
6. Stream state and late-Frame validity.
7. Carrier Generation replacement state.
8. MAX_CARRIERS negotiation and active logical Carrier accounting.
9. ACTIVE / DORMANT Session lifecycle and recovery.
10. Protocol Version compatibility and downgrade behavior.
11. HANDSHAKE_REJECT encoding and candidate-only failure semantics.
12. Session-ID collision and Stream/Transmission identifier exhaustion.
13. Cross-Carrier credit reordering and pre-open cancellation races.
14. Transmission retirement and tombstone convergence.
15. Session-scoped MAX_RECORD_SIZE reinjection guarantees.
16. Error Code failure scope and close behavior.
17. TCP byte-stream framing and transport-loss behavior.

A failure at an earlier layer should be corrected before using later cryptographic vectors.

Optional extension vectors are maintained with their defining extension. See [../extensions/capacity-hint.json](../extensions/capacity-hint.json) for the Carrier Receive Capacity Hint extension.

The repository validator performs full positive/negative VarInt checks, Frame field-to-wire encode/decode checks, complete Secure Record metadata/wire reconstruction, review-driven state oracles, and confirmation-class checks. `tools/mutation_test.py` corrupts representative vectors and requires every corruption to make validation fail.
