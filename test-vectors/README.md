# MPX/4 Test Vectors

This directory contains machine-readable interoperability vectors for MPX/4.

The vectors allow independent implementations to verify that they produce identical canonical encodings and cryptographic derivations.

Current sets:

- [varint.json](varint.json) — canonical MPX variable-length integer encodings and invalid inputs.
- [frame-encoding.json](frame-encoding.json) — plaintext Frame encodings before Secure Record encryption.
- [key-schedule.json](key-schedule.json) — Draft 02 handshake transcript, Finished values, application secrets, traffic keys, and traffic IVs.
- [secure-record.json](secure-record.json) — Draft 02 AES-256-GCM nonce, AAD, ciphertext, tag, and complete wire Record.
- [state-validity.json](state-validity.json) — lifecycle and late-Frame conformance cases from the Draft 02 state-machine supplement.

Unless explicitly stated otherwise, test vectors are subordinate to the normative protocol specification. If a vector conflicts with the current specification, the specification controls and the vector must be corrected.

## Validation order

An implementation can validate interoperability in this order:

1. VarInt parsing and canonical encoding.
2. Frame encode/decode.
3. Handshake message and Parameter encoding.
4. Draft 02 key schedule and Finished authentication.
5. Secure Record encryption and decryption.
6. Stream state and late-Frame validity.

A failure at an earlier layer should be corrected before using later cryptographic vectors.
