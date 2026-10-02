# MPX/4 Test Vectors

This directory contains machine-readable interoperability vectors for MPX/4.

Test vectors are intended to help independent implementations verify that they produce identical wire representations.

Current sets:

- [varint.json](varint.json) — MPX variable-length integer encodings and malformed inputs.
- [frame-encoding.json](frame-encoding.json) — decoded Frame encodings before Secure Record encryption.

Unless explicitly stated otherwise, test vectors are subordinate to the normative protocol specification. If a vector conflicts with the current specification, the specification controls and the vector should be corrected.
