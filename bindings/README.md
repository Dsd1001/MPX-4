# MPX/4 Transport Bindings

The MPX/4 Core Protocol is defined independently of a specific packetization boundary.

This directory is reserved for documents specifying how MPX/4 maps onto an underlying transport.

A transport-binding specification should define:

- connection establishment;
- ordering and reliability assumptions;
- mapping of Connection Preface, Handshake Messages, and Secure Records;
- transport-specific timeouts;
- path identity and reconnection behavior;
- interaction with congestion control and flow control;
- maximum record considerations;
- operational and security considerations.

The initial Core specification assumes a reliable ordered octet stream and describes TCP as the baseline binding.
