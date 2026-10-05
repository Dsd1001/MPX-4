# MPX/4 Protocol Version 4 Stability Declaration

**Protocol:** MPX/4
**Protocol Version:** 4
**Specification revision:** Draft 11
**Stable release tag:** `protocol-v4.0.0`
**Declared:** 2026-10-06
**Status:** Stable

This document declares MPX/4 **Protocol Version 4 stable**.

Draft 11 is the frozen specification revision for Protocol Version 4. The `protocol-v4.0.0` tag identifies the source-tree release boundary covered by this declaration. This stability release does not introduce a new wire version or change the immediately preceding reviewed Draft 11 wire format, successful-handshake transcript, key schedule, Secure Record format, registry assignments, or mandatory Core semantics.

After this release boundary, the compatibility rules in [COMPATIBILITY.md](COMPATIBILITY.md) apply as stable-version requirements. Incompatible mandatory Core evolution requires a new Protocol Version.

## 1. Frozen normative document set

The following files are the normative Protocol Version 4 document set at the stable release boundary:

| Document | Role | SHA-256 |
|---|---|---|
| [SPECIFICATION.md](SPECIFICATION.md) | Core Protocol | `e3aac0ae5c1da741fd64489a6b182768e262bde14905092b37ed872dcb913863` |
| [STATE-MACHINES.md](STATE-MACHINES.md) | State machines and Frame validity | `28fd5a9b5f92068e2b0fe3f4711f12a5dbbd9b5e6dd4d526aa7ee9737e1087d3` |
| [ERROR-HANDLING.md](ERROR-HANDLING.md) | Error handling and failure scope | `a36723b4bef5158f6db36a263716d0746584ea7fbfcb06ac0dc63f906ab60ebd` |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Versioning, compatibility, registry, and extension rules | `7bf720c4ff68efd79263f149137743578b8f6b942fee3842834630c45ca6d5c0` |
| [bindings/tcp.md](bindings/tcp.md) | TCP transport binding | `1ccd6d794921c2ca7fd6f45601304ecb0e58d320e4ca19eb5bd2beef35d2b4ff` |

The Draft 11 revision label remains part of the documents for traceability. Stability changes the compatibility commitment of on-wire Protocol Version 4; it does not create a Draft 12 or a new wire Protocol Version.

## 2. Stable registry snapshot

[REGISTRIES.md](REGISTRIES.md) is the registry snapshot frozen with Protocol Version 4.

**Registry SHA-256:** `786ac7a84cbdc87a3fa2e4d9852abe1207a0edd19323ccbcdf1ca808bdbbdb81`

Within Protocol Version 4:

- an assigned numeric value MUST NOT be reassigned;
- an assigned Core meaning MUST NOT be changed incompatibly;
- removed assignments remain Reserved unless a later Protocol Version explicitly defines otherwise;
- extension-range assignments remain governed by explicit extension negotiation and do not become mandatory Core behavior merely because they are registered.

The published `RECEIVE_CAPACITY_HINT` extension assignment remains optional. It is not required for Core Protocol Version 4 conformance.

## 3. Mandatory interoperability profile

[INTEROPERABILITY.md](INTEROPERABILITY.md) is the stable Mandatory interoperability profile.

**Profile SHA-256:** `aec06b20c3b719449f970122085f6e0d82049c59e376341d4678e31396809e3a`

A conforming implementation claiming the stable Core interoperability profile MUST satisfy all Mandatory groups A–L defined there:

- A — Codec and framing;
- B — Handshake and cryptography;
- C — Single-Carrier Stream;
- D — Multi-Carrier Session;
- E — Reliability and reinjection;
- F — Flow control;
- G — Terminal behavior;
- H — Opening reordering;
- I — Tombstones;
- J — Carrier replacement;
- K — Close behavior;
- L — Negative protocol tests.

The repository profile contains 121 explicit Mandatory case IDs. At the stable release boundary, the repository Gate 4 evidence requires both implementation profiles to report 121/121 with zero model-only Mandatory cases, while preserving codec, cross-wire, and endpoint-wire evidence classes where each is the appropriate executable surface.

The stable release also retains the authenticated endpoint, sensitivity, review, recovery, cancellation, cleanup, and cross-runtime regression suites used by the repository CI. These additional suites strengthen the evidence supporting the 121-case Mandatory profile; they do not create extra wire protocol requirements beyond the normative document set.

## 4. Mandatory machine-readable vectors

The following Core JSON files are the mandatory machine-readable vector set frozen with Protocol Version 4:

| Vector | SHA-256 |
|---|---|
| [test-vectors/carrier-generation.json](test-vectors/carrier-generation.json) | `75ccbc63e1466aa711a5986989bb3e137e2ca3dd21e3e0f4b977aa68911b0014` |
| [test-vectors/close-ordering.json](test-vectors/close-ordering.json) | `abd4ca495797775b0ea75cbec36fdc120ef2cd1991ec28784e2bd0c62ef125c0` |
| [test-vectors/confirmation-validity.json](test-vectors/confirmation-validity.json) | `cf3ccafe12b1b33ad65dad99068af28985c1e5cc6751ecff758fbda6484af7a6` |
| [test-vectors/error-scope.json](test-vectors/error-scope.json) | `6021dcc87ffea1f300da66b53e3dcc9a73cba65606938c2b6bae7dab6eef26c4` |
| [test-vectors/frame-encoding.json](test-vectors/frame-encoding.json) | `387091c064836ed33ee692e5c3063580afea40c69f81c9cdd6f9ce3162f21f52` |
| [test-vectors/handshake-ambiguity.json](test-vectors/handshake-ambiguity.json) | `dcc9518011ad06e5d204c0a7e75d4a074c86c06e7f56b0614410fd5e21673709` |
| [test-vectors/handshake-reject.json](test-vectors/handshake-reject.json) | `79002353709d0005e99b311416e835245701a98407c5814d1c912668852cd0dd` |
| [test-vectors/identity-lifecycle.json](test-vectors/identity-lifecycle.json) | `614471d243aa804e0d54b6e530da58234c9804081dc528bb94735491369da62c` |
| [test-vectors/key-schedule.json](test-vectors/key-schedule.json) | `f1d5a174e70d21caf6b613e797511c86cb99abce801f7ee018b6ede5a19ae234` |
| [test-vectors/max-carriers.json](test-vectors/max-carriers.json) | `f7b9657e1a677a2b59f0d4a949f9def8f7c888f1bdbe7c1057b43764e0ed765f` |
| [test-vectors/recovery-progress.json](test-vectors/recovery-progress.json) | `9a5ac76df31fa4779023081db1aaf528825cfee6e7edec7f845bae7859dfe880` |
| [test-vectors/reordering-reliability.json](test-vectors/reordering-reliability.json) | `cbe0bd6dc2ad82a2b924ce8cf00ba664f72d0162061d89711a3a1963be0075f0` |
| [test-vectors/secure-record.json](test-vectors/secure-record.json) | `5920a5a4115f6df47f1a1f6d978c93f4b840513a2be2f052f60227086164ccf0` |
| [test-vectors/session-lifecycle.json](test-vectors/session-lifecycle.json) | `bb65263664e331768eb9a12acf3a79c6ac660dc9201bae8dfd1bb0889e06d598` |
| [test-vectors/state-validity.json](test-vectors/state-validity.json) | `dc5b51a7bd274ddcabb1d3c0da7108dfd8dd58191bec3f1c121aa5e492921177` |
| [test-vectors/tcp-binding.json](test-vectors/tcp-binding.json) | `8550690bab4335d980976803c39de216f294b40b833c53e6bd8133396a913312` |
| [test-vectors/terminal-flow-control.json](test-vectors/terminal-flow-control.json) | `2e1d47e3bd80491b7e935dde94be36661035ca1ba0a9127883b18c332590fe8c` |
| [test-vectors/transmission-allocation.json](test-vectors/transmission-allocation.json) | `4110b4bf976821fc80af656dcd3240bdfaab8f437541cb7098ae9a4b86dae954` |
| [test-vectors/varint.json](test-vectors/varint.json) | `d538fc28383dcc76192937a4d5678f44922ca76e081649f1b26947c8aa204539` |
| [test-vectors/version-compatibility.json](test-vectors/version-compatibility.json) | `f27b0d32408b41c44a2d31bd6fee108789c87fb6b3260b9fe3c7fb4686452a94` |

Extension-specific vectors, including `extensions/capacity-hint.json`, are not part of mandatory Core conformance unless the corresponding extension is negotiated.

If a machine-readable vector conflicts with the frozen normative document set, the normative documents control. Such a vector defect may be corrected editorially only when the correction does not change stable Protocol Version 4 mandatory wire behavior or semantics.

## 5. Compatibility after stability

From the `protocol-v4.0.0` release boundary onward:

- changing an existing mandatory Core field, Parameter, Frame, Error Code, state transition, transcript rule, key derivation, Secure Record rule, Stream/Carrier/Session/Transmission semantic, or failure scope incompatibly requires a new Protocol Version;
- Protocol Version 4 MUST NOT acquire a new unconditionally mandatory Core Parameter, Frame, handshake element, or semantic requirement that an older conforming Version 4 implementation would not understand;
- editorial clarification, additional non-normative examples, stronger implementation guidance, and fixes to tooling or tests MAY be published without a new Protocol Version when peer-visible mandatory behavior is unchanged;
- optional extensions MAY evolve only under the negotiation, safe-ignore, registry, and compatibility rules in [COMPATIBILITY.md](COMPATIBILITY.md);
- an extension MUST NOT silently reinterpret frozen Core semantics.

## 6. Release identity

The authoritative stable source tree is the commit referenced by the annotated Git tag `protocol-v4.0.0` and its corresponding GitHub Release.

The tag is intentionally the release identity rather than an embedded commit SHA in this file, avoiding a self-referential source-content hash. The release notes record the exact Git commit selected after the full exact-head validation and CI gates pass.

## 7. Scope of the stability claim

Stable Protocol Version 4 means the mandatory Core compatibility contract is frozen.

It does **not** by itself claim:

- production-scale capacity qualification;
- long-lived Internet-path behavior across every deployment environment;
- implementation by a separate third-party organization;
- a formal independent cryptographic audit;
- suitability for every application or threat model.

The repository contains two source/module-isolated implementations and extensive authenticated interoperability/fault evidence. That evidence supports the stable protocol declaration while remaining distinct from production acceptance and independent external audit.
