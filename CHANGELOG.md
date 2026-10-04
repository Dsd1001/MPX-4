# Changelog

All notable MPX/4 specification changes are recorded here.

MPX/4 remains in draft status. Draft revisions may make explicitly documented incompatible changes until a Protocol Version is declared stable.

## Draft 11 — 2026-10-04

Draft 11 is a freeze-preparation revision driven by the consolidated Draft 10 cross-review. It keeps Protocol Version 4 and the Draft 10 wire format while closing recovery/progress contracts and making repository validation coverage explicit and fail-closed.

### Establishment recovery and progress

- Defines the Client-side ambiguous-establishment condition when CLIENT_FINISHED was sent but SERVER_FINISHED was not authenticated.
- Recovery never treats unauthenticated HANDSHAKE_REJECT, including SESSION_NOT_FOUND, as proof that Server Session state exists or does not exist.
- Existing logical-Carrier replacement retries use a Generation above every locally accepted or ambiguity-causing attempted Generation; an ambiguous first use of a Carrier ID instead recovers through another unused Carrier ID at Generation 0.
- An ambiguous CREATE can probe the retained Session ID with an authenticated JOIN, or be locally abandoned in favor of a fresh Session ID; the ambiguous Session ID is not intentionally reused for CREATE while recovery state is retained.
- After DORMANT recovery or Carrier replacement, required Session credit, probed Stream credit, and useful TRANSMISSION_RETIRE watermarks now have eventual refresh obligations while authenticated writable Carrier state exists.
- Transmission ID allocation is tied to committing immutable reliable semantic state. Once allocated, a reliable Transmission cannot be silently abandoned; it remains outstanding until its required confirmation or Session closure.

### Stream termination and error namespaces

- FIN and RESET explicitly cross-reference the existing Stream and Session commitment/credit rules. A terminal Final Offset that raises commitment beyond retained credit is FLOW_CONTROL_ERROR; an already-established contradictory final size remains FINAL_SIZE_ERROR.
- RESET_STREAM and STOP_SENDING now name their carried reason as Stream Error Code. It is an opaque Stream/application termination reason and does not inherit Core Error Code failure scope. The VarInt wire layout is unchanged.

### Secure Record lifecycle and close ordering

- Once a send sequence number is assigned to a serialized Secure Record, that exact record is the next record emitted in that direction; implementations may not skip a generated record and continue with a later sequence number on the same Carrier.
- The TCP Client is responsible for initiating fresh Carrier replacement sufficiently before either traffic direction reaches the 2^24-record key lifetime when continued service is required. The old key is never used beyond the limit.
- CARRIER_CLOSE and SESSION_CLOSE are terminal within their Secure Record: senders place them last, and trailing authenticated Frames cannot create protocol state.
- A syntactically valid unknown extension/private reason in CARRIER_CLOSE or SESSION_CLOSE does not cancel the terminal action.

### Security and compatibility boundaries

- Draft 11 explicitly documents that Core has no on-wire PSK selector. The transport key is selected by the configured service context before Finished verification; multi-key shared listeners need external demultiplexing or a negotiated extension.
- Unaudited VERSION_NEGOTIATION still enforces local enabled/minimum policy but does not prove the highest mutually supported version. Deployments requiring strict downgrade resistance pin the permitted minimum/version until an authenticated compatible-version mechanism is defined.
- Generic extension Handshake Message insertion is not implied by registry range allocation; an extension must define negotiation, placement, transcript participation, and unsupported behavior before such a message can be used.

### Validation

- Removes protocol-validator dependence on Python assert so checks remain active under python -O.
- Follow-up conformance hardening executes all 42 declared Stream/state validity cases from their state, Frame, conditions, expected result, error, and response fields; unknown combinations fail closed.
- Terminal flow-control vectors distinguish previous authenticated End Offset, previous commitment, and established final size, including lower-Final-Offset and duplicate/no-new-commitment cases.
- Secure Record validation separately enforces protocol legality (`1 <= Ciphertext Length <= peer MAX_RECORD_SIZE`, complete Frame boundaries, valid Core/extension ranges, negotiated `MAX_FRAME_PAYLOAD`, close Reason <= 256 UTF-8 octets, and sequence number below `2^24`) in addition to AEAD consistency.
- Secure Record validation now derives directional receive limits from the authenticated CLIENT_INIT/SERVER_INIT wire, cross-checks decoded fixture metadata, selects the direction-matching traffic key/IV, decodes every known Core Frame body, and enforces CARRIER_CLOSE/SESSION_CLOSE as record-final Frames.
- Opening decisions in OPENING and OPENING_CANCEL_PENDING share the same Stream/Transmission identity validation; recovery progress checks terminal Session state explicitly; retired reliable Frames require retirement coverage or retained confirmation replay state.
- Legacy case-name-only state assertions were removed so the input-driven state evaluator is the single authority for state-validity cases.
- Mutation coverage includes paired legal/illegal Record controls, directional key context, handshake-limit metadata tampering, cancellation identity, closed-Session recovery, retired replay coverage, and lifecycle-input flips.
- Mutation tests require ordinary and optimized baseline PASS before corrupting inputs and count only explicit conformance-validation failures as successful rejection; runtime/tool failures no longer create false green results.
- Validation CI covers Python 3.11 and 3.12 without changing the Draft 11 wire format.
- Validates Secure Record Flags=0 and credit structural validity before stale/newer merge.
- Executes semantic handlers for the previously metadata-only MAX_CARRIERS, Session lifecycle, version compatibility, HANDSHAKE_REJECT, identity lifecycle, Carrier Generation, and error-scope vectors.
- Expands Core Frame vectors to PADDING, PONG, CARRIER_CLOSE, and SESSION_CLOSE, making all 18 assigned Core Frame types executable.
- Adds recovery, terminal-flow-control, Transmission-allocation, and close-ordering vectors plus matching mutation coverage.
- Gate 0 mutation coverage now includes exact-boundary positive controls for 32768-octet STREAM_DATA and 256-octet close Reason plus negative 32769/257 cases.
- Real endpoint execution uncovered and closed additional runtime gaps while eliminating model-only coverage: peer confirmation replay detail is retained until TRANSMISSION_RETIRE; safe candidate-reservation conflicts emit HANDSHAKE_REJECT instead of silent EOF; unsupported Preface versions use VERSION_NEGOTIATION without parsing pipelined CLIENT_INIT; Session Protocol Version is fixed at CREATE; Session close/failure closes all active Carriers; Stream/Transmission ID exhaustion is non-wrapping; and opening/tombstone/DORMANT retention behavior is now represented in the executable runtimes.

### Executable reference and interoperability evidence

- Adds a deliberately small Draft 11 Core-over-TCP reference Client/Server that is independent from the specification validator and uses real sockets, fresh handshake randomness, Finished authentication, AES-GCM Secure Records, explicit Session/Stream credit, reliable DATA/FIN confirmation, and SESSION_CLOSE.
- Adds a canonical-vector self-test so reference-to-reference runtime success cannot rely only on a shared implementation bug in handshake/crypto encoding.
- Adds a Gate 1 process harness that launches Client and Server separately, verifies per-Stream application bytes/digests, credit-before-DATA ordering, 16 simultaneous Streams, 1 MiB in each direction, and full-duplex overlap using each endpoint's own event order rather than cross-clock subtraction.
- Adds a TCP fault-proxy scaffold for deterministic byte fragmentation, delay/backpressure, and connection abort. The proxy does not model UDP-style Record dropping on an ordered TCP Carrier.
- CI runs both direct and fragmented-proxy Gate 1 integration on Python 3.11 and 3.12.
- Adds a Gate 2 Session-level runtime and process harness for deterministic real-TCP fault/recovery scenarios without changing the Draft 11 wire format.
- Gate 2 currently exercises sparse-ID Carrier JOIN, cross-Carrier same-Transmission reinjection and duplicate suppression, unexpected Carrier loss, higher-Generation replacement with fresh Carrier record spaces, two-stage DORMANT recovery with credit/retirement refresh, ambiguous SERVER_FINISHED loss after Server commit for both replacement and first-use Carrier identity, FIN/STOP_SENDING/RESET_STREAM supersession with late FIN reinjection and retirement-prefix closure, and Session-scoped TRANSMISSION_ID_ERROR from a never-allocated acknowledgement.
- The complete Gate 2 scenario set also runs with 257-octet endpoint TCP write fragmentation so the recovery evidence does not depend on write boundaries.
- Adds Gate 3 A–L profile execution with 121 explicit case IDs (A1–L25 as grouped by INTEROPERABILITY.md), combining real TCP evidence, canonical wire/crypto reproduction, authenticated endpoint-wire controls, and cross-runtime execution. The final Draft 11 profile contains **18 codec, 30 cross-wire, 73 endpoint-wire, and 0 model-only** case IDs; state/oracle models may supplement assertions but are no longer the sole evidence for any Mandatory case.
- Post-implementation review found and fixed real receive-path defects: DATA now enforces an established Final Offset, RESET remains authoritative for application delivery while late in-range DATA can still be acknowledged, Stream/Session credit retains and merges complete `(Consumed, Maximum)` pairs with Draft 11 window limits, and FINAL_SIZE_ERROR now executes the Session failure contract with the decoded offending Frame as Trigger Frame Type.
- Credit structural/window validation is performed in Session semantics rather than prematurely inside the Frame decoder so FLOW_CONTROL_ERROR retains Session scope and the actual Trigger Frame Type. Authentication and Record/Frame encoding failures retain Carrier scope.
- Adds `interop/endpoint_wire.py`: full CREATE/Finished plus authenticated Secure Record probes against both runtime implementations and both endpoint roles where symmetric. The aggregate currently runs 96 executions covering paired positive/negative Final Offset, RESET, credit, aggregate commitment, byte identity, Transmission-ID, Record encoding, Stream lifecycle/limit, candidate admission, shutdown, and error-scope cases.
- Adds `interop/endpoint_mandatory.py`, eliminating the remaining model-only Mandatory evidence with 43 real-runtime executions per implementation / 86 total. It covers VERSION_NEGOTIATION/HANDSHAKE_REJECT, JOIN/version consistency, Stream/Transmission ID exhaustion, Carrier capacity and replacement, confirmation retirement, opening/cancellation races, STREAM_CONSUMED, tombstones, DORMANT retirement, simultaneous candidates, EOF/half-close, and close behavior. Four formerly-model-only IDs (E4, F3, J7, K6) reuse existing authenticated endpoint-wire cases.
- Adds `interop/endpoint_sensitivity.py`: eight deliberate real-handler defects (four per runtime) must make the guarded endpoint-wire case fail, preventing a green profile from masking handler regressions.
- Adds a source-isolated second implementation under `independent/` with its own VarInt, handshake, HKDF/Finished, AES-GCM Secure Record, Core Frame, endpoint, Carrier/Session runtime, and model-zero Mandatory-profile execution. An AST import audit rejects dependencies on `reference/`, `tools/`, or validator modules; Gate 4 also requires the five critical receive/runtime handlers to be structurally non-identical by AST.
- Gate 4 now requires both 121-case model-zero profiles, 96 baseline authenticated endpoint-wire executions, 86 formerly-model-only endpoint executions, eight sensitivity controls, real-TCP A→B/B→A basic role reversal, and all five deterministic fault scenarios in direct and fragmented modes. The aggregate therefore runs 182 authenticated endpoint executions, four cross-basic runs, and twenty cross-fault scenario executions.
- Gate 4's independence claim remains source/module isolation within the same repository/project, not external organizational independence. Model-only Mandatory coverage is now zero, but codec and cross-wire remain the appropriate executable evidence for 48 of 121 Mandatory IDs, so this is not restated as "all 121 are endpoint-wire". Gate 4 does not declare Protocol Version 4 stable.

### Compatibility

Draft 11 retains development Protocol Version 4 and introduces no new Core numeric assignment or successful-handshake transcript change relative to Draft 10. RESET_STREAM/STOP_SENDING keep the same VarInt wire shape; Draft 11 clarifies that the field is a Stream/application reason rather than a Core failure-scope code. Recovery and liveness obligations are tightened before Version 4 stability.

## Draft 10 — 2026-10-04

Draft 10 closes the remaining Draft 09 reliability-prefix and confirmation-validation gaps and hardens repository validation so that reported PASS results execute the claimed positive, negative, wire, and state checks.

### FIN / RESET reliability closure

- RESET_STREAM created in response to STOP_SENDING supersedes an outstanding STREAM_FIN only for application-visible termination semantics.
- The original FIN remains an outstanding reliable Transmission and continues retransmission/reinjection with its original Transmission ID until its own TRANSMISSION_ACK arrives.
- A peer that already processed RESET acknowledges a later FIN with the same Final Offset without restoring graceful EOF.
- This fills otherwise permanent holes in the Session-wide contiguous Settled Through prefix and makes subsequent TRANSMISSION_RETIRE watermarks valid without a separate skip/supersession wire mechanism.

### Confirmation-class validation

- Each reliable Transmission retains its original Frame type and required confirmation class.
- STREAM_OPEN is settled only by STREAM_OPEN_OK or STREAM_OPEN_REJECT.
- TRANSMISSION_ACK for STREAM_OPEN, or an opening decision that references another Frame type, Stream, or never-allocated Transmission, is TRANSMISSION_ID_ERROR.
- Added `confirmation-validity.json` and explicit state/error-scope negative cases.

### Final-size errors

- Core wording now consistently classifies a conflicting established final size or DATA beyond final size as FINAL_SIZE_ERROR.

### Validator hardening

- VarInt validation now requires and executes all `vectors` and `invalid` cases; missing or empty schemas fail closed.
- Frame vectors are fully re-encoded from declared fields, checked against Registry assignments and wire bytes, then decoded back to fields.
- Secure Record validation now verifies flags, length VarInt, AAD, sequence representation, nonce, ciphertext, authentication tag, complete wire bytes, and decryption.
- Review-driven cases now run small state oracles for credit reordering, pre-open cancellation, ACK-loss retirement, FIN/RESET supersession, and confirmation class.
- Added `tools/mutation_test.py`; CI deliberately corrupts VarInt, Frame, state, and Secure Record fixtures and requires every corruption to make validation fail.

### Compatibility

Draft 10 retains Protocol Version 4 and makes no new wire assignment relative to Draft 09. The successful handshake, cryptographic vectors, Frame encodings already defined in Draft 09, and TRANSMISSION_RETIRE wire format remain unchanged. Draft 10 is wire-compatible with Draft 09 but intentionally changes edge-case reliability/error semantics before Version 4 stability.

## Draft 09 — 2026-10-04

Draft 09 closes cross-Carrier reordering, cancellation, reliable-state retirement, record-size failover, version-negotiation pipelining, and executable conformance gaps identified during Draft 07 review and revalidated against Draft 08.

### Core semantics

- STREAM_CREDIT and SESSION_CREDIT are generated monotonically but received with a component-wise merge rule: fully stale advertisements are ignored, while crossed pairs are FLOW_CONTROL_ERROR.
- Pre-open local cancellation has an explicit OPENING_CANCEL_PENDING semantic state. RESET_STREAM(0) emitted in response to pre-open STOP_SENDING is a cancellation response, not acceptance evidence; a matching later STREAM_OPEN_REJECT completes cancellation normally.
- MAX_RECORD_SIZE is Session-scoped and must be repeated unchanged on JOIN, guaranteeing that any eligible Carrier can carry an already-created Frame that satisfied Session limits.
- VERSION_NEGOTIATION now explicitly supports Preface+CLIENT_INIT pipelining: the Server may answer after parsing only the unsupported Preface, and the Client may accept VN after sending CLIENT_INIT until SERVER_INIT has been accepted.

### Transmission retirement

- Added Core Frame Type `0x1a` `TRANSMISSION_RETIRE` with one `Retired Through` VarInt.
- Each sender tracks the largest contiguous prefix of settled local Transmission IDs.
- A receiver retains enough confirmation-replay state for peer reliable Transmissions until the peer retirement watermark covers them.
- This prevents tombstone/retired-state compaction from causing an outstanding reliable terminal Transmission to lose its ability to receive a repeated confirmation after an ACK loss.

### Test and fixture corrections

- TCP binding fixtures are generated from current `key-schedule.json` and `secure-record.json`; stale Draft 06 scheduler bytes and mismatched ciphertext are removed.
- Protocol JSON integers above JavaScript's safe-integer range are represented as decimal strings.
- Added `reordering-reliability.json` and expanded state/version/error vectors.
- Added `tools/validate.py`, deterministic TCP fixture generation, and GitHub Actions validation.

### Compatibility

Draft 09 keeps development Protocol Version 4 and preserves the Draft 08 successful handshake transcript, key schedule, and baseline encrypted records. The new Core `TRANSMISSION_RETIRE` Frame is not understood by Draft 08 peers, so established-session interoperability is not guaranteed once it is sent. This incompatibility remains permitted before Version 4 stability.

## Draft 08 — 2026-10-04

Draft 08 is a Core closure / freeze-preparation revision. It does not add application features; it closes pre-establishment failure signaling and identifier-lifecycle edge cases before a future Protocol Version 4 stability review.

### Added

- Core Handshake Message Type `0x06` `HANDSHAKE_REJECT`.
- Machine-readable [handshake-reject.json](test-vectors/handshake-reject.json) cases.
- Machine-readable [identity-lifecycle.json](test-vectors/identity-lifecycle.json) cases covering Session-ID collision and Stream/Transmission exhaustion.

### HANDSHAKE_REJECT

- Carries exactly one Error Code VarInt and terminates only the current candidate Carrier handshake.
- Is unauthenticated and is not part of a successful Finished transcript.
- MUST NOT authenticate the peer, modify an existing Session, advance Carrier Generation, or trigger Protocol Version downgrade.
- Is used only when a pre-establishment failure is classifiable and a safe response can be emitted before SERVER_FINISHED; otherwise candidate transport close remains valid.
- Does not replace VERSION_NEGOTIATION for an unsupported Connection Preface version.
- Core permits INTERNAL_ERROR, PROTOCOL_VIOLATION, AUTHENTICATION_FAILED, RESOURCE_LIMIT, SESSION_NOT_FOUND, SESSION_CONFLICT, CARRIER_CONFLICT, and UNSUPPORTED_PARAMETER in HANDSHAKE_REJECT.

### Identifier lifecycle

- Transmission IDs are now explicitly consecutive positive integers beginning at 1; gaps, reuse, and wrap are forbidden.
- `2^62 - 1` is the final Transmission ID. If another reliable Transmission is required after exhaustion, the Session closes with RESOURCE_LIMIT when possible.
- Client Stream IDs remain consecutive odd values and explicitly never wrap. `2^62 - 1` is the final Stream ID; further local Stream-open requests fail without requiring Session closure.
- CREATE using a Session ID that still maps to CREATING, ACTIVE, DORMANT, CLOSING, or retained CLOSED retirement state is SESSION_CONFLICT and cannot overwrite, merge with, or reopen that state.
- Once all state for an old Session ID has been discarded, a later random collision cannot be distinguished from a fresh ID and follows normal CREATE processing.

### Corrected

- Reuse of one Transmission ID with different semantic Frame contents is consistently `TRANSMISSION_ID_ERROR`. Draft 07 Core Specification text that said PROTOCOL_VIOLATION was inconsistent with the state machine, Error Handling, interoperability profile, and test vectors.

### Compatibility

Draft 08 keeps development Protocol Version 4. Successful CREATE/JOIN handshake bytes, H0/H1/H2, Finished values, traffic secrets, keys, IVs, Frame encodings, and Secure Record vectors are unchanged from Draft 07 except revision metadata.

`HANDSHAKE_REJECT` exists only on failed candidate handshakes, so it does not alter the successful transcript. Draft 07 peers do not understand Handshake Message Type `0x06`; failed-candidate diagnostics are therefore not Draft 07/08 interoperable even though the successful baseline handshake is byte-compatible.

## Draft 07 — 2026-10-04

Draft 07 is a Core-slimming revision. It removes scheduler-mode negotiation and capacity signaling from the mandatory Core protocol so that Carrier-selection policy remains local to each sending endpoint.

### Removed from Core

- Handshake Parameter `SCHEDULER` at Draft 06 Parameter Type `0x10`.
- Handshake Parameter `PATH_CAPACITY` at Draft 06 Parameter Type `0x11`.
- Error Code `SCHEDULER_MISMATCH` at Draft 06 Error Code `0x0b`.
- The Core Scheduler-ID registry and the Core `AUTO`, `AGGREGATE`, `PROTECT`, and `WEIGHTED` mode names.
- Any requirement that both endpoints agree on or expose the same scheduling policy.

The retired Draft 06 numeric assignments remain Reserved and are not reused by Draft 07 Core.

### Core Carrier-selection model

Each endpoint chooses an eligible Carrier independently for each locally originated Transmission Attempt. Core standardizes only the invariants that local policy must preserve: Stream byte identity, Transmission identity, flow-control accounting, Carrier eligibility, Generation supersession, duplicate suppression, and Session/Stream reliability.

Round-robin, aggregate, protect, weighted, latency-aware, cost-aware, and adaptive selection are implementation policies rather than wire protocol state.

### Carrier Receive Capacity Hint extension

Draft 07 publishes the optional [Carrier Receive Capacity Hint extension](extensions/capacity-hint.md).

The extension allocates Handshake Parameter Type `0x40` from the published-extension range:

    RECEIVE_CAPACITY_HINT

The Parameter is Carrier-scoped, uses `CRITICAL=0`, and carries one configured estimate for traffic the peer sends toward the advertising endpoint. It is unilateral and safely ignorable; it does not activate a shared scheduler mode.

Transparent Relays do not participate. The hint describes the Carrier end to end and does not expose or standardize Client-to-Relay / Relay-to-Server topology segments.

An implementation may consume the hint in a local policy it calls Weighted, but the weighting algorithm remains implementation-defined.

### Cryptographic vectors

Draft 07 keeps the Draft 06 key-schedule algorithm, cryptographic algorithms, Secure Record syntax, and Frame encodings.

Because `SCHEDULER` was present in every Draft 06 Core CLIENT_INIT / SERVER_INIT transcript, removing it changes H0, Finished values, application traffic secrets, traffic keys, traffic IVs, and dependent Secure Record vectors. Draft 07 therefore publishes regenerated key-schedule and Secure Record vectors.

### Compatibility

Draft 07 remains development Protocol Version 4 and is intentionally not Core-handshake-compatible with Draft 06. This incompatibility is permitted before Version 4 stability under COMPATIBILITY.md.

After Protocol Version 4 is declared stable, removing or adding mandatory Core handshake elements would require a new Protocol Version.

## Draft 06 — 2026-10-04

Draft 06 is a stabilization revision focused on long-term protocol evolution, retained zero-Carrier Sessions, and implementation-neutral WEIGHTED capacity semantics.

### Added

- Normative [COMPATIBILITY.md](COMPATIBILITY.md) separating on-wire Protocol Version from draft specification revision.
- Immutable Session Protocol Version established by CREATE and enforced on every JOIN/replacement Carrier.
- Explicit stable-version rules defining which future changes require a new Protocol Version versus an optional negotiated extension.
- VERSION_NEGOTIATION downgrade-safety rules, including fresh-connection retry and local minimum-version enforcement.
- DORMANT Session lifecycle for retained Sessions with Active Carrier Count zero.
- DORMANT recovery rules preserving Stream, flow-control, Generation, tombstone, retired-identity, and reliable Transmission state.
- Machine-readable [session-lifecycle.json](test-vectors/session-lifecycle.json) cases.
- Machine-readable [version-compatibility.json](test-vectors/version-compatibility.json) cases.
- Machine-readable `path-capacity.json` encoding and WEIGHTED hint-availability cases (retired from the current tree by Draft 07; retained in Git history).

### Changed

- PATH_CAPACITY remains Parameter Type `0x11` with the same two-VarInt wire shape, but its fields are now endpoint-relative `Transmit Capacity Units` and `Receive Capacity Units`.
- Both Client and Server send PATH_CAPACITY for every WEIGHTED Carrier.
- PATH_CAPACITY preserves the Draft 05 configured-value ceiling: zero means no configured estimate from that endpoint for that direction; non-zero values are `1 .. 65535` units.
- WEIGHTED requires at least one applicable non-zero configured hint for each Session direction across the two endpoint advertisements.
- Conflicting local and peer capacity hints are independent authenticated hints, not a protocol conflict and not a negotiated bandwidth guarantee.
- Loss or graceful closure of the last active Carrier transitions a retained Session to DORMANT instead of leaving the zero-Carrier state ambiguously ACTIVE.
- DORMANT Sessions prohibit new Stream creation and new application DATA commitment until a Carrier returns to ESTABLISHED.
- A Session created under one Protocol Version cannot accept a JOIN/replacement Carrier using another Protocol Version, even when the endpoint supports both versions.

### Clarified

- Draft revision labels such as Draft 05 and Draft 06 are repository specification revisions and are not transmitted on the wire.
- Protocol Version 4 remains a development version until an explicit stability declaration.
- Once a Protocol Version is declared stable, adding a new unconditionally mandatory Core Parameter or changing mandatory Core semantics incompatibly requires a new Protocol Version.
- Optional negotiated extensions can evolve without changing the Core Protocol Version when an unaware peer can safely ignore or reject them according to the extension contract.
- VERSION_NEGOTIATION is unauthenticated and cannot override disabled-version or minimum-version policy.
- Authentication or post-preface protocol failure is not a downgrade signal.
- DORMANT retention duration is local implementation policy and is not a negotiated availability guarantee.

### Compatibility

Draft 06 keeps Protocol Version 4 and does not allocate a new Frame Type, Parameter Type, Error Code, or Scheduler ID.

AUTO, AGGREGATE, and PROTECT handshakes preserve Draft 05 wire bytes and cryptographic derivations; the published key-schedule and Secure Record vectors therefore retain their Draft 05 byte values with only revision metadata updated.

WEIGHTED semantics are intentionally tightened before Protocol Version 4 stability: a Draft 06 WEIGHTED peer expects PATH_CAPACITY from both endpoints and interprets its fields from the advertising endpoint's transmit/receive perspective. Draft 05 WEIGHTED behavior is therefore not the Draft 06 interoperability profile.

## Draft 05 — 2026-10-03

Draft 05 decouples Carrier identity space from active Carrier concurrency. It removes the fixed eight-Carrier Core limit and introduces bilateral MAX_CARRIERS negotiation.

### Added

- Core Handshake Parameter `MAX_CARRIERS` at Parameter Type `0x0a`.
- Mandatory CRITICAL=1 encoding for MAX_CARRIERS.
- Client Carrier Limit and Server Carrier Limit advertisements during CREATE.
- Session-wide `Effective Carrier Limit = min(Client Carrier Limit, Server Carrier Limit)`.
- Active logical Carrier counting rules independent of Carrier ID magnitude.
- Explicit slot accounting for new Carrier IDs, active replacement, inactive replacement, CARRIER_CLOSE, SESSION_CLOSE, and detected transport loss.
- Machine-readable [max-carriers.json](test-vectors/max-carriers.json) encoding and state-conformance cases.
- Mandatory interoperability tests for asymmetric negotiation, high/sparse Carrier IDs, limit enforcement, slot release, and replacement at the limit.

### Changed

- CARRIER_ID now uses the full non-zero MPX VarInt range `1 .. 2^62-1` instead of the fixed Draft 04 range `1 .. 8`.
- `Maximum Carriers per Session = 8` is removed from Core resource limits.
- Every CREATE and JOIN handshake now carries MAX_CARRIERS in both directions.
- JOIN MUST repeat each endpoint's original CREATE-time MAX_CARRIERS value; a change is SESSION_CONFLICT.
- A candidate that would increase Active Carrier Count beyond the Effective Carrier Limit is rejected with RESOURCE_LIMIT without modifying the established Session.
- A higher Generation replacing an already active logical Carrier does not consume an additional active Carrier slot.
- Replacing an inactive logical Carrier requires a free active Carrier slot at commit time.
- A closed or lost logical Carrier releases active capacity while retaining its historical Carrier ID and Highest Accepted Generation.
- Handshake transcript vectors, Finished values, application secrets, traffic keys, traffic IVs, and dependent Secure Record vectors are regenerated because MAX_CARRIERS is authenticated as part of CLIENT_INIT and SERVER_INIT.

### Clarified

- Carrier ID numeric magnitude is identity only and does not imply Carrier count.
- Sparse Carrier IDs are legal.
- HANDSHAKING candidates do not count against MAX_CARRIERS.
- Historical Carrier IDs, retained Generation state, and tombstones do not consume active Carrier slots.
- MAX_CARRIERS is an upper bound and does not guarantee admission when another valid resource or protocol rejection applies.
- Local active counts can temporarily differ because endpoints may detect transport loss at different times; the negotiated Effective Carrier Limit itself remains identical and immutable.

### Compatibility

Draft 05 preserves Draft 04 Frame encodings, Secure Record format, VarInt format, Scheduler IDs, Error Codes, and cryptographic algorithms.

Draft 05 is intentionally not CREATE/JOIN-handshake-compatible with Draft 04 because MAX_CARRIERS is a new mandatory critical Parameter. A Draft 04 endpoint that does not understand Parameter `0x0a` rejects it instead of silently assuming the obsolete fixed-eight rule.

Because MAX_CARRIERS changes the authenticated handshake transcript, Draft 04 Finished and traffic-key test vectors are not valid Draft 05 vectors even though the underlying HKDF/HMAC/AES-GCM algorithms are unchanged.

## Draft 04 — 2026-10-03

Draft 04 is a protocol-semantics and interoperability-precision revision. It preserves Draft 03 Core wire encodings, cryptographic derivations, Frame and Parameter assignments, and TCP binding framing.

### Added

- Normative [ERROR-HANDLING.md](ERROR-HANDLING.md) defining Stream-opening, Carrier, Session, and pre-establishment failure scopes.
- A complete Core Carrier Generation acceptance and replacement state machine.
- Highest Accepted Generation retention rules for each used Carrier ID.
- Atomic higher-Generation commit semantics after authenticated Carrier establishment.
- Explicit superseded-Carrier behavior.
- Generation exhaustion and no-wrap semantics.
- Protocol-level Scheduler contracts for AUTO, AGGREGATE, PROTECT, and WEIGHTED without standardizing implementation algorithms.
- Machine-readable [carrier-generation.json](test-vectors/carrier-generation.json) conformance cases.
- Machine-readable [error-scope.json](test-vectors/error-scope.json) conformance cases.

### Clarified

- The first accepted incarnation of an unused Carrier ID uses Generation 0.
- Equal Generation is always a Carrier-incarnation reuse conflict, even after the earlier transport is lost or closed.
- A failed replacement candidate does not advance Generation and does not mutate the existing Session.
- A higher Generation supersedes lower Generations only after the candidate reaches ESTABLISHED.
- Superseded Carriers receive no new Attempts, contribute no new path samples, and cannot create new protocol state after Generation commit.
- Replacement preserves Stream state, flow-control state, tombstones, retired identities, Scheduler ID, and the Session-wide Transmission-ID namespace.
- PONG is returned on the same Carrier as its PING when a response is sent; Core does not define probe cadence, timeout count, or path-quality thresholds.
- STREAM_OPEN_REJECT Core reasons and their failure scope.
- FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR, and TRANSMISSION_ID_ERROR are Session-scoped.
- FRAME_ENCODING_ERROR and authentication/integrity failure are Carrier-scoped.
- Candidate JOIN errors do not alter an existing Session.
- SESSION_CLOSE is required for Session-scoped errors when an authenticated writable Carrier is available.
- Scheduler algorithms, scoring functions, weight normalization, retry timers, probe intervals, queue models, and congestion policies remain implementation-defined.

### Interoperability

Draft 04 extends the Mandatory Carrier-replacement and negative-protocol test groups with:

- first-Generation validation;
- equal-Generation non-reuse after loss;
- failed-candidate non-mutation;
- superseded-Carrier rejection behavior;
- replacement preservation of Session state;
- exact Core error scopes and close actions;
- Session-error atomicity across multiple Carriers.

### Compatibility

Draft 04 is wire-compatible with Draft 03.

No new Core Frame Type, Handshake Parameter Type, Error Code, or Scheduler ID is allocated by this revision.

Implementations that already encode Draft 03 correctly can advance to Draft 04 without changing the MPX/4 wire codec or cryptographic vectors, but must implement the tightened Carrier Generation, error-scope, measurement, and Scheduler semantic rules.

## Draft 03 — 2026-10-03

Draft 03 adds the normative TCP transport binding and a common interoperability profile. It does not change the Draft 02 Core Frame layouts, Secure Record cryptography, Stream state semantics, or existing registry assignments.

### Added

- Normative [MPX/4 over TCP](bindings/tcp.md) transport binding.
- [INTEROPERABILITY.md](INTEROPERABILITY.md) with Mandatory Core interoperability test groups.
- TCP byte-stream parsing rules independent of TCP segment, write, and receive-call boundaries.
- Explicit handling for incomplete handshake messages and partial Secure Records.
- Carrier-loss and replacement behavior over TCP.
- TCP half-close rules.
- Graceful CARRIER_CLOSE and SESSION_CLOSE mapping to TCP teardown.
- TCP_NODELAY and TCP keepalive operational guidance.
- Lower-layer multipath interaction guidance.
- TCP Carrier example.
- Machine-readable TCP fragmentation, coalescing, and mid-record EOF vectors.

### Clarified

- One TCP connection maps to exactly one MPX Carrier.
- Carrier identity is CARRIER_ID plus CARRIER_GENERATION, not the TCP four-tuple.
- A replacement Carrier never resumes the failed Carrier's cryptographic record stream.
- Replacement begins with a new handshake, fresh keys, and Record Sequence Number 0.
- Bare TCP EOF is Carrier loss, not MPX graceful close.
- TCP half-close does not substitute for any MPX Stream or Session terminal Frame.
- MPX protocol size limits are independent of TCP MSS and path MTU.
- MPX flow control does not replace TCP congestion control.
- MPX/4 Draft 03 does not assign a well-known TCP port.

### Interoperability

Draft 03 defines Mandatory test groups for:

- codec and framing;
- handshake and cryptography;
- single-Carrier Streams;
- multi-Carrier Sessions;
- retransmission and reinjection;
- flow control;
- terminal behavior;
- opening reordering and cancellation;
- tombstones and retired identities;
- Carrier loss and replacement;
- close behavior;
- negative protocol tests.

### Compatibility

Draft 03 preserves Draft 02 Core wire encoding and state semantics.

A Draft 02 implementation can generally advance to Draft 03 without changing its Core encoder or cryptographic vectors, but must satisfy the normative TCP binding when claiming TCP interoperability.

## Draft 02 — 2026-10-02

Draft 02 is a state-machine and terminal-semantics revision. It does not change the Draft 01 cryptographic profile, Secure Record encoding, VarInt encoding, or Core Frame wire layouts.

### Added

- Normative [STATE-MACHINES.md](STATE-MACHINES.md).
- Explicit Session and Carrier lifecycle states.
- Separate Stream opening state and independent send/receive direction state machines.
- Frame-validity matrices for opening, active, terminal, tombstone, and retired states.
- Acceptance-evidence rules for cross-Carrier reordering around STREAM_OPEN_OK.
- Pre-open RESET_STREAM and STOP_SENDING cancellation rules.
- Explicit behavior for late DATA after FIN and RESET.
- TRANSMISSION_ACK validity rules for outstanding, settled, compacted, and never-allocated Transmission IDs.
- Tombstone entry conditions and minimum retained semantic state.
- Retired Stream identity rules that prevent Stream-ID reuse without requiring full Stream state forever.
- Deterministic state-error precedence.
- Machine-readable state-validity cases.
- Terminal Stream lifecycle example.

### Registry changes

- Added STREAM_STATE_ERROR at 0x0e.
- Added FINAL_SIZE_ERROR at 0x0f.
- Added TRANSMISSION_ID_ERROR at 0x10.

### Clarified

- A FIN establishes final size even when earlier DATA is still missing.
- DATA below a FIN final size can arrive later and fill holes.
- DATA arriving after RESET has no application delivery effect.
- Terminal reliable Frames are retransmitted with the same Transmission ID.
- A Stream ID remains permanently used after rejection or retirement.
- Detailed tombstones can be compacted only after terminal reliability and receive accounting are settled.
- Retired identities never recreate application Stream state.

### Compatibility

Draft 02 preserves the Draft 01 wire encodings for existing handshake messages, Secure Records, Parameters, and Frames.

Implementations that follow Draft 01 wire encoding but not Draft 02 state rules can still fail interoperability under cross-Carrier reordering or late terminal traffic.

## Draft 01 — 2026-10-02

Draft 01 is a precision and interoperability revision. It intentionally adds no new transport feature set.

### Changed

- Made shortest-width VarInt encoding mandatory and non-canonical encodings invalid.
- Defined canonical handshake Parameter ordering and duplicate-Parameter rejection.
- Defined directional semantics for MAX_FRAME_PAYLOAD, MAX_RECORD_SIZE, and MAX_STREAMS.
- Defined PATH_CAPACITY wire format and 0.1 Mbit/s capacity units.
- Replaced the conceptual key schedule with an exact HKDF-SHA256 derivation.
- Defined exact CLIENT_FINISHED and SERVER_FINISHED calculations.
- Defined application traffic key and IV derivation.
- Defined Secure Record Flags, length semantics, sequence-number origin, nonce construction, AAD, tag length, and per-key record limit.
- Clarified that one Transmission represents one reliable logical Frame and that retransmission/reinjection retain the same Transmission ID.
- Introduced the local Attempt concept for individual Carrier sends.
- Required Session-wide monotonically allocated, non-reused Transmission IDs.
- Added a reliable-control confirmation table.
- Defined Stream-ID allocation and out-of-order STREAM_OPEN handling across Carriers.
- Defined duplicate and overlapping STREAM_DATA semantics.
- Defined exact Stream and Session credit accounting.
- Defined CREDIT_PROBE behavior.
- Split CONNECTION_CLOSE into CARRIER_CLOSE and SESSION_CLOSE.
- Defined Carrier-scoped versus Session-scoped protocol errors.
- Expanded bidirectional Stream lifecycle and final-size rules.
- Defined same-Carrier acknowledgement guidance for unambiguous path measurement.
- Made registry allocation ranges explicit.

### Registry changes

- Added CARRIER_CLOSE at Frame Type 0x03.
- Added SESSION_CLOSE at Frame Type 0x04.
- Removed Draft 00 placeholder allocations for unspecified path-management Frames.
- Returned unspecified Datagram and KEY_SHARE Parameters to reserved space.
- Returned implicit initial-credit Parameters to reserved space; Draft 01 uses explicit credit Frames.

### Test material

- Updated VarInt and Frame vectors to Draft 01.
- Added a complete key-schedule / Finished test vector.
- Added an AES-256-GCM Secure Record test vector.

### Compatibility

Draft 01 is not wire-compatible with the Draft 00 document.

No stable MPX/4 wire-compatibility commitment existed for Draft 00.

## Draft 00 — 2026-10-02

Initial publication of the MPX/4 working specification.

### Added

- Session, Carrier, Stream, Transmission, Frame, and Secure Record abstractions.
- MPX/4 Connection Preface and version-negotiation model.
- 1/2/4/8-octet MPX VarInt encoding.
- CLIENT_INIT, SERVER_INIT, CLIENT_FINISHED, and SERVER_FINISHED handshake state machine.
- Extensible handshake Parameter format with a CRITICAL flag.
- Session creation and authenticated Carrier joining.
- Carrier ID and Carrier Generation model.
- Initial HKDF-SHA256 and AES-256-GCM security design.
- Secure Records capable of carrying multiple complete Frames.
- Typed Frame encoding using VarInt Type and Length fields.
- Reliable ordered Stream model.
- Stream and Session flow-control concepts.
- Carrier-aware scheduling, retransmission, and reinjection concepts.
- Initial protocol registries.
