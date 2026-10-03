# MPX/4 Versioning and Compatibility

**Document:** MPX/4 Versioning and Compatibility
**Revision:** Draft 06
**Protocol Version:** 4
**Status:** Normative Working Draft

This document is a normative companion to [SPECIFICATION.md](SPECIFICATION.md). It defines the relationship between the on-wire Protocol Version, draft specification revisions, Core evolution, and extensions.

## 1. Protocol Version versus draft revision

The Connection Preface carries a **Protocol Version**.

The repository's labels such as Draft 05 and Draft 06 are **specification revisions** and are not transmitted on the wire.

A draft revision and a Protocol Version are therefore different concepts.

During development before a Protocol Version is declared stable, two draft revisions using the same Protocol Version MAY intentionally be incompatible. Such incompatibility MUST be documented in CHANGELOG.md.

Once a Protocol Version is declared stable, its mandatory Core wire syntax and mandatory Core semantics are frozen by the rules in this document.

## 2. Session Protocol Version

CREATE establishes an immutable **Session Protocol Version** equal to the Protocol Version in the Connection Preface of the first Carrier that establishes the Session.

Every JOIN or replacement Carrier for that Session MUST use the same Protocol Version.

A candidate Carrier using a Protocol Version unsupported by the endpoint is handled by VERSION_NEGOTIATION before Session attachment.

If an endpoint supports the candidate Protocol Version but the candidate later identifies a Session created under a different Protocol Version, the candidate MUST be rejected with SESSION_CONFLICT. The existing Session MUST NOT be modified.

A Session Protocol Version is never renegotiated by JOIN, Carrier replacement, scheduler selection, or an extension.

## 3. VERSION_NEGOTIATION

VERSION_NEGOTIATION is connection-scoped and unauthenticated.

It may be sent only after a valid MPX magic value and before CLIENT_INIT for that candidate Carrier.

A Client receiving VERSION_NEGOTIATION:

- MUST treat the message only as a list of versions the peer claims to support;
- MUST NOT treat it as authenticated peer identity;
- MUST NOT enable a locally disabled version;
- MUST NOT select a version below a locally configured minimum acceptable version;
- SHOULD select the highest mutually supported permitted version when retrying;
- MUST perform any retry on a fresh underlying transport connection with a fresh Connection Preface and fresh handshake state.

An authentication failure, Secure Record failure, or other post-preface protocol failure MUST NOT be interpreted as permission to downgrade the Protocol Version automatically.

## 4. Stable-version compatibility rules

After a Protocol Version is declared stable, the following changes require a new Protocol Version:

- changing the encoding or semantic interpretation of an existing mandatory Core field, Parameter, Frame, Error Code, or state transition in a way that can change peer-visible behavior;
- adding a new mandatory Core handshake element that an older conforming implementation would not understand;
- removing a mandatory Core element;
- changing transcript construction, key derivation, Secure Record syntax, or mandatory cryptographic behavior incompatibly;
- changing Stream, Carrier, Session, Transmission, or flow-control semantics such that two conforming implementations of the same version could interpret the same authenticated bytes differently.

The following changes do not by themselves require a new Protocol Version:

- editorial clarification that does not change peer-visible behavior;
- additional non-normative examples;
- new optional extensions that are explicitly negotiated or safely ignored under existing extension rules;
- new registry assignments in extension ranges whose use is negotiated;
- stronger implementation guidance that does not alter mandatory wire behavior.

A stable Protocol Version MUST NOT acquire a new unconditionally mandatory Core Parameter or Frame through a later editorial revision.

## 5. Critical Parameters

The CRITICAL flag provides safe handshake rejection for an unknown Parameter, but it is not a substitute for Protocol Versioning after a version is stable.

Before stability, a draft MAY introduce a new mandatory critical Parameter while retaining the same development Protocol Version, provided the draft incompatibility is explicit.

After stability, adding a mandatory critical Core Parameter requires a new Protocol Version.

Optional Parameters MAY use CRITICAL=0 only when an endpoint that ignores the Parameter can still interoperate correctly.

## 6. Extensions

An extension MUST define how support is established before its semantics become required.

An extension MAY use:

- an optional handshake Parameter;
- a published extension Frame Type;
- a published extension Error Code;
- a published scheduler profile;
- another explicitly defined negotiation mechanism.

An extension MUST NOT assume that the peer implements it merely because both endpoints use the same Core Protocol Version.

If ignoring an extension would cause the endpoints to interpret authenticated state differently, the extension MUST use explicit negotiation or a critical handshake signal.

Private Use values are interoperable only within the separately agreed private profile that defines them.

## 7. Registry stability

Within a stable Protocol Version:

- an assigned numeric value MUST NOT be reassigned;
- the semantic meaning of an assigned Core value MUST NOT be changed incompatibly;
- a removed assignment remains Reserved unless a later Protocol Version explicitly defines otherwise.

Draft revisions before stability MAY change assignments, but every such change MUST be recorded in CHANGELOG.md and reflected in machine-readable vectors.

## 8. Cross-version Session isolation

Session state is interpreted only according to its Session Protocol Version.

An implementation supporting more than one Protocol Version MUST keep version-specific parsing and state rules logically separated.

A Carrier using one Protocol Version MUST NOT inject Frames, credit, Transmission acknowledgements, Carrier Generation state, or close state into a Session created under another Protocol Version.

## 9. Stability declaration

A future specification revision may declare Protocol Version 4 stable.

That declaration SHOULD identify:

- the exact normative document set;
- the registry snapshot;
- mandatory interoperability test groups;
- mandatory machine-readable vectors;
- the extension and versioning policy that remains applicable after stability.

Until such a declaration, MPX/4 Version 4 remains a development protocol version and draft revisions may still make explicitly documented incompatible changes.
