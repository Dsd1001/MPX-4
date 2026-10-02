## Summary

Describe the protocol or editorial change.

## Change classification

- [ ] Editorial only
- [ ] Clarification
- [ ] Compatible extension
- [ ] Incompatible draft change
- [ ] Security correction
- [ ] Test-vector update

## Protocol impact

Identify affected Sections, Frames, Parameters, Error Codes, Scheduler IDs, or transport bindings.

## Interoperability

Describe how existing and independent implementations are expected to behave.

## Transport-binding impact

Describe any change to byte-stream mapping, connection establishment, Carrier loss, replacement, or transport close behavior. Update `bindings/tcp.md`, `test-vectors/tcp-binding.json`, and `INTEROPERABILITY.md` when applicable.

## State-machine impact

Describe any change to Session, Carrier, Stream, Transmission, terminal, tombstone, or late-Frame behavior. Update `STATE-MACHINES.md` and `test-vectors/state-validity.json` when applicable.

## Security considerations

Describe any effect on authentication, confidentiality, integrity, replay handling, resource usage, or downgrade behavior.

## Checklist

- [ ] Registry assignments are updated when required.
- [ ] CHANGELOG.md is updated for normative wire or state-machine changes.
- [ ] Test vectors are added or updated when wire encoding changes.
- [ ] State-machine cases are updated when lifecycle behavior changes.
- [ ] Transport-binding vectors and interoperability cases are updated when TCP mapping changes.
- [ ] Normative MUST/SHOULD/MAY language is intentional.
