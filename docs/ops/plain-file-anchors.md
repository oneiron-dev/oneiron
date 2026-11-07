# Anchors on plain-text artifact versions

Plain-text blob artifacts use the existing numbered version chain. The
annotation doors can list line units, pin a character span, open a thread on
it, and use the existing comment and assignment lifecycle. This does not turn
enum membership into support for every artifact kind.

## Coordinates and public forms

The bytes must be valid UTF-8. A Text locator names a half-open span in the
exact stored version text. Offsets count Unicode characters, not bytes or
UTF-16 code units. A leading byte-order mark is excluded from those
coordinates. There is no line or part id. Carriage returns and newlines stay
in the text and count separately.

The typed facade form is:

```json
{"format":"text","char_start":0,"char_end":5}
```

The dedicated artifact HTTP routes use their existing `place` form:

```json
{"text":{"char_start":0,"char_end":5}}
```

`vault.artifacts.units` returns the resolved version number, its stored
content hash, and one unit per line. A line's span excludes its line break;
an empty line has no quote. Use that explicit version when opening a thread;
an omitted version on a pin selects the current head. As for the existing
formats, a pin needs a readable, non-empty quote. Invalid UTF-8 is not decoded
lossily.

## Visibility

Coordinates always refer to the stored text, even when the caller reads a
masked copy. Quotes use the existing file sight. The adapter maps raw
character boundaries to the served copy only when that copy has the same text
layout, either unchanged or with the existing mask filler in place of keys.
A handle-substituted or rebuilt copy with no such mapping yields no quote;
it never falls back to raw text or a nearby match.

The Unattached list retains its existing row admission. Dedicated HTTP reads
also project plain-text snapshots and offers for masked callers with no record
caveats, without adding record admission or dropping the listed thread.
Reattach offers first read the head through the same sight and match the
admitted projected snapshot against that projected head. Only then are match
boundaries mapped back to raw character coordinates. A sealed or withheld head
does not bypass its existing read error. Final reattachment still checks the
native stored snapshot and remains an explicit act; an offer is not an
attachment.

A masked caller's reattachment checks both the pinned and target Text span
inside the same native write transaction before comparing raw words. Hidden
or unmappable spans cannot expose that equality. Persisted key spans govern
visibility even when a secret's bytes happen to equal the mask filler. Their
stored byte offsets include any byte-order mark excluded from the locator.
Owner and granted native sights keep their existing behavior.

## Versions and scope

The Text adapter diffs lines first, then characters inside each changed run
that touches the span. Direct appends enter through the existing append hook;
the explicit annotation sweeps use the same Text context. Existing Keep and
settlement gates are unchanged. A span with no surviving characters drifts,
retaining its old version and quote for the existing Unattached workflow.
No fuzzy search automatically reattaches a drifted thread.

The text media adapter covers UTF-8 plain text beside the existing HTML and
Office readers. Code revision adapters, image locators and a Canvas body
remain separate work. The integration keeps main's Text locator, line units
and remapping; the earlier whole-file unit and `file` locator are not retained
as a second format.

Rollout needs matching engine/server and normally regenerated clients for the
Text locator variant. No organ, guest, worker, configuration, numeric limit,
default or schema-version change is needed. Source-format and generator checks
are not runtime or compiler proof.
