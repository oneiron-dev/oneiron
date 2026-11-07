# Calendar archive provenance

An imported `calendar.passport` can carry `source: {artifact, version}`. It names
the immutable BLOB_ARTIFACT version from which the passport's applied content was
parsed. The artifact is a canonical entity id and the version is positive. This
is provenance, not a grant, a dependency edge, or a source-erasure rule.

## Producers

- A feed poll carries the artifact and version returned by the raw archive write.
- An owner upload or instance amendment carries the exact version that the owner
  read through the existing scoped blob-version door.
- A connector pull carries the pair returned by its resource archive write.
- Authored booking, invite, and outbound-receipt passports have no imported source.
  A record-only admission with no archived bytes also has no imported source.

The `hex#vN` source labels and existing `source_record_id` / `importSource` strings
remain projections. They are not parsed to manufacture the typed pair.
`content_hash` retains its existing meaning; an inbound passport's canonical
VEVENT hash is not a hash of the whole raw archived file.

## Updates and reads

The pair moves with an applied passport revision through the existing screen and
Gate. An unchanged SEQUENCE/hash poll still writes no passport. A source-absence
head clones its prior content source: the omitted event's content did not come
from the feed that proved its absence. That omitting feed remains cited by the
existing admission evidence.

A connector's archived-source reader keeps its existing local remote-object
precedence. When it reads a passport with a typed source, it asks the blob store
for that exact version. It does not substitute the artifact's current head or
fall back to the same passport's locator if that version is absent. Admissions
without a typed source retain their existing locator read. Existing blob-store
integrity checks and caller admission are unchanged.

No `DerivedFrom` edge is added. Imported EVENT visibility, Native/Imported origin,
source-withdrawal handling, edits, and cancellation remain unchanged. Broader
explicit source-erasure semantics remain open under FIX4250. This document makes
no runtime or whole-erasure claim.

## Integration

The optional source is current metadata, not an old-format reader or a migration.
Deploy matching engine/server and generated clients when rollout is authorized.
Keep the CAL-09 screener, authenticated operation, sealed calendar literals, and
moved connector admission helpers when integrating another calendar change.
