# Scoped touch source format: source-only foundation

The bound batch router still keeps noncanonical touches on its full native raw
path. This foundation does not enable world-bearing touch routing or projection.
It must not be released as a complete scope-aware communication feature.

`COMM_RECORD` has a required `source_position` key. Ordinary events, gates and
receipts encode `nil`. A scoped, explicitly born `TouchAsserted` can instead
carry the five-element tuple: world id, facet id, project id, native sensitivity
band, and a 32-byte admitted-origin digest. This requires `original_head`.
There is no old-format reader or migration.

The digest covers the actual original stored row and its immutable base birth.
The scoped source identity binds the original id, digest, frozen position and
normalized touch tuple. These are data identities, not grants. A new scope stamp
requires the live original CLAIM, its actual native birth, matching touch value,
standing state, and its `ClaimOf` edge. A consumed rewrite retains the accepted
stamp and cannot change the bound fields by treating metadata as authority.

The physical row and stamp kind remain `COMM_RECORD`. Its disclosure position
retains the original CLAIM band. Native scope reads and export require both the
frozen position and the current original CLAIM's effective position. Missing,
erased or retyped originals provide no source disclosure. Required value sets
are combined as record requirements, not as capability intersections. The
higher sensitivity classification remains required. Capability `Scope::meet`
is unchanged. The relationship reader also uses the actual current original
CLAIM's native relationship and private-scope fields.

Reader-side source code now carries the actual current original CLAIM's full
row from the same content view and transaction into the existing audience
predicate, under the same credential and held authority. Its private-thread,
own-entry, world, room and peer checks remain conjuncts of the touch's own
checks. The original must be a live CLAIM, so that forwarding cannot enter
another scoped-touch source edge.

The native word-source and body-cover ports also expose the original as the
touch's source. Existing thread and own-entry walks retain their base-plus-view
rules, visited sets and source ordering. The existing cover stack retains its
base-store reads and cycle checks; the direct original-row audience check is
the additional actual-view check, not a replacement for base obligations. An
unavailable recognized source is unresolved, not an ordinary event.

The consumed-event rewrite preserves the bound key and tuple. No other native
COMM tuple rewrite was found in the bounded source map; this is not a global
erasure or runtime proof. The world-bearing producer, adopter and
context-specific LastTouch matcher are not wired in this source-only
foundation. No runtime or full privacy claim is made. The ordinary canonical
source path still uses its existing identity and checks.
