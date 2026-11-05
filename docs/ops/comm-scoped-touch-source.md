# Scoped, explicitly born touch sources

The bound batch router can project an explicitly born LastTouch whose only
noncanonical context is a non-base world. The original Put, ClaimOf edge and
native birth still land through their existing gates before its source is
created in the same writer. Other noncanonical contexts and unsupported births
keep their full native raw path.

`COMM_RECORD` has a required `source_position` key. Ordinary events without an
original head, gates and receipts encode `nil`. Every explicitly born
`TouchAsserted`, canonical base-world touches included, carries the five-element
tuple: world id, facet id, project id, native sensitivity band, and a 32-byte
admitted-origin digest. `original_head` and `source_position` must be present
together. There is no old-format reader or migration. All born source ids use
`COMM_BORN_TOUCH_EVENT` with the same typed position and origin binding.

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
erasure or runtime proof. The producer and adopter both bind the actual full
original row and native base birth. A changed row cannot be adopted merely
because it still states the same touch value. A source whose original is
missing, closed or retracted never recreates that original.

LastTouch winner selection compares the event's frozen context with every
candidate's actual CLAIM context before supersession: normalized world,
relationship, facet, project, opaque scope, native sensitivity and session tag.
This applies to both scoped events and ordinary canonical events. A base event
cannot close a world-bearing head, nor the reverse. Other communication rules
keep their existing matching and admission. Canonical born sources meet the
same original-CLAIM disclosure and audience requirements as world-bearing
ones; a COMM_RECORD-only selector cannot expose their CLAIM data.

Within one deferred batch, born and ordinary routed touch assertions share
one original-order schedule after native apply. Each earlier assertion excludes
later unprocessed born heads from its winner and supersession set. Those later
Puts remain untouched until their own source is recorded and projected. The
later assertion wins a time tie, including mixed born/routed batches. Other
event kinds keep their pre-apply phase; without born touches all routed events
keep that phase. Normal source and housekeeping passes carry no exclusion.
No runtime or full privacy claim is made.
