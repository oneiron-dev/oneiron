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

Before activation, the implementation still needs the original head's separate
private-thread, derived-source and owner-audience read obligations, and native
source mutation/erase continuity, to be qualified and carried through. The
world-bearing producer, adopter and context-specific LastTouch matcher are not
wired in this source-only foundation. No runtime or full privacy claim is made.
The ordinary canonical source path still uses its existing identity and checks.
