# Signed Connect origin positions

A Connect export can carry the stored birth positions of the NOTEs, ASSETs
and source-bound ASSET_TEXTs (captions) that the same guest export carries.
Without one, such a row lands with no birth facet, so only the receiver's
owner can read it. With one, a reader the receiver's grants admit to that
foreign world reads it too (ARCH-0043: guest content "is available when the
user or agent brings that world into scope"). The `origin_positions` Loro root is inside the existing signed
ConnectWindow update. It is not a new signature, permission, wire tag or side
table.

## The source side

The source compares each exported carrier with its current canonical row on
one read snapshot. The witness binds:

- the full metadata header, and the body or file manifest;
- the masking-safe birth process, time and input hash;
- the stored scope and the one birth facet. A guest export never carries
  the row's `FacetOf` edge, because the FACET row sits in base reality, which
  the window does not read. So the position names the facet, and the window
  signature covers it;
- for a caption, its exact `DerivedFrom` set. Every source must be a live
  ASSET under the same facet, with a position of its own in the same window.

An ASSET takes its worlds from its live `InWorld` edges, and a caption takes
the worlds all its sources share (FIX 22223). The witness holds each row at
the worlds that both the grant and the window's world read. The text fence
holds each source of a caption there too, so a caption whose source ASSET is
in two worlds still leaves in the window's one. The scoped-read text fence
(`records_in_scope`) holds the sources at the door's worlds in the same way.

The export carries a kept row's `InWorld` edge to the window's own world,
although the WORLD row sits in base reality and does not leave. Guest
admission rewrites that edge to the receiver's foreign copy of the world. The position
carries the one world the row has there. A row that is only in base reality
carries no position, because no Connect grant names base reality. A witness
never infers a position from peer-provided edges, and never turns an
unstamped row into a local birth.

## The receiver side

Only the verified Connect branch that imports at once calls the receiver
importer. In its writer, the importer checks these again: the current pact,
the pinned source key, the epoch and the unchanged live local grant. It
compares the signed carriers, birth incarnations and source set with the
current rows. A `FacetOf` edge the receiver stores for the row must name the
signed facet. The receiver does not hold the sender's FACET, so it can hold no
`FacetOf` edge to it. It keeps the signed facet beside the stamp instead
(`scope:origin_facet:v1:`), where `birth_facet` reads it, and retires it with
the stamp. A file ASSET also needs its exact bound reference, its
complete current descriptor and a successful streaming check of the resident
file.

A position must name the window's signed world (`world_ref`). It lands in
this vault's foreign copy of that world (`foreign_world_for` over the
authenticated source vault). That is the same world the guest admission
rewrites the row's `InWorld` edges to, so the stamp and the live worlds agree.
The importer installs a position only where the row already sits in that
foreign world. An `InWorld` edge waits while this vault holds no WORLD row
for its copy of the world. Until it lands, the row keeps no position, and
only the owner reads it, rather than reading as base reality.
The other signed axes stay unchanged. Audience and sensitivity are not
recipient permissions.

The importer installs positions beside matching rows in the same writer. It
never overwrites a conflicting position. It checks source positions first. A
caption gets its position only beside all its matching source positions. A
later content write keeps the verified foreign position; it does not replace
it with a new base birth. Every normal read still checks the current reader's
six axes, every live readable source and causal admission.

Missing or invalid witness evidence does not refuse the raw Connect export or
import. A failed witness pass records a warning with no values, and the raw
operation goes on unchanged. Generic federation admission does not keep or
forward the new root as authority.

## Boundaries

This covers the immediate Imported case, with current matching caption and
source rows and resident file bodies. These are separate work: Deferred and
Pending replay, a body that arrives later, unsigned live delivery, and origin
positions over more than one hop.

There is no deployment setting, new numeric limit, format compatibility
reader, migration or retention rule. No tests were added or run (build rule).
