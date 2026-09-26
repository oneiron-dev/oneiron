//! The one edge-kind list: each variant with its stored byte and its snake_case
//! name, generating `EdgeKind` and every name and number lookup.

/// Generates [`EdgeKind`] from one line per variant, `Variant = byte => "name"`,
/// together with `ALL`, `name`, `from_name`, `try_from_u8` and `from_wire`.
/// A new kind is one new line here and nothing else in the name tables.
macro_rules! edge_kinds {
    ($($(#[$doc:meta])* $variant:ident = $byte:literal => $name:literal,)+) => {
        /// Relationship kind used by graph edges.
        ///
        /// Storage ABI: these discriminants are pinned to the ARCH-0034 `edgeKinds`
        /// registry. They are encoded into `edges_out`/`edges_in` keys and EdgeRef/CRDT
        /// edge-key refs; vaults written with the pre-M0-1 order need the M0-4
        /// schema-version migration (ONE-1081) before those bytes are read under this
        /// ordering.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum EdgeKind {
            $($(#[$doc])* $variant = $byte,)+
        }

        impl EdgeKind {
            /// Every edge kind, in stored-byte order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The kind's snake_case name, the spelling canon's `edgeKinds`
            /// table uses and every name-carrying door accepts.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// Parses a snake_case name; any other spelling is `None`.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Converts a stored byte into an edge kind.
            #[must_use]
            pub const fn try_from_u8(value: u8) -> Option<Self> {
                match value {
                    $($byte => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Converts a host-boundary number (N-API, FFI) into an edge kind:
            /// the stored byte widened to `u32`, so any value above `u8::MAX`
            /// is `None`.
            #[must_use]
            pub fn from_wire(value: u32) -> Option<Self> {
                u8::try_from(value).ok().and_then(Self::try_from_u8)
            }
        }
    };
}

edge_kinds! {
    /// Entity was authored by another entity.
    AuthoredBy = 0 => "authored_by",
    /// Entity is scoped to another entity.
    ScopedTo = 1 => "scoped_to",
    /// Entity is part of another entity.
    PartOf = 2 => "part_of",
    /// Entity supersedes another entity.
    Supersedes = 3 => "supersedes",
    /// Entity belongs to another entity.
    BelongsTo = 4 => "belongs_to",
    /// Entity is a claim of another entity.
    ClaimOf = 5 => "claim_of",
    /// Task is a child of another task (tree hierarchy).
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.");
    /// read via the dedicated `subtree` / `ancestors` tree APIs.
    ChildOf = 6 => "child_of",
    /// Task is assigned to a machine for execution.
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.").
    AssignedTo = 7 => "assigned_to",
    /// Entity is derived from another entity.
    DerivedFrom = 8 => "derived_from",
    /// Entity mentions another entity.
    Mentions = 9 => "mentions",
    /// Entity is about another entity.
    About = 10 => "about",
    /// Entity supports another entity.
    Supports = 11 => "supports",
    /// Entity opposes another entity.
    Opposes = 12 => "opposes",
    /// Entity participates in another entity.
    ParticipatesIn = 13 => "participates_in",
    /// Entity is attached to another entity.
    Attached = 14 => "attached",
    /// Person is employed by an organization.
    EmployedBy = 15 => "employed_by",
    /// Person has a behavioral facet.
    HasFacet = 16 => "has_facet",
    /// Claim is scoped to a facet.
    FacetOf = 17 => "facet_of",
    /// Person exists in a world context.
    InWorld = 18 => "in_world",
    /// Relationship is set in a world context.
    SetIn = 19 => "set_in",
    /// Two PERSON entities are the same person across vaults (ONE-1414).
    ///
    /// A structural, NON-TRAVERSING identity link: `lambda_for_kind` is
    /// `None`, which IS the no-pooling contract. The link states coreference
    /// and nothing else — no claim of either endpoint is copied, rewritten,
    /// re-sourced, or re-worlded, and retrieval seeded on one endpoint never
    /// reaches the other's claims through it. It carries no stored-weight
    /// prior (writers pass an explicit `0.0`), and its status and per-pact
    /// share consent live in `core.coreference.*` edge-subject Claims rather
    /// than in the edge bytes.
    SameAs = 20 => "same_as",
    /// Entity was merged into a surviving entity (ARCH-0055 r1). Canonical
    /// D11 redirect edge — sole source of truth, no body-field twin; the
    /// source entity is a `merged` redirect shell, never a tombstone.
    /// Writes are reserved to the identity-topology apply/undo door.
    MergedInto = 21 => "merged_into",
    /// Entity was split into a head entity (ARCH-0055 r2). Canonical D11
    /// redirect edge — the original resolves to its head SET. Writes are
    /// reserved to the identity-topology apply/undo door.
    SplitInto = 22 => "split_into",
    /// Task is blocked by another task — a directed TASK → TASK ordering
    /// dependency; wave DAGs ride it. Never traversed by PPR or the
    /// context-pack walk (contract `lambda: null`, "Not traversed."), like
    /// `child_of`. Readiness stays COMPUTED at read time over task status
    /// plus outgoing `blocked_by` edges (ARCH-0068 §RC5): this edge is the
    /// sole source of truth, with no stored counter, `blocked` status, or
    /// materialized projection twinning it.
    BlockedBy = 23 => "blocked_by",
    /// Readiness dependency `blocker → blocked` over CODE entities
    /// (ARCH-0050 R6 L2 addendum, ONE-1608). NOT the reverse of
    /// [`Self::BlockedBy`], which is the TASK-plane ordering relation on
    /// byte 23: this byte is the L2 code-memory readiness edge and the two
    /// never share a door.
    ///
    /// Closed, authority-gated, acyclic, non-decaying, and never traversed by
    /// PPR (`lambda_for_kind` is `None`). Both generic public doors reject it
    /// (`validate_public_edge_kind`); the only writers are
    /// `code_memory::insert_blocks_edge` / `remove_blocks_edge`, which bind
    /// the actor entity to its asserted
    /// [`EdgeActorClass`](crate::edge::EdgeActorClass) and refuse a
    /// permit-requiring `ClaimSource`. Local-only in v1: sync reverse
    /// rematerialization skips it.
    Blocks = 24 => "blocks",
    /// A completed task brief discharges the target `commitment.record`
    /// CLAIM (CMT-4, ONE-1541).
    ///
    /// Structural and never traversed by PPR (`lambda_for_kind` is `None`):
    /// a brief that happens to discharge an obligation is not evidence that
    /// the two share retrieval relevance. It carries no stored-weight prior
    /// — the validated door writes an explicit `1.0` — and both generic
    /// public doors reject it (`validate_public_edge_kind`), leaving
    /// `commitment_lifecycle::link_brief_fulfillment` as the sole writer.
    Fulfills = 25 => "fulfills",
    /// Inverse traversal edge: this commitment is discharged BY the target
    /// task brief (CMT-4, ONE-1541).
    ///
    /// Deliberately NOT a creation-causation claim — the brief did not cause
    /// the commitment to exist, it closed it. Same trust class, layout and
    /// non-traversal contract as [`Self::Fulfills`], and written only in the
    /// same validated transaction as its forward twin.
    DischargedBy = 26 => "discharged_by",
    /// Record-to-parent edge in the conversation DAG.
    Parent = 27 => "parent",
    /// Sub-session-to-spawning-record edge.
    SpawnedBy = 28 => "spawned_by",
    /// Addressing, never a visibility restriction.
    AddressedTo = 29 => "addressed_to",
    /// Reply pointer, independent of the canonical parent.
    RepliesTo = 30 => "replies_to",
}
