//! Exhaustive tables over [`EdgeKind`]. `EdgeKind` is `#[non_exhaustive]`, so
//! a match that names every kind compiles only in this crate: the PPR
//! per-kind budget and the kinds the public memory door accepts live here,
//! re-exported at their old `oneiron` paths (`ppr::policy`,
//! `code_run::dispatcher::memory_verbs`).

use crate::edge::EdgeKind;
use crate::error::{Error, Result};

/// Per-kind λ_τ traversal budget (ARCH-0039 Layer 1). The values are the
/// LITERAL `edgeKinds.lambda` column of the pinned contract module
/// (`oneiron-docs` `site/src/data/oneiron-contracts.ts`):
///
/// - `None` — the kind is NEVER traversed by PPR (`child_of`, `assigned_to`,
///   `blocked_by`; contract `lambda: null`, "Not traversed."). Tree queries go
///   through the dedicated `subtree` / `ancestors` read APIs instead, and
///   TASK readiness is computed at read time over `blocked_by`.
/// - `Some(0.0)` — `opposes` blocks propagation at the KIND level regardless
///   of the stored per-edge weight byte (contradiction isolation).
/// - The five world-model kinds carry pinned ARCH-0039 budgets that
///   deliberately DIFFER from their stored-weight priors (`pprWeight`):
///   `employed_by` λ = 0.10 (prior 0.8); `has_facet` / `facet_of` /
///   `in_world` / `set_in` λ = 0.05 (prior 0.7). Do NOT derive this table
///   from `EdgeKind::default_weight`.
pub const fn lambda_for_kind(kind: EdgeKind) -> Option<f32> {
    match kind {
        // Source-code relations are not shared-vault PPR relevance.
        EdgeKind::Calls | EdgeKind::Imports | EdgeKind::Refs => None,
        EdgeKind::AuthoredBy => Some(0.9),
        EdgeKind::ScopedTo => Some(0.7),
        EdgeKind::PartOf => Some(0.8),
        EdgeKind::Supersedes => Some(0.3),
        EdgeKind::BelongsTo => Some(1.0),
        EdgeKind::ClaimOf => Some(1.0),
        EdgeKind::ChildOf => None,
        EdgeKind::AssignedTo => None,
        EdgeKind::BlockedBy => None,
        // ONE-1608 (ARCH-0050 R6 L2): the code-memory readiness edge is
        // NEVER an ordinary PPR edge. `None` is the traversal exclusion —
        // strictly stronger than λ = 0.0 — so a note attached to a blocked
        // symbol can never inherit relevance through a readiness dependency.
        EdgeKind::Blocks => None,
        // CMT-4 (ONE-1541): a brief discharging an obligation says nothing
        // about retrieval relevance, so neither ruled direction is traversed.
        EdgeKind::Fulfills | EdgeKind::DischargedBy => None,
        EdgeKind::DerivedFrom => Some(0.2),
        EdgeKind::Mentions => Some(0.6),
        EdgeKind::About => Some(0.5),
        EdgeKind::Supports => Some(1.0),
        EdgeKind::Opposes => Some(0.0),
        EdgeKind::ParticipatesIn => Some(1.0),
        EdgeKind::Attached => Some(0.8),
        EdgeKind::EmployedBy => Some(0.10),
        EdgeKind::HasFacet => Some(0.05),
        EdgeKind::FacetOf => Some(0.05),
        EdgeKind::InWorld => Some(0.05),
        EdgeKind::SetIn => Some(0.05),
        // ARCH-0055 redirect edges: traversed like `supersedes` (λ 0.3) so
        // shell mass reaches the canonical head.
        EdgeKind::MergedInto => Some(0.3),
        EdgeKind::SplitInto => Some(0.3),
        // ONE-1414 cross-vault coreference: `None` IS the no-pooling
        // contract. A `same_as` link asserts that two PERSON entities are one
        // person; it does NOT merge their claim sets, so no PPR mass may
        // cross it in either direction. Gate 1 below drops the hop outright,
        // which is strictly stronger than λ = 0.0 (`opposes`): the edge also
        // contributes nothing to the `s_out`/`s_in` normalizers, so its mere
        // presence cannot even reweight a node's other hops. A traversable
        // λ here — however small — would be exactly the claim pooling this
        // ticket exists to prevent.
        // Conversation topology is not semantic retrieval mass, and neither
        // is a Retry reply's link to the reply it answers again.
        EdgeKind::SameAs
        | EdgeKind::Parent
        | EdgeKind::SpawnedBy
        | EdgeKind::AddressedTo
        | EdgeKind::RepliesTo
        | EdgeKind::Regenerates => None,
    }
}

pub fn ensure_public_memory_edge_kind(kind: EdgeKind) -> Result<()> {
    match kind {
        EdgeKind::Calls | EdgeKind::Imports | EdgeKind::Refs
        | EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => Ok(()),
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto
        | EdgeKind::BlockedBy
        // ONE-1608: `blocks` is the L2 code-memory readiness edge. Its
        // dedicated door binds the actor entity to its asserted class and
        // proves acyclicity; a guest `vault.edges.put` carries neither,
        // so guest code may not mint readiness dependencies.
        | EdgeKind::Blocks
        // ONE-1541 (CMT-4): the brief-fulfillment pair is structural and its
        // ruled directions are only meaningful written together, after both
        // endpoint classes have been proven. Guest code proves neither and
        // can only ask for one direction at a time, so both bytes land on
        // the refusal side with the rest of the structural kinds.
        | EdgeKind::Fulfills
        | EdgeKind::DischargedBy
        | EdgeKind::Parent | EdgeKind::SpawnedBy | EdgeKind::AddressedTo | EdgeKind::RepliesTo
        // A Retry reply's link is written with the reply, by its stream.
        | EdgeKind::Regenerates
        // ONE-1414: `same_as` is structural and its writes belong to the
        // federation coreference door (`put_coreference_link`), which writes
        // the link and its status Claim in ONE transaction under an actor
        // gate. A raw link here would assert identity with no status, no
        // consent surface, and no actor — so it lands on the refusal side
        // with the rest of the structural kinds.
        | EdgeKind::SameAs => Err(Error::InvalidClaimBody(
            "vault.edges.put rejects structural edge kinds",
        )),
    }
}
