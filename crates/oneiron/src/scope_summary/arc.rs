//! A conversation's Arc (FIX 7509 P8, ARCH-0026 Dreamer row 4): one stable
//! summary per conversation path, written from the summary lines of the
//! closed sittings below it (owner SUMMARY-SOURCE = A), never from its own
//! earlier body (CLM-009). Facts and conflicts stay on claims.
//!
//! The Arc's projection identity is its declaration: the scope, purpose and
//! requester, never which sittings lie below it, so a new sitting advances
//! the same projection. What it was written from is its source set
//! ([`super::arc_sources`]), apart from that identity.

use super::arc_sources::ArcSources;
use super::codec::{invalid, parse_scope};
use super::request::{ScopeSummaryPlan, ScopeSummaryRequest, ScopeSummaryTarget};
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_consolidation::ScopeSummaryEvidence;
use crate::error::Result;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};
use heed::RwTxn;
use rmpv::Value;
use std::collections::BTreeSet;

/// The declaration key an Arc names its scope under.
pub(super) const ARC_KEY: &str = "arc";
/// The purpose an Arc takes.
pub(super) const ARC_PURPOSE: &str = "milestone_arc_narrative";

/// Whether `input` declares an Arc.
pub(super) fn is_arc_declaration(input: &Value) -> bool {
    input
        .as_map()
        .is_some_and(|fields| fields.iter().any(|(key, _)| key.as_str() == Some(ARC_KEY)))
}

/// An Arc's target from its declared scope. An Arc spans sittings, so its
/// scope restricts to none; a declared path is its own Arc.
pub(super) fn decode_target(value: Option<&Value>) -> Result<ScopeSummaryTarget> {
    let scope = parse_scope(value.ok_or_else(|| invalid("arc declaration has no scope"))?)?;
    if scope.session.is_some() {
        return Err(invalid("an arc spans sittings"));
    }
    Ok(ScopeSummaryTarget::Arc { scope })
}

/// The Arc a retained conversation has by default: its canonical path with
/// its forks, declared by the vault's Dreamer, as the Weave declares its
/// whole-conversation summary.
pub(super) fn conversation_arc(conversation: EntityId) -> Result<ScopeSummaryRequest> {
    Ok(ScopeSummaryRequest {
        target: ScopeSummaryTarget::Arc {
            scope: ScopeSelector {
                conversation,
                session: None,
                path: ScopePath::Canonical,
                include_forks: true,
            },
        },
        requester: WriteActor::new(
            crate::dreamer_runner::authority::dreamer_actor_id()?,
            EdgeActorClass::System,
        ),
    })
}

/// What a landing or an exact reuse means for Arcs, in its writer. An Arc's
/// own landing records what its words came from beyond its covers (each
/// sitting's summary and each claim it read) and advances its last
/// successful set. A sitting's landing marks the Arc of each conversation its
/// turns stand in dirty and runs its gate. Any other landing is no Arc's.
pub(super) fn landed_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    plan: &ScopeSummaryPlan,
    evidence: &ScopeSummaryEvidence,
    summary: EntityId,
) -> Result<()> {
    if let Some(arc) = &plan.arc {
        return arc_landed_in_txn(vault, txn, plan, arc, evidence, summary);
    }
    if plan.session.is_none() {
        return Ok(());
    }
    let mut conversations = BTreeSet::new();
    for turn in &plan.sources {
        // A turn in no conversation stands under no Arc.
        if let Ok(conversation) = crate::conversation_dag::conversation_of(&vault.store, txn, turn)
        {
            conversations.insert(conversation);
        }
    }
    let now = vault.store.clock.now_recorded_at();
    super::arc_gate::sittings_landed_in_txn(vault, txn, &conversations, now)
}

fn arc_landed_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    plan: &ScopeSummaryPlan,
    arc: &ArcSources,
    evidence: &ScopeSummaryEvidence,
    summary: EntityId,
) -> Result<()> {
    // Erasing a sitting's summary or a claim the Arc read reaches the Arc.
    for lower in &arc.lower {
        crate::ports::record_derived_edge_in_txn(&vault.store, txn, &summary, &lower.summary)?;
    }
    for claim in evidence.arc_claims() {
        crate::ports::record_derived_edge_in_txn(&vault.store, txn, &summary, &claim)?;
    }
    super::arc_gate::succeeded_in_txn(vault, txn, &plan.input, arc)
}
