//! Doors for `tests/summary_as_record_permit.rs` (SUMMARY-AS-RECORD-PERMIT):
//! a summary minted as the Dreamer writes one, so the test lands it through
//! `Vault::land_header` with no model.

use crate::Vault;
use crate::conversation_dag::ScopeSelector;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Mints a summary of `text` over every source `scope` resolves to, written
/// as the Dreamer, and returns its id.
///
/// # Errors
/// The mint's: a scope that does not resolve, or an actor the vault lacks.
pub fn mint_scope_summary(vault: &Vault, scope: &ScopeSelector, text: &str) -> Result<EntityId> {
    crate::scope_summary::mint_scope_summary_for_test(vault, scope, text)
}

/// Raw-puts `body` at `id` with DAG edges, copying `template`'s TURN times.
///
/// The shared put/edge path a copied landing reply takes: one atomic batch
/// with `ChildOf` to `room` plus `Parent`/`RepliesTo` when named. The caller
/// mutates `body` (its `txt`, `reply_to`, `summary`) and computes revisions;
/// this door copies only metadata, so no header layout leaks into the test.
///
/// # Errors
/// A missing or non-TURN `template`, or the put/edge guards' refusal.
pub fn apply_raw_landing_reply(
    vault: &Vault,
    template: &EntityId,
    id: &EntityId,
    body: &[u8],
    room: EntityId,
    parent: Option<EntityId>,
    reply_to: Option<EntityId>,
) -> Result<()> {
    let header = vault
        .read_entity_header(template)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_TURN {
        return Err(crate::error::Error::InvalidConfig(
            "template is not a TURN".to_owned(),
        ));
    }
    let occurred = crate::TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    let learned_at = header.learned_at;
    vault.with_write_txn_grouped(|txn| {
        let mut batch = vault.batch_in().put(
            id,
            crate::registry::ENTITY_TYPE_TURN,
            occurred,
            learned_at,
            body,
        );
        let fields = crate::batch::EdgeValueFields {
            weight: 1.0,
            created_at: learned_at,
            vad: oneiron_contracts::affect::Vad::NEUTRAL,
            provenance: None,
        };
        batch = batch.edge_with_value_fields(id, crate::edge::EdgeKind::ChildOf, &room, fields);
        if let Some(parent) = parent {
            batch =
                batch.edge_with_value_fields(id, crate::edge::EdgeKind::Parent, &parent, fields);
        }
        if let Some(reply_to) = reply_to {
            batch = batch.edge_with_value_fields(
                id,
                crate::edge::EdgeKind::RepliesTo,
                &reply_to,
                fields,
            );
        }
        batch.apply(txn)
    })
}

/// Stages only DAG edges for `id` (no body put): the edge-only adversary.
///
/// `ChildOf` to `room` plus `Parent`/`RepliesTo` when named, in one atomic
/// batch, timestamped at `id`'s own `learned_at` when it is stored.
///
/// # Errors
/// The edge guards' refusal.
pub fn apply_raw_landing_reply_edges(
    vault: &Vault,
    id: &EntityId,
    room: EntityId,
    parent: Option<EntityId>,
    reply_to: Option<EntityId>,
) -> Result<()> {
    let learned_at = vault
        .read_entity_header(id)?
        .map(|header| header.learned_at)
        .unwrap_or_else(|| vault.now_recorded_at());
    vault.with_write_txn_grouped(|txn| {
        let fields = crate::batch::EdgeValueFields {
            weight: 1.0,
            created_at: learned_at,
            vad: oneiron_contracts::affect::Vad::NEUTRAL,
            provenance: None,
        };
        let mut batch =
            vault
                .batch_in()
                .edge_with_value_fields(id, crate::edge::EdgeKind::ChildOf, &room, fields);
        if let Some(parent) = parent {
            batch =
                batch.edge_with_value_fields(id, crate::edge::EdgeKind::Parent, &parent, fields);
        }
        if let Some(reply_to) = reply_to {
            batch = batch.edge_with_value_fields(
                id,
                crate::edge::EdgeKind::RepliesTo,
                &reply_to,
                fields,
            );
        }
        batch.apply(txn)
    })
}
