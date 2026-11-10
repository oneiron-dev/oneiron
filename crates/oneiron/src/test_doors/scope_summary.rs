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
        let mut batch = vault.batch_in().edge_with_value_fields(
            id,
            crate::edge::EdgeKind::ChildOf,
            &room,
            fields,
        );
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

/// Puts a `merge.summary` header signed by a key the vault's fold does not bind.
///
/// The header names (`target`, `summary`) by the landing writer, is signed with a fresh
/// Ed25519 key, and goes through the replicated put path with its `ClaimOf` edge to
/// `target`. The header is otherwise well-formed: its
/// candidate evidence carries the summary's covers, its envelope is the landing writer's
/// Generated/Auto, and its `machine_signature` is a valid signature over the engine's
/// transcript (`Vault::machine_claim_transcript`). The replicated put lands provisional
/// (origin-verifiable, history unresolved), as a peer's row would; whether it admits a
/// reply is the binding rule under test.
///
/// # Errors
/// A missing summary, the transcript or facet read, or the replicated put/edge refusal.
#[cfg(feature = "sync")]
pub fn put_unbound_landing_header(
    vault: &Vault,
    summary: &EntityId,
    target: &EntityId,
) -> Result<EntityId> {
    use ed25519_dalek::Signer as _;

    let writer = crate::scope_summary::landing_writer_id()?;
    let writer_actor = crate::WriteActor::new(writer, crate::edge::EdgeActorClass::System);
    let covers = vault.scope_summary_covers(summary)?;
    let candidate = crate::ClaimCandidate::new(
        "merge.summary",
        crate::ClaimSubject::Entity(*target),
        rmpv::Value::from(summary.to_hex()),
        1.0,
    )
    .with_evidence(rmpv::Value::Array(
        covers
            .iter()
            .map(|id| rmpv::Value::from(id.to_hex()))
            .collect(),
    ));
    let envelope = crate::WriteEnvelope::new(
        writer_actor,
        crate::ClaimSource::Generated,
        crate::WriteProvenance::new(rmpv::Value::from("scope_summary test"))?,
        crate::ClaimApprovalStatus::Auto,
    );
    let id = EntityId::now();
    let transcript = vault.machine_claim_transcript(&id, &candidate, &envelope)?;
    // Fresh key the fold does not bind: fixed seed distinct from the engine's
    // host-derived keys, so the test is deterministic.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x5E; 32]);
    let signature = crate::write_envelope::MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    };
    let signed = envelope.with_machine_signature(signature);
    let facet = {
        let txn = vault.store.env.read_txn()?;
        crate::batch::claim_candidate_apply::claim_candidate_birth_facet(&vault.store, &txn, &id)?
    };
    let body = candidate.into_claim_body(&signed, facet)?;
    let bytes = crate::claim::encode_claim_body(&body)?;
    let now = vault.now_recorded_at();
    let occurred = crate::TimeRange {
        start: now,
        end: now,
    };
    vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                now,
                None,
                &bytes,
            )
            .edge(&id, crate::edge::EdgeKind::ClaimOf, target, 1.0)
            .apply(txn)
    })?;
    Ok(id)
}

/// Replays `entities` and `edges_in_order` from `source` to `receiver` through one window.
///
/// Seeds a window document from `source`'s stored bytes (entities via `get_raw_unsealed`,
/// edges via `port_edge_encoded`) under the month of `window_anchor`'s `learned_at`, then
/// runs the forward entity pass plus the forward edge pass over the caller's order
/// (`sync::window::replay_window_in_edge_order_for_test`, including its same-page retry
/// for landing waits). Returns the window key string (for `rm:w:` marker asserts) and the
/// combined write count. The test door omits settle, so a deferred marker stays set even
/// after a later retry in the same call lands the edge: tests assert quarantine via `x:`
/// rows and placement via room reads, not marker absence after landing.
///
/// # Errors
/// A missing anchor, entity or edge in `source`, or the replay's local failure.
#[cfg(feature = "sync")]
pub fn replay_landing_edges_in_order(
    source: &Vault,
    receiver: &Vault,
    window_anchor: &EntityId,
    entities: &[EntityId],
    edges_in_order: &[(EntityId, crate::edge::EdgeKind, EntityId)],
) -> Result<(String, u32)> {
    let header = source
        .read_entity_header(window_anchor)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    let window_key = crate::sync::types::WindowKey::from_timestamp(header.learned_at);
    let doc = crate::sync::schema::create_window_doc("landing-test", &window_key);
    for id in entities {
        let blob = source
            .get_raw_unsealed(id)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        crate::sync::loro_support::map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    }
    let mut keys_in_order = Vec::with_capacity(edges_in_order.len());
    for (src, kind, tgt) in edges_in_order {
        let key = crate::sync::bridge::format_edge_key(src, *kind, tgt);
        let rtxn = source.store.env.read_txn()?;
        let blob = crate::ports::EdgeStoreStaging::port_edge_encoded(
            &source.store,
            &rtxn,
            src,
            *kind,
            tgt,
        )?
        .ok_or(crate::error::Error::EntityNotFound)?;
        crate::sync::loro_support::map_insert_bytes(&doc.get_map("edges"), &key, &blob)?;
        keys_in_order.push(key);
    }
    doc.commit();
    let count = crate::sync::window::replay_window_in_edge_order_for_test(
        receiver,
        &doc,
        &window_key,
        &keys_in_order,
    )?;
    Ok((window_key.as_str().to_owned(), count))
}
