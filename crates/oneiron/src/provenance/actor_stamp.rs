//! Opaque actor stamp tokens (FIX 10930, Engine 10-30 20:20).
//!
//! A commit message that names its writer names an opaque per-vault token in
//! the actor's place: the generic stamp's `actor=<token>.<class>`, its
//! receipt's `made_by.process.actor`, a proposal artifact's stamp and
//! receipt, a NOTE's stamp, and a reference-refusal receipt's `actor`. One
//! `actor.stamp_token` CLAIM resolves a token: its id is the token, its
//! subject the actor and its value the actor's class. The claim replicates
//! through the CLAIM substrate as a peer binding does, so every device of
//! the vault resolves a stamp another device wrote.
//!
//! An actor's erase hard-erases its token claims, and their tombstones take
//! them from the vault's other devices (a crypto-shred): every message that
//! names one then names a token nothing resolves, and readers show no one.
//! No history is rewritten. A token whose claim is absent here (erased,
//! purged, or not yet synced) resolves to no one. A legal hold that keeps a
//! reference-refusal receipt naming a token keeps that token's claim until
//! it lifts.
//!
//! A writer finds its actor's token through this device's cache
//! ([`ACTOR_STAMP_TOKEN`]); a miss mints a token claim and its cache row in
//! the writer's own transaction.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_ACTOR_STAMP_TOKEN,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_RECEIPT_RECORD};
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// This device's cache from an actor to its stamp token. Key: id16 (actor);
/// value: id16 (token).
const ACTOR_STAMP_TOKEN: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::PROVENANCE_ACTOR_STAMP_TOKEN);

/// Value-map key carrying the actor class on an `actor.stamp_token` claim.
const STAMP_TOKEN_VALUE_KEY_CLASS: &str = "class";

/// What a commit stamp names of its writer (FIX 10930): the opaque token in
/// the actor's place, and the actor's class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorStamp {
    /// The id of the actor's `actor.stamp_token` claim.
    pub token: EntityId,
    /// The writing actor's class, which a stamp spells after its token.
    pub class: EdgeActorClass,
}

/// `actor`'s stamp token, in the writer's transaction: the cached one while
/// its claim still names `actor`, else a fresh token claim and its cache row
/// (FIX 10930). The claim's subject is `actor`'s row, which every stamping
/// door has already checked is live.
///
/// # Errors
///
/// Storage errors, or a token claim the reserved door refuses.
pub(crate) fn actor_stamp_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: WriteActor,
) -> Result<ActorStamp> {
    let stamp = |token| ActorStamp {
        token,
        class: actor.actor_class(),
    };
    if let Some(token) = ACTOR_STAMP_TOKEN.get(&vault.store, &*wtxn, &actor.entity_ref())?
        && resolve_actor_stamp_in_txn(vault, &*wtxn, &token)? == Some(actor)
    {
        return Ok(stamp(token));
    }
    // The id first: the floor `recorded_at_in_txn` persists covers it.
    let token = vault.store.clock.entity_id()?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut body = ClaimBody::new(
        PREDICATE_ACTOR_STAMP_TOKEN,
        ClaimSubject::Entity(actor.entity_ref()),
        Value::Map(vec![(
            Value::from(STAMP_TOKEN_VALUE_KEY_CLASS),
            Value::from(crate::edit_distance::actor_class_token(actor.actor_class())),
        )]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.valid_from = Some(at);
    // Observed: a token is this vault's own fact, as a peer binding is.
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(wtxn, &token, &body, TimeRange { start: at, end: at }, at)?;
    ACTOR_STAMP_TOKEN.put(&vault.store, wtxn, &actor.entity_ref(), &token)?;
    Ok(stamp(token))
}

/// [`actor_stamp_in_txn`] on a grouped write of its own, for a writer that
/// holds none.
///
/// # Errors
///
/// As [`actor_stamp_in_txn`].
pub(crate) fn actor_stamp(vault: &Vault, actor: WriteActor) -> Result<ActorStamp> {
    vault.with_write_txn_grouped(|wtxn| actor_stamp_in_txn(vault, wtxn, actor))
}

/// The actor `token` stands for, by one point read of its claim: `None` when
/// no `actor.stamp_token` claim of this vault's own observation is stored
/// under it (erased, purged, never synced here, or another row), or when its
/// actor is hard-erased here (FIX 10930).
///
/// # Errors
///
/// Storage errors, or a stored CLAIM that does not decode.
pub(crate) fn resolve_actor_stamp_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    token: &EntityId,
) -> Result<Option<WriteActor>> {
    let is_claim = vault
        .store
        .port_entity_record(txn, token)?
        .is_some_and(|row| row.entity_type == ENTITY_TYPE_CLAIM);
    if !is_claim {
        return Ok(None);
    }
    let Some(body) = crate::ports::ClaimStore::port_claim_get(vault, txn, token)? else {
        return Ok(None);
    };
    let Some(actor) = stamped_actor(&body) else {
        return Ok(None);
    };
    // A token claim that outlived its actor's erase here names no one.
    if vault.carrier_actor_erased_in_txn(txn, &actor.entity_ref())? {
        return Ok(None);
    }
    Ok(Some(actor))
}

/// [`resolve_actor_stamp_in_txn`] under a read transaction of its own.
///
/// # Errors
///
/// As [`resolve_actor_stamp_in_txn`].
pub(crate) fn resolve_actor_stamp(vault: &Vault, token: &EntityId) -> Result<Option<WriteActor>> {
    let rtxn = vault.store.env.read_txn()?;
    resolve_actor_stamp_in_txn(vault, &rtxn, token)
}

/// The actor a token claim names: its subject, in the class its value names.
/// `None` for another predicate, a row that is not this vault's own
/// observation (an imported or generated copy vouches for no one, as a peer
/// binding does not), a retracted row, or a malformed value.
fn stamped_actor(body: &ClaimBody) -> Option<WriteActor> {
    if body.predicate != PREDICATE_ACTOR_STAMP_TOKEN
        || body.source != Some(ClaimSource::Observed)
        || body.lifecycle == ClaimLifecycleStatus::Retracted
        || crate::claim::claim_generated_origin(body)
        || crate::claim::claim_evidence_taint(body)
            .is_some_and(|taint| matches!(taint, ClaimSource::Imported | ClaimSource::ToolOutput))
    {
        return None;
    }
    let ClaimSubject::Entity(actor) = body.subject else {
        return None;
    };
    let Value::Map(entries) = &body.value else {
        return None;
    };
    let class = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(STAMP_TOKEN_VALUE_KEY_CLASS))
        .and_then(|(_, value)| value.as_str())
        .and_then(crate::edit_distance::actor_class_from_token)?;
    Some(WriteActor::new(actor, class))
}

/// Erasing `actor` (FIX 10930): each `actor.stamp_token` claim naming it is
/// hard-erased in the erase's own transaction, its tombstone staged so the
/// vault's other devices purge their copy, and every stamp naming its token
/// names no one from then on. A token a legal hold keeps (its claim held, or
/// a held reference-refusal receipt naming it, FIX 11040) stays until the
/// hold lifts: [`release_held_actor_stamps_in_txn`] erases it then. The
/// cache row goes with the declared table's scrub
/// ([`erase_actor_stamp_cache_in_txn`]).
///
/// # Errors
///
/// Storage errors, or a stored token claim that does not decode.
pub(crate) fn erase_actor_stamp_tokens_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, &*wtxn, actor)? {
        return Ok(());
    }
    erase_tokens_of_in_txn(vault, wtxn, &BTreeSet::from([*actor]))
}

/// The token claims a legal hold kept from the scrubs of the hard-erased ids
/// `erased`, once nothing holds them (FIX 10930, 11040): each goes as
/// [`erase_actor_stamp_tokens_in_txn`] takes one. A token still held stays.
///
/// # Errors
///
/// Storage errors, or a stored token claim that does not decode.
pub(crate) fn release_held_actor_stamps_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    erase_tokens_of_in_txn(vault, wtxn, erased)
}

/// Whether a token claim naming one of `actors` is still stored here: one a
/// legal hold kept from its actor's scrub. An erase of one of `actors` is
/// not complete while one is.
///
/// # Errors
///
/// Storage errors, or a stored token claim that does not decode.
pub(crate) fn actor_stamp_tokens_remain_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<bool> {
    Ok(!tokens_of_in_txn(vault, txn, actors)?.is_empty())
}

/// Erasing `actor` from this device's token cache: its cache row goes (FIX
/// 10930). Its token claims go through [`erase_actor_stamp_tokens_in_txn`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_actor_stamp_cache_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    ACTOR_STAMP_TOKEN.delete(&vault.store, wtxn, actor)?;
    Ok(())
}

/// Hard-erases each token claim naming one of `actors` that no legal hold
/// keeps.
fn erase_tokens_of_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<()> {
    let tokens = tokens_of_in_txn(vault, &*wtxn, actors)?;
    if tokens.is_empty() {
        return Ok(());
    }
    let held = held_tokens_in_txn(vault, &*wtxn)?;
    for token in tokens {
        if held.contains(&token)
            || crate::store::legal_hold::held_in_txn(&vault.store, &*wtxn, token.as_bytes())?
        {
            continue;
        }
        hard_erase_token_in_txn(vault, wtxn, &token)?;
    }
    Ok(())
}

/// Every stored `actor.stamp_token` claim whose subject is one of `actors`,
/// found by the type-0 scan an erase may afford.
fn tokens_of_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<Vec<EntityId>> {
    if actors.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vault
        .claims_with_predicate_in_txn(txn, PREDICATE_ACTOR_STAMP_TOKEN)?
        .into_iter()
        .filter(|(_, body)| {
            matches!(body.subject, ClaimSubject::Entity(subject) if actors.contains(&subject))
        })
        .map(|(token, _)| token)
        .collect())
}

/// What the hold check reads of a RECEIPT_RECORD carrier: its receipt.
#[derive(serde::Deserialize)]
struct ReceiptCarrier {
    receipt: ReceiptRecord,
}

/// The tokens a held reference-refusal receipt names (FIX 11040), read from
/// every RECEIPT_RECORD a standing legal hold keeps. A vault that keeps no
/// hold row holds none. A carrier that does not decode names no token.
fn held_tokens_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<BTreeSet<EntityId>> {
    let mut held = BTreeSet::new();
    if crate::store::legal_hold::holds_in_txn(&vault.store, txn)?.is_empty() {
        return Ok(held);
    }
    let mut records = Vec::new();
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_RECEIPT_RECORD, None)?
    {
        records.push(id?);
    }
    for id in records {
        if !crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
            continue;
        }
        let Some(row) = vault.store.port_entity_record(txn, &id)? else {
            continue;
        };
        let Ok(carrier) = rmp_serde::from_slice::<ReceiptCarrier>(&row.body) else {
            continue;
        };
        if carrier.receipt.receipt_kind != ReceiptKind::ReferenceRefusal {
            continue;
        }
        let token = carrier
            .receipt
            .actor
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok());
        held.extend(token);
    }
    Ok(held)
}

/// Hard-erases one token claim: the row and its indexes go, its permanent
/// `dt:` marker is written, and its tombstone is staged in the window of its
/// learned time, which the window's next load publishes so every other
/// device purges its copy.
fn hard_erase_token_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>, token: &EntityId) -> Result<()> {
    let Some(learned_at) = vault
        .store
        .port_entity_record(&*wtxn, token)?
        .map(|row| row.learned_at)
    else {
        return Ok(());
    };
    let (_, vector, graph, neighbors) = crate::batch::deindex_entity(&vault.store, wtxn, token)?;
    crate::ppr::invalidate_ppr_for_delete(&vault.store, wtxn, token, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(&vault.store, wtxn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(&vault.store, wtxn)?;
    }
    let erased_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    crate::deletion::stage_engine_row_hard_erasure_in_txn(
        &vault.store,
        wtxn,
        token,
        learned_at,
        &crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserHardDelete,
            deleted_at: erased_at,
            request_id: *token.as_bytes(),
        },
    )
}
