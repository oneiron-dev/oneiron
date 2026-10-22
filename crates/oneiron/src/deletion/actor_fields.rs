//! An erased actor's name, out of the rows that record it outside its own
//! record (FIX 3520).
//!
//! A side table that records an actor names its scrub in its declaration
//! (`side_table::decls`, an entry ending `=> scrub`), and this sweep walks
//! them, so a new table reaches the erase by declaring its scrub there.
use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::ActorScrub;

use super::tombstone::HARD_DELETE_MARKER;

/// Identity ops are an entity family, not a side table: their decisions stay
/// and the actor's author carriers go.
const IDENTITY_OPS: ActorScrub = Vault::scrub_identity_op_actor_in_txn;

/// Origin's intent, publication and change claims are claims, not a side
/// table: each that names the actor is rewritten naming no one (FIX 3877).
const ORIGIN_CLAIMS: ActorScrub = crate::origin::actor_erase::erase_publication_claim_actor_in_txn;

/// Runs in the purge's transaction: the identity ops first, then origin's
/// claims, then every declared table's scrub in catalog order. Behind the
/// permanent hard-delete marker, the dispatch text the actor owns leaves the
/// attempt payloads too (FIX 7076), and the planned intents' declared scrub
/// leaves each intent it asked or whose plan seats it in its erased form
/// (Engine 10-22); a delete writes no marker and keeps the text.
pub(super) fn erase_actor_fields_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    scrub_actor_fields_in_txn(vault, wtxn, actor)?;
    // A marker-only hard path writes the marker before this sweep and never
    // reaches the provenance door's erase.
    if HARD_DELETE_MARKER.contains(&vault.store, wtxn, &crate::side_table::HexId(*actor))? {
        crate::attempt_queue::erase_attempt_payload_actor_in_txn(&vault.store, wtxn, actor)?;
    }
    Ok(())
}

/// The sweep's scrubs without the attempt payloads, which a restore's sweep
/// clears for all its ids in one pass.
fn scrub_actor_fields_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    IDENTITY_OPS(vault, wtxn, actor)?;
    ORIGIN_CLAIMS(vault, wtxn, actor)?;
    crate::workspace_roster::erase_audience_actor_in_txn(vault, wtxn, actor)?;
    for scrub in crate::side_table::actor_scrubs() {
        scrub(vault, wtxn, actor)?;
    }
    Ok(())
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the rows that record actors. Each lane's actor scrub asks it (FIX 8908).
pub(crate) fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Every id `vault`'s hard-delete markers name: each hard-erased id, actor or
/// not, a marker-only one a replay left included. Read while a restore's
/// live source still stands, so its erasures since the checkpoint carry over.
pub(crate) fn hard_erased_ids_in(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    hard_erased_ids_in_txn(vault, &rtxn)
}

fn hard_erased_ids_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<BTreeSet<EntityId>> {
    let mut ids = BTreeSet::new();
    for row in HARD_DELETE_MARKER.iter_raw_from(&vault.store, rtxn, &[])? {
        let (key, _) = row?;
        // A key that spells no id names no actor.
        if let Some(id) = std::str::from_utf8(&key)
            .ok()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// A checkpoint restore's actor sweep, in its image-write transaction once
/// the type index is back (FIX 3655): every id a restored hard-delete marker
/// names, and each of `live`, gets the erase's actor sweep again, so a
/// restored row does not bring back an erased actor's name. The text an
/// erase takes from planned intents and attempt payloads goes again too;
/// the rest of the restored content stays.
pub(crate) fn rerun_actor_scrubs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    live: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut erased = hard_erased_ids_in_txn(vault, wtxn)?;
    erased.extend(live);
    // The planned intents they asked or are seated by take their erased
    // form first, while each still names its asker (Engine 10-22).
    crate::agent_dispatch::AgentDispatcher::erase_planned_intent_content_in_txn(
        &vault.store,
        wtxn,
        &erased,
    )?;
    // A Gate decision the image brings back bound to an erased claim, or a
    // bundle citing one, takes its skeleton again, or is owed it while a hold
    // keeps its partition (FIX 7994).
    let now = vault.store.clock.now_recorded_at();
    vault
        .store
        .rerun_gate_claim_scrubs_in_txn(wtxn, &erased, now)?;
    for actor in &erased {
        scrub_actor_fields_in_txn(vault, wtxn, actor)?;
        // The image's cleanup rows name it again; they go once more (FIX 7517).
        crate::vault_cleanup::erase_in_txn(&vault.store, wtxn, actor)?;
    }
    // Their dispatch text, carried back by the image's attempt rows, goes
    // again: one pass over the ledger for every id (FIX 7076).
    crate::attempt_queue::erase_attempt_payload_actors_in_txn(&vault.store, wtxn, &erased)?;
    Ok(())
}

/// A legal hold's release, in its own transaction (FIX 6280): the births a
/// hold kept from an erased actor's scrub, and their window carriers, go
/// once nothing holds their rows, a carrier whose birth never landed here
/// too (FIX 6386); no other scrub runs again. The `dt:` markers and the
/// holds as they now stand say what is owed. A vault that keeps no hold row,
/// standing or released, owes nothing: only a hold keeps a birth past its
/// actor's scrub, and a released one keeps its row for 24 months, well past
/// the release pass that settles it.
pub(super) fn rerun_birth_actor_scrubs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    // Kept gate (lead, 10-22): a hold row outlives its owed birth work. Only
    // `store::legal_hold::expire_in_txn` removes hold rows, called only by
    // `Vault::sweep_legal_hold_log`, whose one caller (deletion/legal_hold/
    // mod.rs:613, `maintain_legal_holds`) runs it after that pass's due run
    // (:611) succeeded.
    if crate::store::legal_hold::holds_in_txn(&vault.store, wtxn)?.is_empty() {
        return Ok(());
    }
    let erased = hard_erased_ids_in_txn(vault, wtxn)?;
    crate::provenance::birth::release_held_births_in_txn(vault, wtxn, &erased)
}

/// How two carrier copies of one row settle when they differ only in who
/// they name (FIX 3878): a window's copy, a recovery artifact's or another
/// machine's. It is never an authority or a replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierActorMerge {
    /// Where one copy names an actor and the other names no one, the erased
    /// copy wins. Two different live actors still conflict.
    ErasedWins,
    /// Any difference conflicts.
    Exact,
}

/// Erase wins over every copy (FIX 3878, 4227, 4228; a call, from the erase
/// rule): a carrier copy that still names an erased actor takes the erased
/// form wherever it meets one that does not.
pub const ACTOR_ERASE_CARRIER_MERGE: CarrierActorMerge = CarrierActorMerge::ErasedWins;

/// What tells a receiver that an actor a carrier copy names is erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierEraseSource {
    /// This vault's own hard-delete marker for the actor (`dt:`): never an
    /// absent row, nor a peer's word.
    LocalHardDeleteMarker,
}

/// A receiver reads an actor as erased by its own marker (FIX 3878, 4227,
/// 4228; a call).
pub const ACTOR_ERASE_CARRIER_SOURCE: CarrierEraseSource =
    CarrierEraseSource::LocalHardDeleteMarker;

/// Two copies' actors as one under [`ACTOR_ERASE_CARRIER_MERGE`]: the actor
/// that stands, or `None` when they conflict. `erased` is the type's no one.
pub(crate) fn carrier_actor_merged<T: Copy + Eq>(held: T, carried: T, erased: T) -> Option<T> {
    if held == carried {
        return Some(held);
    }
    match ACTOR_ERASE_CARRIER_MERGE {
        CarrierActorMerge::ErasedWins if held == erased || carried == erased => Some(erased),
        CarrierActorMerge::ErasedWins | CarrierActorMerge::Exact => None,
    }
}

impl Vault {
    /// Whether a carrier copy that names `actor` reads it as no one here, as
    /// [`ACTOR_ERASE_CARRIER_SOURCE`] says (FIX 3878).
    pub(crate) fn carrier_actor_erased_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: &EntityId,
    ) -> Result<bool> {
        match ACTOR_ERASE_CARRIER_SOURCE {
            CarrierEraseSource::LocalHardDeleteMarker => {
                self.local_hard_delete_marker_exists_in_txn(txn, actor)
            }
        }
    }
}
