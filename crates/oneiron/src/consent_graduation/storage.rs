//! Typed side-table bindings, stored-row converters and version guard.

use super::scope::RampScope;
use super::state::Counters;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity_topology::ProposalOutcome;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable};
use serde::{Deserialize, Serialize};

/// Per-scope outcome-statistics projection. Key: [`RampScope::key`].
///
/// These bindings live with the family that owns the keyspace rather than in
/// `store.rs`, for the same reason `identity_redirect::REDIRECT_TABLE_META_PREFIX`
/// does: `vault_meta` readers already ignore unknown prefixes.
pub(super) const RAMP_STATS: SideTable<[u8; 16], StoredScopeStats, Named> =
    SideTable::new(&side_table::RAMP_STATS);

/// Per-scope streak-floor OVERRIDE. Absence means
/// [`DEFAULT_GRADUATION_STREAK_FLOOR`]. Key: [`RampScope::key`].
///
/// A floor is POLICY, not projection: it is stored apart from the stats rows
/// precisely so [`Vault::rebuild_ramp_stats_from_receipts`] — which drops and
/// refolds every stats row — cannot erase the owner's dial.
pub(super) const RAMP_FLOOR: SideTable<[u8; 16], StreakFloor, Raw> =
    SideTable::new(&side_table::RAMP_FLOOR);

/// The append-only demotion log. Key: `at` (u64 big-endian) ‖ row id, so two
/// demotions in the same second cannot collide.
///
/// These rows are TRUTH, not projection — they record an act, and a rebuild
/// folds them rather than regenerating them.
pub(super) const RAMP_DEMOTION: SideTable<(u64, EntityId), StoredDemotion, Named> =
    SideTable::new(&side_table::RAMP_DEMOTION);

/// The append-only DOOR-RECORDED outcome log, keyed like the demotion log.
///
/// A ruling that arrives through [`Vault::record_proposal_outcome_for_ramp`]
/// has no identity-topology ledger event behind it, so without this row the
/// streak it feeds would be trust nothing durable witnesses: the next rebuild
/// would delete it, and until then the engine would surface a graduation offer
/// no receipt can explain. Rulings that DO carry a ledger event never write
/// here — the type-76 row is their witness, and a second one would double-count
/// on refold.
pub(super) const RAMP_OUTCOME: SideTable<(u64, EntityId), StoredRampOutcome, Named> =
    SideTable::new(&side_table::RAMP_OUTCOME);

/// The streak floor override: four little-endian bytes (unlike the crate's
/// usual big-endian `u64` raw values, this module's pre-existing layout).
#[derive(Debug, Clone, Copy)]
pub(super) struct StreakFloor(pub(super) u32);

impl RawValue for StreakFloor {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("ramp streak floor row"))?;
        Ok(Self(u32::from_le_bytes(bytes)))
    }
}

/// Receipt-id prefix of a demotion receipt, and the discriminator
/// [`is_ramp_demotion_receipt`] tests inside the `Gate` receipt family.
pub(super) const RAMP_DEMOTION_RECEIPT_PREFIX: &str = "ramp_demotion:";

/// Receipt-id prefix of a door-recorded outcome receipt — the
/// [`is_ramp_outcome_receipt`] discriminator.
pub(super) const RAMP_OUTCOME_RECEIPT_PREFIX: &str = "ramp_outcome:";

/// Pinned `outcome` string of a demotion receipt.
pub(super) const RAMP_DEMOTION_OUTCOME: &str = "demoted";

/// Only accepted schema version for either stored row.
pub(super) const RAMP_ROW_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredScopeStats {
    pub(super) v: u8,
    pub(super) op_kind: String,
    pub(super) target_class: String,
    pub(super) actor: String,
    pub(super) untouched_streak: u32,
    pub(super) amended: u32,
    pub(super) rejected: u32,
    pub(super) last_outcome: Option<String>,
    pub(super) updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredDemotion {
    pub(super) v: u8,
    pub(super) op_kind: String,
    pub(super) target_class: String,
    pub(super) actor: String,
    pub(super) reason: String,
    /// The grant this demotion revoked, when the scope held one.
    pub(super) grant_ref: Option<String>,
    /// Who demoted, as an entity id in lower hex: the owner's or a policy
    /// holder's person, the agent whose run spawned the scope's actor, the
    /// actor itself, or the person whose ruling caused the demotion. `None` on
    /// a row written before the field existed, and on an identity-topology
    /// ruling that bound no deciding actor. Old rows decode: the key is
    /// absent from their map.
    #[serde(default)]
    pub(super) demoted_by: Option<String>,
    /// The identity-topology causality clock at write time — see [`FoldKey`].
    pub(super) after_seq: u64,
    pub(super) at: u64,
}

/// One ruling recorded through the ramp door rather than through an
/// identity-topology resolution (which carries its own ledger event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRampOutcome {
    pub(super) v: u8,
    pub(super) op_kind: String,
    pub(super) target_class: String,
    pub(super) actor: String,
    pub(super) outcome: String,
    /// The identity-topology causality clock at write time — see [`FoldKey`].
    pub(super) after_seq: u64,
    pub(super) at: u64,
}

pub(super) fn stats_row_parts(row: StoredScopeStats) -> Result<(RampScope, Counters)> {
    if row.v != RAMP_ROW_VERSION {
        return Err(Error::CorruptedIndex("ramp stats row"));
    }
    let scope = RampScope::new(row.op_kind, row.target_class, row.actor)
        .map_err(|_| Error::CorruptedIndex("ramp stats row"))?;
    let counters = Counters {
        untouched_streak: row.untouched_streak,
        amended: row.amended,
        rejected: row.rejected,
        last_outcome: row.last_outcome.as_deref().and_then(ProposalOutcome::parse),
        updated_at: row.updated_at,
    };
    Ok((scope, counters))
}

pub(super) fn stats_row(scope: &RampScope, counters: Counters) -> StoredScopeStats {
    StoredScopeStats {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        untouched_streak: counters.untouched_streak,
        amended: counters.amended,
        rejected: counters.rejected,
        last_outcome: counters
            .last_outcome
            .map(|outcome| outcome.as_str().to_owned()),
        updated_at: counters.updated_at,
    }
}

pub(super) const RAMP_OUTCOME_ROW_LABEL: &str = "ramp outcome row";

pub(super) const RAMP_DEMOTION_ROW_LABEL: &str = "ramp demotion row";

/// Rejects a decoded ramp row whose version this build cannot read. Both
/// stored rows carry `v` in the same slot, so both are guarded here — the
/// domain check the `Named` codec cannot express on its own.
pub(super) fn validated_ramp_row<T: RampRowVersion>(row: T, label: &'static str) -> Result<T> {
    if row.version() != RAMP_ROW_VERSION {
        return Err(Error::CorruptedIndex(label));
    }
    Ok(row)
}

/// The one question every append-only ramp row answers before it is read.
pub(super) trait RampRowVersion {
    fn version(&self) -> u8;
}

impl RampRowVersion for StoredDemotion {
    fn version(&self) -> u8 {
        self.v
    }
}

impl RampRowVersion for StoredRampOutcome {
    fn version(&self) -> u8 {
        self.v
    }
}

/// Rebuilds the scope a stored ramp row names. An engine-authored row that
/// cannot form a scope is corruption, never a row to skip past.
pub(super) fn stored_row_scope(
    op_kind: String,
    target_class: String,
    actor: String,
    label: &'static str,
) -> Result<RampScope> {
    RampScope::new(op_kind, target_class, actor).map_err(|_| Error::CorruptedIndex(label))
}

/// Erasing `actor` from the ramp (FIX 3520; review of #7514;
/// RAMP-SCOPE-ACTOR-ERASE, Engine RULING NEXT-ROW-18 = A1, 14 Nov), in the
/// erase's own transaction and one-way, so no ramp row or receipt names the
/// erased actor afterwards:
/// - each scope whose actor is `actor` loses its stats row and its
///   streak-floor override;
/// - each demotion and door-recorded outcome in such a scope keeps its act,
///   reason, grant and times, and its scope actor reads
///   [`ERASED_CALL_IDENTITY`](crate::receipt::ERASED_CALL_IDENTITY), so its
///   receipt's `actor` does too;
/// - each demotion `actor` made keeps its row, and its `demoted_by` reads
///   [`ERASED_CALL_IDENTITY`](crate::receipt::ERASED_CALL_IDENTITY);
/// - the offer answers and threshold overrides of those scopes go the same
///   way ([`crate::edit_distance::graduation::erase_scope_actor_in_txn`]).
///
/// The fold reads no row whose actor is erased, so an erased actor's history
/// forms no shared scope. An id whose entity is no actor scans nothing. Each
/// ramp table that spells an actor names this scrub; the first run does them
/// all, and a later one finds nothing left. A floor dialed on a scope that has
/// no stats, outcome, demotion or answer row is keyed only by the scope's
/// digest and spells no actor: this erase cannot find it, and it stays.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_ramp_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let erased = crate::receipt::ERASED_CALL_IDENTITY;
    let scope_key = |op_kind: &str, target_class: &str| {
        RampScope {
            op_kind: op_kind.to_owned(),
            target_class: target_class.to_owned(),
            actor: hex.clone(),
        }
        .key()
    };
    let mut scopes = std::collections::BTreeSet::new();
    for (key, row) in RAMP_STATS.scan(&vault.store, wtxn)? {
        if row.actor == hex {
            scopes.insert(key);
        }
    }
    let mut demotions = Vec::new();
    for (key, mut row) in RAMP_DEMOTION.scan(&vault.store, wtxn)? {
        let in_scope = row.actor == hex;
        let by_actor = row.demoted_by.as_deref() == Some(hex.as_str());
        if in_scope {
            scopes.insert(scope_key(&row.op_kind, &row.target_class));
            row.actor = erased.to_owned();
        }
        if by_actor {
            row.demoted_by = Some(erased.to_owned());
        }
        if in_scope || by_actor {
            demotions.push((key, row));
        }
    }
    for (key, row) in demotions {
        RAMP_DEMOTION.put(&vault.store, wtxn, &key, &row)?;
    }
    let mut outcomes = Vec::new();
    for (key, mut row) in RAMP_OUTCOME.scan(&vault.store, wtxn)? {
        if row.actor == hex {
            scopes.insert(scope_key(&row.op_kind, &row.target_class));
            row.actor = erased.to_owned();
            outcomes.push((key, row));
        }
    }
    for (key, row) in outcomes {
        RAMP_OUTCOME.put(&vault.store, wtxn, &key, &row)?;
    }
    for scope in
        crate::edit_distance::graduation::erase_scope_actor_in_txn(&vault.store, wtxn, &hex)?
    {
        scopes.insert(scope.key());
    }
    for key in scopes {
        RAMP_STATS.delete(&vault.store, wtxn, &key)?;
        RAMP_FLOOR.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}
