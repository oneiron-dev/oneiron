//! Name index, borrowing admission projection, sealed put, and Vault doors.

mod admission;

use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result, SideTableRowProblem};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::codec::invalid_body;
use super::types::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SECRET_NAME_MAX_BYTES, SecretBinding,
    SecretCustodyFloor, SecretCustodyMetadata, SecretCustodyRecord, SecretCustodyStatus, TierBand,
};
use crate::error::SecretError;

pub(crate) use self::admission::{SecretCustodyAdmission, read_secret_custody_admission_in_txn};

// ---------------------------------------------------------------------------
// Name index
// ---------------------------------------------------------------------------

/// Live secret name -> custody `EntityId` and the name's generation
/// high-water, keyed by the name itself. `run_bound` reads a run's names
/// and forgets them with their records (FIX 8028).
pub(super) const NAME_INDEX: SideTable<String, NameEntry, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_NAME_INDEX);

/// One name's index row: the custody record the name resolves to, and the
/// highest `rotation_generation` a record has held under the name here. The
/// high-water outlives its record: a name whose record is gone from the store
/// starts its next life above it, never at the caller's number (FIX 5958).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NameEntry {
    pub(super) id: EntityId,
    high_water: u32,
}

/// The record's id bytes, then the high-water as four big-endian bytes.
impl RawValue for NameEntry {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = self.id.as_bytes().to_vec();
        raw.extend_from_slice(&self.high_water.to_be_bytes());
        Ok(raw)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let undecodable = || CodecError::Row(SideTableRowProblem::Undecodable);
        let (id, high_water) = bytes
            .split_at_checked(ENTITY_ID_LEN)
            .ok_or_else(undecodable)?;
        let high_water = <[u8; 4]>::try_from(high_water).map_err(|_| undecodable())?;
        Ok(Self {
            id: <EntityId as RawValue>::from_raw(id)?,
            high_water: u32::from_be_bytes(high_water),
        })
    }
}

/// One above `generation`, the generation a name's next life starts at.
fn next_generation(generation: u32) -> Result<u32> {
    generation
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("secret rotation generation"))
}

/// Resolves a live secret name to its custody `EntityId` inside an
/// existing txn. `pub(crate)` for SECRET-02's lease doors (ONE-1920), which
/// hold their own write txn and must not open a nested read txn.
pub(crate) fn resolve_secret_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<EntityId>> {
    Ok(NAME_INDEX
        .get(store, txn, &name.to_owned())?
        .map(|entry| entry.id))
}

/// Reads a custody record under either a read or write txn, its value
/// opened from current custody (KS-6): the caller holds a writer, or took
/// the custody read guard before its snapshot. Strict: a key that does not
/// open is an error. A read that needs no value takes
/// [`super::read_secret_custody_meta_in_txn`], which never touches custody.
/// `pub(crate)` for SECRET-02's lease doors (ONE-1920) — value reads still
/// route ONLY through the bound door [`Vault::get_secret_value_in_txn`].
pub(crate) fn read_secret_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyRecord>> {
    super::storage_seal::read_opened_in_txn(store, txn, id)
}

// ---------------------------------------------------------------------------
// Vault doors
// ---------------------------------------------------------------------------

/// Enforces the narrow-only rule against the LIVE floor and hands back the
/// live band for `rec`'s class.
///
/// The floor is resolved from the vault INSIDE the caller's transaction,
/// never from the caller-supplied snapshot (which may be stale). Every
/// binding's tier ceiling must fit inside the live band for the record's
/// class: a CrossVault record read against the default snapshot (its band
/// T0..T0) but binding T2 is rejected here, not after commit.
///
/// `pub(crate)` for SECRET-04's `Vault::rotate_secret` (ONE-1922): a
/// rotation is a FRESH authorization of the record's exposure, not a
/// grandfather clause for the posture it registered under, so a floor
/// narrowed since registration must refuse to re-bless a wider binding
/// through exactly this body rather than a second, unmarked copy of it.
pub(crate) fn refuse_bindings_wider_than_live_floor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    rec: &SecretCustodyRecord,
) -> Result<TierBand> {
    let live_band = SecretCustodyFloor::resolve(store, txn)?.band_for(rec.class);
    for b in &rec.bindings {
        if b.tier_ceiling > live_band.max {
            return Err(Error::Secret(SecretError::ManifestWidensFloor {
                secret_ref: rec.name.clone(),
                class: rec.class,
                requested: b.tier_ceiling,
                floor_max: live_band.max,
            }));
        }
    }
    Ok(live_band)
}

/// Writes one custody body through the ONE sealed put shape, stamping
/// `occurred_at` as both the occurrence range and the learned-at.
///
/// Local custody writes use the engine-internal non-replicated shape
/// (`allow_maintenance && !allow_reserved_predicate`). Public raw puts and
/// every replicated door stay sealed (`reject_secret_custody_byte`).
///
/// `pub(crate)` for SECRET-04's `Vault::rotate_secret` and
/// `Vault::revoke_secret` (ONE-1922), which re-put an existing record inside
/// their own write transaction: registration mints the id and all three land
/// through this body, so the seal shape has exactly one definition.
pub(crate) fn put_secret_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
    occurred_at: u64,
) -> Result<()> {
    put_custody_body_in_txn(&CustodyWrite::of(vault), wtxn, id, rec, occurred_at)
}

/// What a custody write applies through: the vault's store, config and
/// analyzer, and whether its text index is trusted. The batch door's mask on
/// write (OF-560) holds these without a [`Vault`].
pub(crate) struct CustodyWrite<'a> {
    pub(crate) store: &'a Store,
    pub(crate) config: &'a crate::config::VaultConfig,
    pub(crate) analyzer: &'a crate::analyzer::MultilingualAnalyzer,
    pub(crate) text_index_trusted: bool,
}

impl<'a> CustodyWrite<'a> {
    pub(crate) fn of(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
            config: &vault.config,
            analyzer: &vault.analyzer,
            text_index_trusted: vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
        }
    }
}

/// [`put_secret_custody_in_txn`] through `write`: the value sealed under its
/// generation's custody key first, minted in this writer (KS-6).
fn put_custody_body_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
    occurred_at: u64,
) -> Result<()> {
    let data = super::storage_seal::sealed_body_in_txn(write.store, wtxn, id, rec)?;
    let at = TimeRange {
        start: occurred_at,
        end: occurred_at,
    };
    apply_custody_body_in_txn(write, wtxn, id, rec, data, (at, occurred_at))
}

/// Puts stored body `data` of `rec` (its value sealed, or none) as record
/// `id`, and keeps the name's high-water and the known-value index with it.
/// An erased credential's id is never put again (KS-6 part 2).
pub(super) fn apply_custody_body_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
    data: Vec<u8>,
    (occurred, occurred_at): (TimeRange, u64),
) -> Result<()> {
    write.store.refuse_erased_credential_in_txn(wtxn, id)?;
    apply_ops(
        write.store,
        write.config,
        write.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_SECRET_CUSTODY,
            occurred,
            learned_at: occurred_at,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        write.text_index_trusted,
        false,
        true,
    )?;
    // A rotation raises its name's high-water with it (FIX 5958). Only the
    // record the name resolves to moves it, so a superseded record never
    // takes the name back.
    if let Some(entry) = NAME_INDEX.get(write.store, wtxn, &rec.name)?
        && entry.id == *id
        && entry.high_water < rec.rotation_generation
    {
        let entry = NameEntry {
            high_water: rec.rotation_generation,
            ..entry
        };
        NAME_INDEX.put(write.store, wtxn, &rec.name, &entry)?;
    }
    // Every custody write lands here, so the known-value index keys each
    // value a record holds, at each generation (OF-560 C). A value newly
    // known reaches the files stored before it: a pass of the lift sweep
    // marks them, in the writer that made it known (FIX 2781). A run-bound
    // record's value is its run's alone and is never keyed (FIX 8028): a
    // short code one run's browser found masks nothing else in the vault.
    // Nor is a cloud registration slot's (`known_values::never_keyed`).
    if !super::known_values::never_keyed(&rec.name)
        && super::known_values::remember_in_txn(write.store, wtxn, id, rec)?
    {
        crate::batch::secret_scan::enqueue_known_remark_in_txn(write.store, wtxn, occurred_at)?;
    }
    Ok(())
}

impl Vault {
    /// Registers an active custody-portable secret from outside any manifest
    /// flow, for out-of-crate tests. No door outside the crate registers a
    /// record yet, and the record itself stays unconstructible out of crate.
    #[cfg(feature = "test-support")]
    pub fn register_test_secret(
        &self,
        name: &str,
        value: &[u8],
        bindings: Vec<SecretBinding>,
        registered_at: u64,
    ) -> Result<EntityId> {
        self.register_secret(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: name.to_owned(),
            class: CustodyClass::CustodyPortable,
            device_only: false,
            value_bytes: value.to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at,
            rotated_at: None,
            rotation_generation: 0,
            bindings,
            manifest_ref: String::new(),
            declared_paths: Vec::new(),
            policy_floor_snapshot: SecretCustodyFloor::default(),
        })
    }

    /// Registers a secret-custody record, minting the `EntityId` and writing
    /// the name index. Denies a duplicate LIVE name (a name held by an
    /// `Active`/`Suspended` record); a `Revoked` name frees for
    /// re-registration. The record must register `Active`, carry the resolved
    /// floor snapshot narrower-or-equal to the live floor, and name its
    /// manifest ref when it came from a declared entry.
    ///
    /// Reclaiming a `Revoked` name does NOT restart the generation counter:
    /// the new life is stamped one above the dead life's `rotation_generation`
    /// (SECRET-04 monotonicity, see the reclaim branch in
    /// `register_secret_in_txn`). A caller that
    /// supplies a nonzero generation at or below that high-water is refused
    /// rather than silently corrected.
    pub fn register_secret(&self, mut rec: SecretCustodyRecord) -> Result<EntityId> {
        let id = self.store.clock.entity_id()?;
        let mut wtxn = self.store.env.write_txn()?;
        // FIX 7592: the embedded handle's live owner binds an import-fetch
        // binding that names no actor. FIX 9325: a fault reading that owner
        // keeps the binding for the vault's one recorded Owner.
        if let Some(owner) = import_fetch_default_owner(self, &wtxn) {
            super::owner_door::default_import_fetch_actor(&mut rec.bindings, &owner);
        }
        register_secret_in_txn(self, &mut wtxn, &id, &mut rec)?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Resolves a live secret name to its custody `EntityId`. Returns `None`
    /// when the name has no live record.
    pub fn resolve_secret_ref(&self, name: &str) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        resolve_secret_ref_in_txn(&self.store, &rtxn, name)
    }

    /// Reads the value-less metadata projection. This is the ONLY read most
    /// callers get: it has no value field.
    pub fn get_secret_metadata(&self, id: &EntityId) -> Result<Option<SecretCustodyMetadata>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(
            super::read_secret_custody_meta_in_txn(&self.store, &rtxn, id)?
                .map(|rec| rec.metadata()),
        )
    }

    /// Door/lease paths only (SECRET-02). Reads the raw value bytes for a
    /// record within a read or write txn, requiring a binding that covers `effector`
    /// AND declares the [`SECRET_SCOPE_READ`] grant: anything else ⇒
    /// [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied). Naming the effector is not by itself a
    /// read grant — the binding's declared scope is what admits plaintext, and
    /// an empty scope list is no grant at all.
    /// The value never escapes into claims/CRDT/export/receipts/logs; this
    /// door is the narrowest possible read and exists so SECRET-02's door /
    /// lease machinery is the single value-read call-site. Consumed by
    /// [`crate::secret_lease`] (ONE-1920).
    pub(crate) fn get_secret_value_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        effector: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(rec) = read_secret_custody_in_txn(&self.store, txn, id)? else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::Secret(SecretError::SecretCustodyNotActive {
                name: rec.name,
            }));
        }
        // An admitted revoke of the id ends every use, settled here yet or
        // not (WILL L04 row 04).
        super::refuse_revoked_use_in_txn(self, txn, id, rec.class, &rec.name)?;
        if !rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            return Err(Error::Secret(SecretError::SecretBindingDenied {
                effector: effector.to_owned(),
                secret_ref: rec.name,
            }));
        }
        Ok(Some(rec.value_bytes))
    }
}

/// The actor an import-fetch binding that names none takes at
/// [`Vault::register_secret`]: the embedded owner while it is a live vault
/// owner. A fault reading that owner (its id or the live-owner census) keeps
/// the binding for the vault's one recorded Owner, so the import still runs
/// instead of answering `binding_actor_missing` (FIX 9325). A vault that
/// records several owners, or none, binds none on a fault.
fn import_fetch_default_owner(vault: &Vault, txn: &heed::RoTxn<'_>) -> Option<EntityId> {
    let live = crate::vault::embedded_owner_actor_id().and_then(|owner| {
        crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &owner)
            .map(|live| live.then_some(owner))
    });
    match live {
        Ok(owner) => owner,
        Err(_) => crate::policy_model::sole_recorded_owner_in_txn(vault, txn)
            .ok()
            .flatten(),
    }
}

/// The body of [`Vault::register_secret`], inside the caller's write
/// transaction: the owner's door (`owner_door.rs`) rechecks its proof in the
/// same transaction before it stores the value through here.
pub(super) fn register_secret_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &mut SecretCustodyRecord,
) -> Result<()> {
    register_custody_in_txn(&CustodyWrite::of(vault), wtxn, id, rec)
}

/// [`register_secret_in_txn`] through `write`: the batch door's mask on write
/// (OF-560) registers each secret it lifts here, in the batch's transaction.
pub(crate) fn register_custody_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &mut SecretCustodyRecord,
) -> Result<()> {
    if rec.status != SecretCustodyStatus::Active {
        return Err(invalid_body("registration requires status active"));
    }
    if rec.name.is_empty() {
        return Err(invalid_body("secret name must not be empty"));
    }
    // Checked before the name reaches an index key.
    if rec.name.len() > SECRET_NAME_MAX_BYTES {
        return Err(invalid_body("secret name is longer than 255 bytes"));
    }
    if rec.schema_version != SECRET_CUSTODY_SCHEMA_VERSION {
        return Err(invalid_body("unsupported secret custody schema version"));
    }

    // Resolve the floor against the LIVE vault inside this write
    // transaction and enforce narrow-only against it (never against the
    // caller-supplied snapshot, which may be stale).
    let live_band = refuse_bindings_wider_than_live_floor(write.store, wtxn, rec)?;
    // The audit snapshot attached to the record must be narrower-or-equal
    // to the live floor: a caller-attested WIDER floor would lie about
    // the register-time posture. Most-restrictive-wins merge means a
    // snapshot equal to or narrower than live is accepted as-is.
    let snap_band = rec.policy_floor_snapshot.band_for(rec.class);
    if snap_band.max > live_band.max {
        return Err(Error::Secret(SecretError::ManifestWidensFloor {
            secret_ref: rec.name.clone(),
            class: rec.class,
            requested: snap_band.max,
            floor_max: live_band.max,
        }));
    }

    let indexed = NAME_INDEX.get(write.store, wtxn, &rec.name)?;
    if let Some(entry) = indexed {
        // A live name denies; a revoked or missing record frees the index.
        // The admission projection reads status and generation without
        // copying the existing value out of the store.
        let held = read_secret_custody_admission_in_txn(write.store, wtxn, &entry.id)?;
        if let Some(existing) = held {
            if existing.status != SecretCustodyStatus::Revoked {
                return Err(Error::Secret(SecretError::SecretNameInUse {
                    name: rec.name.clone(),
                }));
            }
            // NAME RECLAIM. The dead record's generation is this name's
            // HIGH-WATER, and the new life must start strictly above it.
            //
            // `SecretTaintRef` identity is `(secret_ref, generation)` and
            // nothing else, and the taint check resolves the name to
            // whatever record the index points at NOW. A reclaimed name
            // that restarted at the caller's generation (every in-tree
            // constructor writes 0, exactly where the dead life started)
            // would let exhaust tagged against the REVOKED value compare
            // equal to the live record and read `TaintedLive` — dead
            // exhaust publishing unstamped and ungated as live. Advancing
            // the counter across the reclaim is what keeps the old tag
            // unmatched forever, without a reverse index and without
            // rewriting one byte of exhaust (S7, amended 2026-08-05).
            //
            // The vault stamps this generation itself: the caller's
            // number is not evidence of anything. A caller that
            // nonetheless ASSERTS a generation the dead life already
            // used is refused rather than silently corrected — that
            // assertion is a replay of a dead value's identity. The
            // default 0 asserts nothing and is simply stamped over.
            if rec.rotation_generation != 0
                && rec.rotation_generation <= existing.rotation_generation
            {
                return Err(invalid_body(
                    "reclaimed name requires a generation above the revoked record",
                ));
            }
            rec.rotation_generation = next_generation(existing.rotation_generation)?;
        } else if entry.id != *id {
            // A record gone from the store frees its name as a revoked one
            // does, and the reclaim starts above the high-water the index
            // kept for it (FIX 5958), the same advance with no record left to
            // read it from. The owner's archive restoring the very record the
            // name names continues that record's own life.
            rec.rotation_generation = next_generation(entry.high_water)?;
        }
    }

    // SECRET-01 dedicated door: the sealed type-77 put shape lives in
    // `put_secret_custody_in_txn`, shared with SECRET-04's rotate/revoke.
    put_custody_body_in_txn(write, wtxn, id, rec, rec.registered_at)?;
    let entry = NameEntry {
        id: *id,
        high_water: indexed.map_or(rec.rotation_generation, |entry| {
            entry.high_water.max(rec.rotation_generation)
        }),
    };
    NAME_INDEX.put(write.store, wtxn, &rec.name, &entry)?;
    Ok(())
}

/// The generation a registration under `name` starts at here, before it is
/// written: zero, or one above the revoked record that held the name, its
/// high-water, or above the high-water the index kept for a record gone from
/// the store (the reclaim rule [`register_custody_in_txn`] stamps). A live
/// name refuses: a door that hands the registration to another holder
/// states this generation in the request.
pub(crate) fn register_generation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<u32> {
    let Some(entry) = NAME_INDEX.get(store, txn, &name.to_owned())? else {
        return Ok(0);
    };
    let Some(held) = read_secret_custody_admission_in_txn(store, txn, &entry.id)? else {
        return next_generation(entry.high_water);
    };
    if held.status != SecretCustodyStatus::Revoked {
        return Err(Error::Secret(SecretError::SecretNameInUse {
            name: name.to_owned(),
        }));
    }
    next_generation(held.rotation_generation)
}

/// Whether the name index may point `name` at record `id`, which a custody
/// transition at `generation` writes (OF-422): the name is well formed, and
/// it belongs to no other record here that is not revoked, nor to a revoked
/// one at `generation` or later (a reclaimed name's generation only climbs).
/// Reads only: [`bind_synced_name_in_txn`] binds by it, and the pending
/// custody pass asks it before it opens a carrier's value (FIX 5408).
pub(super) fn can_bind_synced_name_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
    id: &EntityId,
    generation: u32,
) -> Result<bool> {
    if name.is_empty() || name.len() > SECRET_NAME_MAX_BYTES {
        return Ok(false);
    }
    if let Some(entry) = NAME_INDEX.get(store, txn, &name.to_owned())?
        && entry.id != *id
        && read_secret_custody_admission_in_txn(store, txn, &entry.id)?.is_some_and(|held| {
            held.status != SecretCustodyStatus::Revoked || held.rotation_generation >= generation
        })
    {
        return Ok(false);
    }
    Ok(true)
}

/// Points the name index at record `id`, which a custody transition writes
/// (OF-422), when [`can_bind_synced_name_in_txn`] lets it. Returns whether
/// the name is the record's. The name's high-water never goes down.
pub(super) fn bind_synced_name_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    name: &str,
    id: &EntityId,
    generation: u32,
) -> Result<bool> {
    if !can_bind_synced_name_in_txn(store, wtxn, name, id, generation)? {
        return Ok(false);
    }
    let name = name.to_owned();
    let entry = NameEntry {
        id: *id,
        high_water: NAME_INDEX
            .get(store, wtxn, &name)?
            .map_or(generation, |entry| entry.high_water.max(generation)),
    };
    NAME_INDEX.put(store, wtxn, &name, &entry)?;
    Ok(true)
}

/// OF-222: restores one custody record from the owner's own whole-vault
/// archive under its archived id, inside the import's write transaction and
/// through every check registration makes. The owner's own archive carries
/// custody records so a re-import keeps every key (owner ruling 2026-10-17);
/// no export to a contact or share carries one. Returns whether it restored
/// it: a portable record whose id an admitted revoke names stays dead, and
/// nothing is written (WILL L04 row 04); so does an erased one (KS-6 part 2).
pub(crate) fn restore_secret_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &mut SecretCustodyRecord,
) -> Result<bool> {
    if !vault.store.credential_readmits_in_txn(wtxn, id)
        || (rec.class == CustodyClass::CustodyPortable
            && super::control::custody_revoked_in_txn(vault, wtxn, id)?)
    {
        return Ok(false);
    }
    register_secret_in_txn(vault, wtxn, id, rec)?;
    Ok(true)
}

/// Revokes, in `wtxn`, each custody record the side-row wall minted from the
/// row outside the entity tables that `origin` names (FIX 6710): an erase
/// that takes the row reaches every value it lifted. A record is minted from
/// the row when its mask origin names it; a value custody held before, which
/// the row only named, keeps its record. Each live record is revoked as the
/// revoke door's body revokes one, its value erased at rest, with its
/// receipt; one revoked already gives up only the bytes it still holds.
pub(crate) fn revoke_side_row_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    origin: &EntityId,
) -> Result<()> {
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    for id in super::found_keys::found_key_custody_in_txn(&vault.store, wtxn, origin)? {
        let minted = crate::batch::secret_scan::mask_origin_in_txn(&vault.store, wtxn, &id)?
            .is_some_and(|mask| mask.record == *origin);
        if !minted {
            continue;
        }
        let Some(record) = super::read_secret_custody_meta_in_txn(&vault.store, wtxn, &id)? else {
            continue;
        };
        let cause = crate::secret_rotation::RevokeCause::Revoked;
        if record.status == SecretCustodyStatus::Revoked {
            crate::secret_rotation::revoke_custody_in_txn(vault, wtxn, &id, cause, at)?;
        } else {
            vault.revoke_secret_in_txn(wtxn, &record.name, cause, at)?;
        }
    }
    Ok(())
}
