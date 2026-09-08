//! Name index, borrowing admission projection, sealed put, and Vault doors.

use rmpv::ValueRef;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::codec::{decode_secret_custody_body, encode_secret_custody_body, invalid_body};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SECRET_NAME_INDEX_PREFIX, SecretBinding, SecretCustodyFloor, SecretCustodyMetadata,
    SecretCustodyRecord, SecretCustodyStatus, TierBand,
};

// ---------------------------------------------------------------------------
// Name index
// ---------------------------------------------------------------------------

/// Resolves a live secret name to its custody `EntityId` inside an
/// existing txn. `pub(crate)` for SECRET-02's lease doors (ONE-1920), which
/// hold their own write txn and must not open a nested read txn.
pub(crate) fn resolve_secret_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<EntityId>> {
    let Some(bytes) = store.vault_meta.get(txn, &name_index_key(name))? else {
        return Ok(None);
    };
    let id_bytes: [u8; 16] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
    let id = EntityId::from_bytes(id_bytes)
        .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
    Ok(Some(id))
}

/// The `vault_meta` index key for a live secret name.
fn name_index_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(SECRET_NAME_INDEX_PREFIX.len() + name.len());
    key.extend_from_slice(SECRET_NAME_INDEX_PREFIX.as_bytes());
    key.extend_from_slice(name.as_bytes());
    key
}

/// Reads and decodes a custody record under either a read or write txn.
/// `pub(crate)` for SECRET-02's lease doors (ONE-1920): they resolve the
/// record inside their own write txn to drive admission and read
/// `declared_paths` — value reads still route ONLY through the bound door
/// [`Vault::get_secret_value_in_txn`].
pub(crate) fn read_secret_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyRecord>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("secret custody entity header"));
    };
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::CorruptedIndex("secret custody entity type"));
    }
    decode_secret_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

// ---------------------------------------------------------------------------
// Admission projection (SECRET-02, SOL-1920-04)
// ---------------------------------------------------------------------------

/// The admission projection of a custody record: every field SECRET-02's
/// lease doors need to ADMIT and to drive T2, and nothing else. Has no
/// value field by construction — admission never heap-copies plaintext;
/// the ONE value decode is the bound door [`Vault::get_secret_value_in_txn`]
/// itself (its caller wraps the bytes in `Zeroizing`). Raw-record access is
/// not broadened: the full decode stays behind
/// [`read_secret_custody_in_txn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretCustodyAdmission {
    /// The secret name.
    pub(crate) name: String,
    /// The custody class.
    pub(crate) class: CustodyClass,
    /// Lifecycle status.
    pub(crate) status: SecretCustodyStatus,
    /// Rotation generation counter (the S6 staleness signal leases stamp).
    pub(crate) rotation_generation: u32,
    /// Effector bindings.
    pub(crate) bindings: Vec<SecretBinding>,
    /// Manifest-declared local paths (the T2 target set).
    pub(crate) declared_paths: Vec<String>,
}

impl SecretCustodyAdmission {
    /// Looks up the binding covering `effector` — mirrors
    /// [`SecretCustodyRecord::binding_for`], drives tier admission.
    #[must_use]
    pub(crate) fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }
}

/// The borrowing half of [`required_value`]: a MISSING or DUPLICATED key
/// both yield `None`, over [`ValueRef`] entries.
fn required_value_ref<'a, 'b>(
    entries: &'b [(ValueRef<'a>, ValueRef<'a>)],
    key: &str,
) -> Option<&'b ValueRef<'a>> {
    let mut found = None;
    for (k, v) in entries {
        if let ValueRef::String(s) = k
            && s.as_str() == Some(key)
        {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

/// A string field out of a borrowing value, tied to the body buffer.
fn str_ref<'a>(value: &ValueRef<'a>, reason: &'static str) -> Result<&'a str> {
    match value {
        ValueRef::String(s) => s.into_str().ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// An integer field out of a borrowing value (the owned codec's `as_u64`
/// discipline: u64 direct, else a non-negative i64).
fn u64_ref(value: &ValueRef<'_>, reason: &'static str) -> Result<u64> {
    match value {
        ValueRef::Integer(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|v| u64::try_from(v).ok()))
            .ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// The borrowing half of [`binding_from_value`].
fn binding_from_value_ref(value: &ValueRef<'_>) -> Result<SecretBinding> {
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("binding must be a map"));
    };
    let effector = str_ref(
        required_value_ref(entries, "effector").ok_or(invalid_body("binding effector"))?,
        "binding effector",
    )?
    .to_owned();
    let tier_raw = u64_ref(
        required_value_ref(entries, "tier_ceiling").ok_or(invalid_body("binding tier_ceiling"))?,
        "binding tier_ceiling",
    )?;
    let tier_ceiling = CustodyTier::from_u8(
        u8::try_from(tier_raw).map_err(|_| invalid_body("binding tier_ceiling"))?,
    )
    .ok_or(invalid_body("binding tier_ceiling"))?;
    let scopes = match required_value_ref(entries, "scopes") {
        Some(ValueRef::Array(items)) => {
            let mut scopes = Vec::with_capacity(items.len());
            for item in items {
                scopes.push(str_ref(item, "binding scope")?.to_owned());
            }
            scopes
        }
        Some(_) => return Err(invalid_body("binding scopes must be an array")),
        None => Vec::new(),
    };
    Ok(SecretBinding {
        effector,
        tier_ceiling,
        scopes,
    })
}

/// Decodes the admission projection from a custody body WITHOUT
/// materializing the value: the borrowing MessagePack reader leaves
/// `value_bytes` a slice of the LMDB-resident page, so the admission path
/// holds no heap copy of the plaintext at all (SOL-1920-04). The keys the
/// doors consume plus the presence/shape of `value_bytes` validate with
/// the same missing-or-duplicated reject discipline as
/// [`decode_secret_custody_body`]; keys the doors never read stay the full
/// codec's affair (registration already ran it).
pub(crate) fn decode_secret_custody_admission_body(bytes: &[u8]) -> Result<SecretCustodyAdmission> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value_ref(&mut cursor)
        .map_err(|_| invalid_body("decode secret custody body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret custody body"));
    }
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("secret custody body must be a map"));
    };
    // Present and byte-shaped, never copied: the value stays a borrow of
    // the store page and dies with the decoded tree.
    match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[4]) {
        Some(ValueRef::Binary(_)) | Some(ValueRef::String(_)) => {}
        _ => return Err(invalid_body("value_bytes")),
    }
    let name = str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[1]).ok_or(invalid_body("name"))?,
        "name",
    )?
    .to_owned();
    let class = CustodyClass::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[2]).ok_or(invalid_body("class"))?,
        "class",
    )?)
    .ok_or(invalid_body("class"))?;
    let status = SecretCustodyStatus::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[5]).ok_or(invalid_body("status"))?,
        "status",
    )?)
    .ok_or(invalid_body("status"))?;
    let rotation_generation = u32::try_from(u64_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[8])
            .ok_or(invalid_body("rotation_generation"))?,
        "rotation_generation",
    )?)
    .map_err(|_| invalid_body("rotation_generation"))?;
    let bindings = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[9]) {
        Some(ValueRef::Array(items)) => {
            let mut bindings = Vec::with_capacity(items.len());
            for item in items {
                bindings.push(binding_from_value_ref(item)?);
            }
            bindings
        }
        Some(_) => return Err(invalid_body("bindings must be an array")),
        None => return Err(invalid_body("bindings")),
    };
    let declared_paths = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[11]) {
        Some(ValueRef::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                paths.push(str_ref(item, "declared_path")?.to_owned());
            }
            paths
        }
        Some(_) => return Err(invalid_body("declared_paths must be an array")),
        None => return Err(invalid_body("declared_paths")),
    };
    Ok(SecretCustodyAdmission {
        name,
        class,
        status,
        rotation_generation,
        bindings,
        declared_paths,
    })
}

/// Reads the admission projection under either txn kind — the doors of
/// SECRET-02 resolve this instead of the full record (SOL-1920-04).
pub(crate) fn read_secret_custody_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyAdmission>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("secret custody entity header"));
    };
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::CorruptedIndex("secret custody entity type"));
    }
    decode_secret_custody_admission_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
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
            return Err(Error::ManifestWidensFloor {
                secret_ref: rec.name.clone(),
                class: rec.class,
                requested: b.tier_ceiling,
                floor_max: live_band.max,
            });
        }
    }
    Ok(live_band)
}

/// Writes one custody body through the ONE sealed put shape, stamping
/// `occurred_at` as both the occurrence range and the learned-at.
///
/// Type-77 bodies are sealed from the raw/CRDT planes until ONE-1865: the
/// `apply_put` seal admits byte 77 only through the engine-internal
/// non-replicated shape (`allow_maintenance && !allow_reserved_predicate`,
/// the shape the default policy-manifest seeder uses). Any public or
/// replicated CRDT carry of byte 77 rejects there until then.
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
    let data = encode_secret_custody_body(rec)?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_SECRET_CUSTODY,
            occurred: TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            learned_at: occurred_at,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

impl Vault {
    /// Registers a secret-custody record, minting the `EntityId` and writing
    /// the name index. Denies a duplicate LIVE name (a name held by an
    /// `Active`/`Suspended` record); a `Revoked` name frees for
    /// re-registration. The record must register `Active`, carry the resolved
    /// floor snapshot narrower-or-equal to the live floor, and name its
    /// manifest ref when it came from a declared entry.
    ///
    /// Reclaiming a `Revoked` name does NOT restart the generation counter:
    /// the new life is stamped one above the dead life's `rotation_generation`
    /// (SECRET-04 monotonicity, see the reclaim branch below). A caller that
    /// supplies a nonzero generation at or below that high-water is refused
    /// rather than silently corrected.
    pub fn register_secret(&self, mut rec: SecretCustodyRecord) -> Result<EntityId> {
        if rec.status != SecretCustodyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if rec.name.is_empty() {
            return Err(invalid_body("secret name must not be empty"));
        }
        if rec.schema_version != SECRET_CUSTODY_SCHEMA_VERSION {
            return Err(invalid_body("unsupported secret custody schema version"));
        }
        let id = EntityId::now();

        let mut wtxn = self.store.env.write_txn()?;
        let index_key = name_index_key(&rec.name);

        // Resolve the floor against the LIVE vault inside this write
        // transaction and enforce narrow-only against it (never against the
        // caller-supplied snapshot, which may be stale).
        let live_band = refuse_bindings_wider_than_live_floor(&self.store, &wtxn, &rec)?;
        // The audit snapshot attached to the record must be narrower-or-equal
        // to the live floor: a caller-attested WIDER floor would lie about
        // the register-time posture. Most-restrictive-wins merge means a
        // snapshot equal to or narrower than live is accepted as-is.
        let snap_band = rec.policy_floor_snapshot.band_for(rec.class);
        if snap_band.max > live_band.max {
            return Err(Error::ManifestWidensFloor {
                secret_ref: rec.name.clone(),
                class: rec.class,
                requested: snap_band.max,
                floor_max: live_band.max,
            });
        }

        if let Some(existing_bytes) = self.store.vault_meta.get(&wtxn, &index_key)? {
            let id_bytes: [u8; 16] = existing_bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
            let existing_id = EntityId::from_bytes(id_bytes)
                .map_err(|_| Error::CorruptedIndex("secret name index id"))?;
            // A live name denies; a revoked or missing record frees the index.
            if let Some(existing) = read_secret_custody_in_txn(&self.store, &wtxn, &existing_id)? {
                if existing.status != SecretCustodyStatus::Revoked {
                    return Err(Error::SecretNameInUse { name: rec.name });
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
                rec.rotation_generation = existing
                    .rotation_generation
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("secret rotation generation"))?;
            }
        }

        // SECRET-01 dedicated door: the sealed type-77 put shape lives in
        // `put_secret_custody_in_txn`, shared with SECRET-04's rotate/revoke.
        put_secret_custody_in_txn(self, &mut wtxn, &id, &rec, rec.registered_at)?;
        self.store
            .vault_meta
            .put(&mut wtxn, &index_key, id.as_bytes())?;
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
        Ok(read_secret_custody_in_txn(&self.store, &rtxn, id)?.map(|rec| rec.metadata()))
    }

    /// Door/lease paths only (SECRET-02). Reads the raw value bytes for a
    /// record within a write txn, requiring a binding that covers `effector`
    /// AND declares the [`SECRET_SCOPE_READ`] grant: anything else ⇒
    /// [`Error::SecretBindingDenied`]. Naming the effector is not by itself a
    /// read grant — the binding's declared scope is what admits plaintext, and
    /// an empty scope list is no grant at all.
    /// The value never escapes into claims/CRDT/export/receipts/logs; this
    /// door is the narrowest possible read and exists so SECRET-02's door /
    /// lease machinery is the single value-read call-site. Consumed by
    /// [`crate::secret_lease`] (ONE-1920).
    pub(crate) fn get_secret_value_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        effector: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(rec) = read_secret_custody_in_txn(&self.store, txn, id)? else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::SecretCustodyNotActive { name: rec.name });
        }
        if !rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            return Err(Error::SecretBindingDenied {
                effector: effector.to_owned(),
                secret_ref: rec.name,
            });
        }
        Ok(Some(rec.value_bytes))
    }
}
