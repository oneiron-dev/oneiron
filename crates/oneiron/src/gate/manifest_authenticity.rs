//! Local write-door authentication for manifest contributions. Replay never creates permits.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::side_table::{self, CodecError, HexId, Raw, RawValue, SideTable};
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord, Store,
};
use crate::{EntityId, Vault};

/// Authenticity hash stamped when a policy manifest is contributed directly (non-replicated),
/// with the time this vault first trusted that body. Key: hex32.
const TRUSTED_ORIGIN: SideTable<HexId, TrustedOrigin, Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_TRUSTED_ORIGIN);

/// [`TRUSTED_ORIGIN`]'s value: the trusted body's hash, then the second this vault first
/// trusted that body (FIX 10936), big-endian. A rewrite of the same body keeps the time, so
/// what counts from it never moves. The vault-bootstrap seed writes the bare hash: it records
/// no trust time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedOrigin {
    hash: [u8; 32],
    trusted_at: Option<u64>,
}

impl RawValue for TrustedOrigin {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = self.hash.to_vec();
        if let Some(at) = self.trusted_at {
            bytes.extend_from_slice(&at.to_be_bytes());
        }
        Ok(bytes)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (hash, rest) = bytes.split_at(bytes.len().min(32));
        Ok(Self {
            hash: <[u8; 32]>::from_raw(hash)?,
            trusted_at: if rest.is_empty() {
                None
            } else {
                Some(u64::from_raw(rest)?)
            },
        })
    }
}
/// Marks a policy-manifest contribution as quarantined by an explicit owner action. Key: hex32.
const QUARANTINED: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_QUARANTINED);
/// Maps a legacy policy-manifest id forward to its re-authored replacement id. Key: hex32.
const REKEY: SideTable<HexId, EntityId, Raw> = SideTable::new(&side_table::GATE_MANIFEST_REKEY);
/// Body-bound seed origin, distinct from trust: the body hash of an engine-seeded default policy
/// manifest. An owner write clears it. Key: hex32.
const SEEDED: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_SEEDED_CONFIDENCE);

/// The Gate `content_kind` of every manifest quarantine receipt.
const MANIFEST_QUARANTINE_CONTENT_KIND: &str = "policy_manifest_quarantine";
/// A manifest's current bytes were quarantined.
const MANIFEST_QUARANTINED_REASON: &str = "gate.manifest.quarantined";
/// A manifest's quarantine marker was lifted.
const MANIFEST_QUARANTINE_LIFTED_REASON: &str = "gate.manifest.quarantine_lifted";

/// `store::handle`'s vault-bootstrap seed writes this row directly, before any vault (and so any
/// typed door) exists to read it back through — kept as a plain string builder so that raw write
/// keeps landing under [`TRUSTED_ORIGIN`]'s declared prefix byte-for-byte.
pub(crate) fn trusted_manifest_key(id: &EntityId) -> String {
    format!("manifest:trusted:{}", id.to_hex())
}

/// Separate proof that an authenticated vault owner authored an override
/// row. A generic local manifest trust stamp is not holder authority.
const RETENTION_HOLDER: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_RETENTION_HOLDER);

pub(in crate::gate) fn retention_holder_verified(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(RETENTION_HOLDER
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

/// The bootstrap seed's [`SEEDED`] row key, spelled for the same raw write as
/// [`trusted_manifest_key`].
pub(crate) fn seeded_manifest_key(id: &EntityId) -> String {
    format!("manifest:seeded_confidence:{}", id.to_hex())
}

pub(crate) fn manifest_is_seeded_default(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(SEEDED
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

/// Who stands behind one trusted manifest's numeric policy rows (Engine
/// 10-22 C1). Generic local trust is not holder authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gate) enum PolicyRowOrigin {
    /// The untouched engine seed: shipped values, a fallback only.
    Seeded,
    /// Bytes an authenticated owner or holder door wrote, by the exact-body
    /// holder proof: they replace the fallback.
    Authored,
    /// Any other trusted manifest: it only narrows.
    Narrowing,
}

pub(in crate::gate) fn policy_row_origin(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<PolicyRowOrigin> {
    Ok(if manifest_is_seeded_default(store, txn, id, body)? {
        PolicyRowOrigin::Seeded
    } else if retention_holder_verified(store, txn, id, body)? {
        PolicyRowOrigin::Authored
    } else {
        PolicyRowOrigin::Narrowing
    })
}

/// Marks the body hashed `hash` at `id` as the engine's seeded default,
/// untouched by any local re-authoring.
pub(in crate::gate) fn mark_seeded(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hash: &[u8; 32],
) -> Result<()> {
    SEEDED.put(store, txn, &HexId(*id), hash)
}

pub(crate) fn stamp_manifest_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let hash = blake3::hash(body);
    let origin_key = HexId(*id);
    if !replicated {
        // Every local re-authoring is authored even if it keeps the seeded ID,
        // pack name or byte-identical default value. A body already trusted
        // keeps the time it was first trusted (FIX 10936).
        SEEDED.delete(store, txn, &origin_key)?;
        let trusted_at = match TRUSTED_ORIGIN.get(store, txn, &origin_key)? {
            Some(prior) if prior.hash == *hash.as_bytes() => prior.trusted_at,
            _ => Some(crate::ports::recorded_at_in_txn(store, txn)?),
        };
        TRUSTED_ORIGIN.put(
            store,
            txn,
            &origin_key,
            &TrustedOrigin {
                hash: *hash.as_bytes(),
                trusted_at,
            },
        )?;
    } else {
        let existing_matches = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .is_some_and(|raw| {
                EntityMetadataHeader::parse(&raw)
                    .is_some_and(|h| h.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
                    && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(body)
            });
        if !existing_matches
            || SEEDED
                .get(store, txn, &origin_key)?
                .is_none_or(|old| old != *hash.as_bytes())
        {
            SEEDED.delete(store, txn, &origin_key)?;
        }
        if !existing_matches
            || TRUSTED_ORIGIN
                .get(store, txn, &origin_key)?
                .is_none_or(|old| old.hash != *hash.as_bytes())
        {
            TRUSTED_ORIGIN.delete(store, txn, &origin_key)?;
        }
    }
    Ok(())
}

pub(crate) fn manifest_is_trusted(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(TRUSTED_ORIGIN
        .get(store, txn, &HexId(*id))?
        .is_some_and(|origin| origin.hash == *blake3::hash(body).as_bytes()))
}

/// The second this vault first trusted `body` at manifest `id` (FIX 10936): its trust stamp's
/// time, kept across a rewrite of the same body. `None` when that body is not trusted there,
/// or its stamp records no time (the bootstrap seed's).
pub(crate) fn manifest_trusted_at(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<u64>> {
    Ok(TRUSTED_ORIGIN
        .get(store, txn, &HexId(*id))?
        .filter(|origin| origin.hash == *blake3::hash(body).as_bytes())
        .and_then(|origin| origin.trusted_at))
}

pub(crate) fn manifest_is_quarantined(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(QUARANTINED
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

/// Quarantines the bytes manifest `id` holds now, as the owner's quarantine
/// door does, inside `txn`. False when `id` names no stored manifest.
fn quarantine_current_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    actor: Option<EntityId>,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(false);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|h| h.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
    {
        return Ok(false);
    }
    let hash = blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]);
    QUARANTINED.put(&vault.store, txn, &HexId(*id), hash.as_bytes())?;
    vault.append_quarantine_receipt_in_txn(
        txn,
        actor,
        MANIFEST_QUARANTINED_REASON,
        *id,
        *hash.as_bytes(),
    )?;
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestContribution {
    pub id: String,
    pub trusted: bool,
    pub restrict_only: bool,
    pub quarantined: bool,
}
impl Vault {
    /// Surface unauthenticated narrowing as actionable rows, without granting it authority.
    pub fn manifest_contributions(&self) -> Result<Vec<ManifestContribution>> {
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        let manifests = crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &txn,
            ENTITY_TYPE_POLICY_MANIFEST,
            None,
        )?;
        for id in manifests {
            let id = id?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?
                .ok_or(Error::CorruptedIndex("manifest contribution"))?;
            let body = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("manifest contribution header"))?;
            let trusted = manifest_is_trusted(&self.store, &txn, &id, body)?;
            out.push(ManifestContribution {
                id: id.to_hex(),
                trusted,
                restrict_only: !trusted,
                quarantined: manifest_is_quarantined(&self.store, &txn, &id, body)?,
            });
        }
        Ok(out)
    }

    /// Appends one manifest quarantine receipt in the acting writer and
    /// answers its decision id.
    fn append_quarantine_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: Option<EntityId>,
        reason: &'static str,
        id: EntityId,
        hash: [u8; 32],
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let (actor_class, actor_ref) = match actor {
            Some(actor) => ("human".to_owned(), Some(actor.to_hex())),
            None => ("system".to_owned(), None),
        };
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: "allow".to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                MANIFEST_QUARANTINE_CONTENT_KIND,
                vec![format!("manifest:{}", id.to_hex())],
            ),
            actor_class,
            actor_ref,
            content_kind: MANIFEST_QUARANTINE_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: hash.to_vec(),
            read_frontier_hash: [0; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)?;
        Ok(decision_id)
    }

    /// Human removal of an untrusted narrowing, pinned to these exact bytes.
    /// Once it commits, the custody floor rebinds and the manifest watch
    /// reads it, as every manifest commit does (FIX 11527).
    pub fn quarantine_manifest_contribution(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            return Err(Error::InvalidConfig("not a policy manifest".into()));
        }
        let hash = blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]);
        QUARANTINED.put(&self.store, &mut txn, &HexId(id), hash.as_bytes())?;
        self.append_quarantine_receipt_in_txn(
            &mut txn,
            Some(actor),
            MANIFEST_QUARANTINED_REASON,
            id,
            *hash.as_bytes(),
        )?;
        txn.commit()?;
        self.apply_pending_rebinds_after_commit();
        Ok(())
    }

    /// Lifts the quarantine marker on a manifest id, so bytes declared
    /// under it count again as any declaration does. An id with no marker is
    /// left as it is. An install never lifts it by itself.
    pub fn lift_manifest_quarantine(&self, owner: &AuthenticatedOwner, id: EntityId) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let Some(hash) = QUARANTINED.get(&self.store, &txn, &HexId(id))? else {
            return Ok(());
        };
        QUARANTINED.delete(&self.store, &mut txn, &HexId(id))?;
        self.append_quarantine_receipt_in_txn(
            &mut txn,
            Some(actor),
            MANIFEST_QUARANTINE_LIFTED_REASON,
            id,
            hash,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Shared owner-authenticated manifest write door. Fixture policies and
    /// re-authoring take the same decode, target-type and write checks.
    pub(crate) fn write_owner_policy_manifest_in_txn(
        &self,
        owner: &AuthenticatedOwner,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        owner.revalidate_in_txn(self, txn)?;
        self.write_policy_manifest_in_txn(txn, id, data, now)
    }

    /// [`Self::write_owner_policy_manifest_in_txn`] for a door whose own check,
    /// in this transaction, found `holder`'s actor among the named holders of
    /// the change it writes: a live Owner, or an Admin or Delegate whose
    /// Owner-minted grant names the exact target. The grant is the authority,
    /// so the proof takes the person tier.
    pub(crate) fn write_holder_policy_manifest_in_txn(
        &self,
        holder: &AuthenticatedOwner,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        holder.revalidate_person_in_txn(self, txn)?;
        self.write_policy_manifest_in_txn(txn, id, data, now)
    }

    fn write_policy_manifest_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        // An optional notification table is made explicit on admission, so
        // an authenticated install is immediately editable by the owner.
        let data = super::default_manifest::with_default_owner_policy_notifications(data)?;
        let Some(decoded) = super::decode::decode_policy_manifest(&data) else {
            return Err(Error::InvalidConfig("malformed policy manifest".into()));
        };
        if let Some(row) = super::policy_values::unadmitted_row(&decoded.policy_values) {
            return Err(GateError::PolicyValueLevelNotAdmitted {
                key: row.key.as_str(),
                level: row.scope.level(),
            }
            .into());
        }
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(Error::InvalidConfig(
                    "policy manifest id belongs to another entity".into(),
                ));
            }
        }
        let holder_hash = blake3::hash(&data);
        crate::batch::apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        RETENTION_HOLDER.put(&self.store, txn, &HexId(id), holder_hash.as_bytes())?;
        Ok(())
    }

    /// Installs a locally authored policy manifest through the authenticated
    /// owner door. Hosts can grant connector effects without bypassing origin
    /// attestation or writing a reserved maintenance type through `put_entity`.
    ///
    /// # Errors
    /// Refuses unauthenticated owners, malformed manifests, value rows at a level
    /// their key does not admit, or IDs owned by another type.
    pub fn install_owner_policy_manifest(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        txn.commit()?;
        self.apply_pending_rebinds_after_commit();
        Ok(())
    }

    /// Store a fresh, untrusted policy proposal without contributing to policy.
    /// The ordinary writer validates its bytes, then all local authority stamps
    /// are removed and the exact body is quarantined before this transaction
    /// can commit. No owner proof is created or inherited by this path.
    pub(in crate::gate) fn write_policy_manifest_proposal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        if crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
            return Err(Error::InvalidConfig(
                "a policy proposal requires a fresh id".into(),
            ));
        }
        self.write_policy_manifest_in_txn(txn, id, data, now)?;
        let key = HexId(id);
        TRUSTED_ORIGIN.delete(&self.store, txn, &key)?;
        RETENTION_HOLDER.delete(&self.store, txn, &key)?;
        SEEDED.delete(&self.store, txn, &key)?;
        quarantine_current_in_txn(self, txn, &id, None)?;
        Ok(())
    }

    /// Whether each manifest in `installs`, written in order on the vault as
    /// it stands, narrows the resolved policy the one before it left, on
    /// every axis (ARCH-0070), and what `read` finds once every install is in
    /// place and each of `retires` is quarantined at its current bytes. The
    /// writes go through the install and quarantine doors' own writes, in a
    /// transaction that never commits. A manifest the door refuses, or whose
    /// exact stored bytes the owner quarantined under its id (the install
    /// refuses those too), and every one after it, reads as no narrowing;
    /// then, or when a retire names no stored manifest, `read` does not run.
    /// `folded` sees this writer's snapshot at each policy it resolves and
    /// once the retires are in place, so a caller lists the stored manifests
    /// each one folds (`host_door_lists`).
    ///
    /// # Errors
    /// A store failure, an unreadable manifest row, or `read`'s own.
    pub(crate) fn project_manifest_changes<T>(
        &self,
        installs: &[(EntityId, Vec<u8>)],
        retires: &[EntityId],
        now: u64,
        read: impl FnOnce(&heed::RoTxn<'_>) -> Result<T>,
        folded: &mut dyn FnMut(&heed::RoTxn<'_>),
    ) -> Result<(Vec<bool>, Option<T>)> {
        let mut steps = vec![false; installs.len()];
        let mut txn = self.store.env.write_txn()?;
        let mut before = super::resolve_policy_manifest(&self.store, &txn)?;
        folded(&txn);
        let mut placed = true;
        for ((id, data), step) in installs.iter().zip(&mut steps) {
            // The shape install refuses bytes the owner quarantined under this
            // id (`install_shape_manifest`), so they never land in the
            // projection either (FIX 5956). Bytes that do not decode, the
            // write below refuses itself.
            let quarantined = match super::owner_policy_manifest_as_stored(data.clone()) {
                Ok(stored) => manifest_is_quarantined(&self.store, &txn, id, &stored)?,
                Err(_) => false,
            };
            if quarantined
                || self
                    .write_policy_manifest_in_txn(&mut txn, *id, data.clone(), now)
                    .is_err()
            {
                placed = false;
                break;
            }
            let after = super::resolve_policy_manifest(&self.store, &txn)?;
            folded(&txn);
            *step = super::resolution::manifest_resolution_narrows(&before, &after);
            before = after;
        }
        for id in retires {
            placed = placed && quarantine_current_in_txn(self, &mut txn, id, None)?;
        }
        if placed && !retires.is_empty() {
            folded(&txn);
        }
        let seen = if placed { Some(read(&txn)?) } else { None };
        txn.abort();
        Ok((steps, seen))
    }

    /// Installs `data` as [`Self::install_owner_policy_manifest`] does, only
    /// when it narrows the resolved policy the vault holds just before it,
    /// on every axis (ARCH-0070). The check and the write share one writer,
    /// so no landing in between can make it a widening. `Ok(false)`: nothing
    /// was written. `folded` sees the writer's snapshot at the policy before
    /// and after the write, as [`Self::project_manifest_changes`] shows it.
    ///
    /// # Errors
    /// As [`Self::install_owner_policy_manifest`].
    pub(crate) fn install_owner_policy_manifest_narrowing(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
        folded: &mut dyn FnMut(&heed::RoTxn<'_>),
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let before = super::resolve_policy_manifest(&self.store, &txn)?;
        folded(&txn);
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        let after = super::resolve_policy_manifest(&self.store, &txn)?;
        folded(&txn);
        if !super::resolution::manifest_resolution_narrows(&before, &after) {
            txn.abort();
            return Ok(false);
        }
        txn.commit()?;
        self.apply_pending_rebinds_after_commit();
        Ok(true)
    }

    /// Apply an explanation drafted by a model only to an empty row. An
    /// authenticated owner may instead write their own why; a draft never
    /// overwrites that owner text. The engine never invents the prose.
    pub fn set_policy_value_why(
        &self,
        owner: &AuthenticatedOwner,
        manifest: EntityId,
        row_ref: &str,
        text: &str,
        drafted: bool,
        now: u64,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &manifest)?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            return Err(Error::InvalidConfig("not a policy manifest".into()));
        }
        let Some(updated) = super::policy_values::with_policy_why(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            row_ref,
            text,
            drafted,
        ) else {
            return Ok(false);
        };
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, manifest, updated, now)?;
        txn.commit()?;
        // A floor this commit moved is judged again at once (FIX 5505).
        self.apply_pending_rebinds_after_commit();
        Ok(true)
    }

    /// Explicit owner re-authoring, never grandfathering a product-band permit.
    /// The legacy carrier remains inert; the mapping records the re-key provenance.
    pub fn reauthor_legacy_policy_manifest(
        &self,
        owner: &AuthenticatedOwner,
        legacy: EntityId,
        target: EntityId,
        now: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &legacy)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("legacy manifest header"))?;
        if crate::registry::zone_of(header.entity_type)
            != crate::registry::TypeByteZone::CompiledProduct
            || crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &target)?
        {
            return Err(Error::InvalidConfig(
                "manifest re-key requires legacy source and fresh target".into(),
            ));
        }
        let data = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, target, data, now)?;
        REKEY.put(&self.store, &mut txn, &HexId(legacy), &target)?;
        txn.commit()?;
        // A floor this commit moved is judged again at once (FIX 5505).
        self.apply_pending_rebinds_after_commit();
        Ok(())
    }
}

pub(crate) fn update_manifest_origin(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    // Any generic write (including replay) invalidates the holder's exact
    // body attestation. The authenticated owner door re-stamps it afterwards.
    RETENTION_HOLDER.delete(store, txn, &HexId(*id))?;
    if kind == ENTITY_TYPE_POLICY_MANIFEST
        && (super::project_depth::is_project_depth_id(id)
            || super::project_depth::is_project_depth_contribution(body))
    {
        // A signed project policy is authenticated by its immutable carrier
        // and authority fold, never the local-only trusted-manifest sidecar.
        TRUSTED_ORIGIN.delete(store, txn, &HexId(*id))?;
    } else if kind == ENTITY_TYPE_POLICY_MANIFEST {
        stamp_manifest_origin(store, txn, id, body, replicated)?;
    } else {
        TRUSTED_ORIGIN.delete(store, txn, &HexId(*id))?;
    }
    Ok(())
}
