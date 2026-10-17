//! Federated import admission: window admit, claim revalidation, entity copy, authority-log door, and tombstone rejection.

use std::collections::BTreeSet;

use loro::{CommitOptions, ExportMode, LoroDoc};
#[cfg(feature = "sync")]
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::authority::{
    AuthorityOp, authority_entry_hash, authority_log_entity_id, decode_authority_log_entry_body,
    genesis_vault_id, validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{restamp_federated_claim_source, validate_claim_body_and_decode};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
#[cfg(feature = "test-hooks")]
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN,
};
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

#[cfg(feature = "sync")]
use super::edge::{
    EarlyStamps, HeldStamp, ReleasedStamps, copy_admitted_edges, hold_stamps, pending_births,
    refuse_admitted_stamps, refuse_non_binary_edges, release_born_stamps,
};
use crate::error::{RecordError, SyncError};

/// Role carried by a member/guest federation import path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationAdmissionRole {
    Member,
    Guest,
}

impl FederationAdmissionRole {
    const fn origin(self) -> &'static str {
        match self {
            Self::Member => "federation_admission.member",
            Self::Guest => "federation_admission.guest",
        }
    }
}

/// Produces locally admitted window update bytes for a member/guest federation
/// import.
///
/// The incoming CRDT update is decoded into an unobserved scratch doc. Claim
/// entities are re-stamped to `src=imported` and evaluated against the local
/// source-trust floor before any bytes are copied into the returned update.
/// The returned doc is freshly authored with a federation admission origin,
/// so callers can import it through the ordinary replay/materialization path
/// without giving the original remote op ids trust-blind write authority.
///
/// No facet stamp a peer sends onto a row this vault lacks is in the
/// returned update. With no sender named here, nothing can bind such a stamp
/// to its row's birth, so it is dropped (`copy_admitted_edges`).
#[cfg(feature = "sync")]
pub fn admit_federated_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<Vec<u8>> {
    Ok(admit_window_update(
        vault,
        key,
        update,
        role,
        None,
        super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
    )?
    .bytes)
}

/// [`admit_federated_window_update`] for an update the federation peer
/// `peer` sent. Its facet stamps onto rows this vault lacks wait out of the
/// update ([`AdmittedUpdate`]) until the peer's birth of each row applies.
#[cfg(feature = "sync")]
pub(in crate::sync) fn admit_peer_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    peer: EntityId,
) -> Result<AdmittedUpdate> {
    let lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    // The owner's scale for this peer, read once for the whole update.
    let scale = vault.federation_peer_confidence(&peer)?;
    admit_window_update(vault, key, update, role, Some(lane), scale)
}

/// [`admit_federated_window_update`] for a foreign artifact staged under
/// `receipt_id`. Its facet stamps onto rows this vault lacks wait under the
/// receipt until the confirmation's import births the rows
/// ([`staged_births`]).
#[cfg(feature = "sync")]
pub(crate) fn admit_staged_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    receipt_id: &[u8; 32],
) -> Result<AdmittedUpdate> {
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(staged_lane(receipt_id)),
        super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
    )
}

#[cfg(feature = "sync")]
fn staged_lane(receipt_id: &[u8; 32]) -> String {
    crate::federation::facet_read::HeldLane::Staged(*receipt_id).key()
}

/// An update the federation door admitted, and the facet stamps it sent onto
/// rows this vault lacks, which wait out of its bytes: the ones whose rows it
/// brings until those births apply here, the rest held under its sender.
#[cfg(feature = "sync")]
pub(crate) struct AdmittedUpdate {
    bytes: Vec<u8>,
    rows: u64,
    early: EarlyStamps,
    births: Vec<(EntityId, Vec<u8>)>,
    peer_rows: Vec<(EntityId, [u8; 32])>,
    lane: Option<String>,
}

#[cfg(feature = "sync")]
impl AdmittedUpdate {
    /// The admitted bytes to import.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The writes the update asks of this vault: its rows and edges, and the
    /// stamps that wait out of it (Astra-b F2 on #1432).
    pub(crate) fn writes(&self) -> u64 {
        let early = self.early.held.len() + self.early.with_birth.len();
        self.rows.saturating_add(early as u64).max(1)
    }

    /// Holds the stamps ahead of their rows under the peer that sent the
    /// update and the `grant` it sent them under, within the peer's caps.
    pub(crate) fn hold_from_peer(
        &self,
        vault: &Vault,
        key: &WindowKey,
        grant: EntityId,
    ) -> Result<()> {
        match &self.lane {
            Some(lane) => hold_stamps(vault, key, (lane, Some(grant)), &self.early.held, true),
            None => Ok(()),
        }
    }

    /// Holds every stamp of a staged artifact under its receipt, the ones
    /// whose rows it brings too: those births apply only at its confirmation.
    pub(crate) fn hold_staged(&self, vault: &Vault, key: &WindowKey) -> Result<()> {
        let Some(lane) = &self.lane else {
            return Ok(());
        };
        hold_stamps(vault, key, (lane, None), &self.early.held, false)?;
        hold_stamps(vault, key, (lane, None), &self.early.with_birth, false)
    }

    /// The record of every stamp [`Self::hold_staged`] holds, which the
    /// receipt keeps while it is Pending.
    pub(crate) fn staged_stamps(&self) -> Vec<u8> {
        HeldStamp::record(&[&self.early.held, &self.early.with_birth])
    }

    /// The rows the update brings whose births its import must watch, each
    /// with the bytes it brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// The rows whose door judges a peer's row apart from this vault's own,
    /// each with the digest of the bytes the update brings.
    pub(crate) fn peer_rows(&self) -> &[(EntityId, [u8; 32])] {
        &self.peer_rows
    }

    /// After the update's import, the stamps on the rows that import birthed
    /// (`born`, [`release_born_stamps`]).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        match &self.lane {
            Some(lane) => {
                release_born_stamps(vault, key, lane, &self.births, born, &self.early.with_birth)
            }
            None => Ok(None),
        }
    }
}

/// The rows a staged artifact's admitted bytes bring that this vault lacks
/// and that its receipt holds stamps on, read before the confirmation imports
/// them.
#[cfg(feature = "sync")]
pub(crate) struct StagedBirths {
    lane: String,
    births: Vec<(EntityId, Vec<u8>)>,
}

#[cfg(feature = "sync")]
impl StagedBirths {
    /// The rows the confirmation's import must watch, each with the bytes
    /// the artifact brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// After the confirmation's import, the stamps on the rows that import
    /// birthed (`born`).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        release_born_stamps(vault, key, &self.lane, &self.births, born, &[])
    }
}

/// [`StagedBirths`] of the artifact staged under `receipt_id`.
#[cfg(feature = "sync")]
pub(in crate::sync) fn staged_births(
    vault: &Vault,
    key: &WindowKey,
    (receipt_id, stamps_digest): (&[u8; 32], Option<[u8; 32]>),
    admitted_update: &[u8],
) -> Result<StagedBirths> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    let lane = staged_lane(receipt_id);
    // The held table restores live and maintenance sweeps it, so a hold can
    // be gone while its receipt is Pending. The receipt's own record holds
    // every staged stamp again before its birth is judged: an owner's import
    // never lands a row without the facets it staged (Astra-c F1 on #1432).
    let record = crate::batch::export::vault_import_staged_stamps(vault, receipt_id)?;
    let stamps = HeldStamp::from_receipt_record(&record.unwrap_or_default(), stamps_digest)?;
    hold_stamps(vault, key, (&lane, None), &stamps, false)?;
    let births = pending_births(vault, &lane, &admitted.get_map("entities"), &[])?;
    Ok(StagedBirths { lane, births })
}

#[cfg(feature = "sync")]
fn admit_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    lane: Option<String>,
    scale: f32,
) -> Result<AdmittedUpdate> {
    let remote = create_window_doc("federation-remote", key);
    remote.import(update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import federated update",
            source,
        })
    })?;

    refuse_non_binary_edges(&remote.get_map("edges"))?;
    let admitted = create_admission_doc(key, update, role)?;
    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    reject_federated_tombstones(&remote)?;
    copy_admitted_entities(vault, &policy, &remote, &admitted, scale)?;
    let early = copy_admitted_edges(
        vault,
        key,
        &remote.get_map("entities"),
        &admitted.get_map("entities"),
        &remote.get_map("edges"),
        &admitted.get_map("edges"),
    )?;

    crate::sync::note::copy_judged(vault, &remote, &admitted)?;
    // The sender is another vault, as far as its rows' births go: a ref to a
    // row admission dropped is masked, under that lane's key.
    let withheld = match &lane {
        Some(lane) => crate::provenance::birth::WithheldKey::for_destination(
            vault,
            format!("admit:{lane}").as_bytes(),
        )?,
        None => crate::provenance::birth::WithheldKey::fresh(),
    };
    crate::sync::row_birth::copy_births_within(
        &remote,
        &admitted,
        crate::sync::row_birth::BirthReach::OtherVault(&withheld),
    )?;
    let births = match &lane {
        Some(lane) => pending_births(
            vault,
            lane,
            &admitted.get_map("entities"),
            &early.with_birth,
        )?,
        None => Vec::new(),
    };
    let peer_rows = crate::sync::ingest::peer_rows(&admitted.get_map("entities"));
    admitted.commit_with(CommitOptions::new().origin(role.origin()));
    let rows = admitted.get_map("entities").len() + admitted.get_map("edges").len();
    let bytes = admitted
        .export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))?;
    Ok(AdmittedUpdate {
        bytes,
        rows: rows as u64,
        early,
        births,
        peer_rows,
        lane,
    })
}

/// Re-runs federated claim admission over ALREADY-ADMITTED window bytes using
/// the policy resolved RIGHT NOW.
///
/// `admit_federated_window_update` evaluates claims against the policy that was
/// resolved at ADMISSION time. A staged vault import parks those bytes behind a
/// durable Pending receipt, and the human confirmation that releases them can
/// land arbitrarily later — so the policy the operator actually consented under
/// is the one in force at CONFIRM time, not the one that happened to be loaded
/// when the artifact was first staged. This door re-resolves the manifest with
/// the same resolver the stage leg uses and re-applies the same claim gate.
///
/// It deliberately re-checks the admitted bytes AS THEY ARE rather than
/// re-deriving a fresh admitted doc: the receipt pins their digest, so a
/// re-admission would produce different bytes and break the digest bind. The
/// claims inside are already restamped to `src=imported`, which is exactly the
/// source the gate must judge on the import path, so no restamp is repeated.
///
/// Non-claim rows were admitted by identity/kind rules that do not depend on
/// resolved policy, so they are left alone here, except an agent definition:
/// it is judged again against the definition stored now, so one turned off
/// since the stage does not come back on through the confirmation.
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_federated_claims(
    vault: &Vault,
    key: &WindowKey,
    admitted_update: &[u8],
    role: FederationAdmissionRole,
) -> Result<()> {
    let admitted = create_window_doc(role.origin(), key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;

    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    let rtxn = vault.store.env.read_txn()?;
    let mut result = Ok(());
    map_for_each_value_bytes(&admitted.get_map("entities"), |key, value| {
        if result.is_err() {
            return;
        }
        result = recheck_admitted_claim_blob(&vault.store, &policy, value).and_then(|()| {
            let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
            let blob = value.ok_or(Error::InvalidKey)?;
            refuse_peer_agent_definition_widening(&vault.store, &rtxn, &id, blob)
        });
    });
    result
}

/// Refuses ALREADY-ADMITTED window bytes that carry a facet stamp
/// ([`refuse_admitted_stamps`]), so a staged artifact an older door admitted
/// with its stamps in its bytes is not confirmed (non-terminal, as a claim
/// refusal is).
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_facet_stamps(
    key: &WindowKey,
    admitted_update: &[u8],
) -> Result<()> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    refuse_admitted_stamps(&admitted.get_map("edges"))
}

#[cfg(feature = "sync")]
fn recheck_admitted_claim_blob(
    store: &crate::store::Store,
    policy: &crate::gate::PolicyManifestResolution,
    value: Option<&[u8]>,
) -> Result<()> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        return validate_federated_pack(store, blob);
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    crate::gate::check_federated_claim_admission(store, &body, policy)
}

#[cfg(feature = "sync")]
fn create_admission_doc(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(federated_admission_peer_id(key, update, role))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;
    let _entities = doc.get_map("entities");
    let _edges = doc.get_map("edges");
    let _tombstones = doc.get_map("tombstones");
    doc.commit();
    Ok(doc)
}

#[cfg(feature = "sync")]
fn federated_admission_peer_id(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> u64 {
    let mut material = Vec::with_capacity(
        b"oneiron.federation.admission.peer.v0".len()
            + role.origin().len()
            + key.as_str().len()
            + std::mem::size_of::<u64>()
            + update.len(),
    );
    material.extend_from_slice(b"oneiron.federation.admission.peer.v0");
    material.extend_from_slice(&(role.origin().len() as u64).to_le_bytes());
    material.extend_from_slice(role.origin().as_bytes());
    material.extend_from_slice(&(key.as_str().len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_str().as_bytes());
    material.extend_from_slice(&(update.len() as u64).to_le_bytes());
    material.extend_from_slice(update);

    match xxh3_64(&material) {
        0 => 1,
        u64::MAX => u64::MAX - 1,
        peer_id => peer_id,
    }
}

/// Test-only helper for downstream crates that need to seed a grant-backed
/// selector without opening the public maintenance-band write gate.
#[cfg(feature = "test-hooks")]
pub fn put_selector_test_federation_grant(
    vault: &Vault,
    grant_id: &EntityId,
    grant: &crate::federation::FederationGrant,
    learned_at: u64,
) -> Result<()> {
    let body = crate::federation::encode_federation_grant_body(grant)?;
    vault
        .batch()
        .put_replicated(
            grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            crate::temporal::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
}

#[cfg(feature = "sync")]
fn copy_admitted_entities(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    source: &LoroDoc,
    target: &LoroDoc,
    scale: f32,
) -> Result<()> {
    let source_entities = source.get_map("entities");
    let target_entities = target.get_map("entities");
    let rtxn = vault.store.env.read_txn()?;
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |key, value| {
        if result.is_err() {
            return;
        }
        result = admit_federated_entity_blob_scaled(vault, policy, &rtxn, key, value, scale)
            .and_then(|blob| map_insert_bytes(&target_entities, key, &blob));
    });
    result
}

#[cfg(feature = "sync")]
pub(crate) fn admit_federated_entity_blob(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    admit_federated_entity_blob_scaled(
        vault,
        policy,
        txn,
        key,
        value,
        super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
    )
}

/// [`admit_federated_entity_blob`] with the sending peer's confidence
/// `scale` for a CLAIM.
#[cfg(feature = "sync")]
fn admit_federated_entity_blob_scaled(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
    scale: f32,
) -> Result<Vec<u8>> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
    if key != id.to_hex() {
        return Err(Error::InvalidKey);
    }

    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        validate_federated_pack(&vault.store, blob)?;
        return Ok(blob.to_vec());
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            admit_federated_authority_log(vault, &id, &blob[ENTITY_METADATA_HEADER_LEN..])?;
            return Ok(blob.to_vec());
        }
        // The same registry classification decides writability and admission.
        // Unknown bytes cannot become peer-writable because they lie in a range.
        vault
            .store
            .validate_public_entity_type(header.entity_type)?;
        if crate::federation::selector_range_of(header.entity_type).is_none()
            && vault
                .structural_kind_registration(header.entity_type)
                .is_none_or(|registration| registration.family.is_none())
        {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        validate_admitted_replicated_body(
            &id,
            header.entity_type,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?;
        refuse_peer_agent_definition_widening(&vault.store, txn, &id, blob)?;
        if matches!(
            header.entity_type,
            ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION
        ) {
            return restamp_federated_transcript(blob);
        }
        return Ok(blob.to_vec());
    }

    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    let body = downweight_federated_claim(restamp_federated_claim_source(body), scale)?;
    crate::gate::check_federated_claim_admission(&vault.store, &body, policy)?;
    let encoded = crate::claim::encode_claim_body(&body)?;

    let mut admitted = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + encoded.len());
    admitted.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    admitted.extend_from_slice(&encoded);
    Ok(admitted)
}

/// Refuses a peer's agent definition that turns the one stored at `id` back
/// on, read in `txn`. Turning a definition back on is the owner's, and a peer
/// is not the owner. Typed as the peer's bytes, so the frame quarantines.
#[cfg(feature = "sync")]
fn refuse_peer_agent_definition_widening(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF
        && crate::agent_def::agent_definition_put_widens_in_txn(
            store,
            txn,
            id,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?
    {
        return Err(Error::Artifact(
            crate::error::ArtifactError::InvalidAgentDefBody(
                "a federation peer cannot turn an agent definition back on",
            ),
        ));
    }
    Ok(())
}

/// The source a foreign TURN or CONVERSATION is stamped with (OF-149).
pub(crate) const FEDERATION_IMPORT_SOURCE: &str = "federation";

/// A peer's TURN or CONVERSATION is imported evidence, never the owner's live
/// words: its body is stamped with the federation import source unless the
/// peer already named one. The stamp is a birth fact, so a peer row landing
/// on an unstamped local one is refused by the put door, never relabelled.
/// An empty body (a deleted shell) carries no words and passes unchanged.
#[cfg(feature = "sync")]
fn restamp_federated_transcript(blob: &[u8]) -> Result<Vec<u8>> {
    let body = &blob[ENTITY_METADATA_HEADER_LEN..];
    if body.is_empty() {
        return Ok(blob.to_vec());
    }
    let refused = || -> Error {
        RecordError::InvalidConversationBody("a federated transcript body must be a map").into()
    };
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| refused())?;
    if cursor.position() != body.len() as u64 {
        return Err(refused());
    }
    let rmpv::Value::Map(mut entries) = value else {
        return Err(refused());
    };
    let key = crate::memory::IMPORTED_SOURCE_KEY;
    match entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key))
        .count()
    {
        0 => entries.push((
            rmpv::Value::from(key),
            rmpv::Value::from(FEDERATION_IMPORT_SOURCE),
        )),
        1 => return Ok(blob.to_vec()),
        _ => return Err(refused()),
    }
    let mut encoded = Vec::with_capacity(blob.len() + 32);
    encoded.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).map_err(|_| refused())?;
    Ok(encoded)
}

/// ARCH-0043 requires a down-weight but does not prescribe a factor. The
/// sending peer's owner-set scale applies, by default
/// [`super::DEFAULT_FEDERATED_CONFIDENCE_SCALE`] for every federated role.
fn downweight_federated_claim(
    mut body: crate::claim::ClaimBody,
    scale: f32,
) -> Result<crate::claim::ClaimBody> {
    const AUDIT_KEY: &str = "federated_original_confidence";
    let original = body.confidence;
    body.confidence *= scale;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        // The wrapper and value record carry the same confidence. Keep both
        // graded values equal so admission cannot create an invalid replay row.
        let mut record = crate::provenance::decode_edge_provenance_body(&body.value)?;
        record.confidence = body.confidence;
        body.value = crate::provenance::encode_edge_provenance_value(&record);
    }
    let mut entries = match body.scope.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        Some(scope) => vec![(rmpv::Value::from("pre_federated_confidence_scope"), scope)],
        None => Vec::new(),
    };
    entries.retain(|(key, _)| key.as_str() != Some(AUDIT_KEY));
    entries.push((rmpv::Value::from(AUDIT_KEY), rmpv::Value::F32(original)));
    body.scope = Some(rmpv::Value::Map(entries));
    Ok(body)
}

/// Per-kind body validation for the non-CLAIM federation admission arm.
///
/// FED-1093: kind WRITABILITY is not admission. This arm previously checked
/// only that the metadata header parsed and that the type byte was not
/// engine-authored, then copied the peer's bytes verbatim — so a body that
/// `apply_put` is guaranteed to refuse (a TASK carrying no role, an undecodable
/// SKILL) entered the ADMITTED doc. The staged foreign import then pinned that
/// doc's digest, the confirmation marked the receipt `Confirmed`
/// unconditionally, and replay quarantined the offending row and continued —
/// so the operator consented to an import that silently dropped it. The
/// confirm GCs the staged content in the same txn, and the artifact's
/// `receipt_id` is re-derived from its own bytes, so the drop cannot be undone
/// by re-presenting it. CLAIM and AUTHORITY_LOG already refuse their invalid
/// bodies at this door; every other kind whose body schema is PINNED refuses
/// here too, before any receipt exists.
///
/// Only the STATELESS half of `apply_put`'s per-kind chain is mirrored, and it
/// delegates to the very same validators, so this door cannot judge a body
/// materialization would accept. Store-reading rules (authority-log store-key
/// binding and gate policy) stay where they can
/// read a transaction — this is a fail-closed prefilter, never the authority:
/// materialization still re-validates every row it is handed. Kinds with no
/// pinned body schema stay opaque here exactly as they are at the storage
/// layer, and the maintenance kinds are unreachable — the writability test
/// above has already rejected them.
///
/// A FACET is a scenario mask, never a store for PERSON identity: an
/// identity-shaped FACET body takes the shared sync identity refusal before an
/// import receipt can be staged, so a peer cannot confirm bytes that
/// materialization must discard.
#[cfg(feature = "sync")]
fn validate_admitted_replicated_body(id: &EntityId, entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type != crate::registry::ENTITY_TYPE_AGENT_DEF {
        crate::agent_def::validate_put_at_seeded_id(id, entity_type, None)?;
    }
    validate_sync_identity_body(entity_type, body)?;
    match entity_type {
        crate::registry::ENTITY_TYPE_RECEIPT_RECORD => {
            crate::receipt::validate_receipt_record_body(id, body)?;
        }
        crate::registry::ENTITY_TYPE_TASK => {
            crate::habit::task_role_from_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_CODE_ARTIFACT => {
            crate::code_artifact::validate_code_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT => {
            crate::blob_artifact::validate_blob_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_SKILL => {
            crate::skill::decode_skill_record(body)?;
        }
        crate::registry::ENTITY_TYPE_AGENT_DEF => {
            let definition = crate::agent_def::decode_agent_definition(body)?;
            crate::agent_def::validate_reserved_logical_id(id, &definition)?;
            crate::agent_def::validate_put_at_seeded_id(id, entity_type, Some(&definition))?;
        }
        _ => {}
    }
    Ok(())
}

/// The one sync identity-body refusal. PERSON holds identity and a FACET is a
/// scenario mask, so a FACET body shaped as a persona or relationship is
/// refused. Federated body admission and raw full-window admission both call
/// this; neither copies the predicate.
#[cfg(feature = "sync")]
pub(in crate::sync) fn validate_sync_identity_body(entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_FACET
        && crate::companion::is_identity_facet_body(body)
    {
        return Err(Error::InvalidClaimBody(
            "FACET cannot carry PERSON identity",
        ));
    }
    Ok(())
}

/// Federation admission door for a AUTHORITY_LOG carrier.
///
/// ONE-1604-D1 (fix-leg 4): the CRDT row's KEY is bound to the id derived
/// from the decoded body, exactly as `check_authority_log_store_key` binds it
/// at the write door. Without the bind, admission validated the body and the
/// vault root but never checked that the body belonged at `id` — so a
/// wrong-key authority row entered the ADMITTED doc and only failed later at
/// materialize. That is strictly worse than rejecting here: the admitted doc
/// is what the ordinary replay path imports, so the mismatch surfaced after
/// the row had already been copied into locally authored bytes, and anything
/// this door scopes off the same key operated on a row that could never be
/// admitted under it.
///
/// The bind is a REMOTE rejection, not a local failure:
/// `AuthorityLogStoreKeyMismatch` is already classified in
/// `quarantine::remote_rejection_reason`, so the replay sites quarantine the
/// row and continue rather than aborting the window (H2). Deriving the id
/// costs one hash over bytes this function has already decoded.
#[cfg(feature = "sync")]
fn admit_federated_authority_log(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    validate_authority_log_entry_body_bytes(body)?;
    let entry = decode_authority_log_entry_body(body)?;
    if authority_log_entity_id(&entry)? != *id {
        return Err(Error::Record(RecordError::AuthorityLogStoreKeyMismatch {
            id: *id,
        }));
    }
    let entry_vault_id = match &entry.op {
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        _ => entry
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing authority vault id",
            )))?,
    };
    let local = vault.authority_fold()?;
    let local_vault_id =
        local
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing local authority root",
            )))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        )));
    }
    let rtxn = vault.store.env.read_txn()?;
    let evidence = crate::authority::adopted_evidence_in_txn(&vault.store, &rtxn)?;
    if !crate::authority::authority_row_resident(&vault.store, &rtxn, &entry)?
        && crate::authority::door_refuses_retired_standing(
            &vault.store,
            &local,
            &authority_entry_hash(&entry)?,
            &entry,
            &mut |hash| {
                crate::authority::door_ancestor_row(&vault.store, &rtxn, evidence.as_deref(), hash)
            },
        )?
    {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "authority row signed by a key a handoff retired",
        )));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn reject_federated_tombstones(source: &LoroDoc) -> Result<()> {
    let mut has_tombstone = false;
    map_for_each_tombstone_value(&source.get_map("tombstones"), |_, _| {
        has_tombstone = true;
    });
    if has_tombstone {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::FederatedTombstoneAdmission,
        ));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn validate_federated_pack(store: &crate::store::Store, blob: &[u8]) -> Result<()> {
    let source = crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(
        &blob[ENTITY_METADATA_HEADER_LEN..],
    )?;
    let txn = store.env.read_txn()?;
    let (handle, local) = store.remap_pack_instance_in_txn(&txn, &source)?;
    store.validate_pack_instance_in_txn(&txn, handle, &local.to_bytes()?)
}

#[cfg(all(test, feature = "sync"))]
mod retired_facet_tests {
    use super::*;

    #[test]
    fn valid_legacy_facet_refused_before_sync_admission_but_scenario_is_allowed() {
        let person = crate::test_util::entity(0x71);
        let id = crate::test_util::entity(0x72);
        let legacy = crate::companion::tests::support::retired_persona_facet_body(person);
        assert!(matches!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &legacy),
            Err(Error::Record(RecordError::InvalidCompanionRecordBody(_)))
        ));
        let scenario = rmp_serde::to_vec_named(&serde_json::json!({
            "kind": "scenario", "person_ref": person.to_hex()
        }))
        .expect("scenario fixture");
        assert!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &scenario,)
                .is_ok()
        );
    }
}

#[cfg(all(test, feature = "sync"))]
mod suppression_carrier_tests {
    use super::*;
    use crate::receipt::{ReceiptKind, ReceiptRecord};
    use serde::Serialize;

    #[derive(Serialize)]
    struct ForgedCarrier {
        intent_id: [u8; 32],
        receipt: ReceiptRecord,
    }

    #[test]
    fn replicated_admission_refuses_truncated_and_wrong_id_suppression_assets() {
        let id = EntityId::from_bytes([0x87; 16]).expect("fixture id");
        let malformed = b"invalid receipt";
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                malformed
            )
            .is_err()
        );
        let receipt = ReceiptRecord {
            receipt_id: format!(
                "outbound:suppression:{}",
                crate::entity_id::bytes_to_hex_lower(&[0x88; 32])
            ),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 1,
            actor: None,
            on_behalf_of: None,
            outcome: "suppressed".to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: [
                ("suppression".to_owned(), "dedupe".to_owned()),
                ("dedupe_key".to_owned(), "same".to_owned()),
            ]
            .into(),
        };
        let body = rmp_serde::to_vec_named(&ForgedCarrier {
            intent_id: [0x88; 32],
            receipt,
        })
        .expect("encode forged carrier");
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                &body
            )
            .is_err()
        );
    }
}
