//! Federated import admission: window admit, claim revalidation, entity copy, authority-log door, and tombstone rejection.

use loro::{CommitOptions, ExportMode, LoroDoc};
#[cfg(feature = "sync")]
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::authority::{
    AuthorityOp, authority_log_entity_id, decode_authority_log_entry_body, genesis_vault_id,
    validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{restamp_federated_claim_source, validate_claim_body_and_decode};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT,
    EntityClassification, TypeByteZone, entity_type_registry_entry, zone_of,
};
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

#[cfg(feature = "sync")]
use super::edge::copy_admitted_edges;
use crate::error::{RecordError, RegistryError, SyncError};

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
#[cfg(feature = "sync")]
pub fn admit_federated_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<Vec<u8>> {
    let remote = create_window_doc("federation-remote", key);
    remote.import(update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import federated update",
            source,
        })
    })?;

    let admitted = create_admission_doc(key, update, role)?;
    let policy =
        vault.with_write_txn(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    reject_federated_tombstones(&remote)?;
    copy_admitted_entities(vault, &policy, &remote, &admitted)?;
    copy_admitted_edges(
        vault,
        key,
        &remote.get_map("entities"),
        &remote.get_map("edges"),
        &admitted.get_map("edges"),
    )?;

    admitted.commit_with(CommitOptions::new().origin(role.origin()));
    admitted
        .export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))
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
/// resolved policy, so they are left alone here.
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

    let policy =
        vault.with_write_txn(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    let mut result = Ok(());
    map_for_each_value_bytes(&admitted.get_map("entities"), |_, value| {
        if result.is_err() {
            return;
        }
        result = recheck_admitted_claim_blob(&vault.store, &policy, value);
    });
    result
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
) -> Result<()> {
    let source_entities = source.get_map("entities");
    let target_entities = target.get_map("entities");
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |key, value| {
        if result.is_err() {
            return;
        }
        result = admit_federated_entity_blob(vault, policy, key, value)
            .and_then(|blob| map_insert_bytes(&target_entities, key, &blob));
    });
    result
}

#[cfg(feature = "sync")]
fn admit_federated_entity_blob(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    key: &str,
    value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
    if key != id.to_hex() {
        return Err(Error::InvalidKey);
    }

    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            admit_federated_authority_log(vault, &id, &blob[ENTITY_METADATA_HEADER_LEN..])?;
            return Ok(blob.to_vec());
        }
        // Engine-authored kinds are CLASSIFICATION-routed, never byte-range
        // routed. Before byte-space v3 the second arm here was a "byte >= 120"
        // band test, which was only ever a PROXY for "engine-authored" — and
        // the v3 re-key moves every maintenance kind DOWN into 64–99, so
        // keeping that test would have silently begun admitting peer-written
        // maintenance records. The zone arm below now covers only bytes with
        // no static kind at all: the canon-reserved system bytes (72/74/75)
        // and the entire pack half, neither of which a peer may author.
        // DIAGNOSTIC (69) left that reserve set in ONE-1394 and is now caught
        // by the CLASSIFICATION arm instead — engine-authored either way.
        let engine_authored = entity_type_registry_entry(header.entity_type).map_or_else(
            || {
                !matches!(
                    zone_of(header.entity_type),
                    TypeByteZone::Semantic | TypeByteZone::Core | TypeByteZone::CompiledProduct
                )
            },
            |entry| entry.classification == EntityClassification::Maintenance,
        );
        if engine_authored {
            return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            )));
        }
        validate_admitted_replicated_body(
            &id,
            header.entity_type,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?;
        return Ok(blob.to_vec());
    }

    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    let body = restamp_federated_claim_source(body);
    crate::gate::check_federated_claim_admission(&vault.store, &body, policy)?;
    let encoded = crate::claim::encode_claim_body(&body)?;

    let mut admitted = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + encoded.len());
    admitted.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    admitted.extend_from_slice(&encoded);
    Ok(admitted)
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
/// materialization would accept. The store-reading rules (companion duplicate
/// keys, the authority-log store-key bind, gate policy) stay where they can
/// read a transaction — this is a fail-closed prefilter, never the authority:
/// materialization still re-validates every row it is handed. Kinds with no
/// pinned body schema stay opaque here exactly as they are at the storage
/// layer, and the maintenance kinds are unreachable — the writability test
/// above has already rejected them.
///
/// FED-1380 closes COMPANION_REGISTER, the one pinned-body kind this door still
/// skipped. Leaving it open was not harmless. An undecodable companion body
/// entered the ADMITTED doc and staged `Pending`; the operator's confirmation
/// won the CAS and deleted the staged bytes in the SAME write txn; replay then
/// quarantined the row as a remote rejection (`InvalidClaimBody`) and continued,
/// so the entity never materialized — while the receipt read `Confirmed`
/// forever. Re-presenting the artifact cannot repair it either: `receipt_id` is
/// re-derived from the same bytes, finds the terminal receipt, and returns an
/// idempotent EMPTY admitted update. A `Confirmed` receipt for a row that can
/// never materialize is silent consent to a permanent drop, so the body is
/// judged here, before any receipt exists.
///
/// The refusal is deliberately RETRYABLE, which is what preserves the
/// quarantine-not-terminal choice at materialization:
/// `decode_companion_record_body` reports faults as `InvalidClaimBody`, which
/// `stage_foreign_vault_import` classifies TERMINAL, so this arm re-labels them
/// `InvalidCompanionRecordBody` — same verdict text, same coarse `ErrorKind`,
/// and absent from that terminal list by design. Nothing is staged, so nothing
/// is left for a confirmation to GC. Only the STATELESS half is mirrored here,
/// as everywhere else in this function: the duplicate-`(scope, subject)` rule
/// reads a transaction and stays at materialization, which still re-validates
/// every row it is handed.
#[cfg(feature = "sync")]
fn validate_admitted_replicated_body(id: &EntityId, entity_type: u8, body: &[u8]) -> Result<()> {
    match entity_type {
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
        }
        crate::companion::ENTITY_TYPE_COMPANION_REGISTER => {
            // Re-label only the variant whose staging classification is
            // TERMINAL; the verdict text and every other decoder error (already
            // non-terminal) pass through unchanged. See the note above.
            crate::companion::decode_companion_record_body(body).map_err(|error| match error {
                Error::InvalidClaimBody(reason) => {
                    Error::Record(RecordError::InvalidCompanionRecordBody(reason))
                }
                other => other,
            })?;
        }
        _ => {}
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
    let local_vault_id = vault.authority_fold()?.vault_id.ok_or(Error::Record(
        RecordError::InvalidAuthorityLogBody("missing local authority root"),
    ))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "foreign authority log vault id",
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
