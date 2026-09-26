//! Lease-fenced native seal job. No terminal claim precedes self-verification.
use super::{
    ledger::{append, events_in, state_in},
    model::*,
    render::{PdfPreparation, PdfPreparationError, SignatureRaster, prepare_esign_pdf},
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, CompleteAttempt, SetAttemptResult,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Error, Result, TimeRange, Vault};
use oneiron_seal::{PadesProfile, PdfSealEngine, SealError, SealRequest, VerifyReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Sealed document manifest. Key: id16 (document).
pub(super) const CANONICAL: SideTable<EntityId, SealedDocument, LegacyJson> =
    SideTable::new(&side_table::ESIGN_SEALED_DOCUMENT);
/// Completed seal attempt result. Key: id16 (attempt id — `AttemptId`, not `EntityId`, but the
/// same raw 16 bytes).
const RESULT: SideTable<[u8; 16], SealedDocument, LegacyJson> =
    SideTable::new(&side_table::ESIGN_SEAL_RESULT);
#[derive(Debug, thiserror::Error)]
pub enum EsignSealError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Prepare(#[from] PdfPreparationError),
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error("sealed PDF failed post-seal verification")]
    Verification,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedItem {
    pub original_artifact: String,
    pub original_version: u64,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    pub sha256: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDocument {
    pub document: String,
    pub attempt_ref: String,
    pub audit_chain_sha256: [u8; 32],
    pub items: Vec<SealedItem>,
    pub rejected: bool,
}
fn snapshot_hash(rows: &[EsignEventRow]) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(rows).map_err(|_| invalid("seal snapshot encoding"))?;
    Ok(Sha256::digest(bytes).into())
}
fn live_attempt(vault: &Vault, txn: &heed::RoTxn<'_>, attempt: &AttemptRecord) -> Result<()> {
    let current = AttemptQueue::new(vault)
        .get_in_write_txn(txn, attempt.id)?
        .ok_or(Error::EntityNotFound)?;
    if current.kind != super::ESIGN_SEAL_ATTEMPT_KIND
        || current.payload != attempt.payload
        || current.state != AttemptState::Leased
        || current.lease_owner != attempt.lease_owner
        || current.attempt_count != attempt.attempt_count
        || current.lease_owner.is_none()
    {
        return Err(invalid("seal lease is no longer current"));
    }
    Ok(())
}
impl Vault {
    pub fn sealed_esign_document(&self, document: EntityId) -> Result<Option<SealedDocument>> {
        let txn = self.store.env.read_txn()?;
        CANONICAL.get(&self.store, &txn, &document)
    }
    /// Async backend work is outside the writer lock. Immutable original
    /// versions are always used, including for owner-authorized reseals.
    pub async fn seal_esign_attempt<E: PdfSealEngine>(
        &self,
        attempt: &AttemptRecord,
        engine: &E,
        profile: PadesProfile,
        canonical_url: &str,
    ) -> std::result::Result<SealedDocument, EsignSealError> {
        let document = EntityId::from_bytes(
            attempt
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| invalid("seal attempt payload"))?,
        )?;
        let (state, rows, originals, images) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            if let Some(sealed) = RESULT.get(&self.store, &txn, attempt.id.as_bytes())? {
                if sealed.document != document.to_hex()
                    || attempt.kind != super::ESIGN_SEAL_ATTEMPT_KIND
                {
                    return Err(invalid("seal result binding mismatch").into());
                }
                return Ok(sealed);
            }
            live_attempt(self, &txn, attempt)?;
            let state = state_in(self, &txn, document)?;
            if !state.ready_to_seal() {
                return Err(invalid("document is not ready for sealing").into());
            }
            let rows = events_in(self, &txn, document)?;
            let mut originals = Vec::new();
            for item in &state.document.items {
                let id = EntityId::from_hex(&item.artifact_ref)?;
                let metadata = self
                    .get_blob_artifact_in_txn(&txn, &id)?
                    .ok_or(Error::EntityNotFound)?;
                let bytes = self
                    .read_blob_artifact_version_in_txn(&txn, &id, item.original_version)?
                    .ok_or(Error::EntityNotFound)?;
                originals.push((metadata, bytes));
            }
            let mut images = BTreeMap::new();
            let mut image_bytes = 0usize;
            for value in state.signatures.values() {
                if let FieldValue::Signature { image_ref } = &value.value {
                    if images.contains_key(image_ref) {
                        continue;
                    }
                    if !super::signature_image::BINDINGS.contains(
                        &self.store,
                        &txn,
                        &super::signature_image::image_binding_key(
                            document,
                            &value.recipient,
                            image_ref,
                        ),
                    )? {
                        return Err(invalid("signature image binding").into());
                    }
                    let bytes = self
                        .read_blob_artifact_version_in_txn(
                            &txn,
                            &EntityId::from_hex(image_ref)?,
                            1,
                        )?
                        .ok_or(Error::EntityNotFound)?;
                    let image =
                        image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
                            .map_err(|_| invalid("stored signature image"))?
                            .to_rgba8();
                    image_bytes = image_bytes.saturating_add(image.as_raw().len());
                    if image_bytes > 64 * 1024 * 1024 {
                        return Err(invalid("signature raster budget").into());
                    }
                    images.insert(
                        image_ref.clone(),
                        SignatureRaster {
                            width: image.width(),
                            height: image.height(),
                            rgba: image.into_raw(),
                        },
                    );
                }
            }
            (state, rows, originals, images)
        };
        let fingerprint = snapshot_hash(&rows)?;
        let mut outputs = Vec::new();
        for (index, (_, original)) in originals.iter().enumerate() {
            let prepared = prepare_esign_pdf(
                original,
                PdfPreparation {
                    document_ref: &document.to_hex(),
                    item: index as u32,
                    state: &state,
                    audit: &rows,
                    canonical_url,
                    signature_images: &images,
                },
            )?;
            let sealed = engine
                .seal_pdf(
                    &prepared.bytes,
                    &SealRequest {
                        operation_id: format!(
                            "esign:{}:{}:{index}",
                            document.to_hex(),
                            crate::entity_id::bytes_to_hex_lower(&fingerprint)
                        ),
                        target_profile: profile,
                    },
                )
                .await?;
            let checked = engine.verify_sealed_pdf(&sealed.bytes)?;
            if !sealed.self_verify_report.passes_self_verify() || !checked.passes_self_verify() {
                return Err(EsignSealError::Verification);
            }
            let hash: [u8; 32] = Sha256::digest(&sealed.bytes).into();
            if sealed.evidence_sha256 != hash {
                return Err(EsignSealError::Verification);
            }
            outputs.push((sealed.bytes, hash, prepared.audit_chain_sha256));
        }
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            live_attempt(self, txn, attempt)?;
            if snapshot_hash(&events_in(self, txn, document)?)? != fingerprint {
                return Err(Error::ConcurrentWrite("esign changed during seal"));
            }
            let artifact_actor = super::artifact_actor::actor(self, txn, now)?;
            let mut items = Vec::new();
            for (index, (bytes, hash, _)) in outputs.iter().enumerate() {
                let id = EntityId::now();
                let mut body = originals[index].0.clone();
                body.name = format!("sealed-{}.pdf", index + 1);
                let body = super::super::encode_blob_artifact_body(&body)?;
                self.batch_in()
                    .put_internal(
                        &id,
                        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                        TimeRange {
                            start: now,
                            end: now,
                        },
                        now,
                        &body,
                    )
                    .apply(txn)?;
                let version = self.append_blob_artifact_version_in_txn(
                    txn,
                    &id,
                    bytes,
                    &super::super::BlobVersionProvenance::AgentRun {
                        run_ref: format!(
                            "esign.seal:{}",
                            crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes())
                        ),
                    },
                    artifact_actor,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )?;
                let original = &state.document.items[index];
                items.push(SealedItem {
                    original_artifact: original.artifact_ref.clone(),
                    original_version: original.original_version,
                    sealed_artifact: id.to_hex(),
                    sealed_version: version.version,
                    sha256: *hash,
                });
            }
            let manifest = SealedDocument {
                document: document.to_hex(),
                attempt_ref: crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes()),
                audit_chain_sha256: outputs[0].2,
                items,
                rejected: state.rejection.is_some(),
            };
            append(
                self,
                txn,
                document,
                EsignEvent::Sealed {
                    rejected: manifest.rejected,
                    item_sha256: manifest.items.iter().map(|i| i.sha256).collect(),
                },
                EsignAuditActor {
                    actor: format!(
                        "engine:seal:{}",
                        crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes())
                    ),
                    ip: None,
                    user_agent: None,
                },
                now,
            )?;
            CANONICAL.put(&self.store, txn, &document, &manifest)?;
            RESULT.put(&self.store, txn, attempt.id.as_bytes(), &manifest)?;
            let queue = AttemptQueue::new(self);
            let owner = attempt
                .lease_owner
                .clone()
                .ok_or_else(|| invalid("seal lease owner"))?;
            queue.set_result_in_txn(
                txn,
                SetAttemptResult {
                    id: attempt.id,
                    lease_owner: owner.clone(),
                    attempt_count: attempt.attempt_count,
                    result_ref: crate::attempt_queue::AttemptResultRef::new(format!(
                        "esign.sealed:{}",
                        document.to_hex()
                    ))?,
                    now,
                },
            )?;
            queue.complete_in_txn(
                txn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: owner,
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
            Ok(manifest)
        })
        .map_err(Into::into)
    }
    /// Re-hash stored bytes and run the native verifier for the in-app badge.
    pub fn verify_esign_item<E: PdfSealEngine>(
        &self,
        document: EntityId,
        item: usize,
        engine: &E,
    ) -> std::result::Result<VerifyReport, EsignSealError> {
        let manifest = self
            .sealed_esign_document(document)?
            .ok_or(Error::EntityNotFound)?;
        let item = manifest
            .items
            .get(item)
            .ok_or_else(|| invalid("sealed item index"))?;
        let bytes = self
            .read_blob_artifact_version(
                &EntityId::from_hex(&item.sealed_artifact)?,
                item.sealed_version,
            )?
            .ok_or(Error::EntityNotFound)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != item.sha256 {
            return Err(EsignSealError::Verification);
        }
        Ok(engine.verify_sealed_pdf(&bytes)?)
    }
}
