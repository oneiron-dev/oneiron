//! Lease-fenced seal job. No terminal claim precedes self-verification. The
//! sealer is a port ([`EsignSealer`]); the seal itself runs in its own organ,
//! over the signature revisions the engine wrote ([`EsignSealInput`]).
use super::{
    ledger::{append, events_in, state_in},
    model::*,
    render::{
        PdfPreparation, PdfPreparationError, SignatureRaster,
        prepare_esign_pdf_with_replayed_audit, replay_esign_audit,
    },
    sealer::{
        EsignSealRequest, EsignSealed, EsignSealer, EsignSealerError, EsignVerdict, SealProfile,
        SealProfileEvidence, SealVerdict,
    },
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::attempt_inputs::CompleteAttempt;
use crate::store::attempt_inputs::SetAttemptResult;
use crate::store::attempt_state::AttemptState;
use crate::{EntityId, Error, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

mod auto_commit;
pub(in crate::blob_artifact) use auto_commit::{SealJobAutoPermit, SealJobWrite};
use auto_commit::{VerifiedSealJob, VerifiedSealOutput};

/// Sealed document manifest. Key: id16 (document).
pub(super) const CANONICAL: SideTable<EntityId, SealedDocument, LegacyJson> =
    SideTable::new(&side_table::ESIGN_SEALED_DOCUMENT);
/// Successful seal or failed verification result. Key: id16 (attempt id — `AttemptId`, not
/// `EntityId`, but the same raw 16 bytes).
pub(super) const RESULT: SideTable<[u8; 16], EsignSealAttemptResult, LegacyJson> =
    SideTable::new(&side_table::ESIGN_SEAL_RESULT);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub(super) enum EsignSealAttemptResult {
    Sealed(SealedDocument),
    VerificationFailed { verify_reasons: Vec<String> },
}
#[derive(Debug, thiserror::Error)]
pub enum EsignSealError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Prepare(#[from] PdfPreparationError),
    #[error(transparent)]
    Sealer(#[from] EsignSealerError),
    /// The complete native input length was discovered before dispatch.
    /// Re-admit its full call booking only after the producer unwinds.
    #[error("the seal call needs a booking for {lent_bytes} lent bytes")]
    ProducerBooking { lent_bytes: u64 },
    #[error("sealed PDF failed post-seal verification")]
    Verification { verify_reasons: Vec<String> },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedItem {
    pub original_artifact: String,
    pub original_version: u64,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    pub sha256: [u8; 32],
    pub profile: SealProfileEvidence,
    pub active_content: super::sealer::SealActiveContentFacts,
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
/// The verifier's word against the sealer's, field by field: the profile
/// asked for, the one reached, and why it is lower. A seal may fall short of
/// its profile, never pass it, and each shortfall names the profiles it
/// fell between.
fn coherent(sealed: &EsignSealed, checked: &EsignVerdict, profile: SealProfile) -> bool {
    sealed.requested == profile
        && sealed.achieved <= profile
        && checked.verdict == SealVerdict::Passed
        && checked.achieved == Some(sealed.achieved)
        && sealed.degraded.is_empty() == (sealed.achieved == profile)
        && sealed
            .degraded
            .iter()
            .all(|degrade| degrade.requested == profile && degrade.achieved == sealed.achieved)
}
pub(super) fn live_attempt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<()> {
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
    /// The sealer runs outside the writer lock. Immutable original versions
    /// are always used, including for owner-authorized reseals.
    pub fn seal_esign_attempt(
        &self,
        attempt: &AttemptRecord,
        sealer: &dyn EsignSealer,
        profile: SealProfile,
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
            if let Some(result) = RESULT.get(&self.store, &txn, attempt.id.as_bytes())? {
                if attempt.kind != super::ESIGN_SEAL_ATTEMPT_KIND {
                    return Err(invalid("seal result binding mismatch").into());
                }
                return match result {
                    EsignSealAttemptResult::Sealed(sealed) => {
                        if sealed.document != document.to_hex() {
                            return Err(invalid("seal result binding mismatch").into());
                        }
                        Ok(sealed)
                    }
                    EsignSealAttemptResult::VerificationFailed { verify_reasons } => {
                        let current = AttemptQueue::new(self)
                            .get_in_write_txn(&txn, attempt.id)?
                            .ok_or(Error::EntityNotFound)?;
                        if current.kind != attempt.kind || current.payload != attempt.payload {
                            return Err(invalid("seal result binding mismatch").into());
                        }
                        Err(EsignSealError::Verification { verify_reasons })
                    }
                };
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
            // Every signature raster the fields show, each decoded once and
            // under its decoder's own bounds; no budget over them all refuses
            // a seal (Rule 5).
            let mut images = BTreeMap::new();
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
        let pinned_inputs = originals.iter().fold(0u64, |held, (_, bytes)| {
            held.saturating_add(bytes.capacity() as u64)
        });
        let pinned_inputs = images.values().fold(pinned_inputs, |held, image| {
            held.saturating_add(image.rgba.capacity() as u64)
        });
        let mut outputs: Vec<VerifiedSealOutput> = Vec::new();
        let document_hex = document.to_hex();
        for (index, (_, original)) in originals.iter().enumerate() {
            let pinned_buffer_bytes = outputs.iter().fold(pinned_inputs, |held, output| {
                held.saturating_add(output.buffer_capacity() as u64)
            });
            let prep = PdfPreparation {
                document_ref: &document_hex,
                item: index as u32,
                state: &state,
                audit: &rows,
                canonical_url,
                signature_images: &images,
                pinned_buffer_bytes,
            };
            let (chain, trail) = replay_esign_audit(&prep)?;
            let prepared = match sealer.prepare_esign_pdf(original, &prep, chain, &trail)? {
                Some(prepared) => prepared,
                None => prepare_esign_pdf_with_replayed_audit(
                    original,
                    &prep,
                    self.esign_stream_decode_bytes(),
                    chain,
                    trail,
                )?,
            };
            // The seal holds the item whole, however large: past the `[limits]
            // esign_pdf_bytes` row it asks whether everything is okay, and
            // seals it anyway (OF-520).
            self.measure_limit(
                EngineLimit::EsignPdfBytes,
                original.len().max(prepared.bytes.len()) as u64,
            );
            let operation_id = format!(
                "esign:{}:{}:{index}",
                document.to_hex(),
                crate::entity_id::bytes_to_hex_lower(&fingerprint)
            );
            let now_ms = self.now_recorded_at().saturating_mul(1000);
            let codec_bytes = self
                .limit_watch()
                .bound(EngineLimit::EsignSealStreamCodecBytes);
            let request = EsignSealRequest {
                operation_id,
                profile,
            };
            let mut producer = super::input_producer::SealInputProducer::new(
                self,
                prepared.bytes,
                &request.operation_id,
                now_ms,
                codec_bytes,
            );
            let sealed = loop {
                match sealer.seal(&request, &mut producer) {
                    // The CMS needed more than the largest revision held: a
                    // fresh, larger one is written and sealed, and its
                    // signature issued once (FIX 6270).
                    Err(EsignSealError::Sealer(EsignSealerError::ContentsShort { needed })) => {
                        if !producer.rewrite_larger(needed)? {
                            return Err(EsignSealerError::ContentsShort { needed }.into());
                        }
                    }
                    sealed => break sealed?,
                }
            };
            let checked = sealer.verify(&sealed.bytes)?;
            outputs.push(VerifiedSealOutput::verify(
                sealed,
                checked,
                profile,
                prepared.audit_chain_sha256,
            )?);
        }
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            live_attempt(self, txn, attempt)?;
            if snapshot_hash(&events_in(self, txn, document)?)? != fingerprint {
                return Err(Error::ConcurrentWrite("esign changed during seal"));
            }
            let job = VerifiedSealJob::bind(
                self,
                txn,
                attempt,
                document,
                fingerprint,
                &state,
                &outputs,
                now,
            )?;
            let mut items = Vec::new();
            for write in job.writes() {
                let index = write.index();
                let id = write.artifact();
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
                if let Some(project) = state.document.project {
                    self.store
                        .scope_stamps
                        .stamp_blob_project(&self.store, txn, id, project)?;
                }
                let version = self.append_verified_seal_job_version_in_txn(txn, &write)?;
                let original = &state.document.items[index];
                items.push(SealedItem {
                    original_artifact: original.artifact_ref.clone(),
                    original_version: original.original_version,
                    sealed_artifact: id.to_hex(),
                    sealed_version: version.version,
                    sha256: outputs[index].sha256(),
                    profile: outputs[index].profile().clone(),
                    active_content: outputs[index].active_content(),
                });
            }
            let manifest = SealedDocument {
                document: document.to_hex(),
                attempt_ref: crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes()),
                audit_chain_sha256: outputs[0].audit_chain_sha256(),
                items,
                rejected: state.rejection.is_some(),
            };
            let terminal = append(
                self,
                txn,
                document,
                EsignEvent::Sealed {
                    rejected: manifest.rejected,
                    item_sha256: manifest.items.iter().map(|i| i.sha256).collect(),
                    item_profiles: manifest.items.iter().map(|i| i.profile.clone()).collect(),
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
            RESULT.put(
                &self.store,
                txn,
                attempt.id.as_bytes(),
                &EsignSealAttemptResult::Sealed(manifest.clone()),
            )?;
            let recipients = terminal
                .document
                .recipients
                .iter()
                .map(|r| r.id.clone())
                .collect::<Vec<_>>();
            super::lifecycle::notify(
                self,
                txn,
                document,
                &terminal,
                if manifest.rejected {
                    "rejection"
                } else {
                    "completed"
                },
                &recipients,
                super::lifecycle::NoticeTrigger {
                    dispatch_ref: None,
                    now,
                },
            )?;

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
                    result_ref: crate::store::attempt_result::AttemptResultRef::new(format!(
                        "esign.sealed:{}",
                        document.to_hex()
                    ))?,
                    now,
                },
            )?;
            crate::ports::JobQueue::port_job_complete(
                self,
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
    /// Re-hash stored bytes and run the sealer's verifier for the in-app badge.
    pub fn verify_esign_item(
        &self,
        document: EntityId,
        item: usize,
        sealer: &dyn EsignSealer,
    ) -> std::result::Result<EsignVerdict, EsignSealError> {
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
            return Err(EsignSealError::Verification {
                verify_reasons: Vec::new(),
            });
        }
        Ok(sealer.verify(&bytes)?)
    }
}
