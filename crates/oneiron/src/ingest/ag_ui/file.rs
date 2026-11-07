//! File-only AG-UI capture and exact, scoped source observations.

use rmpv::Value as Msgpack;
use serde::{Deserialize, Serialize};

use super::observations::{observations, repair_links, validate_mappings};
use super::{AgUiAppObservation, AgUiCustomMapping, AgUiRepairLink, AgUiSource};
use crate::claim::{ClaimReadStatus, ClaimSource, ClaimSubject, ScopedReadReceipt};
use crate::consent::AuthenticatedOwner;
use crate::core_write::CoreWriteLaneRef;
use crate::edge::EdgeActorClass;
use crate::ingest::admission::imported_candidate;
use crate::ingest::{
    ImportedEvidenceAdmission, ImportedEvidenceEntityResolution, json_to_msgpack_value,
};
use crate::memory::{Memory, MemoryResult};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, TimeRange, Vault};

pub const AG_UI_FILE_PREDICATE: &str = "ingest.ag_ui.file";

/// Registration is snapshotted with this file. It grants no app or training authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgUiFileImport {
    pub claim_ref: Option<String>,
    pub project_ref: String,
    pub app_id: String,
    pub custom_mappings: Vec<AgUiCustomMapping>,
    pub jsonl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    capture_actor_ref: String,
    project_ref: String,
    app_id: String,
    custom_mappings: Vec<AgUiCustomMapping>,
    jsonl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileReceipt {
    pub claim_ref: String,
    pub source_hash: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgUiFileReadInput {
    pub claim_ref: String,
    pub source_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileView {
    pub claim_ref: String,
    pub source_hash: String,
    pub capture_actor_ref: String,
    pub project_ref: String,
    pub app_id: String,
    pub custom_mappings: Vec<AgUiCustomMapping>,
    pub jsonl: String,
    pub event_count: usize,
    pub observations: Vec<AgUiAppObservation>,
    pub repair_links: Vec<AgUiRepairLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileRead {
    pub source: Option<AgUiFileView>,
    pub receipt: ScopedReadReceipt,
}

fn fingerprint(file: &StoredFile) -> Result<String> {
    let bytes = serde_json::to_vec(file)
        .map_err(|_| Error::InvalidClaimBody("AG-UI source encoding failed"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn decode_events(jsonl: &str) -> Result<Vec<super::AgUiDecodedEvent>> {
    AgUiSource::decode(jsonl).map_err(|_| Error::InvalidClaimBody("invalid AG-UI JSONL source"))
}

impl Vault {
    /// Capture one owner-selected file as Imported/Proposed through the ordinary
    /// claim Gate. Source context is data, never a grant or an app-selected actor.
    pub fn ingest_ag_ui_file(
        &self,
        owner: &AuthenticatedOwner,
        input: &AgUiFileImport,
    ) -> Result<AgUiFileReceipt> {
        if input.app_id.is_empty() {
            return Err(Error::InvalidClaimBody("AG-UI app id must be nonempty"));
        }
        validate_mappings(&input.custom_mappings)?;
        let event_count = decode_events(&input.jsonl)?.len();
        let project = EntityId::from_hex(&input.project_ref)?;
        let id = input
            .claim_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?
            .unwrap_or_else(EntityId::now);
        let actor = WriteActor::new(owner.revalidate(self)?, EdgeActorClass::Human);
        let file = StoredFile {
            capture_actor_ref: actor.entity_ref().to_hex(),
            project_ref: project.to_hex(),
            app_id: input.app_id.clone(),
            custom_mappings: input.custom_mappings.clone(),
            jsonl: input.jsonl.clone(),
        };
        let hash = fingerprint(&file)?;
        let value = serde_json::to_value(&file)
            .map_err(|_| Error::InvalidClaimBody("AG-UI source encoding failed"))?;
        self.try_with_actor_content_write_txn(actor, CoreWriteLaneRef::Unbound, |content| {
            owner.revalidate_in_txn(self, content.read())?;
            if self
                .visible_project_in_txn(content.read(), project)?
                .is_none()
            {
                return Err(Error::InvalidClaimBody("AG-UI project is not live"));
            }
            if self.local_hard_delete_marker_exists_in_txn(content.read(), &id)?
                || self.get_raw_in(content.read(), &id)?.is_some()
            {
                return Err(Error::InvalidClaimBody(
                    "AG-UI source claim id must be fresh",
                ));
            }
            let now = self.instant_in_txn(content.read())?.secs();
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            let admission = ImportedEvidenceAdmission::proposed(
                super::AG_UI_SOURCE_ID,
                id,
                ImportedEvidenceEntityResolution::subject(project),
                actor,
                occurred,
                now,
            );
            let (candidate, envelope) = imported_candidate(
                AG_UI_FILE_PREDICATE,
                json_to_msgpack_value(&value),
                &hash,
                &admission,
            )?;
            let candidate = candidate.with_scope(Msgpack::Map(vec![(
                Msgpack::from("scopeProjectId"),
                Msgpack::Binary(project.as_bytes().to_vec()),
            )]));
            content.apply_batch(
                self.batch_in()
                    .claim_candidate(&id, candidate, &envelope, occurred, now),
            )?;
            let stored_claim = self
                .get_claim_in_txn(content.read(), &id)?
                .ok_or(Error::InvalidClaimBody("AG-UI capture was not stored"))?;
            let stored_file: StoredFile = rmpv::ext::from_value(stored_claim.value)
                .map_err(|_| Error::InvalidClaimBody("invalid finalized AG-UI source"))?;
            if fingerprint(&stored_file)? != hash {
                return Err(Error::InvalidClaimBody(
                    "AG-UI exact capture was changed by admission",
                ));
            }
            Ok(AgUiFileReceipt {
                claim_ref: id.to_hex(),
                source_hash: hash.clone(),
                event_count,
            })
        })
    }
}

impl Memory<'_> {
    /// Capture an owner-selected file through the native owner-bound writer.
    pub fn ingest_ag_ui_file(
        &self,
        owner: &AuthenticatedOwner,
        input: &AgUiFileImport,
    ) -> MemoryResult<AgUiFileReceipt> {
        Ok(self.vault().ingest_ag_ui_file(owner, input)?)
    }

    /// Read exactly this capture under the caller's normal credential, locality
    /// and room scope. Missing/withheld rows reveal no source metadata.
    pub fn read_ag_ui_file(&self, input: &AgUiFileReadInput) -> MemoryResult<AgUiFileRead> {
        let id = EntityId::from_hex(&input.claim_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let read = lane.read_projected(
            &[crate::claim::PointRead::id(id)],
            None,
            |txn, rows| -> Result<Option<AgUiFileView>> {
                let Some(row) = rows.into_iter().next().flatten() else {
                    return Ok(None);
                };
                if row.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                    return Err(Error::InvalidClaimBody("AG-UI source is not a claim"));
                }
                let Some(bytes) = row.body else {
                    return Ok(None);
                };
                let claim = crate::claim::decode_claim_body(&bytes, true)?;
                if claim.predicate != AG_UI_FILE_PREDICATE
                    || claim.source != Some(ClaimSource::Imported)
                {
                    return Err(Error::InvalidClaimBody("not an imported AG-UI source"));
                }
                let file: StoredFile = rmpv::ext::from_value(claim.value.clone())
                    .map_err(|_| Error::InvalidClaimBody("invalid AG-UI source record"))?;
                let project = EntityId::from_hex(&file.project_ref)?;
                let actor = EntityId::from_hex(&file.capture_actor_ref)?;
                let author = crate::batch::authenticated_claim_author_in_txn(
                    &self.vault().store,
                    txn,
                    &id,
                    &claim,
                )?;
                if claim.subject != ClaimSubject::Entity(project)
                    || author.is_none_or(|author| author.entity_ref() != actor)
                {
                    return Err(Error::InvalidClaimBody(
                        "AG-UI source capture binding changed",
                    ));
                }
                if !crate::policy_model::is_live_vault_owner_in_txn(self.vault(), txn, &actor)? {
                    return Err(Error::InvalidClaimBody(
                        "AG-UI source mapping is not registered by a live owner",
                    ));
                }
                let hash = fingerprint(&file)?;
                if hash != input.source_hash {
                    return Err(Error::InvalidClaimBody("AG-UI source fingerprint changed"));
                }
                validate_mappings(&file.custom_mappings)?;
                let events = decode_events(&file.jsonl)?;
                let observations = observations(&events, &file.custom_mappings);
                let repair_links = repair_links(&observations);
                Ok(Some(AgUiFileView {
                    claim_ref: id.to_hex(),
                    source_hash: hash,
                    capture_actor_ref: file.capture_actor_ref,
                    project_ref: file.project_ref,
                    app_id: file.app_id,
                    custom_mappings: file.custom_mappings,
                    jsonl: file.jsonl,
                    event_count: events.len(),
                    observations,
                    repair_links,
                }))
            },
        )?;
        Ok(AgUiFileRead {
            source: read.value,
            receipt: read.receipt,
        })
    }
}
