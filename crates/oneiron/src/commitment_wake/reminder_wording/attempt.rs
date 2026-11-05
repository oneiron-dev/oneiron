//! Filing the output of one exact leased reminder-wording attempt.

use super::*;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::blob_artifact::hash_hex;
use crate::error::ArtifactError;
use crate::ports::{EntityRecord, EntityStore, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM};
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};

fn transition(state: &'static str) -> Error {
    ArtifactError::InvalidAttemptQueueTransition {
        action: "file_commitment_reminder_wording_attempt",
        state,
    }
    .into()
}

impl Vault {
    /// Files wording for the frozen reminder of this exact live lease.
    ///
    /// `source_head` and `source_revision` pin the admitted commitment body;
    /// they are consistency evidence, never read authority. The lease,
    /// frozen payload, source revision and approval are checked beside the
    /// artifact mutation in one writer. The raw filing API is unchanged.
    /// The filed version carries the pin as its MadeBy source binding
    /// (FIX 4997): the source row as its input, the revision as its params
    /// hash, under the attempt kind's process identity.
    ///
    /// # Errors
    ///
    /// The lease or source changed, cancellation is pending, the wording
    /// is invalid, or the existing artifact writer failed.
    #[expect(
        clippy::too_many_arguments,
        reason = "the lease and source each carry their exact fence"
    )]
    pub fn file_commitment_reminder_wording_attempt(
        &self,
        id: AttemptId,
        lease_owner: &str,
        generation: u32,
        source_head: EntityId,
        source_revision: [u8; 32],
        text: &str,
        now: u64,
    ) -> Result<()> {
        let text = text.trim();
        if text.is_empty() || text.len() > COMMITMENT_REMINDER_WORDING_MAX_BYTES {
            return Err(Error::InvalidClaimBody(
                "reminder wording is empty or too long",
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let record = AttemptQueue::new(self)
                .get_in_txn(txn, id)?
                .ok_or_else(|| transition("missing"))?;
            if record.kind != COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND {
                return Err(ArtifactError::InvalidAttemptQueueRecord(
                    "reminder wording attempt kind mismatch",
                )
                .into());
            }
            if record.state != AttemptState::Leased {
                return Err(transition(record.state.as_str()));
            }
            if record.lease_owner.as_deref() != Some(lease_owner) {
                return Err(transition("leased_by_other"));
            }
            if record.attempt_count != generation {
                return Err(transition("stale_attempt"));
            }
            if record.cancel_state.landing.is_some()
                || record.cancel_state.cancellation.is_some()
                || record.cancel_state.pressure.pending > 0
            {
                return Err(transition("cancel_pending"));
            }
            let payload: CommitmentReminderWordingPayload = serde_json::from_slice(&record.payload)
                .map_err(|_| Error::InvalidClaimBody("reminder wording payload did not decode"))?;
            let content_ref = payload.content_ref;
            let reminder = ReminderRef::parse(&content_ref).ok_or(Error::InvalidClaimBody(
                "reminder wording names no reminder",
            ))?;
            if self.commitment_head_in_txn(txn, &reminder.instance_id)? != source_head {
                return Err(transition("source_changed"));
            }
            let source = self
                .store
                .port_entity_record(txn, &source_head)?
                .filter(|row| row.entity_type == ENTITY_TYPE_CLAIM)
                .ok_or_else(|| transition("source_changed"))?;
            if *blake3::hash(&source.body).as_bytes() != source_revision {
                return Err(transition("source_changed"));
            }
            let artifact_id = wording_artifact_id(&content_ref)?;
            let at = TimeRange {
                start: now,
                end: now,
            };
            if self.get_blob_artifact_in_txn(txn, &artifact_id)?.is_none() {
                self.port_entity_put(
                    txn,
                    &artifact_id,
                    &EntityRecord {
                        entity_type: ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred: at,
                        learned_at: now,
                        row_version: 0,
                        body: crate::blob_artifact::encode_blob_artifact_body(
                            &BlobArtifactBody::new(
                                format!("{WORDING_RUN_PREFIX}{content_ref}"),
                                WORDING_MEDIA_TYPE,
                            ),
                        )?,
                    },
                )?;
            }
            let run_prefix = if self.commitment_reminder_approved_in_txn(
                txn,
                &reminder.instance_id,
                &content_ref,
            )? {
                tracing::info!(
                    content_ref,
                    "a reminder wording filed after its approval is kept beside the approved words"
                );
                UNSENT_WORDING_RUN_PREFIX
            } else {
                WORDING_RUN_PREFIX
            };
            let authority = self.dreamer_authority_in_txn(txn, now)?;
            let provenance = BlobVersionProvenance::AgentRun {
                run_ref: format!("{run_prefix}{content_ref}"),
            };
            // FIX 4997: the version carries the fenced source it quotes —
            // the source row as its MadeBy input, the row's revision as its
            // params hash — under the attempt kind's process identity, so a
            // served read judges the persisted binding through its own lane.
            let params_hash = hash_hex(&source_revision);
            // The append dedupes a byte-identical head before the envelope
            // binds: the same binding retries into the head, while different
            // bytes, source, revision, identity or provenance fork a new
            // version off it instead of coalescing into it.
            let fork_parent = match crate::blob_artifact::read_blob_artifact_head_in_txn(
                &self.store,
                txn,
                &artifact_id,
            )? {
                Some(head) if *blake3::hash(text.as_bytes()).as_bytes() == head.content_hash => {
                    let same = head.provenance == provenance
                        && head.made_by.process.identity
                            == COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND
                        && head.made_by.process.params_hash == params_hash
                        && head.made_by.inputs.as_slice()
                            == [MadeByInput {
                                row: source_head,
                                role: MadeByInputRole::Input,
                            }];
                    (!same).then_some(head.version)
                }
                _ => None,
            };
            let made_by = MadeBy {
                inputs: vec![MadeByInput {
                    row: source_head,
                    role: MadeByInputRole::Input,
                }],
                process: MadeByProcess {
                    actor: authority.entity_ref(),
                    class: MadeByClass::Concluded,
                    identity: COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND.to_owned(),
                    version: "1".to_owned(),
                    params_hash,
                },
                at: now,
                trigger: None,
            };
            self.append_blob_artifact_version_made_by_in_txn(
                txn,
                &artifact_id,
                fork_parent,
                text.as_bytes(),
                &provenance,
                &made_by,
                authority,
                at,
                now,
            )?;
            Ok(())
        })
    }
}
