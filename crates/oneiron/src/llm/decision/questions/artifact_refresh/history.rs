//! FIX 2337: every ask a standing artifact question makes is kept, one by one, in the
//! question's ask log, beside the `TYPED_QUESTION_ARTIFACT_ASKED` stamp that stays the
//! schedule's latest projection. A completed ask commits its proposal, its stamp and its
//! log entry in one transaction; a failed one is logged on its own and leaves the stamp
//! where it was. `vault.questions.answers` lists them all, across versions, each with
//! where its answers stand now.

use super::super::ask_history::{
    ArtifactAskEvent, append_artifact_ask_in_txn, artifact_events_in_txn,
    ask_history_through_in_txn,
};
use super::super::store::owned_head;
use super::{ASKED, ArtifactAskRecord, ArtifactAskStanding, ArtifactAsked, Asking, baseline};
use crate::edit_roundtrip::ArtifactAskRun;
use crate::edit_settle::PendingProposalView;
use crate::{EntityId, Result, Vault};

impl Asking<'_> {
    /// Runs one ask of `artifact` under an ask id of its own, minted before the ask and
    /// named in its run ref after `kind`, so two asks in one second hold two refs. A
    /// completed ask holds its answers as a proposal, restamps the artifact and logs the
    /// ask, all in one transaction; a failed one, before or at that commit, is logged as
    /// failed and leaves the stamp, and its error stands.
    pub(super) fn ask_recorded(
        &self,
        artifact: EntityId,
        observed: Vec<(EntityId, u64)>,
        kind: &str,
        ask: impl FnOnce(&str) -> Result<ArtifactAskRun>,
    ) -> Result<Option<PendingProposalView>> {
        let vault = self.vault;
        let ask_id = EntityId::now();
        let reference = format!(
            "{kind}:{}:{}:{}:{}",
            &self.question.to_hex()[..16],
            self.version,
            self.now,
            ask_id.to_hex()
        );
        let event = |proposal_ref: Option<String>, failed: Option<String>| ArtifactAskEvent {
            ask_id,
            artifact,
            question_version: self.version,
            versions: observed.clone(),
            asked_at: self.now,
            proposal_ref,
            failed,
        };
        let committed = ask(&reference).and_then(|run| {
            vault.with_write_txn_grouped(|wtxn| {
                let proposed = match &run.proposal {
                    Some(proposal) => Some(vault.retain_edit_proposal_in_txn(
                        wtxn,
                        &artifact,
                        proposal,
                        None,
                        self.actor,
                        self.now,
                    )?),
                    None => None,
                };
                let proposal_ref = proposed.as_ref().map(|_| reference.clone());
                let stamp = ArtifactAsked {
                    question_version: self.version,
                    versions: observed.clone(),
                    asked_at: self.now,
                    proposal_ref: proposal_ref.clone(),
                    ask_id: Some(ask_id),
                };
                ASKED.put(&vault.store, wtxn, &(self.question, artifact), &stamp)?;
                let principal = self.record.principal;
                let asked = event(proposal_ref, None);
                append_artifact_ask_in_txn(vault, wtxn, self.question, principal, asked)?;
                Ok(proposed)
            })
        });
        if let Err(error) = &committed {
            let error_kind = error.kind();
            let failed = event(None, Some(format!("{error_kind:?}")));
            let logged = vault.with_write_txn_grouped(|wtxn| {
                let principal = self.record.principal;
                append_artifact_ask_in_txn(vault, wtxn, self.question, principal, failed)
            });
            if let Err(error) = logged {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a failed standing artifact ask was not logged"
                );
            }
        }
        committed
    }
}

/// One logged ask as its principal reads it back: the pins it read and where its
/// answers stand now, by the walk the next ask's baseline takes.
pub(in crate::llm::decision::questions) fn artifact_event_record(
    vault: &Vault,
    event: &ArtifactAskEvent,
) -> Result<ArtifactAskRecord> {
    let stamp = ArtifactAsked {
        question_version: event.question_version,
        versions: event.versions.clone(),
        asked_at: event.asked_at,
        proposal_ref: event.proposal_ref.clone(),
        ask_id: Some(event.ask_id),
    };
    ask_record(vault, event.artifact, &stamp, event.failed.clone())
}

/// `stamp`'s ask of `artifact`, with where its answers stand: none held, still waiting
/// for Keep, kept past the version it asked, or closed.
fn ask_record(
    vault: &Vault,
    artifact: EntityId,
    stamp: &ArtifactAsked,
    failed: Option<String>,
) -> Result<ArtifactAskRecord> {
    let asked = stamp
        .versions
        .iter()
        .find(|(id, _)| *id == artifact)
        .map_or(0, |(_, version)| *version);
    let standing = match (&stamp.proposal_ref, baseline(vault, artifact, stamp)?) {
        (None, _) => ArtifactAskStanding::Unanswered,
        (Some(_), None) => ArtifactAskStanding::Waiting,
        (Some(_), Some(versions)) => versions
            .iter()
            .find(|(id, _)| *id == artifact)
            .filter(|(_, kept)| *kept > asked)
            .map_or(ArtifactAskStanding::Closed, |(_, kept)| {
                ArtifactAskStanding::Kept { version: *kept }
            }),
    };
    Ok(ArtifactAskRecord {
        artifact,
        question_version: stamp.question_version,
        artifact_version: asked,
        asked_at: stamp.asked_at,
        proposal_ref: stamp.proposal_ref.clone(),
        standing,
        ask_id: stamp.ask_id,
        failed,
    })
}

/// Every ask the caller's standing question has made of its artifacts, across its
/// versions: each artifact's last ask stamped before asks were logged one by one, in
/// artifact order, then every logged ask in the order it committed, a failed one too,
/// each with where its answers stand. Another principal's question is not found, as
/// [`super::super::answer_records`] refuses it.
pub fn artifact_ask_records(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<ArtifactAskRecord>> {
    let (stamps, events) = {
        let txn = vault.store.env.read_txn()?;
        owned_head(vault, &txn, principal, question)?;
        let stamps = ASKED.scan_from(&vault.store, &txn, question.as_bytes())?;
        let through = ask_history_through_in_txn(vault, &txn, question)?;
        let events = artifact_events_in_txn(vault, &txn, question, principal, 0, through)?;
        (stamps, events)
    };
    let mut records = Vec::with_capacity(stamps.len() + events.len());
    for ((_, artifact), stamp) in stamps {
        // A stamp an ask of this log wrote is that ask's projection, listed below.
        if stamp.ask_id.is_none() {
            records.push(ask_record(vault, artifact, &stamp, None)?);
        }
    }
    for (_, event) in &events {
        records.push(artifact_event_record(vault, event)?);
    }
    Ok(records)
}
