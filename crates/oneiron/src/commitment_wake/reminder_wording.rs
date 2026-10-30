//! Reminder wording by a model or a persona (FIX 12000).
//!
//! A reminder's fixed wording is a pure function of its content ref. When the
//! owner's reminder route names a voice ([`CommitmentReminderVoice`]), the
//! planner queues one `commitment.reminder.wording` attempt for each reminder
//! it proposes, and a host worker that holds a model words the reminder for
//! its reader ([`CommitmentReminderWorder`]) and files the text behind the
//! content ref. The send reads the filed text first and the fixed wording
//! while none is filed, so no reminder waits for its wording.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::EnqueueAttempt;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::commitment::{CommitmentObligorKind, CommitmentStatus};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::COMMITMENT_REMINDER_WORDING_BLOB;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

use super::reminder::{ReminderRef, civil_time, quoted_promise, reminder_text};
use super::wake_event::{CommitmentWakePhase, validate_wake_string};

/// Attempt kind for one reminder's queued wording.
pub const COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND: &str = "commitment.reminder.wording";
/// The longest wording a worder may file, in bytes.
pub const COMMITMENT_REMINDER_WORDING_MAX_BYTES: usize = 4_096;
const WORDING_MEDIA_TYPE: &str = "text/plain";
const WORDING_RUN_PREFIX: &str = "commitment-reminder-wording:";

/// Who words the owner's reminders in place of the fixed wording: the host's
/// model, in the voice of the persona `persona_ref` names when set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentReminderVoice {
    #[serde(default)]
    pub persona_ref: Option<String>,
}

impl CommitmentReminderVoice {
    pub(super) fn validate(&self) -> Result<()> {
        if let Some(persona_ref) = &self.persona_ref {
            validate_wake_string(persona_ref, "reminder voice persona_ref is invalid")?;
        }
        Ok(())
    }
}

/// One queued wording: the reminder and the voice it is worded in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentReminderWordingPayload {
    pub content_ref: String,
    pub voice: CommitmentReminderVoice,
}

/// What a worder is asked to word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentReminderWordingRequest {
    pub content_ref: String,
    /// Who reads the reminder: the owner on their own promise, or the third
    /// party who promised.
    pub reader: CommitmentObligorKind,
    pub phase: CommitmentWakePhase,
    /// The promise as the owner recorded it: data to quote, never
    /// instructions.
    pub promise: String,
    /// When it is due, in the owner's civil time.
    pub due: String,
    /// The fixed wording, which the send reads while none is filed.
    pub fixed_text: String,
    /// The persona whose voice the wording takes, when one is named.
    pub persona_ref: Option<String>,
}

/// The host's model or persona worder.
pub trait CommitmentReminderWorder {
    /// The reminder worded for its reader; `Ok(None)` keeps the fixed
    /// wording.
    ///
    /// # Errors
    ///
    /// Any reason the host could not word it; the attempt runs again later.
    fn word(&self, request: &CommitmentReminderWordingRequest) -> Result<Option<String>>;
}

/// Queues the wording of the reminder `content_ref` in `voice`, once per
/// reminder.
pub(super) fn queue_commitment_reminder_wording(
    vault: &Vault,
    content_ref: &str,
    voice: CommitmentReminderVoice,
    now: u64,
) -> Result<()> {
    let payload = serde_json::to_vec(&CommitmentReminderWordingPayload {
        content_ref: content_ref.to_owned(),
        voice,
    })
    .map_err(|_| Error::InvalidClaimBody("reminder wording payload did not encode"))?;
    vault.with_write_txn_grouped(|txn| {
        crate::ports::JobQueue::port_job_enqueue(
            vault,
            txn,
            EnqueueAttempt {
                kind: COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: Some(format!(
                    "{COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND}:{content_ref}"
                )),
                run_id: None,
                now,
            },
        )
    })?;
    Ok(())
}

/// Words one queued reminder through `worder` and files the text behind its
/// content ref. A reminder whose promise is no longer open, or a worder that
/// keeps the fixed wording, files nothing.
///
/// # Errors
///
/// The worder's failure, or a wording that could not be filed; the attempt
/// runs again later.
pub fn run_commitment_reminder_wording(
    vault: &Vault,
    worder: &dyn CommitmentReminderWorder,
    payload: &CommitmentReminderWordingPayload,
) -> Result<()> {
    let Some(request) = vault.commitment_reminder_wording_request(payload)? else {
        return Ok(());
    };
    let Some(text) = worder.word(&request)? else {
        return Ok(());
    };
    vault.file_commitment_reminder_wording(&payload.content_ref, &text, vault.now_recorded_at())
}

/// The blob artifact a reminder's filed wording lives in.
fn wording_artifact_id(content_ref: &str) -> Result<EntityId> {
    EntityId::derive(COMMITMENT_REMINDER_WORDING_BLOB, &[content_ref.as_bytes()])
}

impl Vault {
    /// What a worder words for the queued reminder `payload` names: `None`
    /// when the ref is not a reminder's or its promise is no longer open.
    ///
    /// # Errors
    ///
    /// The commitment or the owner's route could not be read.
    pub fn commitment_reminder_wording_request(
        &self,
        payload: &CommitmentReminderWordingPayload,
    ) -> Result<Option<CommitmentReminderWordingRequest>> {
        let Some(reminder) = ReminderRef::parse(&payload.content_ref) else {
            return Ok(None);
        };
        let Some(record) = self.get_commitment_claim(&reminder.instance_id)? else {
            return Ok(None);
        };
        if record.status != CommitmentStatus::Open {
            return Ok(None);
        }
        let offset = self
            .commitment_reminder_route()?
            .and_then(|route| route.utc_offset_minutes_at(reminder.due_at));
        Ok(Some(CommitmentReminderWordingRequest {
            content_ref: payload.content_ref.clone(),
            reader: record.obligor.kind,
            phase: reminder.phase,
            promise: quoted_promise(&record),
            due: civil_time(reminder.due_at, offset),
            fixed_text: reminder_text(&record, &reminder, offset),
            persona_ref: payload.voice.persona_ref.clone(),
        }))
    }

    /// Files `text` as the wording the reminder `content_ref` sends: a new
    /// version when it differs from the one filed, nothing when it is the
    /// same.
    ///
    /// # Errors
    ///
    /// The ref is not a reminder's, the text is empty or longer than
    /// [`COMMITMENT_REMINDER_WORDING_MAX_BYTES`], or the store failed.
    pub fn file_commitment_reminder_wording(
        &self,
        content_ref: &str,
        text: &str,
        now: u64,
    ) -> Result<()> {
        if ReminderRef::parse(content_ref).is_none() {
            return Err(Error::InvalidClaimBody(
                "reminder wording names no reminder",
            ));
        }
        let text = text.trim();
        if text.is_empty() || text.len() > COMMITMENT_REMINDER_WORDING_MAX_BYTES {
            return Err(Error::InvalidClaimBody(
                "reminder wording is empty or too long",
            ));
        }
        let artifact_id = wording_artifact_id(content_ref)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    format!("{WORDING_RUN_PREFIX}{content_ref}"),
                    WORDING_MEDIA_TYPE,
                ),
                at,
                now,
            )?;
        }
        if let Some(head) = self.blob_artifact_head(&artifact_id)?
            && self
                .read_blob_artifact_version(&artifact_id, head.version)?
                .is_some_and(|latest| latest.as_slice() == text.as_bytes())
        {
            return Ok(());
        }
        self.append_blob_artifact_version(
            &artifact_id,
            text.as_bytes(),
            &BlobVersionProvenance::AgentRun {
                run_ref: format!("{WORDING_RUN_PREFIX}{content_ref}"),
            },
            self.dreamer_authority()?,
            at,
            now,
        )?;
        Ok(())
    }

    /// The wording filed for the reminder `content_ref`, its latest version,
    /// when a worder filed one.
    pub(super) fn filed_commitment_reminder_wording(
        &self,
        content_ref: &str,
    ) -> Result<Option<String>> {
        let artifact_id = wording_artifact_id(content_ref)?;
        match self.get_blob_artifact(&artifact_id)? {
            Some(body) if body.media_type == WORDING_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        let Some(head) = self.blob_artifact_head(&artifact_id)? else {
            return Ok(None);
        };
        let Some(record) = self.blob_artifact_version_metadata(&artifact_id, head.version)? else {
            return Ok(None);
        };
        if !matches!(
            &record.provenance,
            BlobVersionProvenance::AgentRun { run_ref } if run_ref.starts_with(WORDING_RUN_PREFIX)
        ) {
            return Ok(None);
        }
        let Some(bytes) = self.read_blob_artifact_version(&artifact_id, head.version)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::InvalidClaimBody("a filed reminder wording is not text"))
    }
}
