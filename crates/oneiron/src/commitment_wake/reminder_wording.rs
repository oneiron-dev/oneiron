//! Reminder wording by a model or a persona (FIX 12000).
//!
//! A reminder's fixed wording is a pure function of its content ref. When the
//! owner's reminder route names a voice ([`CommitmentReminderVoice`]), the
//! planner queues one `commitment.reminder.wording` attempt for each reminder
//! it proposes, and a host worker that holds a model words the reminder for
//! its reader ([`CommitmentReminderWorder`]) and files the text behind the
//! content ref. The send reads the filed text first and the fixed wording
//! while none is filed, so no reminder waits for its wording.
//!
//! The approval pins the words its send reads (FIX 12239): the words the
//! owner saw, by their content hash, when the approval names them; else the
//! wording filed at that moment; else the fixed wording. The send reads the
//! pinned words, and the fixed wording once the vault no longer holds them.
//! A wording filed after the reminder's proposal was approved is kept beside
//! the approved words, a version of the same artifact under its own run
//! prefix, and never sent (FIX 12167).

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::EnqueueAttempt;
use crate::blob_artifact::{BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance};
use crate::commitment::{CommitmentObligorKind, CommitmentStatus};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::COMMITMENT_REMINDER_WORDING_BLOB;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

use super::reminder::{ReminderRef, civil_time, quoted_promise, reminder_text};
use super::wake_approval::approved_commitment_wake;
use super::wake_event::{
    CommitmentWakePhase, KEY_CONTENT_REF, PREDICATE_COMMITMENT_WAKE_PROPOSAL, validate_wake_string,
};

/// Attempt kind for one reminder's queued wording.
pub const COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND: &str = "commitment.reminder.wording";
/// The longest wording a worder may file, in bytes.
pub const COMMITMENT_REMINDER_WORDING_MAX_BYTES: usize = 4_096;
const WORDING_MEDIA_TYPE: &str = "text/plain";
const WORDING_RUN_PREFIX: &str = "commitment-reminder-wording:";
/// The run prefix of a wording filed after the owner approved its reminder:
/// kept beside the approved words, never sent.
const UNSENT_WORDING_RUN_PREFIX: &str = "commitment-reminder-wording-unsent:";
/// The pin of a reminder approved while no wording was filed for it.
const FIXED_WORDING_PIN: &str = "fixed";

/// The words an approved reminder's send reads, pinned when its approval
/// schedules it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommitmentReminderWordingPin {
    /// The words whose BLAKE3 content hash this is: the filed wording with
    /// that hash, or the fixed wording when the vault holds none.
    Hash([u8; 32]),
    /// No wording was filed at approval: the fixed wording.
    Fixed,
}

impl CommitmentReminderWordingPin {
    fn token(self) -> String {
        match self {
            Self::Hash(hash) => blake3::Hash::from_bytes(hash).to_hex().to_string(),
            Self::Fixed => FIXED_WORDING_PIN.to_owned(),
        }
    }

    fn parse(token: &str) -> Option<Self> {
        if token == FIXED_WORDING_PIN {
            return Some(Self::Fixed);
        }
        // Only the lowercase form a pin is written in reads as one.
        let hash = blake3::Hash::from_hex(token).ok()?;
        (hash.to_hex().as_str() == token).then_some(Self::Hash(*hash.as_bytes()))
    }
}

/// The content ref an approved reminder's send names: the reminder's own ref
/// and the words its approval pinned, `<reminder ref>:<hash hex | fixed>`.
pub(super) fn pinned_content_ref(content_ref: &str, pin: CommitmentReminderWordingPin) -> String {
    format!("{content_ref}:{}", pin.token())
}

/// A send's content ref split into the reminder's own ref and the pin it
/// ends with, when it names one.
pub(super) fn split_wording_pin(content_ref: &str) -> (&str, Option<CommitmentReminderWordingPin>) {
    if let Some((reminder_ref, token)) = content_ref.rsplit_once(':')
        && ReminderRef::parse(reminder_ref).is_some()
        && let Some(pin) = CommitmentReminderWordingPin::parse(token)
    {
        return (reminder_ref, Some(pin));
    }
    (content_ref, None)
}

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
    /// same. Once a proposal that sends the reminder is approved, the new
    /// version is kept beside the approved words and the send still reads
    /// those.
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
        let Some(reminder) = ReminderRef::parse(content_ref) else {
            return Err(Error::InvalidClaimBody(
                "reminder wording names no reminder",
            ));
        };
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
        let run_prefix = if self.commitment_reminder_approved(&reminder.instance_id, content_ref)? {
            tracing::info!(
                content_ref,
                "a reminder wording filed after its approval is kept beside the approved words"
            );
            UNSENT_WORDING_RUN_PREFIX
        } else {
            WORDING_RUN_PREFIX
        };
        self.append_blob_artifact_version(
            &artifact_id,
            text.as_bytes(),
            &BlobVersionProvenance::AgentRun {
                run_ref: format!("{run_prefix}{content_ref}"),
            },
            self.dreamer_authority()?,
            at,
            now,
        )?;
        Ok(())
    }

    /// The wording filed for the reminder `content_ref` to send, its latest
    /// such version, when a worder filed one. Versions kept beside an
    /// approval are passed over.
    pub(super) fn filed_commitment_reminder_wording(
        &self,
        content_ref: &str,
    ) -> Result<Option<String>> {
        let artifact_id = wording_artifact_id(content_ref)?;
        match self.filed_wording_version(&artifact_id)? {
            Some(record) => self.wording_text(&artifact_id, record.version),
            None => Ok(None),
        }
    }

    /// The wording filed for the reminder the proposal `proposal` sends,
    /// with the BLAKE3 hash of its text: `None` for any other proposal, or
    /// a reminder with no wording filed yet (FIX 12319). The hash is the
    /// filed version's content hash, the value an approval names to pin
    /// these words.
    ///
    /// # Errors
    ///
    /// The claim or the wording artifact could not be read.
    pub fn filed_commitment_reminder_wording_for_proposal(
        &self,
        proposal: &EntityId,
    ) -> Result<Option<(String, [u8; 32])>> {
        let Some(body) = self.get_claim(proposal)? else {
            return Ok(None);
        };
        if body.predicate != PREDICATE_COMMITMENT_WAKE_PROPOSAL {
            return Ok(None);
        }
        let Value::Map(entries) = &body.value else {
            return Ok(None);
        };
        let Some(content_ref) = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_CONTENT_REF))
            .and_then(|(_, value)| value.as_str())
        else {
            return Ok(None);
        };
        if ReminderRef::parse(content_ref).is_none() {
            return Ok(None);
        }
        let artifact_id = wording_artifact_id(content_ref)?;
        let Some(record) = self.filed_wording_version(&artifact_id)? else {
            return Ok(None);
        };
        let Some(text) = self.wording_text(&artifact_id, record.version)? else {
            return Ok(None);
        };
        Ok(Some((text, record.content_hash)))
    }

    /// The words an approved send of the reminder `content_ref` pins: the
    /// words the owner saw, by their BLAKE3 hash, when the approval names
    /// them; else the wording filed for it now; else the fixed wording.
    pub(super) fn commitment_reminder_wording_pin(
        &self,
        content_ref: &str,
        seen: Option<[u8; 32]>,
    ) -> Result<CommitmentReminderWordingPin> {
        if let Some(hash) = seen {
            return Ok(CommitmentReminderWordingPin::Hash(hash));
        }
        let filed = self.filed_wording_version(&wording_artifact_id(content_ref)?)?;
        Ok(filed.map_or(CommitmentReminderWordingPin::Fixed, |record| {
            CommitmentReminderWordingPin::Hash(record.content_hash)
        }))
    }

    /// The words `pin` names for the reminder `content_ref`: the filed
    /// wording with the pinned hash, kept beside an approval or not. `None`
    /// for the fixed wording, or a pinned wording the vault no longer holds.
    pub(super) fn pinned_commitment_reminder_wording(
        &self,
        content_ref: &str,
        pin: CommitmentReminderWordingPin,
    ) -> Result<Option<String>> {
        let CommitmentReminderWordingPin::Hash(hash) = pin else {
            return Ok(None);
        };
        let artifact_id = wording_artifact_id(content_ref)?;
        match self.get_blob_artifact(&artifact_id)? {
            Some(body) if body.media_type == WORDING_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        for version in self.blob_artifact_versions(&artifact_id)?.iter().rev() {
            if version.content_hash != hash {
                continue;
            }
            let Some(record) =
                self.blob_artifact_version_metadata(&artifact_id, version.version)?
            else {
                continue;
            };
            if matches!(
                &record.provenance,
                BlobVersionProvenance::AgentRun { run_ref }
                    if run_ref.starts_with(WORDING_RUN_PREFIX)
                        || run_ref.starts_with(UNSENT_WORDING_RUN_PREFIX)
            ) && let Some(text) = self.wording_text(&artifact_id, record.version)?
            {
                return Ok(Some(text));
            }
        }
        Ok(None)
    }

    /// The latest version of the wording artifact `artifact_id` filed to
    /// send. Versions kept beside an approval are passed over.
    fn filed_wording_version(&self, artifact_id: &EntityId) -> Result<Option<BlobArtifactVersion>> {
        match self.get_blob_artifact(artifact_id)? {
            Some(body) if body.media_type == WORDING_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        for version in self.blob_artifact_versions(artifact_id)?.iter().rev() {
            let Some(record) = self.blob_artifact_version_metadata(artifact_id, version.version)?
            else {
                return Ok(None);
            };
            match &record.provenance {
                BlobVersionProvenance::AgentRun { run_ref }
                    if run_ref.starts_with(UNSENT_WORDING_RUN_PREFIX) => {}
                BlobVersionProvenance::AgentRun { run_ref }
                    if run_ref.starts_with(WORDING_RUN_PREFIX) =>
                {
                    return Ok(Some(record));
                }
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// The text of one wording version, `None` once its bytes are gone.
    fn wording_text(&self, artifact_id: &EntityId, version: u64) -> Result<Option<String>> {
        let Some(bytes) = self.read_blob_artifact_version(artifact_id, version)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::InvalidClaimBody("a filed reminder wording is not text"))
    }

    /// Whether an approved wake proposal about the commitment `instance_id`
    /// that still stands sends the reminder `content_ref`.
    fn commitment_reminder_approved(
        &self,
        instance_id: &EntityId,
        content_ref: &str,
    ) -> Result<bool> {
        for claim in self.claims_for_subject(instance_id)? {
            if approved_commitment_wake(self, &claim)
                .is_ok_and(|approved| approved.content_ref() == Some(content_ref))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
