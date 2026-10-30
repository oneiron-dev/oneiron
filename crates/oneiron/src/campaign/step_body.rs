//! One campaign program step's filed outbound body (FIX 11513). A program
//! write keeps the words each outbound step sends in the vault before the
//! leg names them: one BLOB artifact per (program, step, call_seq), written
//! as the program's author. The leg pins the latest version in its envelope,
//! so a retried send carries the same words, and the body syncs, restores
//! and erases with the vault. This carries out the campaign's own sends;
//! erasing the person stops them.

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::entity_id::derived_domains::CAMPAIGN_STEP_BODY_BLOB;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// Every campaign step body ref starts with this:
/// `campaign-step-body:<artifact hex>@<version>`.
pub const CAMPAIGN_STEP_BODY_PREFIX: &str = "campaign-step-body:";
const STEP_BODY_MEDIA_TYPE: &str = "text/plain";
/// The run-ref prefix a campaign step body's versions are written under.
const STEP_BODY_RUN_PREFIX: &str = "campaign-step:";

/// The deterministic artifact id of one outbound step's body: derived under
/// [`CAMPAIGN_STEP_BODY_BLOB`] from the program, the step and the durable
/// call sequence, so the program doors, the leg and the sender all name the
/// same body without carrying it.
///
/// # Errors
/// The id does not derive (a result in the reserved sentinel range).
pub fn campaign_step_body_artifact_id(
    program_ref: EntityId,
    step_ref: EntityId,
    call_seq: u64,
) -> Result<EntityId> {
    let call_seq_bytes = call_seq.to_be_bytes();
    EntityId::derive(
        CAMPAIGN_STEP_BODY_BLOB,
        &[
            program_ref.as_bytes().as_slice(),
            step_ref.as_bytes().as_slice(),
            &call_seq_bytes,
        ],
    )
}

/// The hex of [`campaign_step_body_artifact_id`]: the derived id with no
/// prefix and no `@version` suffix.
///
/// # Errors
/// As [`campaign_step_body_artifact_id`].
pub fn campaign_step_body_ref(
    program_ref: EntityId,
    step_ref: EntityId,
    call_seq: u64,
) -> Result<String> {
    Ok(campaign_step_body_artifact_id(program_ref, step_ref, call_seq)?.to_hex())
}

impl Vault {
    /// The versioned ref of the latest filed body for one outbound step:
    /// `campaign-step-body:<artifact hex>@<latest>`. `None` before any is
    /// filed, or when no version stays.
    ///
    /// # Errors
    /// The artifact's version chain does not read.
    pub fn campaign_step_body_latest_ref(
        &self,
        program_ref: EntityId,
        step_ref: EntityId,
        call_seq: u64,
    ) -> Result<Option<String>> {
        let artifact_id = campaign_step_body_artifact_id(program_ref, step_ref, call_seq)?;
        Ok(self
            .blob_artifact_head(&artifact_id)?
            .map(|head| step_body_ref(&artifact_id, head.version)))
    }

    /// The versioned ref of the latest filed body for one outbound step, but
    /// only when the latest filed bytes equal `expected`: the leg pins the
    /// body's ref against the program row it is about to send, so a blob
    /// whose latest version ran ahead of the accepted row (an update files
    /// the new body before the program write is validated) reads as absent
    /// and the send waits instead of carrying words the program never
    /// accepted (FIX 11513 K11). `None` before any is filed, when no version
    /// stays, or when the latest bytes differ.
    ///
    /// # Errors
    /// The artifact's version chain does not read.
    pub fn campaign_step_body_latest_ref_if_matches(
        &self,
        program_ref: EntityId,
        step_ref: EntityId,
        call_seq: u64,
        expected: &[u8],
    ) -> Result<Option<String>> {
        let artifact_id = campaign_step_body_artifact_id(program_ref, step_ref, call_seq)?;
        let Some(head) = self.blob_artifact_head(&artifact_id)? else {
            return Ok(None);
        };
        let Some(latest) = self.read_blob_artifact_version(&artifact_id, head.version)? else {
            return Ok(None);
        };
        if latest.as_slice() != expected {
            return Ok(None);
        }
        Ok(Some(step_body_ref(&artifact_id, head.version)))
    }

    /// Files `body` as one outbound step's words, as `actor`: the first
    /// write creates the artifact and appends version 1, a later write
    /// appends a new version only when the bytes differ from the latest,
    /// and unchanged bytes return the latest ref without a write. Answers
    /// the versioned content ref the leg pins.
    ///
    /// # Errors
    /// The body could not be written.
    pub fn save_campaign_step_body(
        &self,
        program_ref: EntityId,
        step_ref: EntityId,
        call_seq: u64,
        body: &[u8],
        actor: WriteActor,
        now: u64,
    ) -> Result<String> {
        let artifact_id = campaign_step_body_artifact_id(program_ref, step_ref, call_seq)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    format!(
                        "{STEP_BODY_RUN_PREFIX}{}:{}",
                        program_ref.to_hex(),
                        step_ref.to_hex()
                    ),
                    STEP_BODY_MEDIA_TYPE,
                ),
                at,
                now,
            )?;
        }
        if let Some(head) = self.blob_artifact_head(&artifact_id)?
            && self
                .read_blob_artifact_version(&artifact_id, head.version)?
                .is_some_and(|latest| latest.as_slice() == body)
        {
            return Ok(step_body_ref(&artifact_id, head.version));
        }
        let version = self.append_blob_artifact_version(
            &artifact_id,
            body,
            &BlobVersionProvenance::AgentRun {
                run_ref: format!(
                    "{STEP_BODY_RUN_PREFIX}{}:{}:{call_seq}",
                    program_ref.to_hex(),
                    step_ref.to_hex()
                ),
            },
            actor,
            at,
            now,
        )?;
        Ok(step_body_ref(&artifact_id, version.version))
    }

    /// The text a campaign step body ref names: that version of a live
    /// campaign-step-body artifact, written by a campaign step run. `None`
    /// for any other ref, or a body the vault no longer holds. Never a
    /// fallback string: an unresolvable body reads as absent, so the send
    /// fails closed instead of carrying a literal placeholder to the wire.
    ///
    /// # Errors
    /// The version does not read, or its bytes are not text.
    pub fn campaign_step_body_text(&self, content_ref: &str) -> Result<Option<String>> {
        let Some((artifact, version)) = content_ref
            .strip_prefix(CAMPAIGN_STEP_BODY_PREFIX)
            .and_then(|rest| rest.split_once('@'))
        else {
            return Ok(None);
        };
        let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(artifact), version.parse()) else {
            return Ok(None);
        };
        match self.get_blob_artifact(&artifact_id)? {
            Some(body) if body.media_type == STEP_BODY_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        let Some(record) = self.blob_artifact_version_metadata(&artifact_id, version)? else {
            return Ok(None);
        };
        if !matches!(
            &record.provenance,
            BlobVersionProvenance::AgentRun { run_ref } if run_ref.starts_with(STEP_BODY_RUN_PREFIX)
        ) {
            return Ok(None);
        }
        let Some(bytes) = self.read_blob_artifact_version(&artifact_id, version)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::InvalidClaimBody("a campaign step body is not text"))
    }
}

fn step_body_ref(artifact_id: &EntityId, version: u64) -> String {
    format!(
        "{CAMPAIGN_STEP_BODY_PREFIX}{}@{version}",
        artifact_id.to_hex()
    )
}
