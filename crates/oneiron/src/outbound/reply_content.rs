//! The body of an agent's reply to a connector event (OF-519). A served
//! responder keeps the words its agent wrote in the vault before it names
//! the reply: one BLOB artifact per (event, agent, reply), written as that
//! agent. The reply's `content_ref` pins the version first written, so a
//! retried send carries the same words and replays instead of sending
//! twice, and the body syncs, restores and erases with the vault.

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::entity_id::derived_domains::CONNECTOR_REPLY_BODY_BLOB;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// Every connector reply body ref starts with this:
/// `connector-reply-body:<artifact hex>@<version>`.
pub const CONNECTOR_REPLY_BODY_PREFIX: &str = "connector-reply-body:";
const REPLY_BODY_MEDIA_TYPE: &str = "text/plain";
/// The run ref a reply body's version is written under.
const REPLY_RUN_PREFIX: &str = "connector-reply:";

/// One kept reply body: the ref its send names, and when it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorReplyBody {
    pub content_ref: String,
    pub written_at: u64,
}

impl Vault {
    /// The body `agent` already wrote for its reply `reply_ref` to the
    /// connector event `event_id`: the version first written, never a later
    /// head. `None` before any is kept.
    ///
    /// # Errors
    /// The artifact's version chain does not read.
    pub fn connector_reply_body(
        &self,
        event_id: &str,
        agent: EntityId,
        reply_ref: &str,
    ) -> Result<Option<ConnectorReplyBody>> {
        let artifact_id = reply_body_artifact(event_id, agent, reply_ref)?;
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            return Ok(None);
        }
        Ok(self
            .blob_artifact_versions(&artifact_id)?
            .first()
            .map(|version| ConnectorReplyBody {
                content_ref: reply_body_ref(&artifact_id, version.version),
                written_at: version.created_at,
            }))
    }

    /// Keeps the words `agent` wrote for its reply `reply_ref` to the
    /// connector event `event_id`, once: a body already kept for that reply
    /// is returned as it is, whatever `text` says.
    ///
    /// # Errors
    /// The body could not be written.
    pub fn save_connector_reply_body(
        &self,
        event_id: &str,
        agent: EntityId,
        reply_ref: &str,
        text: &str,
        now: u64,
    ) -> Result<ConnectorReplyBody> {
        if let Some(kept) = self.connector_reply_body(event_id, agent, reply_ref)? {
            return Ok(kept);
        }
        let artifact_id = reply_body_artifact(event_id, agent, reply_ref)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    format!("{REPLY_RUN_PREFIX}{event_id}"),
                    REPLY_BODY_MEDIA_TYPE,
                ),
                at,
                now,
            )?;
        }
        let version = self.append_blob_artifact_version(
            &artifact_id,
            text.as_bytes(),
            &BlobVersionProvenance::AgentRun {
                run_ref: format!("{REPLY_RUN_PREFIX}{event_id}"),
            },
            WriteActor::new(agent, EdgeActorClass::Agent),
            at,
            now,
        )?;
        Ok(ConnectorReplyBody {
            content_ref: reply_body_ref(&artifact_id, version.version),
            written_at: version.created_at,
        })
    }

    /// The text a connector reply body ref names: that version of a live
    /// reply-body artifact, written by a connector reply run. `None` for any
    /// other ref, or a body the vault no longer holds.
    ///
    /// # Errors
    /// The version does not read, or its bytes are not text.
    pub fn connector_reply_body_text(&self, content_ref: &str) -> Result<Option<String>> {
        let Some((artifact, version)) = content_ref
            .strip_prefix(CONNECTOR_REPLY_BODY_PREFIX)
            .and_then(|rest| rest.split_once('@'))
        else {
            return Ok(None);
        };
        let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(artifact), version.parse()) else {
            return Ok(None);
        };
        match self.get_blob_artifact(&artifact_id)? {
            Some(body) if body.media_type == REPLY_BODY_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        let Some(record) = self.blob_artifact_version_metadata(&artifact_id, version)? else {
            return Ok(None);
        };
        if !matches!(
            &record.provenance,
            BlobVersionProvenance::AgentRun { run_ref } if run_ref.starts_with(REPLY_RUN_PREFIX)
        ) {
            return Ok(None);
        }
        let Some(bytes) = self.read_blob_artifact_version(&artifact_id, version)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::InvalidClaimBody("a connector reply body is not text"))
    }
}

fn reply_body_artifact(event_id: &str, agent: EntityId, reply_ref: &str) -> Result<EntityId> {
    EntityId::derive(
        CONNECTOR_REPLY_BODY_BLOB,
        &[
            event_id.as_bytes(),
            agent.as_bytes().as_slice(),
            reply_ref.as_bytes(),
        ],
    )
}

fn reply_body_ref(artifact_id: &EntityId, version: u64) -> String {
    format!(
        "{CONNECTOR_REPLY_BODY_PREFIX}{}@{version}",
        artifact_id.to_hex()
    )
}
