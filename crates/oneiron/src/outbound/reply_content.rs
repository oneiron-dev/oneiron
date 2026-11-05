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
pub(super) const REPLY_BODY_MEDIA_TYPE: &str = "text/plain";
/// The run ref a reply body's version is written under.
pub(super) const REPLY_RUN_PREFIX: &str = "connector-reply:";

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
        let rtxn = self.store.env.read_txn()?;
        self.connector_reply_body_in_txn(&rtxn, event_id, agent, reply_ref)
    }

    pub(crate) fn connector_reply_body_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        event_id: &str,
        agent: EntityId,
        reply_ref: &str,
    ) -> Result<Option<ConnectorReplyBody>> {
        let artifact_id = reply_body_artifact(event_id, agent, reply_ref)?;
        if self.get_blob_artifact_in_txn(rtxn, &artifact_id)?.is_none() {
            return Ok(None);
        }
        Ok(self
            .blob_artifact_versions_in_txn(rtxn, &artifact_id)?
            .first()
            .map(|version| ConnectorReplyBody {
                content_ref: reply_body_ref(&artifact_id, version.version),
                written_at: version.created_at,
            }))
    }

    /// Keeps the words `agent` wrote for its reply `reply_ref` to `event`,
    /// once: a body already kept for that reply is returned as it is,
    /// whatever `text` says. The hard-erasure checks, first-version read,
    /// artifact creation and append share one writer transaction.
    ///
    /// `None` when the agent or an event participant has been hard-erased;
    /// nothing is written. Saving and enqueueing remain separate operations.
    ///
    /// # Errors
    /// The body could not be written.
    pub fn save_connector_reply_body(
        &self,
        event: &crate::connector_key::events::ConnectorEvent,
        agent: EntityId,
        reply_ref: &str,
        text: &str,
        now: u64,
    ) -> Result<Option<ConnectorReplyBody>> {
        let artifact_id = reply_body_artifact(&event.event_id, agent, reply_ref)?;
        let participants = super::reply_job::connector_event_participant_ids(event);
        self.with_write_txn_grouped(|wtxn| {
            for id in std::iter::once(agent).chain(participants.iter().copied()) {
                if self.local_hard_delete_marker_exists_in_txn(wtxn, &id)? {
                    return Ok(None);
                }
            }
            let existing = self.get_blob_artifact_in_txn(wtxn, &artifact_id)?;
            if existing.is_some()
                && let Some(first) = self
                    .blob_artifact_versions_in_txn(wtxn, &artifact_id)?
                    .first()
            {
                return Ok(Some(ConnectorReplyBody {
                    content_ref: reply_body_ref(&artifact_id, first.version),
                    written_at: first.created_at,
                }));
            }
            let at = TimeRange {
                start: now,
                end: now,
            };
            if existing.is_none() {
                crate::ports::EntityStore::port_entity_put(
                    self,
                    wtxn,
                    &artifact_id,
                    &crate::ports::EntityRecord {
                        entity_type: crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred: at,
                        learned_at: now,
                        body: crate::blob_artifact::encode_blob_artifact_body(
                            &BlobArtifactBody::new(
                                format!("{REPLY_RUN_PREFIX}{}", event.event_id),
                                REPLY_BODY_MEDIA_TYPE,
                            ),
                        )?,
                    },
                )?;
            }
            let version = self.append_blob_artifact_version_in_txn(
                wtxn,
                &artifact_id,
                text.as_bytes(),
                &BlobVersionProvenance::AgentRun {
                    run_ref: format!("{REPLY_RUN_PREFIX}{}", event.event_id),
                },
                WriteActor::new(agent, EdgeActorClass::Agent),
                at,
                now,
            )?;
            Ok(Some(ConnectorReplyBody {
                content_ref: reply_body_ref(&artifact_id, version.version),
                written_at: version.created_at,
            }))
        })
    }

    /// The text a connector reply body ref names: that version of a live
    /// reply-body artifact, written by a connector reply run. `None` for any
    /// other ref, or a body the vault no longer holds.
    ///
    /// # Errors
    /// The version does not read, or its bytes are not text.
    pub fn connector_reply_body_text(&self, content_ref: &str) -> Result<Option<String>> {
        let rtxn = self.store.env.read_txn()?;
        self.connector_reply_body_text_in_txn(&rtxn, content_ref)
    }

    pub(crate) fn connector_reply_body_text_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_ref: &str,
    ) -> Result<Option<String>> {
        let Some((artifact, version)) = content_ref
            .strip_prefix(CONNECTOR_REPLY_BODY_PREFIX)
            .and_then(|rest| rest.split_once('@'))
        else {
            return Ok(None);
        };
        let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(artifact), version.parse()) else {
            return Ok(None);
        };
        match self.get_blob_artifact_in_txn(rtxn, &artifact_id)? {
            Some(body) if body.media_type == REPLY_BODY_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        let Some(record) =
            self.blob_artifact_version_metadata_in_txn(rtxn, &artifact_id, version)?
        else {
            return Ok(None);
        };
        if !matches!(
            &record.provenance,
            BlobVersionProvenance::AgentRun { run_ref } if run_ref.starts_with(REPLY_RUN_PREFIX)
        ) {
            return Ok(None);
        }
        let Some(bytes) = self.read_blob_artifact_version_in_txn(rtxn, &artifact_id, version)?
        else {
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
