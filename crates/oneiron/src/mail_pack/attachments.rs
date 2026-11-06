//! Attachments on open (FIX 12559; MAIL-GOOGLE = A): a message's
//! attachments land described, never fetched; a reader of its thread opens
//! one (`vault.mail.attachments.open`), and the source's next import step
//! fetches its bytes once into an artifact bound to the thread's audience in
//! its birth commit, so the bytes read only to the thread's readers.

use serde::{Deserialize, Serialize};

use super::pack::require_pack_active_in;
use super::source::SOURCES;
use super::state::{MailPresence, OCCURRENCES, occurrence_key};
use super::wire::{MailAttachmentRef, MailProviderWire, MailSyncSource};
use crate::entity_id::derived_domains::MAIL_ATTACHMENT;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault, source_audience};

/// The attachments readers opened, by source and the BLAKE3 of the
/// provider's message id and the part id.
const ATTACHMENTS: SideTable<(EntityId, [u8; 32]), MailAttachmentRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_ATTACHMENT);

/// The opened-attachment artifacts owed their own delete, by the artifact;
/// the value is when they were owed.
const ERASE_OWED: SideTable<EntityId, u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_ATTACHMENT_ERASE);
/// The most owed artifacts one collection deletes.
const ERASES_PER_COLLECTION: usize = 64;

/// The largest attachment fetched.
const MAX_ATTACHMENT_BYTES: usize = 32 * 1024 * 1024;

/// One opened attachment's fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailAttachmentRow {
    provider_id: String,
    attachment: MailAttachmentRef,
    /// The thread's audience policy the stored artifact is bound to.
    thread: EntityId,
    state: MailAttachmentState,
    artifact: Option<EntityId>,
    version: Option<u64>,
    reason: Option<String>,
    opened_at: u64,
    updated_at: u64,
}

/// Where an opened attachment stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailAttachmentState {
    /// The source's next import step fetches it.
    Waiting,
    /// Its bytes are in its artifact.
    Stored,
    /// The provider no longer had it, or it could not be read.
    Failed,
}

/// `vault.mail.attachments.open`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailAttachmentOpenRequest {
    /// The message's source, 32-hex.
    pub source_ref: String,
    /// The message's TURN, 32-hex (an inbox item's `turn_ref`).
    pub turn_ref: String,
    /// The attachment's MIME part id.
    pub part_id: String,
}

/// An opened attachment, as its reader sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailAttachmentView {
    pub state: MailAttachmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub media_type: String,
    pub size_bytes: u64,
    /// The artifact its bytes are in, 32-hex, once stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn attachment_key(source: EntityId, provider_id: &str, part_id: &str) -> (EntityId, [u8; 32]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(provider_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(part_id.as_bytes());
    (source, *hasher.finalize().as_bytes())
}

fn view(row: &MailAttachmentRow) -> MailAttachmentView {
    MailAttachmentView {
        state: row.state,
        filename: row.attachment.filename.clone(),
        media_type: row.attachment.media_type.clone(),
        size_bytes: row.attachment.size_bytes,
        artifact_ref: row.artifact.map(|artifact| artifact.to_hex()),
        version: row.version,
        reason: row.reason.clone(),
    }
}

impl Memory<'_> {
    /// Opens one attachment of a message to a reader of its thread: its
    /// fetch is queued for the source's next import step, or its stored
    /// artifact answered. A message whose body has not landed has no
    /// attachments described yet.
    pub fn mail_attachments_open(
        &self,
        input: &MailAttachmentOpenRequest,
    ) -> MemoryResult<MailAttachmentView> {
        let source = EntityId::from_hex(&input.source_ref)?;
        let turn = EntityId::from_hex(&input.turn_ref)?;
        let vault = self.vault();
        let actor = self.actor();
        let unknown = || MemoryError::not_found("no attachment by that ref");
        let (provider_id, attachment, thread) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            require_pack_active_in(vault, &txn)?;
            if !SOURCES
                .get(&vault.store, &txn, &source)?
                .is_some_and(|row| row.kind.is_mailbox())
            {
                return Err(unknown());
            }
            let mut found = None;
            for occurrence in OCCURRENCES.iter_from(&vault.store, &txn, source.as_bytes())? {
                let (_, occurrence) = occurrence?;
                if occurrence.turn == turn {
                    found = Some(occurrence);
                    break;
                }
            }
            let occurrence = found.ok_or_else(unknown)?;
            let thread = source_audience::binding_in(vault, &txn, &occurrence.conversation)?
                .ok_or_else(unknown)?;
            if !source_audience::actor_reads_in(vault, &txn, &thread, actor)? {
                return Err(unknown());
            }
            let attachment = occurrence
                .attachments
                .iter()
                .find(|attachment| attachment.part_id == input.part_id)
                .cloned()
                .ok_or_else(|| {
                    MemoryError::bad_request_with(
                        "the message has no such attachment, or its body has not landed yet",
                        &["List the thread again once its message has landed whole."],
                    )
                })?;
            (occurrence.provider_id, attachment, thread)
        };
        let key = attachment_key(source, &provider_id, &attachment.part_id);
        let at = crate::unix_seconds_now();
        let row = vault
            .with_write_txn_grouped(|txn| {
                if let Some(row) = ATTACHMENTS.get(&vault.store, txn, &key)? {
                    return Ok(Some(row));
                }
                // A message erased since the read above queues nothing.
                if !attachment_described_in(
                    &vault.store,
                    txn,
                    source,
                    &provider_id,
                    &attachment.part_id,
                )? {
                    return Ok(None);
                }
                let row = MailAttachmentRow {
                    provider_id: provider_id.clone(),
                    attachment: attachment.clone(),
                    thread,
                    state: MailAttachmentState::Waiting,
                    artifact: None,
                    version: None,
                    reason: None,
                    opened_at: at,
                    updated_at: at,
                };
                ATTACHMENTS.put(&vault.store, txn, &key, &row)?;
                Ok(Some(row))
            })?
            .ok_or_else(unknown)?;
        Ok(view(&row))
    }
}

/// Whether `source`'s message `provider_id` still stands, not forgotten,
/// and still describes the attachment `part_id`. An erase scrubs the
/// message's occurrence, so nothing of its attachments is queued or stored
/// after it, whatever a reader or a fetch read before (REVIEW-6005).
fn attachment_described_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    provider_id: &str,
    part_id: &str,
) -> Result<bool> {
    Ok(OCCURRENCES
        .get(store, txn, &occurrence_key(source, provider_id))?
        .is_some_and(|occurrence| {
            !matches!(occurrence.presence, MailPresence::Forgotten { .. })
                && occurrence
                    .attachments
                    .iter()
                    .any(|attachment| attachment.part_id == part_id)
        }))
}

/// The artifacts the opened attachments of one message were stored in.
pub(super) fn message_artifacts(
    vault: &Vault,
    source: EntityId,
    provider_id: &str,
) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut artifacts = Vec::new();
    for row in ATTACHMENTS.iter_from(&vault.store, &txn, source.as_bytes())? {
        let (_, row) = row?;
        if row.provider_id == provider_id
            && let Some(artifact) = row.artifact
        {
            artifacts.push(artifact);
        }
    }
    Ok(artifacts)
}

/// Removes the opened-attachment rows of one forgotten or erased message,
/// with the file names they kept. Each stored artifact they name is owed its
/// own delete, which runs once this writer commits
/// ([`collect_after_delete`]): an eraser cannot delete another row in its
/// writer, and the bytes go with their message.
pub(super) fn forget_message_attachments_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    provider_id: &str,
) -> Result<()> {
    let mut keys = Vec::new();
    let mut artifacts = Vec::new();
    for row in ATTACHMENTS.iter_from(store, txn, source.as_bytes())? {
        let (key, row) = row?;
        if row.provider_id == provider_id {
            keys.push(key);
            artifacts.extend(row.artifact);
        }
    }
    for key in keys {
        ATTACHMENTS.delete(store, txn, &key)?;
    }
    let at = crate::unix_seconds_now();
    for artifact in artifacts {
        ERASE_OWED.put(store, txn, &artifact, &at)?;
    }
    Ok(())
}

/// Deletes the opened-attachment artifacts whose message was erased, a
/// bounded batch at a time: after every delete commits, and at each import
/// step. An artifact stays owed until its delete has committed, so one
/// that fails, or a crash between, is tried again; a failure is logged. A
/// collection the deletes it runs reach again returns at once.
pub(crate) fn collect_after_delete(vault: &Vault) {
    let Some(_running) = Collecting::enter() else {
        return;
    };
    if let Err(error) = collect_owed_erases(vault) {
        tracing::warn!(
            reason = "mail_attachment_erase_owed",
            %error,
            "an erased message's attachment artifact is owed its delete; the next delete or import step retries"
        );
    }
}

thread_local! {
    /// Whether this thread is collecting owed attachment erases now.
    static COLLECTING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// This thread's one collection while it runs.
struct Collecting;

impl Collecting {
    fn enter() -> Option<Self> {
        if COLLECTING.with(|running| running.replace(true)) {
            return None;
        }
        Some(Self)
    }
}

impl Drop for Collecting {
    fn drop(&mut self) {
        COLLECTING.with(|running| running.set(false));
    }
}

fn collect_owed_erases(vault: &Vault) -> Result<()> {
    let owed: Vec<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        let mut owed = Vec::new();
        for row in ERASE_OWED.iter_from(&vault.store, &txn, &[])? {
            if owed.len() >= ERASES_PER_COLLECTION {
                break;
            }
            owed.push(row?.0);
        }
        owed
    };
    for artifact in owed {
        if vault.get_blob_artifact(&artifact)?.is_some() {
            vault
                .delete_entity_with_reason(&artifact, crate::deletion::DeleteReason::UserDelete)?;
        }
        vault.with_write_txn_grouped(|txn| {
            ERASE_OWED.delete(&vault.store, txn, &artifact).map(drop)
        })?;
    }
    Ok(())
}

/// Fetches up to `limit` of `source`'s waiting attachments through `wire`,
/// each into its artifact bound to its thread's audience at birth, written
/// as `actor`. Answers how many were stored.
///
/// A message erased while its attachment is fetched keeps nothing of it
/// (REVIEW-5972): before any byte lands, one writer finds the queue row
/// still waiting and links its artifact to it, so the erase that removes
/// the row from then on owes that artifact's delete; and the outcome only
/// completes a queue row that is still there, never one the erase removed.
pub(super) fn fetch_waiting_attachments(
    vault: &Vault,
    source: EntityId,
    wire_source: &MailSyncSource,
    wire: &dyn MailProviderWire,
    actor: EntityId,
    limit: u32,
) -> Result<u64> {
    let waiting = {
        let txn = vault.store.env.read_txn()?;
        let mut waiting = Vec::new();
        for row in ATTACHMENTS.iter_from(&vault.store, &txn, source.as_bytes())? {
            let (key, row) = row?;
            if row.state == MailAttachmentState::Waiting {
                waiting.push((key, row));
                if waiting.len() >= limit as usize {
                    break;
                }
            }
        }
        waiting
    };
    let mut stored = 0;
    for (key, row) in waiting {
        let at = crate::unix_seconds_now();
        let outcome = match wire.attachment(wire_source, &row.provider_id, &row.attachment) {
            Ok(Some(bytes)) if bytes.len() <= MAX_ATTACHMENT_BYTES => {
                let Some(artifact) = link_attachment_artifact(vault, source, &key, &row, at)?
                else {
                    continue;
                };
                let version = append_attachment_version(vault, &artifact, &bytes, actor, at)?;
                AttachmentOutcome::Stored { artifact, version }
            }
            Ok(Some(_)) => AttachmentOutcome::Failed(
                "the attachment is larger than this host fetches".to_owned(),
            ),
            Ok(None) => AttachmentOutcome::Failed("the provider no longer has it".to_owned()),
            Err(error) => AttachmentOutcome::Failed(error.to_string()),
        };
        let landed = matches!(outcome, AttachmentOutcome::Stored { .. });
        if settle_attachment_row(vault, &key, outcome, at)? && landed {
            stored += 1;
        }
    }
    Ok(stored)
}

/// How one fetch ended.
enum AttachmentOutcome {
    Stored { artifact: EntityId, version: u64 },
    Failed(String),
}

/// Links `row`'s artifact (born bound to the thread's audience when it is
/// not here yet) to its queue row at `key`, in one writer that finds the
/// row still there and waiting for the same attachment. `None` when the
/// row is gone or changed: the fetched bytes are dropped.
fn link_attachment_artifact(
    vault: &Vault,
    source: EntityId,
    key: &(EntityId, [u8; 32]),
    row: &MailAttachmentRow,
    at: u64,
) -> Result<Option<EntityId>> {
    let artifact = EntityId::derive(
        MAIL_ATTACHMENT,
        &[
            source.as_bytes(),
            row.provider_id.as_bytes(),
            row.attachment.part_id.as_bytes(),
        ],
    )?;
    let occurred = crate::TimeRange { start: at, end: at };
    let name = row
        .attachment
        .filename
        .clone()
        .unwrap_or_else(|| "attachment".to_owned());
    let data = crate::blob_artifact::encode_blob_artifact_body(
        &crate::blob_artifact::BlobArtifactBody::new(name, row.attachment.media_type.as_str()),
    )?;
    vault.with_write_txn_grouped(|txn| {
        let Some(mut live) = ATTACHMENTS.get(&vault.store, txn, key)? else {
            return Ok(None);
        };
        if live.state != MailAttachmentState::Waiting
            || live.provider_id != row.provider_id
            || live.attachment.part_id != row.attachment.part_id
            || !attachment_described_in(
                &vault.store,
                txn,
                source,
                &row.provider_id,
                &row.attachment.part_id,
            )?
        {
            return Ok(None);
        }
        if crate::vault::live_entity_row_in_txn(&vault.store, txn, &artifact)?
            == crate::vault::LiveEntityRow::Absent
        {
            vault
                .batch_in()
                .put(&artifact, ENTITY_TYPE_BLOB_ARTIFACT, occurred, at, &data)
                .apply(txn)?;
            source_audience::bind_record_in_txn(vault, txn, &artifact, &live.thread)?;
        }
        live.artifact = Some(artifact);
        live.updated_at = at;
        ATTACHMENTS.put(&vault.store, txn, key, &live)?;
        Ok(Some(artifact))
    })
}

/// One attachment's bytes as a new version of its linked `artifact`.
fn append_attachment_version(
    vault: &Vault,
    artifact: &EntityId,
    bytes: &[u8],
    actor: EntityId,
    at: u64,
) -> Result<u64> {
    let version = vault.append_blob_artifact_version(
        artifact,
        bytes,
        &crate::blob_artifact::BlobVersionProvenance::AgentRun {
            run_ref: format!("mail-attachment:{}", artifact.to_hex()),
        },
        crate::WriteActor::new(actor, crate::edge::EdgeActorClass::Human),
        crate::TimeRange { start: at, end: at },
        at,
    )?;
    Ok(version.version)
}

/// Records `outcome` on the queue row at `key` when it is still there.
/// Whether it was: a row an erase removed is never written again, and the
/// erase already owes the delete of the artifact linked to it.
fn settle_attachment_row(
    vault: &Vault,
    key: &(EntityId, [u8; 32]),
    outcome: AttachmentOutcome,
    at: u64,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut live) = ATTACHMENTS.get(&vault.store, txn, key)? else {
            return Ok(false);
        };
        match outcome {
            AttachmentOutcome::Stored { artifact, version } => {
                live.state = MailAttachmentState::Stored;
                live.artifact = Some(artifact);
                live.version = Some(version);
                live.reason = None;
            }
            AttachmentOutcome::Failed(reason) => {
                live.state = MailAttachmentState::Failed;
                live.reason = Some(reason);
            }
        }
        live.updated_at = at;
        ATTACHMENTS.put(&vault.store, txn, key, &live)?;
        Ok(true)
    })
}
