//! The files a drafted Gmail reply carries (fix list row 17645): each one
//! exact version of an artifact, never its head, an ASSET id, a path, a URL,
//! a provider part or inline bytes.
//!
//! - **Admission.** The drafter's own read lane reads the artifact and that
//!   version's rows, and any source the version quotes, in one snapshot with
//!   every recipient's disclosure judgement
//!   (`disclosure::mail_attachment_denial_in`): each To and Cc recipient must
//!   be cleared for each file and each source it quotes, and one who is not
//!   refuses the whole draft. Then the drafter's sighted copy of each version
//!   is exported once, no `why` with it, so nothing is revealed.
//! - **Freeze.** The plan seals each file's description and the exact
//!   message's length and BLAKE3; the message is written once, here, and
//!   kept sealed beside the draft (`reply_custody`). The kept plan names the
//!   files only by their manifest's digest: the draft keeps them.
//! - **Standing.** At the press, at egress and in the credential door's
//!   writer the frozen send is judged again in the snapshot it is read in:
//!   the mailbox still sends, the thread, the answered TURN and its MESSAGE
//!   rows are still live, each file is still its pinned version quoting its
//!   source as it did, each recipient is still cleared, the message is still
//!   held and within Gmail's raw limit. Policy and liveness only: nothing is
//!   exported, masked or written again.
//! - **Completion.** A press whose send the ledger already completed
//!   replays that outcome and settles the draft; it judges none of this
//!   again.

use heed::RoTxn;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::reply::{DRAFTS, MailReplyDraftRow, MailReplyDraftState};
use super::reply_custody::{holds_reply_message_in, open_reply_message_in, reply_carrier_ref};
use super::source::{MailProvider, MailSourceKind, MailSourceStatus, SOURCES};
use super::state::{MailOccurrence, MailPresence, OCCURRENCES};
use crate::Vault;
use crate::channel_identity_provider::gmail::GmailSendPlan;
use crate::channel_identity_provider::mail_attachments::{
    ATTACHMENT_DISPOSITION, MailAttachment, MailManifest, MailMessageIdentity, RetainedMailMessage,
};
use crate::claim::ScopedRead;
use crate::disclosure::{MailAttachmentRows, mail_attachment_denial_in};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::outbound::{OutboundDispatchRequest, OutboundRecipient};
use crate::outbound_intent_ledger::{IntentLedgerError, IntentState};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Gmail's limit on one raw message (`users.messages.send`): 35 MiB, that is
/// 36,700,160 octets of the exact RFC 5322 message Gmail receives before its
/// own base64url encoding, every header, boundary and base64 line counted,
/// not the files' own sizes. A reply above it is refused before its Ask,
/// again at the press and again at egress.
pub(super) const MAX_GMAIL_RAW_MESSAGE_OCTETS: u64 = 35 * 1024 * 1024;

/// One file a drafted reply carries: one exact version of an artifact the
/// caller reads (fix list row 17645).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyAttachment {
    /// The artifact, 32-hex.
    pub artifact_ref: String,
    /// The exact version that sends, 1 or more; never the head.
    pub version: u64,
}

/// One file a drafted reply carries, as its reviewer sees it: exactly the
/// copy that sends (fix list row 17645).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyAttachmentView {
    /// The artifact, 32-hex.
    pub artifact_ref: String,
    /// Its exact version.
    pub version: u64,
    /// The file's name, as it sends.
    pub name: String,
    /// Its media type, as it sends.
    pub media_type: String,
    /// `attachment`: a file never shows inline.
    pub disposition: String,
    /// The exact copy's size, in bytes.
    pub size: u64,
    /// BLAKE3 of the exact copy that sends, 64 lower-hex.
    pub content_blake3: String,
    /// BLAKE3 of the stored version, 64 lower-hex. It differs from
    /// `content_blake3` when the copy that sends is masked, or names its
    /// default author.
    pub stored_version_blake3: String,
}

/// What one revision of a drafted reply with files froze: its files, the
/// exact message they send in, the message it answers, and every row the
/// revision depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReplyAttached {
    /// The files, in their order.
    pub(super) attachments: Vec<MailAttachment>,
    /// The exact message, kept sealed beside the draft (`reply_custody`).
    pub(super) message: MailMessageIdentity,
    /// The files' artifacts and their versions' CLAIM and ASSET rows, the
    /// thread, the answered TURN and its MESSAGE rows, and the mailbox
    /// source, each once: the erase or retirement of any of them ends the
    /// draft (`reply_erase`).
    pub(super) dependencies: Vec<EntityId>,
    /// The message the revision answers, as the thread held it when the
    /// revision was drafted; `None` answers nothing, and sends nothing.
    #[serde(default)]
    pub(super) answered: Option<AnsweredMessage>,
}

/// The message a drafted reply answers, exactly as its thread held it when
/// the revision was drafted (fix list row 17645): its occurrence under the
/// mailbox source and the MESSAGE rows it landed as. The revision lands and
/// sends only while that occurrence still stands on the thread for the
/// answered TURN with each of those rows, every one of them live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AnsweredMessage {
    /// BLAKE3 of the provider's id of the message: its occurrence's key
    /// under the source.
    pub(super) occurrence: [u8; 32],
    /// Its MESSAGE rows, as the occurrence listed them.
    pub(super) messages: Vec<EntityId>,
}

impl AnsweredMessage {
    /// The message `occurrence` of the mailbox source `source` is, as its
    /// thread holds it now.
    pub(super) fn of(source: EntityId, occurrence: &MailOccurrence) -> Self {
        let (_, key) = super::state::occurrence_key(source, &occurrence.provider_id);
        Self {
            occurrence: key,
            messages: occurrence.messages.clone(),
        }
    }
}

impl ReplyAttached {
    /// The manifest the kept plan names by its digest: the files and the
    /// exact message, as this row keeps them.
    pub(super) fn manifest(&self) -> MailManifest {
        MailManifest {
            attachments: self.attachments.clone(),
            message: self.message,
        }
    }

    /// The files as their reviewer sees them, in their order.
    pub(super) fn views(&self) -> Vec<MailReplyAttachmentView> {
        self.attachments
            .iter()
            .map(|file| MailReplyAttachmentView {
                artifact_ref: file.artifact.to_hex(),
                version: file.version,
                name: file.filename.clone(),
                media_type: file.media_type.clone(),
                disposition: ATTACHMENT_DISPOSITION.to_owned(),
                size: file.octets,
                content_blake3: crate::blob_artifact::hash_hex(&file.copy_blake3),
                stored_version_blake3: crate::blob_artifact::hash_hex(&file.stored_blake3),
            })
            .collect()
    }
}

/// The files one draft admitted: each one's description, its exact copy,
/// and the rows it is.
pub(super) struct AdmittedFiles {
    pub(super) attachments: Vec<MailAttachment>,
    copies: Vec<Vec<u8>>,
    rows: Vec<MailAttachmentRows>,
}

impl AdmittedFiles {
    /// Every row the files are (each artifact and its version's CLAIM and
    /// ASSET), then each of `also`, each once, in order: the revision's
    /// dependencies.
    pub(super) fn dependencies(&self, also: impl IntoIterator<Item = EntityId>) -> Vec<EntityId> {
        let mut dependencies = Vec::new();
        for id in self.rows.iter().flat_map(|rows| rows.file).chain(also) {
            if !dependencies.contains(&id) {
                dependencies.push(id);
            }
        }
        dependencies
    }
}

/// One version as a read judged it: its CLAIM, its stored BLAKE3, and the
/// rows it is, with every source it quotes.
struct Pinned {
    claim: EntityId,
    stored: [u8; 32],
    rows: MailAttachmentRows,
}

/// The sources the version `record` quotes, read in `txn`, as its own
/// binding names them (a reminder wording's source claim, FIX 4997): none
/// for a version that quotes nothing; `None` when its binding is malformed
/// or a source no longer holds the revision the version quotes, a live
/// CLAIM whose body hashes to it.
fn quoted_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &crate::blob_artifact::BlobArtifactVersion,
) -> Result<Option<Vec<EntityId>>> {
    let binding = match crate::commitment_wake::wording_source_binding(record) {
        Ok(None) => return Ok(Some(Vec::new())),
        Ok(Some(binding)) => binding,
        Err(_) => return Ok(None),
    };
    let holds = matches!(
        live_entity_row_in_txn(&vault.store, txn, &binding.source)?,
        LiveEntityRow::Live { entity_type, body }
            if entity_type == ENTITY_TYPE_CLAIM
                && *blake3::hash(&body).as_bytes() == binding.revision
    );
    Ok(holds.then(|| vec![binding.source]))
}

/// `artifact`'s `version` as `txn` reads it, with every source it quotes;
/// `None` when the artifact is no live BLOB_ARTIFACT, has no such version,
/// quotes a source that no longer holds what it quoted, or `lane` (a
/// reader's, when given) does not read each of its rows and sources.
fn pinned_in(
    vault: &Vault,
    lane: Option<&ScopedRead<'_>>,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
) -> Result<Option<Pinned>> {
    if !vault
        .entity_header_in_txn(txn, artifact)?
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_BLOB_ARTIFACT)
    {
        return Ok(None);
    }
    let Some(record) = vault.blob_artifact_version_metadata_in_txn(txn, artifact, version)? else {
        return Ok(None);
    };
    let Some(version_rows) = vault.blob_artifact_version_rows_in_txn(txn, artifact, version)?
    else {
        return Ok(None);
    };
    let [claim, asset] = version_rows.as_slice() else {
        return Err(Error::CorruptedIndex("blob artifact version rows"));
    };
    let Some(quoted) = quoted_sources_in(vault, txn, &record)? else {
        return Ok(None);
    };
    let rows = MailAttachmentRows {
        file: [*artifact, *claim, *asset],
        quoted,
    };
    if let Some(lane) = lane
        && lane
            .entities_readable_in_txn(txn, &rows.ids().copied().collect::<Vec<_>>())?
            .contains(&false)
    {
        return Ok(None);
    }
    Ok(Some(Pinned {
        claim: record.claim_id,
        stored: record.content_hash,
        rows,
    }))
}

/// Why a recipient of `recipients` may not be shown a file of `rows`, read
/// in `txn`, naming only that recipient's address and the file's slot.
fn disclosure_refusal_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    recipients: &[String],
    rows: &[MailAttachmentRows],
) -> Result<Option<String>> {
    Ok(
        mail_attachment_denial_in(vault, txn, recipients, rows)?.map(|denial| {
            format!(
                "attachment {} may not be shown to {}; the reply is refused whole",
                denial.attachment + 1,
                recipients
                    .get(denial.recipient)
                    .map_or("a recipient", String::as_str)
            )
        }),
    )
}

/// Why `files`, frozen for a reply to `recipients`, no longer send as they
/// were frozen, read in `txn`; `None` while they do: each still its pinned
/// version, stored as it was, each source it quotes still holding what it
/// quoted, read by `lane` (the drafter's, when given), and every recipient
/// cleared for each file and each source it quotes.
fn files_refusal_in(
    vault: &Vault,
    lane: Option<&ScopedRead<'_>>,
    txn: &RoTxn<'_>,
    files: &[MailAttachment],
    recipients: &[String],
) -> Result<Option<String>> {
    let mut rows = Vec::with_capacity(files.len());
    for (slot, file) in files.iter().enumerate() {
        match pinned_in(vault, lane, txn, &file.artifact, file.version)? {
            Some(pinned)
                if pinned.claim == file.version_claim && pinned.stored == file.stored_blake3 =>
            {
                rows.push(pinned.rows);
            }
            _ => {
                return Ok(Some(format!(
                    "attachment {} is no longer the version the reply was drafted with, \
                     or no longer quotes its source as it did",
                    slot + 1
                )));
            }
        }
    }
    disclosure_refusal_in(vault, txn, recipients, &rows)
}

/// The addresses a frozen reply goes to: every To and Cc of a reply to
/// several, in its place, else its one recipient.
pub(super) fn frozen_addresses(to: &str, recipients: &[OutboundRecipient]) -> Vec<String> {
    if recipients.is_empty() {
        vec![to.to_owned()]
    } else {
        recipients
            .iter()
            .map(|named| named.address.clone())
            .collect()
    }
}

fn too_large(octets: u64) -> String {
    format!(
        "the reply with its files is {octets} octets; Gmail sends at most \
         {MAX_GMAIL_RAW_MESSAGE_OCTETS}"
    )
}

/// The refusal a standing check's [`Error::InvalidConfig`] is, as the
/// caller's error; any other error as it stands.
fn refusal_error(error: Error) -> MemoryError {
    match error {
        Error::InvalidConfig(reason) => MemoryError::bad_request(reason),
        other => other.into(),
    }
}

impl Memory<'_> {
    /// Admits the files `requested` names for a reply to `recipients`, its
    /// canonical To and Cc in their places (fix list row 17645): each an
    /// exact version of a live artifact the caller's own read lane `lane`
    /// reads, its rows with it, and every recipient cleared for it, judged in
    /// one snapshot before any byte is read; then the caller's sighted copy
    /// of each version, exported once with no `why`. A refusal names only
    /// the file's slot and the recipient's address.
    pub(super) fn reply_attachments_admitted(
        &self,
        lane: &ScopedRead<'_>,
        requested: &[MailReplyAttachment],
        recipients: &[String],
    ) -> MemoryResult<AdmittedFiles> {
        let vault = self.vault();
        let absent = |slot: usize| {
            MemoryError::not_found(format!(
                "attachment {}: no artifact version by that ref",
                slot + 1
            ))
        };
        let mut pins = Vec::with_capacity(requested.len());
        for (slot, file) in requested.iter().enumerate() {
            let artifact = EntityId::from_hex(&file.artifact_ref)?;
            if file.version == 0 {
                return Err(MemoryError::bad_request(format!(
                    "attachment {} names no version; name the exact version, 1 or more",
                    slot + 1
                )));
            }
            pins.push((artifact, file.version));
        }
        let pinned = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let mut pinned = Vec::with_capacity(pins.len());
            for (slot, (artifact, version)) in pins.iter().enumerate() {
                pinned.push(
                    pinned_in(vault, Some(lane), &txn, artifact, *version)?
                        .ok_or_else(|| absent(slot))?,
                );
            }
            let rows = pinned
                .iter()
                .map(|pinned| pinned.rows.clone())
                .collect::<Vec<_>>();
            if let Some(refusal) = disclosure_refusal_in(vault, &txn, recipients, &rows)? {
                return Err(MemoryError::bad_request(refusal));
            }
            pinned
        };
        let mut attachments = Vec::with_capacity(pinned.len());
        let mut copies = Vec::with_capacity(pinned.len());
        let mut octets = 0_u64;
        for (slot, ((artifact, version), pinned)) in pins.iter().zip(&pinned).enumerate() {
            let copy = self
                .export_blob_artifact_pinned_copy(artifact, *version)?
                .ok_or_else(|| absent(slot))?;
            if copy.stored_blake3 != pinned.stored {
                return Err(MemoryError::bad_request(format!(
                    "attachment {} changed while it was read; draft the reply again",
                    slot + 1
                )));
            }
            let file = MailAttachment {
                artifact: *artifact,
                version: *version,
                version_claim: pinned.claim,
                stored_blake3: copy.stored_blake3,
                filename: copy.export.name,
                media_type: copy.export.media_type,
                octets: copy.export.bytes.len() as u64,
                copy_blake3: copy.copy_blake3,
            };
            file.validate().map_err(|error| {
                MemoryError::bad_request(format!("attachment {}: {error}", slot + 1))
            })?;
            octets = octets.saturating_add(file.octets);
            if octets > MAX_GMAIL_RAW_MESSAGE_OCTETS {
                return Err(MemoryError::bad_request(too_large(octets)));
            }
            attachments.push(file);
            copies.push(copy.export.bytes);
        }
        Ok(AdmittedFiles {
            attachments,
            copies,
            rows: pinned.into_iter().map(|pinned| pinned.rows).collect(),
        })
    }
}

/// The admission of a drafted reply's files, judged again in `txn`, the
/// writer that lands the draft (fix list row 17645): each still its pinned
/// version, stored as it was exported, read by `lane`, the drafter's, and
/// every recipient of `recipients` still cleared for each.
///
/// # Errors
///
/// The refusal, and storage failures.
pub(super) fn readmit_reply_attachments_in(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    attached: &ReplyAttached,
    recipients: &[String],
) -> MemoryResult<()> {
    match files_refusal_in(vault, Some(lane), txn, &attached.attachments, recipients)? {
        Some(refusal) => Err(MemoryError::bad_request(refusal)),
        None => Ok(()),
    }
}

/// One revision of a drafted Gmail reply, frozen with its files: its plan,
/// the exact message it sends, and what its row keeps.
pub(super) struct FrozenGmailReply {
    pub(super) plan: GmailSendPlan,
    pub(super) message: Zeroizing<Vec<u8>>,
    pub(super) attached: ReplyAttached,
}

/// Freezes `admitted`'s files into `plan` (fix list row 17645): the plan
/// seals their descriptions, its exact message is written once, refused
/// above [`MAX_GMAIL_RAW_MESSAGE_OCTETS`], and its length and BLAKE3 seal
/// into the plan's content ref, so the owner's one press is for exactly that
/// message, held in the carrier `carrier` names. `answered` is the message
/// the reply answers and `dependencies` every row the revision depends on.
///
/// # Errors
///
/// A file a part header may not carry, or a message above Gmail's limit.
pub(super) fn freeze_gmail_reply(
    plan: GmailSendPlan,
    admitted: AdmittedFiles,
    carrier: String,
    answered: AnsweredMessage,
    dependencies: Vec<EntityId>,
) -> MemoryResult<FrozenGmailReply> {
    let refuse = |error: Error| MemoryError::bad_request(error.to_string());
    let plan = plan
        .with_attachments(admitted.attachments.clone())
        .map_err(refuse)?;
    let files = admitted
        .copies
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let message = Zeroizing::new(plan.render_with_files(&files).map_err(refuse)?);
    let identity = MailMessageIdentity::of(&message);
    if identity.octets > MAX_GMAIL_RAW_MESSAGE_OCTETS {
        return Err(MemoryError::bad_request(too_large(identity.octets)));
    }
    Ok(FrozenGmailReply {
        plan: plan.with_message(identity, carrier),
        message,
        attached: ReplyAttached {
            attachments: admitted.attachments,
            message: identity,
            dependencies,
            answered: Some(answered),
        },
    })
}

/// Why the message revision `row` answers no longer stands, read in `txn`;
/// `None` while it does (fix list row 17645): the occurrence the revision
/// froze still stands under its mailbox source, not forgotten, on the
/// revision's thread for its answered TURN with each MESSAGE it froze, and
/// the thread, that TURN and each of those MESSAGE rows are live. An erase
/// of any of them that committed before this read is seen here.
///
/// # Errors
///
/// Storage failures.
pub(super) fn answered_refusal_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &MailReplyDraftRow,
    attached: &ReplyAttached,
) -> Result<Option<String>> {
    let gone =
        || Some("the thread or the message the reply answers is gone; draft it again".to_owned());
    let Some(answered) = &attached.answered else {
        return Ok(gone());
    };
    let stands = OCCURRENCES
        .get(&vault.store, txn, &(row.source, answered.occurrence))?
        .is_some_and(|occurrence| {
            occurrence.conversation == row.thread
                && occurrence.turn == row.parent_turn
                && !matches!(occurrence.presence, MailPresence::Forgotten { .. })
                && answered
                    .messages
                    .iter()
                    .all(|message| occurrence.messages.contains(message))
        });
    if !stands {
        return Ok(gone());
    }
    for id in [row.thread, row.parent_turn]
        .iter()
        .chain(&answered.messages)
    {
        if !matches!(
            live_entity_row_in_txn(&vault.store, txn, id)?,
            LiveEntityRow::Live { .. }
        ) {
            return Ok(gone());
        }
    }
    Ok(None)
}

/// Why revision `row` of the drafted reply `draft` no longer sends as it
/// was frozen with its files, read in `txn`; `None` while it does, and for a
/// reply without files (fix list row 17645): its mailbox still an active
/// Google personal mailbox, its message within Gmail's raw limit, the
/// thread and the message it answers still live as it froze them
/// ([`answered_refusal_in`]), each file still its pinned version quoting
/// its source as it did, with every recipient cleared for each file and
/// each source, and its message still held. Policy and liveness only.
///
/// # Errors
///
/// Storage failures.
pub(super) fn standing_refusal_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    row: &MailReplyDraftRow,
) -> Result<Option<String>> {
    let Some(attached) = &row.attached else {
        return Ok(None);
    };
    let sends = SOURCES
        .get(&vault.store, txn, &row.source)?
        .is_some_and(|source| {
            source.status == MailSourceStatus::Active
                && source.kind == MailSourceKind::PersonalMailbox
                && matches!(
                    source.provider,
                    MailProvider::GoogleWorkspace | MailProvider::Google
                )
        });
    if !sends {
        return Ok(Some(
            "the mailbox does not send now; its reply with files waits".to_owned(),
        ));
    }
    if attached.message.octets > MAX_GMAIL_RAW_MESSAGE_OCTETS {
        return Ok(Some(too_large(attached.message.octets)));
    }
    if let Some(refusal) = answered_refusal_in(vault, txn, row, attached)? {
        return Ok(Some(refusal));
    }
    let recipients = frozen_addresses(&row.to, &row.recipients);
    if let Some(refusal) = files_refusal_in(vault, None, txn, &attached.attachments, &recipients)? {
        return Ok(Some(refusal));
    }
    if !holds_reply_message_in(&vault.store, txn, draft, row.revision)? {
        return Ok(Some(
            "the reply's message is no longer held; draft it again".to_owned(),
        ));
    }
    Ok(None)
}

/// Whether `lane`, a reader's, reads every file `attached` names, its rows
/// with it, in `txn`: a reader that does not is shown no draft that carries
/// it (fix list row 17645).
///
/// # Errors
///
/// Storage failures.
pub(super) fn reader_reads_attachments_in(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    attached: &ReplyAttached,
) -> Result<bool> {
    for file in &attached.attachments {
        if pinned_in(vault, Some(lane), txn, &file.artifact, file.version)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether the ledger already completed the send `request` is, of the plan
/// `plan_ref` (fix list row 17645): that request's exact attempt stands Done
/// on the same channel and verb, its frozen content that plan. Read under
/// the custody read guard, as the dispatch reads it. A press for such a
/// send replays the recorded outcome and settles its draft, judging none of
/// today's files, recipients or message.
///
/// # Errors
///
/// Storage failures, and a ledger row that does not read.
pub(super) fn reply_send_completed(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    plan_ref: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct Frozen {
        #[serde(default)]
        content_ref: Option<String>,
    }
    let identity = request
        .ledger_identity_ref
        .as_deref()
        .unwrap_or(&request.intent_ref);
    let attempt = crate::outbound::outbound_dispatch_attempt_id(identity)
        .map_err(|_| Error::InvariantViolation("mail reply dispatch attempt"))?;
    let txn = vault.store.custody_snapshot()?;
    let record =
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(vault, &txn, attempt, 0)
            .map_err(|error| match error {
                IntentLedgerError::Engine(error) => error,
                _ => Error::CorruptedIndex("mail reply dispatch ledger row"),
            })?;
    let Some(record) = record.filter(|record| {
        record.state == IntentState::Done
            && record.server == request.intent.channel
            && record.tool == request.intent.verb
    }) else {
        return Ok(false);
    };
    Ok(serde_json::from_slice::<Frozen>(record.payload())
        .is_ok_and(|frozen| frozen.content_ref.as_deref() == Some(plan_ref)))
}

/// The one send with files a Gmail reply's approval dispatches, bound to
/// its revision and plan (fix list row 17645): it judges the send again in
/// the Gate's writer, at egress and in the credential door's writer, opens
/// the revision's retained message, checked against its frozen length and
/// BLAKE3, and hands the kept plan its manifest from the draft's own row.
pub(super) struct ReplyRetainedMessage<'v> {
    vault: &'v Vault,
    draft: EntityId,
    revision: u64,
    plan_ref: String,
    /// The ref of the revision's carrier, as its kept plan names it.
    carrier: String,
}

impl<'v> ReplyRetainedMessage<'v> {
    /// Binds the send of revision `row` of the draft `draft`, once its send
    /// still stands and its message opens as it was frozen, in a snapshot
    /// under the custody read guard: the check before the press.
    ///
    /// # Errors
    ///
    /// The refusal, and storage and custody failures.
    pub(super) fn for_press(
        vault: &'v Vault,
        draft: EntityId,
        row: &MailReplyDraftRow,
    ) -> MemoryResult<Self> {
        let bound = Self {
            vault,
            draft,
            revision: row.revision,
            plan_ref: row.plan_ref.clone(),
            carrier: reply_carrier_ref(&draft, row.revision)?,
        };
        bound
            .opened(&[MailReplyDraftState::Proposed, MailReplyDraftState::Approved])
            .map_err(refusal_error)?;
        Ok(bound)
    }

    /// The draft's row in `txn`, while it is still this revision of this
    /// plan in one of `states` and its send still stands.
    fn current_in(
        &self,
        txn: &RoTxn<'_>,
        states: &[MailReplyDraftState],
    ) -> Result<MailReplyDraftRow> {
        let row = DRAFTS
            .get(&self.vault.store, txn, &self.draft)?
            .filter(|row| {
                row.revision == self.revision
                    && row.plan_ref == self.plan_ref
                    && states.contains(&row.state)
            })
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "the drafted reply changed or was erased since it was reviewed".to_owned(),
                )
            })?;
        if let Some(refusal) = standing_refusal_in(self.vault, txn, &self.draft, &row)? {
            return Err(Error::InvalidConfig(refusal));
        }
        Ok(row)
    }

    /// The revision's retained message, opened in a snapshot under the
    /// custody read guard once its send still stands there.
    fn opened(&self, states: &[MailReplyDraftState]) -> Result<Zeroizing<Vec<u8>>> {
        let txn = self.vault.store.custody_snapshot()?;
        let row = self.current_in(&txn, states)?;
        let message = row
            .attached
            .as_ref()
            .map(|attached| attached.message)
            .ok_or_else(|| Error::InvalidConfig("the drafted reply carries no files".to_owned()))?;
        let opened = open_reply_message_in(
            &self.vault.store,
            &txn,
            &self.draft,
            self.revision,
            &message,
        )?
        .ok_or_else(|| {
            Error::InvalidConfig("the reply's message is no longer held; draft it again".to_owned())
        })?;
        if opened.len() as u64 > MAX_GMAIL_RAW_MESSAGE_OCTETS {
            return Err(Error::InvalidConfig(too_large(opened.len() as u64)));
        }
        Ok(opened)
    }
}

impl RetainedMailMessage for ReplyRetainedMessage<'_> {
    fn content_ref(&self) -> &str {
        &self.plan_ref
    }

    fn carrier_ref(&self) -> &str {
        &self.carrier
    }

    fn manifest(&self) -> Result<Option<MailManifest>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(DRAFTS
            .get(&self.vault.store, &txn, &self.draft)?
            .filter(|row| row.revision == self.revision && row.plan_ref == self.plan_ref)
            .and_then(|row| row.attached.as_ref().map(ReplyAttached::manifest)))
    }

    fn admit_in(&self, txn: &RoTxn<'_>) -> Result<()> {
        self.current_in(txn, &[MailReplyDraftState::Approved])
            .map(drop)
    }

    fn open_for_egress(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.opened(&[MailReplyDraftState::Approved])
    }
}
