//! ED-00 text by reference (FIX 7818): a finalized proposal keeps refs into
//! its retained document, and every endpoint or change text is read back
//! through it, never from a stored copy.
//!
//! The document is the proposal's own Loro document with its whole op log,
//! kept on the entity-document plane under an ordinary head of the artifact
//! owner kind, in the slot of the artifact's id (FIX 11535); the record names
//! that head. A reader loads the head and its slot in its own snapshot, and
//! reads through [`EntityDoc::text_at`], the plane's retained-history read. A
//! version the document no longer holds reads as [`TextRead::Unavailable`]:
//! never a guessed or stale string, and never an error that fails the
//! listing around it.
//!
//! When the batch door finds a secret in the document, and every secret its
//! served texts hold can be placed, the texts are custody-marked before the
//! document is kept, as an entity document's are (OF-067, FIX 11539): its op
//! stream and versions stay, and every text read of it shows each lifted
//! value as its handle. Otherwise one fallback keeps today's read: the record
//! keeps the endpoint and change texts as the side-row wall admitted them
//! ([`LiftedTexts`], a custody handle where it lifted a secret), and those
//! texts read in its place.

use heed::RoTxn;
use rmpv::Value;

use super::delta::{EndpointDocument, EndpointRef};
use super::{
    FinalizedProposalText, LoroOpRef, OpAttribution, OpSpan, PROPOSAL_ARTIFACT, ProposalArtifactRef,
};
use crate::Vault;
use crate::batch::secret_scan::{CarrierText, LiftedKeys, mark_carrier_texts_in_txn};
use crate::entity_doc::{ArtifactDocumentRows, EntityDoc};
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table;
use crate::store::Store;

/// One stored proposal artifact: the ref-only record, and the head of the
/// document its refs resolve in.
#[derive(Debug, Clone)]
pub(crate) struct StoredProposal {
    pub(crate) record: FinalizedProposalText,
    /// The head of the proposal's document on the entity-document plane;
    /// `None` when no document was kept at finalize, or an erase took it.
    pub(crate) head: Option<ArtifactHead>,
    /// The wall-admitted texts, kept only when no document was kept.
    pub(crate) lifted: Option<LiftedTexts>,
}

/// The document head a finalized proposal's record names (FIX 11535): a
/// head of the artifact owner kind under the artifact's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactHead {
    /// The head's incarnation: a head under the artifact's id at any other
    /// is not this document.
    incarnation: EntityId,
    /// Whether the document's served texts were custody-marked before it
    /// was kept (FIX 11539): its texts then read only as their masked
    /// copies.
    marked: bool,
}

/// Pinned MessagePack keys of a record's head.
const HEAD_KEY_INCARNATION: &str = "incarnation";
const HEAD_KEY_MARKED: &str = "marked";

/// The record codec's member for `head`: `Nil` when absent.
pub(super) fn encode_head(head: Option<&ArtifactHead>) -> Value {
    let Some(head) = head else {
        return Value::Nil;
    };
    Value::Map(vec![
        (
            Value::from(HEAD_KEY_INCARNATION),
            Value::Binary(head.incarnation.as_bytes().to_vec()),
        ),
        (Value::from(HEAD_KEY_MARKED), Value::Boolean(head.marked)),
    ])
}

/// Inverse of [`encode_head`].
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on a malformed member.
pub(super) fn decode_head(value: &Value) -> Result<Option<ArtifactHead>> {
    let corrupt = || Error::CorruptedIndex("proposal artifact document head");
    let entries = match value {
        Value::Nil => return Ok(None),
        Value::Map(entries) => entries,
        _ => return Err(corrupt()),
    };
    let member = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    let Some(Value::Binary(incarnation)) = member(HEAD_KEY_INCARNATION) else {
        return Err(corrupt());
    };
    let incarnation: [u8; ENTITY_ID_LEN] = incarnation.clone().try_into().map_err(|_| corrupt())?;
    let Some(Value::Boolean(marked)) = member(HEAD_KEY_MARKED) else {
        return Err(corrupt());
    };
    Ok(Some(ArtifactHead {
        incarnation: EntityId::from_bytes(incarnation).map_err(|_| corrupt())?,
        marked: *marked,
    }))
}

/// A stored proposal with its document's rows, read in one snapshot; it
/// opens later, outside it ([`RetainedProposal::open`]).
#[derive(Debug, Clone)]
pub(crate) struct JoinedProposal {
    record: FinalizedProposalText,
    /// The document's rows, or why there is no document to read.
    document: std::result::Result<ArtifactDocumentRows, TextUnavailable>,
    /// The texts its reads go through in the document's place: the
    /// record's wall-admitted texts, or a marked document's masked copies.
    lifted: Option<LiftedTexts>,
}

/// A proposal's endpoint and change texts as the side-row wall admitted
/// them, a custody handle where it lifted a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiftedTexts {
    proposed: String,
    finalized: String,
    /// Each recorded change's (before, after) texts, in replay order.
    changes: Vec<(String, String)>,
}

/// Pinned MessagePack keys of a record's lifted texts.
const LIFTED_KEY_PROPOSED: &str = "proposed";
const LIFTED_KEY_FINAL: &str = "final";
const LIFTED_KEY_CHANGES: &str = "changes";

impl LiftedTexts {
    /// Every text `record` names, read out of its document.
    fn read(document: &EntityDoc, record: &FinalizedProposalText) -> Option<Self> {
        let at = |frontier: &LoroOpRef| document.text_at(frontier.as_bytes()).ok();
        let changes = record
            .ops_by_actor
            .iter()
            .map(|(_, span)| Some((at(&span.before_ref)?, at(&span.after_ref)?)))
            .collect::<Option<_>>()?;
        Some(Self {
            proposed: at(&record.proposed_ref)?,
            finalized: at(&record.final_ref)?,
            changes,
        })
    }

    /// Every text kept: both ends, then each change's (before, after).
    fn served(&self) -> Vec<String> {
        let mut texts = vec![self.proposed.clone(), self.finalized.clone()];
        for (before, after) in &self.changes {
            texts.push(before.clone());
            texts.push(after.clone());
        }
        texts
    }

    /// The texts as a reader other than the owner reads them: each value
    /// `keys` holds as its handle.
    fn masked(self, keys: &LiftedKeys) -> Self {
        let mask = |text: String| keys.masked(&text).unwrap_or(text);
        Self {
            proposed: mask(self.proposed),
            finalized: mask(self.finalized),
            changes: self
                .changes
                .into_iter()
                .map(|(before, after)| (mask(before), mask(after)))
                .collect(),
        }
    }

    /// The text `record` names at `frontier`.
    fn at(&self, record: &FinalizedProposalText, frontier: &LoroOpRef) -> Option<&str> {
        if *frontier == record.proposed_ref {
            return Some(&self.proposed);
        }
        if *frontier == record.final_ref {
            return Some(&self.finalized);
        }
        record
            .ops_by_actor
            .iter()
            .zip(&self.changes)
            .find_map(|((_, span), (before, after))| {
                if span.before_ref == *frontier {
                    Some(before.as_str())
                } else if span.after_ref == *frontier {
                    Some(after.as_str())
                } else {
                    None
                }
            })
    }
}

/// The record codec's member for `lifted`: `Nil` when absent.
pub(super) fn encode_lifted(lifted: Option<&LiftedTexts>) -> Value {
    let Some(lifted) = lifted else {
        return Value::Nil;
    };
    let changes = lifted
        .changes
        .iter()
        .map(|(before, after)| {
            Value::Array(vec![
                Value::from(before.as_str()),
                Value::from(after.as_str()),
            ])
        })
        .collect();
    Value::Map(vec![
        (
            Value::from(LIFTED_KEY_PROPOSED),
            Value::from(lifted.proposed.as_str()),
        ),
        (
            Value::from(LIFTED_KEY_FINAL),
            Value::from(lifted.finalized.as_str()),
        ),
        (Value::from(LIFTED_KEY_CHANGES), Value::Array(changes)),
    ])
}

/// Inverse of [`encode_lifted`].
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on a malformed member.
pub(super) fn decode_lifted(value: &Value) -> Result<Option<LiftedTexts>> {
    let corrupt = || Error::CorruptedIndex("proposal artifact lifted texts");
    let text = |value: Option<&Value>| -> Result<String> {
        value
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(corrupt)
    };
    let entries = match value {
        Value::Nil => return Ok(None),
        Value::Map(entries) => entries,
        _ => return Err(corrupt()),
    };
    let member = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    let Some(Value::Array(changes)) = member(LIFTED_KEY_CHANGES) else {
        return Err(corrupt());
    };
    let changes = changes
        .iter()
        .map(|change| match change {
            Value::Array(pair) if pair.len() == 2 => Ok((text(pair.first())?, text(pair.get(1))?)),
            _ => Err(corrupt()),
        })
        .collect::<Result<_>>()?;
    Ok(Some(LiftedTexts {
        proposed: text(member(LIFTED_KEY_PROPOSED))?,
        finalized: text(member(LIFTED_KEY_FINAL))?,
        changes,
    }))
}

/// Why a referenced text cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextUnavailable {
    /// No text is retained for this version: the side-row wall withheld the
    /// document and its texts at finalize, or an erase took them.
    NotRetained,
    /// The document, or the version the ref names, does not read in it.
    Unreadable,
}

/// A text a ref names, or the typed reason it cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextRead {
    /// The text at the named version.
    Text(String),
    /// The named version is gone.
    Unavailable(TextUnavailable),
}

impl TextRead {
    /// The text, when it reads.
    #[must_use]
    pub fn into_text(self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text),
            Self::Unavailable(_) => None,
        }
    }
}

/// A finalized proposal with its retained document opened once, for any
/// number of reads.
pub struct RetainedProposal {
    /// The ref-only record.
    pub record: FinalizedProposalText,
    document: std::result::Result<EntityDoc, TextUnavailable>,
    lifted: Option<LiftedTexts>,
}

impl RetainedProposal {
    pub(crate) fn open(joined: JoinedProposal) -> Self {
        let document = joined
            .document
            .and_then(|rows| rows.open().map_err(|_| TextUnavailable::Unreadable));
        Self {
            record: joined.record,
            document,
            lifted: joined.lifted,
        }
    }

    /// The retained document, or why it cannot be read.
    ///
    /// # Errors
    ///
    /// The [`TextUnavailable`] reason the document does not read.
    pub fn document(&self) -> std::result::Result<&EntityDoc, TextUnavailable> {
        self.document.as_ref().map_err(|reason| *reason)
    }

    /// The text at `frontier` of this proposal's document; with the
    /// document withheld, the wall-admitted text the record kept for it. A
    /// marked document reads only through its masked texts, so a frontier
    /// they do not name reads as unreadable.
    #[must_use]
    pub fn text_at(&self, frontier: &LoroOpRef) -> TextRead {
        if let Some(text) = self
            .lifted
            .as_ref()
            .and_then(|lifted| lifted.at(&self.record, frontier))
        {
            return TextRead::Text(text.to_owned());
        }
        match self.document() {
            Ok(document) if self.lifted.is_none() => document.text_at(frontier.as_bytes()).map_or(
                TextRead::Unavailable(TextUnavailable::Unreadable),
                TextRead::Text,
            ),
            Ok(_) => TextRead::Unavailable(TextUnavailable::Unreadable),
            Err(reason) => TextRead::Unavailable(reason),
        }
    }

    /// The text as proposed.
    #[must_use]
    pub fn proposed_text(&self) -> TextRead {
        self.end_text_at(&self.record.proposed_ref, |kept| &kept.proposed)
    }

    /// The text as finalized.
    #[must_use]
    pub fn final_text(&self) -> TextRead {
        self.end_text_at(&self.record.final_ref, |kept| &kept.finalized)
    }

    /// One end of the window: read at `frontier` in the document, else the
    /// kept text for that end. An endpoint-only import keeps both ends and
    /// no window, so its ends are told apart by role, not by frontier.
    fn end_text_at(&self, frontier: &LoroOpRef, kept: fn(&LiftedTexts) -> &String) -> TextRead {
        match self.document() {
            Ok(_) => self.text_at(frontier),
            Err(reason) => self
                .lifted
                .as_ref()
                .map_or(TextRead::Unavailable(reason), |lifted| {
                    TextRead::Text(kept(lifted).clone())
                }),
        }
    }

    /// The text `end` names, when this row retains it: a window end by its
    /// frontier, an imported end by its role.
    #[must_use]
    pub fn end_text(&self, end: &EndpointRef) -> TextRead {
        let at_frontier = |frontier: &LoroOpRef| {
            end.frontier.as_deref() == Some(bytes_to_hex_lower(frontier.as_bytes()).as_str())
        };
        match &end.document {
            EndpointDocument::ImportedProposed(_) => self.proposed_text(),
            EndpointDocument::ImportedFinal(_) => self.final_text(),
            EndpointDocument::ProposalArtifact(_) if at_frontier(&self.record.proposed_ref) => {
                self.proposed_text()
            }
            EndpointDocument::ProposalArtifact(_) if at_frontier(&self.record.final_ref) => {
                self.final_text()
            }
            _ => TextRead::Unavailable(TextUnavailable::Unreadable),
        }
    }

    /// The text on either side of one recorded change.
    #[must_use]
    pub fn change_texts(&self, span: &OpSpan) -> (TextRead, TextRead) {
        (
            self.text_at(&span.before_ref),
            self.text_at(&span.after_ref),
        )
    }
}

/// Persists a finalized proposal artifact and its document (the Loro document
/// with the whole op log), keyed by its artifact ref.
///
/// **Write-once, read-before-write.** An artifact ref survives
/// `from_snapshot`, so two clones of one artifact can each finalize their own
/// divergent history under the SAME key. The divergence is surfaced: an equal
/// record is idempotent (a retried finalize is not an error, and the document
/// first retained stays), a different one is an error.
///
/// The document goes onto the entity-document plane as the artifact's own
/// headed document, written in this writer beside the record that names its
/// head (FIX 11535): the same document, with its birth, receipts and
/// operations. The batch door reads it whole first, as the side-row wall read
/// the snapshot it kept before. A secret there can take no handle in its
/// history, so the document is kept only once every secret its served texts
/// hold is custody-marked (OF-067, FIX 11539). Otherwise the record lands
/// without the document, keeping its endpoint and change texts through the
/// side-row wall, a custody handle where it lifted a secret, so they read as
/// they did before refs. When the wall refuses those texts too (a secret it
/// cannot place, which refused the whole finalize before), only the record
/// lands and its texts read as [`TextUnavailable::NotRetained`]: a finalize
/// never fails for it, and no raw secret is kept.
pub fn put_finalized_proposal_text(
    vault: &Vault,
    record: &FinalizedProposalText,
    document: &EntityDoc,
) -> Result<()> {
    let key = record.artifact_ref.entity_id();
    let snapshot = document.export_snapshot();
    vault.with_write_txn_grouped(|wtxn| {
        match PROPOSAL_ARTIFACT.get(&vault.store, &*wtxn, &key)? {
            Some(stored) if stored.record == *record => return Ok(()),
            Some(_) => {
                return Err(Error::InvariantViolation(
                    "proposal artifact is already finalized with a different record",
                ));
            }
            None => {}
        }
        let stored = |lifted: Option<LiftedTexts>| StoredProposal {
            record: record.clone(),
            head: None,
            lifted,
        };
        // The document and the texts are optional captures: either one's
        // failure falls back, and only the record's own put keeps its
        // contract.
        if let Ok(snapshot) = &snapshot
            && (put_document(vault, wtxn, record, document, snapshot)
                || put_marked_document(vault, wtxn, record, document))
        {
            return Ok(());
        }
        if let Some(lifted) = LiftedTexts::read(document, record)
            && put_optional(vault, wtxn, &key, &stored(Some(lifted)))
        {
            return Ok(());
        }
        PROPOSAL_ARTIFACT.put(vault, wtxn, &key, &stored(None))
    })
}

/// The document as it is, kept under the artifact's head beside its record
/// in one savepoint, when the batch door finds no secret in `snapshot`, the
/// whole document; `true` once it landed. A hit, or any failure, lands
/// nothing, and the caller falls back.
fn put_document(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &FinalizedProposalText,
    document: &EntityDoc,
    snapshot: &[u8],
) -> bool {
    in_savepoint(
        vault,
        wtxn,
        |savepoint| {
            crate::batch::secret_scan::scan_content_in_txn(&vault.store, savepoint, snapshot)?;
            put_headed(vault, savepoint, record, document, false)?;
            Ok(true)
        },
        "a proposal's document did not land; the record falls back",
    )
}

/// The batch door found a secret in the document: when every secret its
/// served texts hold can be placed, the texts are custody-marked and the
/// document is kept under the artifact's head, as an entity document is
/// (FIX 11539), in one savepoint with its record; `true` once it landed.
/// Texts with no secret (the door found one only past them), a secret no
/// span places, or any failure lands nothing: no unmarked document is kept,
/// and the caller falls back.
fn put_marked_document(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &FinalizedProposalText,
    document: &EntityDoc,
) -> bool {
    let Some(texts) = LiftedTexts::read(document, record) else {
        return false;
    };
    let carrier = record.artifact_ref.entity_id().to_hex();
    in_savepoint(
        vault,
        wtxn,
        |savepoint| {
            let marked = mark_carrier_texts_in_txn(
                vault,
                savepoint,
                &side_table::ENTITY_DOC_HEAD,
                carrier.as_bytes(),
                &texts.served(),
            )?;
            if !matches!(marked, CarrierText::Minted(_) | CarrierText::Marked) {
                return Ok(false);
            }
            put_headed(vault, savepoint, record, document, true)?;
            Ok(true)
        },
        "a proposal's marked document did not land; the record falls back",
    )
}

/// Writes `document` under a new head of the artifact owner kind, and
/// `record` naming that head, in `txn`.
fn put_headed(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &FinalizedProposalText,
    document: &EntityDoc,
    marked: bool,
) -> Result<()> {
    let key = record.artifact_ref.entity_id();
    let incarnation = crate::entity_doc::put_artifact_document_in_txn(vault, txn, &key, document)?;
    let stored = StoredProposal {
        record: record.clone(),
        head: Some(ArtifactHead {
            incarnation,
            marked,
        }),
        lifted: None,
    };
    PROPOSAL_ARTIFACT.put(vault, txn, &key, &stored)
}

/// `stored` as its readers read it, its document's rows read in `txn` (FIX
/// 11535). A marked document (FIX 11539) joins with its served texts as a
/// reader other than the owner reads them, each lifted value as its handle:
/// its text reads go through those masked texts only, and its document
/// serves its structure (op stream, birth). A marked document whose served
/// texts do not all read is not joined, so its raw text is never read. A
/// head the record names that no longer stands reads as unreadable.
///
/// # Errors
///
/// Storage errors, and a lifted text's mark that does not resolve.
pub(crate) fn joined_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    stored: StoredProposal,
) -> Result<JoinedProposal> {
    let StoredProposal {
        record,
        head,
        lifted,
    } = stored;
    let Some(head) = head else {
        return Ok(JoinedProposal {
            record,
            document: Err(TextUnavailable::NotRetained),
            lifted,
        });
    };
    let artifact = record.artifact_ref.entity_id();
    let incarnation = head.incarnation.to_hex();
    let Some(rows) =
        crate::entity_doc::artifact_document_rows_in_txn(store, txn, &artifact, &incarnation)?
    else {
        return Ok(JoinedProposal {
            record,
            document: Err(TextUnavailable::Unreadable),
            lifted,
        });
    };
    if !head.marked {
        return Ok(JoinedProposal {
            record,
            document: Ok(rows),
            lifted,
        });
    }
    let Some(texts) = rows
        .open()
        .ok()
        .and_then(|document| LiftedTexts::read(&document, &record))
    else {
        return Ok(JoinedProposal {
            record,
            document: Err(TextUnavailable::NotRetained),
            lifted,
        });
    };
    let keys = LiftedKeys::of_in_txn(store, txn, texts.served())?;
    Ok(JoinedProposal {
        record,
        document: Ok(rows),
        lifted: Some(texts.masked(&keys)),
    })
}

/// Puts `stored` in a savepoint; `true` once it landed. A wall refusal, or
/// any other failure, lands nothing and is never raised: the caller falls
/// back.
fn put_optional(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &crate::entity_id::EntityId,
    stored: &StoredProposal,
) -> bool {
    in_savepoint(
        vault,
        wtxn,
        |savepoint| {
            PROPOSAL_ARTIFACT.put(vault, savepoint, key, stored)?;
            Ok(true)
        },
        "a proposal artifact's optional retention did not land; the record falls back",
    )
}

/// Runs `put` in a savepoint of `wtxn`, kept when `put` says it landed;
/// `true` once it did. A wall or door refusal, or any other failure, lands
/// nothing and is never raised: the caller falls back. `failed` is the
/// warning a failure other than a refusal logs.
fn in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    put: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<bool>,
    failed: &'static str,
) -> bool {
    let landed = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            if !put(&mut savepoint)? {
                return Ok(false);
            }
            savepoint.commit()?;
            Ok(true)
        });
    match landed {
        Ok(landed) => landed,
        Err(Error::Gate(_)) => false,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "{failed}");
            false
        }
    }
}

/// The proposal-artifact table's declared scrub: the erase of `id` (an actor
/// a recorded change is attributed to, a proposal's source turn, or the
/// artifact itself) takes each such proposal's document from the
/// entity-document plane through the common erase (its head, its slot's
/// rows, its pins and floors; FIX 11535) and its kept texts, so every read of
/// them is unavailable, and its changes attributed to `id` read as unknown.
/// The record stays. A restored image's replay of every erased id runs it
/// again. A row that does not decode is passed over with a WARN.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_proposal_texts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let names = |attribution: &OpAttribution| {
        attribution
            .actor()
            .is_some_and(|actor| actor.entity_ref() == *id)
    };
    let mut reached = Vec::new();
    for row in PROPOSAL_ARTIFACT.iter_raw_from(&vault.store, &*txn, &[])? {
        let (_, bytes) = row?;
        let Ok(mut stored) = PROPOSAL_ARTIFACT.decode_value(&bytes) else {
            tracing::warn!("a proposal artifact row does not decode: the erase passes it over");
            continue;
        };
        let record = &mut stored.record;
        let sourced = record.artifact_ref.entity_id() == *id || record.source_turn_ref == Some(*id);
        if !sourced
            && !record
                .ops_by_actor
                .iter()
                .any(|(attribution, _)| names(attribution))
        {
            continue;
        }
        for (attribution, _) in &mut record.ops_by_actor {
            if names(attribution) {
                *attribution = OpAttribution::Unknown;
            }
        }
        stored.head = None;
        stored.lifted = None;
        reached.push(stored);
    }
    for stored in reached {
        let key = stored.record.artifact_ref.entity_id();
        crate::entity_doc::erase_artifact_document_in_txn(&vault.store, txn, &key)?;
        PROPOSAL_ARTIFACT.put(vault, txn, &key, &stored)?;
    }
    Ok(())
}

/// Retains an endpoint-only settlement's two imported texts under its own
/// record (FIX 10176), through the side-row wall: no window, no operations,
/// nothing recorded is minted for them. If the wall refuses the texts, the
/// record lands alone and its ends read as not retained.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_imported_endpoints(
    vault: &Vault,
    record: ProposalArtifactRef,
    source_turn_ref: Option<EntityId>,
    proposed: &str,
    finalized: &str,
) -> Result<()> {
    // An import has no window: its refs are empty, and its ends are read by
    // role.
    let record = FinalizedProposalText {
        artifact_ref: record,
        proposed_ref: LoroOpRef::from_bytes(Vec::new()),
        final_ref: LoroOpRef::from_bytes(Vec::new()),
        ops_by_actor: Vec::new(),
        source_turn_ref,
        birth_attempt: None,
        made_by_inputs: Vec::new(),
    };
    let key = record.artifact_ref.entity_id();
    let kept = LiftedTexts {
        proposed: proposed.to_owned(),
        finalized: finalized.to_owned(),
        changes: Vec::new(),
    };
    vault.with_write_txn_grouped(|wtxn| {
        let stored = |lifted: Option<LiftedTexts>| StoredProposal {
            record: record.clone(),
            head: None,
            lifted,
        };
        if put_optional(vault, wtxn, &key, &stored(Some(kept))) {
            return Ok(());
        }
        PROPOSAL_ARTIFACT.put(vault, wtxn, &key, &stored(None))
    })
}

/// Reads the finalized proposal artifact stored under `artifact_ref`.
pub fn finalized_proposal_text(
    vault: &Vault,
    artifact_ref: ProposalArtifactRef,
) -> Result<Option<FinalizedProposalText>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(PROPOSAL_ARTIFACT
        .get(&vault.store, &rtxn, &artifact_ref.entity_id())?
        .map(|stored| stored.record))
}

/// The finalized proposal under `artifact` with its retained document, in
/// the caller's transaction; `None` when no artifact is stored there.
///
/// # Errors
///
/// Storage errors, and an undecodable record row.
pub(crate) fn retained_proposal_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: ProposalArtifactRef,
) -> Result<Option<RetainedProposal>> {
    PROPOSAL_ARTIFACT
        .get(&vault.store, txn, &artifact.entity_id())?
        .map(|stored| joined_in_txn(&vault.store, txn, stored).map(RetainedProposal::open))
        .transpose()
}

/// [`retained_proposal_in_txn`] in its own read transaction.
///
/// # Errors
///
/// As [`retained_proposal_in_txn`].
pub fn retained_proposal(
    vault: &Vault,
    artifact: ProposalArtifactRef,
) -> Result<Option<RetainedProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    retained_proposal_in_txn(vault, &rtxn, artifact)
}

/// The incarnation of the document head proposal artifact `artifact`'s
/// record names, in the caller's transaction (FIX 11535): what makes a head
/// of the artifact owner kind this artifact's document. `None` when no
/// record is stored under `artifact`, or it names no head.
///
/// # Errors
///
/// Storage errors, and an undecodable record row.
pub(crate) fn artifact_head_incarnation_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Option<String>> {
    Ok(PROPOSAL_ARTIFACT
        .get(store, txn, artifact)?
        .and_then(|stored| stored.head)
        .map(|head| head.incarnation.to_hex()))
}

/// Every version proposal artifact `artifact`'s record names in its document
/// under the head at `incarnation`, in the caller's transaction: both ends of
/// its window and each recorded change's two sides. A purge of that
/// document's history keeps them, as it keeps a settlement receipt's (FIX
/// 11535). Empty for any other id or head.
///
/// # Errors
///
/// Storage errors, and an undecodable record row.
pub(crate) fn artifact_window_refs_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    incarnation: &str,
) -> Result<Vec<Vec<u8>>> {
    let Some(stored) = PROPOSAL_ARTIFACT.get(store, txn, artifact)? else {
        return Ok(Vec::new());
    };
    if stored
        .head
        .is_none_or(|head| head.incarnation.to_hex() != incarnation)
    {
        return Ok(Vec::new());
    }
    let record = stored.record;
    let mut refs = vec![
        record.proposed_ref.as_bytes().to_vec(),
        record.final_ref.as_bytes().to_vec(),
    ];
    for (_, span) in &record.ops_by_actor {
        refs.push(span.before_ref.as_bytes().to_vec());
        refs.push(span.after_ref.as_bytes().to_vec());
    }
    refs.retain(|frontier| !frontier.is_empty());
    Ok(refs)
}
