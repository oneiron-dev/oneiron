//! ED-00 text by reference (FIX 7818): a finalized proposal keeps refs into
//! its retained document, and every endpoint or change text is read back
//! through it, never from a stored copy.
//!
//! The document is the proposal's own Loro document with its whole op log,
//! retained beside the record under the artifact's key. Reads go through
//! [`EntityDoc::from_snapshot`] and [`EntityDoc::text_at`], the entity
//! document plane's retained-history reads. A version the document no longer
//! holds reads as [`TextRead::Unavailable`]: never a guessed or stale string,
//! and never an error that fails the listing around it.
//!
//! One fallback keeps today's read: when the side-row wall refuses the
//! document, the record keeps the endpoint and change texts as the wall
//! admitted them ([`LiftedTexts`], a custody handle where it lifted a
//! secret), and those texts read in its place.

use heed::RoTxn;
use rmpv::Value;

use super::delta::{EndpointDocument, EndpointRef};
use super::{
    FinalizedProposalText, LoroOpRef, OpAttribution, OpSpan, PROPOSAL_ARTIFACT, ProposalArtifactRef,
};
use crate::Vault;
use crate::entity_doc::EntityDoc;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// One stored proposal artifact: the ref-only record, and the retained
/// document its refs resolve in.
#[derive(Debug, Clone)]
pub(crate) struct StoredProposal {
    pub(crate) record: FinalizedProposalText,
    /// The proposal document as a Loro snapshot with its whole op log;
    /// `None` when the side-row wall withheld it at finalize.
    pub(crate) document: Option<Vec<u8>>,
    /// The wall-admitted texts, kept only when the wall withheld the
    /// document.
    pub(crate) lifted: Option<LiftedTexts>,
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
    pub(crate) fn open(stored: StoredProposal) -> Self {
        let document = match stored.document {
            Some(bytes) => {
                EntityDoc::from_snapshot(&bytes).map_err(|_| TextUnavailable::Unreadable)
            }
            None => Err(TextUnavailable::NotRetained),
        };
        Self {
            record: stored.record,
            document,
            lifted: stored.lifted,
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
    /// document withheld, the wall-admitted text the record kept for it.
    #[must_use]
    pub fn text_at(&self, frontier: &LoroOpRef) -> TextRead {
        match self.document() {
            Ok(document) => document.text_at(frontier.as_bytes()).map_or(
                TextRead::Unavailable(TextUnavailable::Unreadable),
                TextRead::Text,
            ),
            Err(reason) => self
                .lifted
                .as_ref()
                .and_then(|lifted| lifted.at(&self.record, frontier))
                .map_or(TextRead::Unavailable(reason), |text| {
                    TextRead::Text(text.to_owned())
                }),
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

/// Persists a finalized proposal artifact and its document (a Loro snapshot
/// with the whole op log), keyed by its artifact ref.
///
/// **Write-once, read-before-write.** An artifact ref survives
/// `from_snapshot`, so two clones of one artifact can each finalize their own
/// divergent history under the SAME key. The divergence is surfaced: an equal
/// record is idempotent (a retried finalize is not an error, and the document
/// first retained stays), a different one is an error.
///
/// The side-row wall reads the document as opaque bytes, so a secret in its
/// history can take no handle there and the wall refuses it (OF-067). The
/// record then lands without the document, keeping its endpoint and change
/// texts through the same wall, a custody handle where it lifted a secret, so
/// they read as they did before refs. When the wall refuses those texts too
/// (a secret it cannot place, which refused the whole finalize before), only
/// the record lands and its texts read as [`TextUnavailable::NotRetained`]: a
/// finalize never fails for it, and no raw secret is kept.
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
        let stored = |snapshot: Option<Vec<u8>>, lifted: Option<LiftedTexts>| StoredProposal {
            record: record.clone(),
            document: snapshot,
            lifted,
        };
        // The document and the texts are optional captures: either one's
        // failure falls back, and only the record's own put keeps its
        // contract.
        if let Ok(snapshot) = &snapshot
            && put_optional(vault, wtxn, &key, &stored(Some(snapshot.clone()), None))
        {
            return Ok(());
        }
        if let Some(lifted) = LiftedTexts::read(document, record)
            && put_optional(vault, wtxn, &key, &stored(None, Some(lifted)))
        {
            return Ok(());
        }
        PROPOSAL_ARTIFACT.put(vault, wtxn, &key, &stored(None, None))
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
    let landed = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            PROPOSAL_ARTIFACT.put(vault, &mut savepoint, key, stored)?;
            Ok(savepoint.commit()?)
        });
    match landed {
        Ok(()) => true,
        Err(Error::Gate(_)) => false,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a proposal artifact's optional retention did not land; the record falls back"
            );
            false
        }
    }
}

/// The proposal-artifact table's declared scrub: the erase of `id` (an actor
/// a recorded change is attributed to, a proposal's source turn, or the
/// artifact itself) takes each such proposal's retained document and kept
/// texts, so every read of them is unavailable, and its changes attributed to
/// `id` read as unknown. A restored image's replay of every erased id runs it
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
        stored.document = None;
        stored.lifted = None;
        reached.push(stored);
    }
    for stored in reached {
        PROPOSAL_ARTIFACT.put(vault, txn, &stored.record.artifact_ref.entity_id(), &stored)?;
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
            document: None,
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
    Ok(PROPOSAL_ARTIFACT
        .get(&vault.store, txn, &artifact.entity_id())?
        .map(RetainedProposal::open))
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
