//! The unclear ledger: every outcome the judge left `unclear`, kept for the
//! Dreamer to cluster (ARCH-0056 §5 #unclear).
//!
//! An `unclear` share charges nobody, so without this ledger it would leave no
//! trace at all. Each row is one judged outcome — a failed attempt or an
//! amendment — with a note per unclear hunk: why it landed there, the label
//! the judge leaned to, and the judge's own words. Beside the notes stands the
//! outcome's context, frozen in the write that files them (FIX 7824): who and
//! what the outcome was about, where it ran, which judge wrote the notes and
//! the rows that judge read. The Dreamer groups notes only within one context,
//! and an erase of anything the context names drops the row whole, notes and
//! all. The clustering that turns recurring notes into a proposed new label is
//! the Dreamer's, and is not built here; [`unclear_attributions`] is its
//! inlet.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

use super::types::{AttributionLane, AttributionVerdict, UnclearNote, UnclearReason};

/// One judged outcome with an `unclear` share.
#[derive(Debug, Clone, PartialEq)]
pub struct UnclearAttribution {
    pub lane: AttributionLane,
    /// Where the outcome is filed in its lane: the evidence sequence for an
    /// attempt, the receipt id for an amendment.
    pub reference: String,
    /// Receipt ids the outcome rests on.
    pub evidence_receipts: Vec<String>,
    /// One note per unclear hunk.
    pub notes: Vec<UnclearNote>,
    /// What the outcome was judged as when its notes were written.
    pub context: UnclearContext,
    pub at: u64,
}

impl UnclearAttribution {
    /// The outcome's whole unclear share.
    #[must_use]
    pub fn share(&self) -> f32 {
        self.notes.iter().map(|note| note.share).sum()
    }
}

/// What one unclear outcome was judged as, frozen in the write that files its
/// notes (FIX 7824). Each field is the lane's own record of the outcome, never
/// read later off today's actor or skill; `None` is unknown, never the vault's
/// default.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UnclearContext {
    /// The actor the outcome names.
    pub actor: Option<EntityId>,
    /// The skill the outcome rode, when it rode one.
    pub skill: Option<EntityId>,
    /// The amendment's normalized consent scope. An attempt records none.
    pub scope: Option<String>,
    /// The project the outcome ran in, where it recorded one.
    pub project: Option<EntityId>,
    /// The task type the outcome ran as, where it recorded one.
    pub type_ref: Option<TypeRef>,
    /// The terminal pack receipt of the attempt the outcome is about: an
    /// attempt's own, an amendment's grounded join. Two outcomes on one
    /// attempt are one recurrence, not two.
    pub attempt_receipt: Option<String>,
    /// The judge revision whose answers left the outcome unclear.
    pub judge_revision: Option<String>,
    /// That judge's answering model, when one model gave every answer.
    pub judge_model: Option<String>,
    /// The rows the judge read beside the outcome: a note's words can come
    /// from any of them.
    pub sources: Vec<EntityId>,
}

impl UnclearContext {
    /// Every entity the context names.
    fn entities(&self) -> impl Iterator<Item = &EntityId> {
        self.actor
            .iter()
            .chain(&self.skill)
            .chain(&self.project)
            .chain(&self.sources)
    }

    /// Whether the context names `id`.
    fn names(&self, id: &EntityId) -> bool {
        self.entities().any(|named| named == id)
    }
}

/// Keyed `lane ":" reference`, so one outcome holds one row and a re-judgment
/// replaces it.
const UNCLEAR: SideTable<String, StoredUnclear, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_UNCLEAR);

/// The same rows by their raw key, for the erase scan.
const UNCLEAR_RAW: SideTable<Vec<u8>, StoredUnclear, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_UNCLEAR);

const ROW_VERSION: u8 = 2;
const ROW_LABEL: &str = "unclear attribution row";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUnclear {
    v: u8,
    lane: String,
    reference: String,
    evidence_receipts: Vec<String>,
    notes: Vec<StoredNote>,
    context: StoredContext,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNote {
    reason: String,
    leaning: Option<String>,
    confidence: f32,
    share: f32,
    note: Option<String>,
}

/// [`UnclearContext`] with its entities as hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredContext {
    actor: Option<String>,
    skill: Option<String>,
    scope: Option<String>,
    project: Option<String>,
    type_ref: Option<TypeRef>,
    attempt_receipt: Option<String>,
    judge_revision: Option<String>,
    judge_model: Option<String>,
    sources: Vec<String>,
}

impl StoredContext {
    fn new(context: &UnclearContext) -> Self {
        Self {
            actor: context.actor.map(|id| id.to_hex()),
            skill: context.skill.map(|id| id.to_hex()),
            scope: context.scope.clone(),
            project: context.project.map(|id| id.to_hex()),
            type_ref: context.type_ref.clone(),
            attempt_receipt: context.attempt_receipt.clone(),
            judge_revision: context.judge_revision.clone(),
            judge_model: context.judge_model.clone(),
            sources: context.sources.iter().map(EntityId::to_hex).collect(),
        }
    }

    fn decode(self) -> Result<UnclearContext> {
        let entity =
            |hex: &str| EntityId::from_hex(hex).map_err(|_| Error::CorruptedIndex(ROW_LABEL));
        Ok(UnclearContext {
            actor: self.actor.as_deref().map(entity).transpose()?,
            skill: self.skill.as_deref().map(entity).transpose()?,
            scope: self.scope,
            project: self.project.as_deref().map(entity).transpose()?,
            type_ref: self.type_ref,
            attempt_receipt: self.attempt_receipt,
            judge_revision: self.judge_revision,
            judge_model: self.judge_model,
            sources: self
                .sources
                .iter()
                .map(|hex| entity(hex))
                .collect::<Result<_>>()?,
        })
    }
}

impl RawValue for StoredUnclear {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| CodecError::Value(Error::InvariantViolation(ROW_LABEL)))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| CodecError::Value(Error::CorruptedIndex(ROW_LABEL)))?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(ROW_LABEL)));
        }
        Ok(row)
    }
}

fn row_key(lane: AttributionLane, reference: &str) -> String {
    format!("{}:{reference}", lane.as_str())
}

/// Files `row`, replacing whatever the same outcome held before.
///
/// An erase of an entity the row's context names, landed since the judge read
/// the outcome, wins: the row is not filed, and the outcome's earlier row goes
/// too, so the notes never outlive what they were written about (FIX 7824).
pub(crate) fn put_unclear_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &UnclearAttribution,
) -> Result<()> {
    let key = row_key(row.lane, &row.reference);
    for id in row.context.entities() {
        if crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &*wtxn, id)?.deleted
        {
            UNCLEAR.delete(&vault.store, wtxn, &key)?;
            return Ok(());
        }
    }
    let stored = StoredUnclear {
        v: ROW_VERSION,
        lane: row.lane.as_str().to_owned(),
        reference: row.reference.clone(),
        evidence_receipts: row.evidence_receipts.clone(),
        notes: row
            .notes
            .iter()
            .map(|note| StoredNote {
                reason: note.reason.as_str().to_owned(),
                leaning: note.leaning.map(|label| label.as_str().to_owned()),
                confidence: note.confidence,
                share: note.share,
                note: note.note.clone(),
            })
            .collect(),
        context: StoredContext::new(&row.context),
        at: row.at,
    };
    UNCLEAR.put(&vault.store, wtxn, &key, &stored)?;
    Ok(())
}

/// Withdraws the outcome's row: a re-judgment that left nothing unclear.
pub(crate) fn delete_unclear_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    lane: AttributionLane,
    reference: &str,
) -> Result<()> {
    UNCLEAR.delete(&vault.store, wtxn, &row_key(lane, reference))?;
    Ok(())
}

/// Drops every unclear row whose context names erased `entity` — its actor,
/// skill, project or a row its judge read — whole, notes and all: a note's
/// words can quote any of them, so nilling a field would leave the words
/// (FIX 7824). A row that no longer decodes names nothing a scrub can match,
/// and goes too. Runs as the table's declared scrub, which an erase and a
/// checkpoint restore's replay reach, and as a derived-row eraser, which both
/// delete doors reach.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_unclear_source_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let rows = UNCLEAR_RAW
        .iter_raw_from(store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        let names = match UNCLEAR_RAW.decode_value(&value) {
            Ok(row) => row
                .context
                .decode()
                .map_or(true, |context| context.names(entity)),
            Err(_) => true,
        };
        if names {
            UNCLEAR_RAW.delete(store, wtxn, &key)?;
        }
    }
    Ok(())
}

/// [`erase_unclear_source_in_txn`] in the declared scrub's shape.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_unclear_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    erase_unclear_source_in_txn(&vault.store, wtxn, entity)
}

/// Every outcome the judge left `unclear`, both lanes, in key order — the
/// Dreamer's clustering inlet.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn unclear_attributions(vault: &Vault) -> Result<Vec<UnclearAttribution>> {
    let rtxn = vault.store.env.read_txn()?;
    let corrupt = || Error::CorruptedIndex(ROW_LABEL);
    let mut out = Vec::new();
    for (_, row) in UNCLEAR.scan(&vault.store, &rtxn)? {
        let mut notes = Vec::with_capacity(row.notes.len());
        for note in row.notes {
            notes.push(UnclearNote {
                reason: UnclearReason::parse(&note.reason).ok_or_else(corrupt)?,
                leaning: note
                    .leaning
                    .as_deref()
                    .map(|label| AttributionVerdict::parse(label).ok_or_else(corrupt))
                    .transpose()?,
                confidence: note.confidence,
                share: note.share,
                note: note.note,
            });
        }
        out.push(UnclearAttribution {
            lane: AttributionLane::parse(&row.lane).ok_or_else(corrupt)?,
            reference: row.reference,
            evidence_receipts: row.evidence_receipts,
            notes,
            context: row.context.decode()?,
            at: row.at,
        });
    }
    Ok(out)
}
