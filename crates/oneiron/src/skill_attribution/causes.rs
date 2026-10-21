//! The labels the attribution judge settled on each attempt's terminal outcome,
//! kept whatever their subject routing (OF-568 L10).
//!
//! The projector routes a label to the entity it charges, and two labels the
//! attempt lane settles charge nobody: an `environment` answer and an
//! `unclear` hold. A judgment row cannot carry those, so this ledger keeps
//! every sole label the projector settles, in the same write as its cursor.
//! It is evidence, never a charge: no row here moves a reliability, an actor
//! claim or a hold, and there is no ENVIRONMENT entity to carry one. Agent
//! health reads it by the exact terminal pack receipt a finding's attempt
//! sealed.

use serde::{Deserialize, Serialize};

use super::judge_supersession::displacing_revision_in_txn;
use super::types::{AttributionVerdict, OutcomeEvidence};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Domain of a cause's source id: one id per terminal receipt and evidence
/// sequence.
const SOURCE_DOMAIN: &[u8] = b"oneiron:skill-attribution-cause:v1";

/// One settled label. Key: blake3 of the terminal pack receipt id, then the
/// evidence sequence.
const CAUSES: SideTable<([u8; 32], u64), CauseRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CAUSE);

/// [`CAUSES`]'s stored row. The label is the judge's stable wire token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CauseRow {
    source: EntityId,
    sequence: u64,
    receipt: String,
    /// `None` once the actor is erased: the label stays with its receipt.
    actor: Option<EntityId>,
    /// `None` once the skill is erased (FIX 8265), as the actor's slot.
    skill: Option<EntityId>,
    label: String,
    share: f32,
    judge_revision: Option<String>,
    at: u64,
}

/// One label the judge settled on an attempt's terminal outcome evidence, as
/// read back. A label is a fact about one evidence row: an `environment`
/// label on one loaded skill explains that skill's outcome, not every skill,
/// call or task of the attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributionCauseRecord {
    /// Immutable: the same receipt and evidence sequence always spell it.
    pub source: EntityId,
    /// The evidence row the label was settled from.
    pub sequence: u64,
    /// The terminal pack receipt that evidence cites.
    pub receipt: String,
    /// The executing actor, `None` once erased.
    pub actor: Option<EntityId>,
    /// The loaded skill the evidence row named, if any; `None` once erased.
    pub skill: Option<EntityId>,
    /// The judge's label for the whole outcome.
    pub label: AttributionVerdict,
    /// The label's share of the outcome, in `0..=1`.
    pub share: f32,
    /// The judge revision that answered; `None` for the rule tier.
    pub judge_revision: Option<String>,
    /// The revision that displaced `judge_revision`, when one has: the label
    /// is history then, not current support.
    pub displaced_by: Option<String>,
    /// Unix seconds the outcome was observed.
    pub at: u64,
}

/// Keeps the sole label one projector pass settled for one evidence row, in
/// that pass's write. A row held for the receipt and sequence keeps its
/// source id. A held `unclear` charged nobody, so a later replay that settles
/// the row takes its place (FIX 8260); any other held label stays as it was
/// written, and a later judge's different answer never rewrites it, as
/// judgments are never rescored.
///
/// # Errors
///
/// Storage and codec errors, which fail the pass's write and leave its
/// cursor where it was.
pub(super) fn put_attribution_cause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    sequence: u64,
    evidence: &OutcomeEvidence,
    label: AttributionVerdict,
    share: f32,
    judge_revision: Option<&str>,
) -> Result<()> {
    let key = (receipt_key(&evidence.receipt_ref), sequence);
    if let Some(mut held) = CAUSES.get(&vault.store, wtxn, &key)? {
        if held.label == AttributionVerdict::Unclear.as_str()
            && label != AttributionVerdict::Unclear
        {
            // The held actor and skill slots stay as they are: an erase
            // that nilled one is never undone by a replay.
            held.label = label.as_str().to_owned();
            held.share = share;
            held.judge_revision = judge_revision.map(str::to_owned);
            return CAUSES.put(&vault.store, wtxn, &key, &held);
        }
        if held.label != label.as_str() || held.judge_revision.as_deref() != judge_revision {
            tracing::debug!(
                sequence,
                held = %held.label,
                label = label.as_str(),
                "attribution cause kept as first settled"
            );
        }
        return Ok(());
    }
    let row = CauseRow {
        source: source_id(&evidence.receipt_ref, sequence)?,
        sequence,
        receipt: evidence.receipt_ref.clone(),
        actor: Some(evidence.actor),
        skill: evidence.skill,
        label: label.as_str().to_owned(),
        share,
        judge_revision: judge_revision.map(str::to_owned),
        at: evidence.at,
    };
    CAUSES.put(&vault.store, wtxn, &key, &row)
}

/// Every label the judge settled on evidence citing `terminal_pack_receipt`,
/// in evidence order, each marked when its judge revision was displaced.
/// Reads stored rows only: it never asks a judge.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] for a stored label that no
/// longer parses.
pub(crate) fn attempt_attribution_causes(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    terminal_pack_receipt: &str,
) -> Result<Vec<AttributionCauseRecord>> {
    let prefix = receipt_key(terminal_pack_receipt);
    let mut causes = Vec::new();
    for row in CAUSES.iter_from(&vault.store, txn, &prefix)? {
        let (_, row) = row?;
        // Two receipt ids sharing a hash would share a prefix: read this one's.
        if row.receipt != terminal_pack_receipt {
            continue;
        }
        let label = AttributionVerdict::parse(&row.label)
            .ok_or(Error::CorruptedIndex("attribution cause label"))?;
        let displaced_by = match &row.judge_revision {
            Some(revision) => displacing_revision_in_txn(vault, txn, revision)?,
            None => None,
        };
        causes.push(AttributionCauseRecord {
            source: row.source,
            sequence: row.sequence,
            receipt: row.receipt,
            actor: row.actor,
            skill: row.skill,
            label,
            share: row.share,
            judge_revision: row.judge_revision,
            displaced_by,
            at: row.at,
        });
    }
    Ok(causes)
}

/// Forgets erased `entity` on every cause row that names it, in the erase's
/// own write: an actor it executed or a skill it loaded (FIX 8265), each slot
/// nil, and the label stays with its receipt, as a call receipt keeps its row
/// and drops its identity. A later projection keeps the row's identity slots
/// as they are held ([`put_attribution_cause_in_txn`]), so it never names
/// either again.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_cause_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in CAUSES.iter_from(&vault.store, wtxn, &[])? {
        let (key, row) = row?;
        if row.actor == Some(*entity) || row.skill == Some(*entity) {
            erased.push((key, row));
        }
    }
    for (key, mut row) in erased {
        if row.actor == Some(*entity) {
            row.actor = None;
        }
        if row.skill == Some(*entity) {
            row.skill = None;
        }
        CAUSES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}

fn receipt_key(receipt: &str) -> [u8; 32] {
    *blake3::hash(receipt.as_bytes()).as_bytes()
}

fn source_id(receipt: &str, sequence: u64) -> Result<EntityId> {
    EntityId::derive(
        SOURCE_DOMAIN,
        &[receipt.as_bytes(), sequence.to_be_bytes().as_slice()],
    )
}
