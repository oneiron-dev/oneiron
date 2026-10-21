//! A saved weave period's loop-decision rows (OF-499 A2): their saved
//! carrier, the erase index over their refs, and their recheck. A saved
//! loop row is rechecked on its own against one current authorised read in
//! the opener's transaction, by its decision id: it serves while it reads
//! exactly as saved, or as the current skeleton once the read returns one;
//! else that row alone is withheld and every other row of the period still
//! serves. A decision the ledger gained since the period saved never joins
//! it. A loop row's refs index its period for erasure, and never gate it.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::loop_decision_read::ReadableLoopDecision;
use super::super::weave_report::admissions::loop_decision_item;
use super::{ScopedRead, WeaveDigestReader, WeaveItem, WeaveReader, WeaveReport};
use super::{invalid, report_sources};
use crate::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;

/// A saved loop decision row: every field its live row carries.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireLoopDecision {
    decision_id: GateDecisionId,
    created_at: u64,
    family: String,
    kind: String,
    outcome: String,
    reason_codes: Vec<String>,
    redacted: bool,
    claim_ref: Option<EntityId>,
    actor_ref: Option<EntityId>,
    evidence_refs: Vec<EntityId>,
}

impl WireLoopDecision {
    /// `item`, a loop decision row, as its period saves it.
    pub(super) fn of(item: &WeaveItem) -> Result<Self> {
        let WeaveItem::LoopDecision {
            decision_id,
            created_at,
            family,
            kind,
            outcome,
            reason_codes,
            redacted,
            claim_ref,
            actor_ref,
            evidence_refs,
        } = item
        else {
            return Err(invalid());
        };
        Ok(Self {
            decision_id: *decision_id,
            created_at: *created_at,
            family: family.clone(),
            kind: kind.clone(),
            outcome: outcome.clone(),
            reason_codes: reason_codes.clone(),
            redacted: *redacted,
            claim_ref: *claim_ref,
            actor_ref: *actor_ref,
            evidence_refs: evidence_refs.clone(),
        })
    }

    /// The saved row as its period's item.
    pub(super) fn into_item(self) -> WeaveItem {
        WeaveItem::LoopDecision {
            decision_id: self.decision_id,
            created_at: self.created_at,
            family: self.family,
            kind: self.kind,
            outcome: self.outcome,
            reason_codes: self.reason_codes,
            redacted: self.redacted,
            claim_ref: self.claim_ref,
            actor_ref: self.actor_ref,
            evidence_refs: self.evidence_refs,
        }
    }
}

/// Every ref a saved period carries, for its erase index: the sources its
/// checks read, and each loop row's claim, actor and evidence refs, so a
/// hard delete of any of them erases the period with its copy.
pub(super) fn indexed_sources(report: &WeaveReport) -> Result<BTreeSet<EntityId>> {
    let mut sources = report_sources(report)?;
    for item in report.sections.iter().flat_map(|section| &section.items) {
        if let WeaveItem::LoopDecision {
            claim_ref,
            actor_ref,
            evidence_refs,
            ..
        } = item
        {
            sources.extend(
                claim_ref
                    .iter()
                    .chain(actor_ref)
                    .chain(evidence_refs)
                    .copied(),
            );
        }
    }
    Ok(sources)
}

/// Whether `report` holds any loop decision row.
fn has_loop_rows(report: &WeaveReport) -> bool {
    report
        .sections
        .iter()
        .flat_map(|section| &section.items)
        .any(|item| matches!(item, WeaveItem::LoopDecision { .. }))
}

/// Rechecks each loop row of `report` against `current`, by decision id:
/// kept while it is exactly the current row, replaced by the current row
/// when that is a redacted skeleton, else withheld alone. No row joins.
fn recheck_loop_rows(report: &mut WeaveReport, current: Vec<ReadableLoopDecision>) {
    let current: BTreeMap<[u8; 16], WeaveItem> = current
        .into_iter()
        .map(|decision| {
            (
                decision.decision_id.as_bytes(),
                loop_decision_item(decision),
            )
        })
        .collect();
    for section in &mut report.sections {
        section.items.retain_mut(|item| {
            let key = match item {
                WeaveItem::LoopDecision { decision_id, .. } => decision_id.as_bytes(),
                _ => return true,
            };
            match current.get(&key) {
                Some(now) if *now == *item => true,
                Some(now @ WeaveItem::LoopDecision { redacted: true, .. }) => {
                    *item = now.clone();
                    true
                }
                _ => false,
            }
        });
    }
}

impl ScopedRead<'_> {
    /// Rechecks a saved period's loop rows in `txn` (see the module doc).
    /// The current read is `opener`'s, the reader the period was bound to;
    /// with none, the owner's proofless background lens, it is the recorded
    /// owner's hook ([`Self::recorded_owner_loop_decisions_in_txn`]). A
    /// period with no loop row reads no ledger.
    pub(super) fn recheck_saved_loop_decisions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader_key: WeaveDigestReader,
        opener: Option<WeaveReader<'_>>,
        report: &mut WeaveReport,
    ) {
        if !has_loop_rows(report) {
            return;
        }
        let current = match (opener, reader_key) {
            (Some(reader), _) => self.readable_loop_decisions_in_txn(txn, reader),
            (None, WeaveDigestReader::Owner(owner)) => {
                self.recorded_owner_loop_decisions_in_txn(txn, owner)
            }
            (None, WeaveDigestReader::Person(_) | WeaveDigestReader::Agent(_)) => Vec::new(),
        };
        recheck_loop_rows(report, current);
    }

    /// The rows a saved period's lens render was written over: an owner's
    /// period's render was written by its proofless background lens, so its
    /// loop rows are rechecked as that lens rechecks them, through the
    /// recorded owner's hook; every other reader's render read `report`
    /// as its opener does. The period's own rows still serve whole.
    pub(crate) fn saved_weave_lens_rows<'r>(
        &self,
        reader: WeaveDigestReader,
        report: &'r WeaveReport,
    ) -> Result<Cow<'r, WeaveReport>> {
        let WeaveDigestReader::Owner(owner) = reader else {
            return Ok(Cow::Borrowed(report));
        };
        if !has_loop_rows(report) {
            return Ok(Cow::Borrowed(report));
        }
        let txn = self.vault.store.env.read_txn()?;
        let mut rows = report.clone();
        recheck_loop_rows(
            &mut rows,
            self.recorded_owner_loop_decisions_in_txn(&txn, owner),
        );
        Ok(Cow::Owned(rows))
    }

    /// FIX 7597 hook: the loop decisions a saved period's recorded owner may
    /// see now, for the owner's proofless background lens. L02 builds
    /// `ScopedRead::authorised_loop_decisions_for_recorded_owner_in_txn(txn,
    /// owner)` with OF-499 A3, and this then returns its answer for `owner`.
    /// Until then it returns none, so that lens leaves out only its loop
    /// rows. It never reads as `Person(owner)` and never makes an owner
    /// proof.
    fn recorded_owner_loop_decisions_in_txn(
        &self,
        _txn: &heed::RoTxn<'_>,
        _owner: EntityId,
    ) -> Vec<ReadableLoopDecision> {
        Vec::new()
    }
}
