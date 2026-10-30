//! Every candidate a Dreamer attempt decided a correction for, kept at the
//! attempt before the branch builds, filters or selects it (FIX 2425). A
//! candidate dropped after its correction was decided, because it does not
//! build or because selection never readies it, keeps the record of that
//! decision, as a written claim and an open-conflict marker keep theirs.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::ParsedCandidate;
use super::corrections::Correction;

/// One decided candidate per row. Key: the attempt's id16 + u64be(the
/// candidate's position in the attempt's extraction).
const DECIDED: SideTable<([u8; 16], u64), DecidedCandidate, Named> =
    SideTable::new(&side_table::DREAMER_CANDIDATE_DECISION);

/// One candidate's decided correction as the attempt keeps it: the ids it
/// names and its kept decisions, never its value. Each decision's receipt
/// names the evidence the pack read, the candidate's turns among it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedCandidate {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub(crate) subject: EntityId,
    /// The listed claim the decisions bound it to; none when they bound none.
    #[serde(default, with = "crate::entity_id::serde_hex::optional")]
    pub(crate) corrects: Option<EntityId>,
    pub(crate) decisions: Vec<KeptDecision>,
}

impl Vault {
    /// Every candidate `attempt` decided a correction for (FIX 11306), each
    /// with its position in the attempt's extraction, in that order, read in
    /// `txn`. Unscoped: the read door judges who sees which.
    pub(crate) fn decided_candidates_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Vec<(u64, DecidedCandidate)>> {
        Ok(DECIDED
            .scan_from(&self.store, txn, attempt.as_bytes())?
            .into_iter()
            .map(|((_, position), row)| (position, row))
            .collect())
    }
}

/// Keeps every candidate of `parsed` whose correction was decided, at
/// `attempt`, in one write, before the branch builds, filters or selects any
/// of them. A candidate the pack asked nothing about has no row.
pub(super) fn record_decided_candidates(
    vault: &Vault,
    attempt: AttemptId,
    parsed: &[ParsedCandidate<'_>],
    corrections: &[Correction],
) -> Result<()> {
    let rows: Vec<(u64, DecidedCandidate)> = parsed
        .iter()
        .zip(corrections)
        .enumerate()
        .filter(|(_, (_, correction))| !correction.decisions.is_empty())
        .map(|(position, (candidate, correction))| {
            (
                u64::try_from(position).unwrap_or(u64::MAX),
                DecidedCandidate {
                    subject: candidate.subject,
                    corrects: correction.corrects,
                    decisions: correction.decisions.clone(),
                },
            )
        })
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        let _hold = crate::dreamer_consolidation::stage_log::WriterHold::start("resolve decided");
        for (position, row) in &rows {
            DECIDED.put(&vault.store, txn, &(*attempt.as_bytes(), *position), row)?;
        }
        Ok(())
    })
}
