//! Skill-filtered label anchors and their native read sources.

use std::collections::BTreeSet;

use super::{JudgeLabel, LABELS};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// `skill` and every revision it superseded, through admitted succession
/// (`Supersedes`, new to old): the revisions whose human picks are this
/// revision's anchor. A fork is another skill and carries none.
fn label_lineage_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
) -> Result<(BTreeSet<EntityId>, Option<Vec<EntityId>>)> {
    let mut lineage = BTreeSet::from([skill]);
    let mut next = vec![skill];
    let mut sources = Some(Vec::new());
    while let Some(revision) = next.pop() {
        let (peers, edge_sources) = vault.filtered_edge_peers_sourced(
            txn,
            crate::ports::EdgeDirection::Out,
            &revision,
            EdgeKind::Supersedes,
            Some(crate::registry::ENTITY_TYPE_SKILL),
        )?;
        sources = crate::attempt_queue::source_rows::union_source_rows([sources, edge_sources]);
        for older in peers {
            if lineage.insert(older) {
                next.push(older);
            }
        }
    }
    Ok((lineage, sources))
}

/// List labels for one skill and campaign, the picks its superseded
/// revisions took included. The persisted anchor is only these rows, never
/// the proposed asks, and never a pick a rubric edit left waiting on its
/// person's re-grade. Order is stable by ask identity.
pub fn judge_label_anchor(
    vault: &Vault,
    skill: EntityId,
    campaign: &str,
) -> Result<Vec<JudgeLabel>> {
    Ok(judge_label_anchor_sourced(vault, skill, campaign)?.0)
}

/// The same anchor scan, including every decoded label and lineage source.
pub(crate) fn judge_label_anchor_sourced(
    vault: &Vault,
    skill: EntityId,
    campaign: &str,
) -> Result<(Vec<JudgeLabel>, Option<Vec<EntityId>>)> {
    let txn = vault.store.env.read_txn()?;
    let (lineage, lineage_sources) = label_lineage_sourced_in_txn(vault, &txn, skill)?;
    let mut labels = Vec::new();
    let mut actual = Vec::new();
    for row in LABELS.iter_from(&vault.store, &txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        actual.push(label.row_id);
        if label.in_anchor() && lineage.contains(&label.ask.skill) && label.ask.campaign == campaign
        {
            labels.push(label);
        }
    }
    let sources =
        crate::attempt_queue::source_rows::union_source_rows([lineage_sources, Some(actual)]);
    Ok((labels, sources))
}

/// Every label in one skill's anchor, whatever campaign asked it and
/// whichever of its superseded revisions it was asked on: the human picks
/// the skill-edit gate measures the judge against. Order is stable by ask
/// identity.
pub(crate) fn skill_label_anchor(vault: &Vault, skill: EntityId) -> Result<Vec<JudgeLabel>> {
    Ok(skill_label_anchor_sourced(vault, skill)?.0)
}

/// The same whole-skill scan, including rows excluded from the anchor.
pub(crate) fn skill_label_anchor_sourced(
    vault: &Vault,
    skill: EntityId,
) -> Result<(Vec<JudgeLabel>, Option<Vec<EntityId>>)> {
    let txn = vault.store.env.read_txn()?;
    let (lineage, lineage_sources) = label_lineage_sourced_in_txn(vault, &txn, skill)?;
    let mut labels = Vec::new();
    let mut actual = Vec::new();
    for row in LABELS.iter_from(&vault.store, &txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        actual.push(label.row_id);
        if label.in_anchor() && lineage.contains(&label.ask.skill) {
            labels.push(label);
        }
    }
    let sources =
        crate::attempt_queue::source_rows::union_source_rows([lineage_sources, Some(actual)]);
    Ok((labels, sources))
}
