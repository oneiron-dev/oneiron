//! Frozen execution and actual-use facts on an attempt's pack receipt.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const ATTEMPT_ATTRIBUTION: SideTable<[u8; 16], PackAttributionFields, Named> =
    SideTable::new(&side_table::ATTEMPT_PACK_ATTRIBUTION);

/// A contribution check is distinct from loading or citing an input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionCheck {
    pub receipt: String,
    pub contributed: bool,
}

/// A derived-from edge the run actually used, directed from output to input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsedProvenanceEdge {
    pub derived: EntityId,
    pub source: EntityId,
    pub check: Option<ContributionCheck>,
}

/// An attributed contribution by a loaded skill, including a team pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillContribution {
    pub skill: EntityId,
    pub check: ContributionCheck,
}

/// The lineage-credit controls in effect for this run. No depth cap means the
/// full used chain; a zero decay or disabled credit passes no late credit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditOptions {
    pub enabled: bool,
    pub depth_cap: Option<u32>,
    pub check_every_hop: bool,
}

/// Execution context is stamped once; actual-use lists may only grow while
/// the lease is live. Every model string is an id pinned as `id@revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackAttributionFields {
    #[serde(rename = "typeRef")]
    pub type_ref: TypeRef,
    pub executor: String,
    pub judge: String,
    pub pattern: EntityId,
    pub team_shape: Vec<String>,
    pub decider: EntityId,
    pub project: Option<EntityId>,
    pub output: Option<EntityId>,
    pub contributions: Vec<SkillContribution>,
    pub used_edges: Vec<UsedProvenanceEdge>,
    pub credit: CreditOptions,
}

/// Provenance retained beside each learning evidence row, not in its cell key.
/// In particular, changing judges never forks a reliability cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackLearningContext {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub attribution: PackAttributionFields,
}

impl PackAttributionFields {
    pub fn validate(&self) -> Result<()> {
        self.type_ref.validate()?;
        for model in [&self.executor, &self.judge] {
            reference(model)?;
            if !model
                .rsplit_once('@')
                .is_some_and(|(id, rev)| !id.is_empty() && !rev.is_empty())
            {
                return Err(Error::InvalidClaimBody(
                    "pack attribution needs model ids at revisions",
                ));
            }
        }
        if self.team_shape.is_empty() {
            return Err(Error::InvalidClaimBody(
                "pack attribution needs a team shape",
            ));
        }
        for role in &self.team_shape {
            reference(role)?;
        }
        let mut skills = std::collections::BTreeSet::new();
        for contribution in &self.contributions {
            reference(&contribution.check.receipt)?;
            if !skills.insert(contribution.skill) {
                return Err(Error::InvalidClaimBody("one contribution check per skill"));
            }
        }
        let mut edges = std::collections::BTreeSet::new();
        for edge in &self.used_edges {
            if edge.derived == edge.source || !edges.insert((edge.derived, edge.source)) {
                return Err(Error::InvalidClaimBody(
                    "used provenance edges are distinct and not self edges",
                ));
            }
            if let Some(check) = &edge.check {
                reference(&check.receipt)?;
            }
        }
        Ok(())
    }

    fn extends(&self, previous: &Self) -> bool {
        let mut fixed = self.clone();
        fixed.contributions = previous.contributions.clone();
        fixed.used_edges = previous.used_edges.clone();
        if previous.output.is_none() {
            fixed.output = None;
        }
        fixed == *previous
            && self.contributions.starts_with(&previous.contributions)
            && self.used_edges.starts_with(&previous.used_edges)
    }
}

pub(crate) fn reference(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return Err(Error::InvalidClaimBody(
            "an attribution reference is 1..=256 bytes without controls",
        ));
    }
    Ok(())
}

pub(crate) fn put_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    fields: &PackAttributionFields,
) -> Result<()> {
    fields.validate()?;
    let key = *id.as_bytes();
    if let Some(previous) = ATTEMPT_ATTRIBUTION.get(store, txn, &key)?
        && !fields.extends(&previous)
    {
        return Err(Error::InvalidClaimBody(
            "pack attribution is immutable and use lists are append-only",
        ));
    }
    ATTEMPT_ATTRIBUTION.put(store, txn, &key, fields)
}

/// The live attribution row of attempt `id`, before its close takes it.
pub(crate) fn attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<Option<PackAttributionFields>> {
    ATTEMPT_ATTRIBUTION.get(store, txn, id.as_bytes())
}

pub(crate) fn has_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<bool> {
    ATTEMPT_ATTRIBUTION.contains(store, txn, id.as_bytes())
}

pub(crate) fn take_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<PackAttributionFields> {
    let key = *id.as_bytes();
    let fields = ATTEMPT_ATTRIBUTION
        .get(store, txn, &key)?
        .ok_or(Error::InvalidClaimBody(
            "an attributable attempt requires typeRef and execution context before closing",
        ))?;
    fields.validate()?;
    ATTEMPT_ATTRIBUTION.delete(store, txn, &key)?;
    Ok(fields)
}
