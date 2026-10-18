//! Late credit over the run's recorded, actually-used derived-from edges.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::learning::{Anchor, LearningCell, LearningPredicate};
use crate::learning_setting::{self, CREDIT_DECAY, SettingMode};
use crate::ports::{EdgeDirection, EdgeStore};
use crate::receipt::{PackAttributionFields, UsedProvenanceEdge};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

pub(super) const CREDIT_RECEIPT: SideTable<String, LateCreditReceipt, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_LATE_CREDIT);

/// One fractional share, with its complete eligible used chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LateCreditShare {
    pub subject: EntityId,
    pub origin_skill: Option<EntityId>,
    pub chain: Vec<UsedProvenanceEdge>,
    pub decay: f64,
    pub weight: f64,
}

/// An anchored projection's receipt. Empty shares explicitly record no late
/// credit, including disabled credit, an environment verdict or an unclear one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LateCreditReceipt {
    pub receipt_id: String,
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub anchor: Anchor,
    pub succeeded: bool,
    pub axis: String,
    pub at: u64,
    /// The goal revision the outcome was checked under, as the host froze it;
    /// `None` is unscoped credit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_revision: Option<String>,
    pub attribution: PackAttributionFields,
    pub direct_subjects: Vec<EntityId>,
    pub shares: Vec<LateCreditShare>,
}

/// Reads the recorded chains and shares, never reconstructing them from a
/// subsequently changed provenance graph or learned decay setting.
pub fn late_credit_receipt(vault: &Vault, receipt_id: &str) -> Result<Option<LateCreditReceipt>> {
    let txn = vault.store.env.read_txn()?;
    CREDIT_RECEIPT.get(&vault.store, &txn, &receipt_id.to_owned())
}

pub(super) fn receipt_id(attempt: &str, outcome: &str, axis: &str) -> String {
    let mut hash = blake3::Hasher::new_derive_key("oneiron pack outcome credit v1");
    for text in [attempt, outcome, axis] {
        hash.update(&(text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    format!("credit:{}", hash.finalize().to_hex())
}

fn ancestors_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    origin: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut seen = BTreeSet::from([origin]);
    let mut queue = VecDeque::from([origin]);
    while let Some(node) = queue.pop_front() {
        for edge in vault.port_edge_neighbors(
            txn,
            &node,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            usize::MAX,
        )? {
            if seen.insert(edge.target) {
                queue.push_back(edge.target);
            }
        }
    }
    Ok(seen)
}

fn decay_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &PackAttributionFields,
    skill: EntityId,
) -> Result<f64> {
    // A pin always wins, including over a task-local learned fit.
    if let Some(pin) =
        learning_setting::owner_row_value(&vault.store, txn, &CREDIT_DECAY, SettingMode::Pin)?
    {
        return Ok(pin);
    }
    let cell = LearningCell::new(LearningPredicate::Setting, fields.project.unwrap_or(skill))
        .setting_key(CREDIT_DECAY.key)
        .type_ref(fields.type_ref.clone());
    if let Some(fit) = crate::learning::read::own_estimate_in_txn(vault, txn, &cell)?
        && fit.runs > 0.0
    {
        return Ok(fit.mean().clamp(CREDIT_DECAY.min, CREDIT_DECAY.max));
    }
    learning_setting::setting_value_in_txn(&vault.store, txn, &CREDIT_DECAY)
}

/// A beneficiary gets at most its strongest path from one anchored outcome.
/// Two paths to the same ancestor are not two independent runs.
pub(super) fn shares_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &PackAttributionFields,
    contributing_skills: &[EntityId],
) -> Result<Vec<LateCreditShare>> {
    if !fields.credit.enabled || fields.credit.depth_cap == Some(0) {
        return Ok(Vec::new());
    }
    let mut used = BTreeMap::<EntityId, Vec<&UsedProvenanceEdge>>::new();
    for edge in &fields.used_edges {
        let exists = vault
            .port_edge_neighbors(
                txn,
                &edge.derived,
                EdgeDirection::Out,
                Some(EdgeKind::DerivedFrom),
                usize::MAX,
            )?
            .iter()
            .any(|stored| stored.target == edge.source);
        if !exists {
            return Err(Error::InvalidClaimBody(
                "a used provenance edge must exist in lineage",
            ));
        }
        if edge.check.as_ref().is_some_and(|check| !check.contributed)
            || fields.credit.check_every_hop && edge.check.is_none()
        {
            continue;
        }
        used.entry(edge.derived).or_default().push(edge);
    }
    let mut shares = BTreeMap::<EntityId, LateCreditShare>::new();
    let mut origins: Vec<_> = contributing_skills.iter().copied().map(Some).collect();
    if origins.is_empty() && fields.output.is_some() {
        origins.push(None);
    }
    for skill in origins {
        let decay = decay_in_txn(vault, txn, fields, skill.unwrap_or(fields.pattern))?;
        if decay <= 0.0 {
            continue;
        }
        // No skill earns evidence from a success by its own descendant.
        // This check uses full lineage, not only the run's eligible subgraph.
        let own_ancestors = match skill {
            Some(skill) => ancestors_in_txn(vault, txn, skill)?,
            None => BTreeSet::new(),
        };
        let mut roots: Vec<_> = skill.into_iter().collect();
        if let Some(output) = fields.output
            && !roots.contains(&output)
        {
            roots.push(output);
        }
        let mut queue: VecDeque<(EntityId, Vec<UsedProvenanceEdge>)> =
            roots.into_iter().map(|root| (root, Vec::new())).collect();
        let mut reached = BTreeSet::new();
        while let Some((node, chain)) = queue.pop_front() {
            if !reached.insert(node) {
                continue;
            }
            if fields
                .credit
                .depth_cap
                .is_some_and(|cap| chain.len() >= cap as usize)
            {
                continue;
            }
            for edge in used.get(&node).into_iter().flatten() {
                if reached.contains(&edge.source) {
                    continue;
                }
                let mut path = chain.clone();
                path.push((**edge).clone());
                let weight = path.iter().fold(1.0, |share, _| share * decay);
                if weight <= 0.0 {
                    continue;
                }
                let subject = edge.source;
                let is_skill = vault.get_raw_in(txn, &subject)?.and_then(|raw| {
                    crate::batch::EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
                }) == Some(crate::registry::ENTITY_TYPE_SKILL);
                if is_skill
                    && !own_ancestors.contains(&subject)
                    && vault.get_skill_record_in_txn(txn, &subject)?.is_some()
                {
                    let share = LateCreditShare {
                        subject,
                        origin_skill: skill,
                        chain: path.clone(),
                        decay,
                        weight,
                    };
                    if shares
                        .get(&subject)
                        .is_none_or(|previous| previous.weight < weight)
                    {
                        shares.insert(subject, share);
                    }
                }
                queue.push_back((subject, path));
            }
        }
    }
    Ok(shares.into_values().collect())
}
