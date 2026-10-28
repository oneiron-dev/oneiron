//! Late credit over the run's recorded, actually-used derived-from edges.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::learning::Anchor;
use crate::learning_setting::CREDIT_DECAY;
use crate::ports::{EdgeDirection, EdgeStore};
use crate::receipt::{PackAttributionFields, UsedProvenanceEdge};
use crate::side_table::{self, Named, SideTable};
use crate::{Result, Vault};

pub(super) const CREDIT_RECEIPT: SideTable<String, LateCreditReceipt, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_LATE_CREDIT);

/// One fractional share, with its complete eligible used chain. An erase
/// redacts only the ids it names (FIX 8988): the share keeps its decay and
/// weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LateCreditShare {
    /// The credited skill; `None` once that skill is erased.
    pub subject: Option<EntityId>,
    /// The contributing skill the chain starts from; `None` for the run's
    /// output root, and once that skill is erased, which clears the chain too.
    pub origin_skill: Option<EntityId>,
    /// The used chain; `None` once an erased entity is one of its ends.
    pub chain: Option<Vec<UsedProvenanceEdge>>,
    pub decay: f64,
    pub weight: f64,
}

/// An anchored projection's receipt. Empty shares explicitly record no late
/// credit, including disabled credit, an environment verdict or an unclear one.
/// It is sealed: what later checks and late landings make of it is appended
/// beside it, with the `credit_decay` it was projected under
/// ([`super::CreditAdjustmentReceipt`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The run's frozen attribution; `None` once an erased entity is one it
    /// names (FIX 8988).
    pub attribution: Option<PackAttributionFields>,
    /// Each subject credited directly; `None` for one since erased.
    pub direct_subjects: Vec<Option<EntityId>>,
    pub shares: Vec<LateCreditShare>,
}

/// Reads the recorded chains and shares, never reconstructing them from a
/// subsequently changed provenance graph or learned decay setting.
pub fn late_credit_receipt(vault: &Vault, receipt_id: &str) -> Result<Option<LateCreditReceipt>> {
    let txn = vault.store.env.read_txn()?;
    CREDIT_RECEIPT.get(&vault.store, &txn, &receipt_id.to_owned())
}

/// The stored projection for one anchored outcome, using the projector's key.
/// This read never runs attribution or mints a receipt.
pub fn late_credit_receipt_for_outcome(
    vault: &Vault,
    attempt: &str,
    outcome: &str,
    axis: &str,
) -> Result<Option<LateCreditReceipt>> {
    late_credit_receipt(vault, &receipt_id(attempt, outcome, axis))
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

/// The `credit_decay` an outcome of the run `fields` attributes is credited
/// under (FIX 10107): the shared scoped read over the run's project, its
/// goal and its task type, read only through `txn`, so the owner's pin or
/// seed at any of those scopes governs it, then a fit the Coach recorded
/// there ([`super::decay_fit`]), then the vault's.
///
/// # Errors
///
/// Storage errors.
pub(super) fn credit_decay_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &PackAttributionFields,
) -> Result<f64> {
    crate::learning_setting::setting_value_in_scope_in_txn(
        vault,
        txn,
        &CREDIT_DECAY,
        fields.project,
        Some(&fields.type_ref),
    )
}

/// A beneficiary gets at most its strongest path from one anchored outcome.
/// Two paths to the same ancestor are not two independent runs. A used edge
/// lineage no longer holds (an erase between the run's close and its outcome)
/// is a hop skipped, with the credit only it reached (FIX 3105, OF-397): the
/// outcome's other credit stands. Every origin's chain decays by the
/// outcome's frozen `decay`.
pub(super) fn shares_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &PackAttributionFields,
    contributing_skills: &[EntityId],
    decay: f64,
) -> Result<Vec<LateCreditShare>> {
    if !fields.credit.enabled || fields.credit.depth_cap == Some(0) || decay <= 0.0 {
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
        if !exists
            || edge.check.as_ref().is_some_and(|check| !check.contributed)
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
                        subject: Some(subject),
                        origin_skill: skill,
                        chain: Some(path.clone()),
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

/// Redacts erased `entity` from every late-credit receipt that names it
/// (FIX 8988): a direct subject or share subject it names is kept in erased
/// form, a chain it ends reads as erased, and a frozen attribution naming it
/// is cleared. Each receipt keeps its anchor, outcome, time and every share
/// it does not name. A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_late_credit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, mut credit) in super::skill_erase::erase_scan_in_txn(vault, wtxn, CREDIT_RECEIPT)? {
        if redact_credit(&mut credit, *entity) {
            CREDIT_RECEIPT.put(&vault.store, wtxn, &key, &credit)?;
        }
    }
    Ok(())
}

/// `credit` with `entity` redacted wherever it names it; whether it did.
fn redact_credit(credit: &mut LateCreditReceipt, entity: EntityId) -> bool {
    let mut named = false;
    if credit
        .attribution
        .as_ref()
        .is_some_and(|fields| crate::learning::pack_attribution_names(fields, entity))
    {
        credit.attribution = None;
        named = true;
    }
    for subject in &mut credit.direct_subjects {
        if *subject == Some(entity) {
            *subject = None;
            named = true;
        }
    }
    redact_shares(&mut credit.shares, entity) || named
}

/// `shares` with `entity` redacted wherever one names it: its subject or
/// origin reads `None`, and a chain it ends or starts reads as erased.
/// Whether any did.
pub(super) fn redact_shares(shares: &mut [LateCreditShare], entity: EntityId) -> bool {
    let mut named = false;
    for share in shares {
        if share.subject == Some(entity) {
            share.subject = None;
            named = true;
        }
        if share.origin_skill == Some(entity) {
            share.origin_skill = None;
            share.chain = None;
            named = true;
        }
        if share.chain.as_ref().is_some_and(|chain| {
            chain
                .iter()
                .any(|edge| edge.derived == entity || edge.source == entity)
        }) {
            share.chain = None;
            named = true;
        }
    }
    named
}
