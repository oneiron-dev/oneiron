//! Three consolidation lanes: free keyed equality, scoped conflicts, cosine nominations.
use super::conflict::{candidate_facts, canonical_value_bytes};
use super::provenance::source_meet;
use super::{ConflictIdentity, ConflictSet, PromotionCandidate};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateKeyRule {
    pub normalize_text: bool,
    /// A question key in a structured value. Missing means the whole predicate
    /// question, never the answer; this conservatively sends ambiguity to judge.
    pub topic_field: Option<String>,
}
pub type PredicateKeyRules = BTreeMap<String, PredicateKeyRule>;

/// Operator-set predicate key rules governing which claim keys the consolidator may fold.
/// Key: ().
pub(super) const KEY_RULES: SideTable<(), PredicateKeyRules, LegacyJson> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_KEY_RULES);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateKeys {
    pub identity: ConflictIdentity,
    pub topic_key: Vec<u8>,
    pub value_key: Vec<u8>,
}

pub fn candidate_keys(
    candidate: &PromotionCandidate,
    rules: &PredicateKeyRules,
) -> Result<CandidateKeys> {
    let facts = candidate_facts(&candidate.candidate)?;
    let rule = rules.get(&facts.predicate);
    let value = if rule.is_some_and(|r| r.normalize_text) {
        normalized_value(&facts.value)
    } else {
        facts.value.clone()
    };
    let topic = rule
        .and_then(|r| r.topic_field.as_deref())
        .and_then(|field| map_field(&value, field))
        .unwrap_or(&Value::Nil)
        .clone();
    Ok(CandidateKeys {
        identity: ConflictIdentity {
            subject: facts.subject,
            predicate: facts.predicate,
            world: facts.world,
            facet: facts.facet,
            rel: facts.rel,
            topic: facts.topic.clone(),
        },
        topic_key: facts.topic.unwrap_or(canonical_value_bytes(&topic)?),
        value_key: canonical_value_bytes(&value)?,
    })
}
fn map_field<'a>(v: &'a Value, field: &str) -> Option<&'a Value> {
    v.as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(field)).then_some(value))
}
fn normalized_value(value: &Value) -> Value {
    match value {
        Value::String(s) => s.as_str().map_or_else(
            || value.clone(),
            |s| {
                Value::from(
                    s.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase(),
                )
            },
        ),
        // Structured values preserve every qualifier (severity, recipient,
        // polarity). The equality key must not collapse reversed answers.
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), normalized_value(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(normalized_value).collect()),
        other => other.clone(),
    }
}

/// Exact keyed re-statements attach their evidence mechanically. Supersession
/// targets participate in equality so a conflicting prior is never hidden.
pub fn attach_duplicate_evidence(
    candidates: Vec<PromotionCandidate>,
    rules: &PredicateKeyRules,
) -> Result<Vec<PromotionCandidate>> {
    let mut kept: BTreeMap<(CandidateKeys, Option<EntityId>), PromotionCandidate> = BTreeMap::new();
    for candidate in candidates {
        let key = (candidate_keys(&candidate, rules)?, candidate.supersedes);
        match kept.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                existing
                    .evidence_turn_refs
                    .extend(candidate.evidence_turn_refs);
                existing.evidence_turn_refs.sort();
                existing.evidence_turn_refs.dedup();
                for hop in candidate.provenance_chain {
                    if !existing.provenance_chain.contains(&hop) {
                        existing.provenance_chain.push(hop);
                    }
                }
                existing.evidence_meet =
                    source_meet(existing.evidence_meet, candidate.evidence_meet);
                existing.learned_at = existing.learned_at.min(candidate.learned_at);
            }
        }
    }
    Ok(kept.into_values().collect())
}

/// Embeddings nominate only inside one subject/scope slice. Every result is a
/// judge question, never a merge verdict. Invalid vectors fail closed.
pub fn judge_queue(
    candidates: &[PromotionCandidate],
    embeddings: &BTreeMap<EntityId, Vec<f32>>,
    rules: &PredicateKeyRules,
    threshold: f64,
) -> Result<Vec<ConflictSet>> {
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err(Error::InvalidConfig("cosine nomination threshold".into()));
    }
    let keys = candidates
        .iter()
        .map(|c| candidate_keys(c, rules))
        .collect::<Result<Vec<_>>>()?;
    let mut parents: Vec<usize> = (0..candidates.len()).collect();
    let mut nominated = BTreeSet::new();
    for (i, a) in keys.iter().enumerate() {
        for (j, b) in keys.iter().enumerate().skip(i + 1) {
            let same_slice = a.identity.subject == b.identity.subject
                && a.identity.world == b.identity.world
                && a.identity.facet == b.identity.facet
                && a.identity.rel == b.identity.rel;
            if !same_slice {
                continue;
            }
            let conflict = a.identity == b.identity
                && a.topic_key == b.topic_key
                && a.value_key != b.value_key;
            let cross_key = a.identity != b.identity || a.topic_key != b.topic_key;
            let similar = if cross_key {
                match (
                    embeddings.get(&candidates[i].claim_id),
                    embeddings.get(&candidates[j].claim_id),
                ) {
                    (Some(a), Some(b)) => cosine(a, b)? >= threshold,
                    _ => false,
                }
            } else {
                false
            };
            if conflict || similar {
                let ai = root(&parents, i);
                let bj = root(&parents, j);
                parents[bj] = ai;
                nominated.insert(i);
                nominated.insert(j);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in nominated {
        groups.entry(root(&parents, index)).or_default().push(index);
    }
    Ok(groups
        .into_values()
        .map(|members| ConflictSet {
            identity: keys[members[0]].identity.clone(),
            candidate_indexes: members,
            prior_head: None,
            prior_heads: Vec::new(),
        })
        .collect())
}
fn root(parents: &[usize], mut i: usize) -> usize {
    while parents[i] != i {
        i = parents[i];
    }
    i
}
fn cosine(a: &[f32], b: &[f32]) -> Result<f64> {
    if a.len() != b.len() || a.is_empty() || a.iter().chain(b).any(|v| !v.is_finite()) {
        return Err(Error::InvalidConfig("invalid nomination embedding".into()));
    }
    let mut dot = 0.0_f64;
    let mut an = 0.0_f64;
    let mut bn = 0.0_f64;
    for (a, b) in a.iter().zip(b) {
        let a = f64::from(*a);
        let b = f64::from(*b);
        dot += a * b;
        an += a * a;
        bn += b * b;
    }
    if an == 0.0 || bn == 0.0 {
        return Err(Error::InvalidConfig("zero nomination embedding".into()));
    }
    Ok((dot / (an.sqrt() * bn.sqrt())).clamp(-1.0, 1.0))
}
impl Vault {
    pub fn consolidation_key_rules(&self) -> Result<PredicateKeyRules> {
        let txn = self.store.env.read_txn()?;
        match KEY_RULES.get(&self.store, &txn, &())? {
            Some(rules) => Ok(rules),
            None => serde_json::from_str(include_str!("key_defaults.json"))
                .map_err(|_| Error::CorruptedIndex("default key rules")),
        }
    }
    pub fn set_consolidation_key_rules(&self, rules: &PredicateKeyRules) -> Result<()> {
        self.with_write_txn(|txn| {
            KEY_RULES.put(&self.store, txn, &(), rules)?;
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests;
