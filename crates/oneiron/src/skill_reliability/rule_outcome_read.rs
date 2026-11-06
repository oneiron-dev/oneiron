//! The rule scanner's complete physical read set, including classification reads.

use crate::side_table::{RawValue, SideKey};
use crate::store::attempt_sources::{RuleOutcomeReadKind, RuleOutcomeReadSource};
use crate::{EntityId, Result, Vault};

use super::RuleOutcomeReadPosition;
use super::ledger::OutcomeRow;
use super::rule_outcome::{RULE_OUTCOME, RuleOutcomeRow};

pub(super) enum ClassifiedRuleOutcome {
    Rule {
        receipt: String,
        row: RuleOutcomeRow,
    },
    Outcome,
    UnreadableKey,
    UnreadableValue,
}

/// Shared with the ordinary reader: decode the key first, then the rule row,
/// then its plain-outcome fallback. Only the original damaged cases warn.
pub(super) fn classify_rule_outcome(
    skill: &EntityId,
    key: &[u8],
    value: &[u8],
) -> ClassifiedRuleOutcome {
    let Some((_, receipt)) = <(EntityId, String) as SideKey>::decode_key(key) else {
        tracing::warn!(
            skill = %skill.to_hex(),
            "a rule skill outcome key is unreadable; it was skipped"
        );
        return ClassifiedRuleOutcome::UnreadableKey;
    };
    match RuleOutcomeRow::from_raw(value) {
        Ok(row) => ClassifiedRuleOutcome::Rule { receipt, row },
        Err(_) if OutcomeRow::from_raw(value).is_ok() => ClassifiedRuleOutcome::Outcome,
        Err(error) => {
            tracing::warn!(
                skill = %skill.to_hex(),
                receipt = %receipt,
                ?error,
                "a rule skill outcome is unreadable; it was skipped"
            );
            ClassifiedRuleOutcome::UnreadableValue
        }
    }
}

pub(crate) struct CanonicalRuleOutcome {
    key: Vec<u8>,
    body: Vec<u8>,
    classified: ClassifiedRuleOutcome,
}

impl CanonicalRuleOutcome {
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn receipt(&self) -> Option<&str> {
        match &self.classified {
            ClassifiedRuleOutcome::Rule { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    pub(crate) fn row_id(&self) -> Option<EntityId> {
        match &self.classified {
            ClassifiedRuleOutcome::Rule { row, .. } => row.row_id,
            _ => None,
        }
    }

    pub(crate) fn read_position(&self) -> Option<&RuleOutcomeReadPosition> {
        match &self.classified {
            ClassifiedRuleOutcome::Rule { row, .. } => row.read_position.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn source(&self) -> RuleOutcomeReadSource {
        let kind = match &self.classified {
            ClassifiedRuleOutcome::Rule { .. } => RuleOutcomeReadKind::Rule,
            ClassifiedRuleOutcome::Outcome => RuleOutcomeReadKind::Outcome,
            ClassifiedRuleOutcome::UnreadableKey => RuleOutcomeReadKind::UnreadableKey,
            ClassifiedRuleOutcome::UnreadableValue => RuleOutcomeReadKind::UnreadableValue,
        };
        RuleOutcomeReadSource {
            key: self.key.clone(),
            body_hash: *blake3::hash(&self.body).as_bytes(),
            kind,
        }
    }
}

pub(crate) fn canonical_rule_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    receipt: &str,
) -> Result<Option<CanonicalRuleOutcome>> {
    let key = (*skill, receipt.to_owned());
    let Some(body) = RULE_OUTCOME.get_bytes(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let key = RULE_OUTCOME.key_bytes(&key);
    let classified = classify_rule_outcome(skill, &key[RULE_OUTCOME.decl().prefix.len()..], &body);
    Ok(Some(CanonicalRuleOutcome {
        key,
        body,
        classified,
    }))
}

/// Every consulted row, in the raw iterator's order, not just returned receipts.
pub(crate) fn canonical_rule_outcomes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<(Vec<CanonicalRuleOutcome>, Vec<u8>)> {
    let mut rows = Vec::new();
    for row in RULE_OUTCOME.iter_raw_from(&vault.store, txn, skill.as_bytes())? {
        let (key, body) = row?;
        let classified = classify_rule_outcome(skill, &key, &body);
        let mut full_key = RULE_OUTCOME.decl().prefix.to_vec();
        full_key.extend_from_slice(&key);
        rows.push(CanonicalRuleOutcome {
            key: full_key,
            body,
            classified,
        });
    }
    let mut prefix = RULE_OUTCOME.decl().prefix.to_vec();
    prefix.extend_from_slice(skill.as_bytes());
    Ok((rows, prefix))
}
