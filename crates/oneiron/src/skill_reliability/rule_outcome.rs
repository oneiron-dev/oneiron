//! Outcomes of a rule skill (FIX 8075): a closed-form recipe with no model
//! and no pack receipt behind its work, scored by an anchored verdict on what
//! it decided. The agent-health reviewer is one: an owner's confirmed or
//! dismissed on a card is one outcome of the revision whose policy raised it.
//! Entry: `record_rule_outcome_in_txn`, `withdraw_rule_outcome_in_txn`,
//! `rule_outcome_receipts_in_txn`.
//! A row sits on the legacy no-executor arm, keyed `(skill, receipt)`, and
//! carries the review receipt it came from in place of a pack receipt and an
//! executor. The attributed-outcome reads (selection, the brief, the
//! held-out split) take it as any outcome row; the executor projection, which
//! reads only named arms and resolves each row's pack receipt, never meets it.

use rmpv::Value;

use super::codec::{decode_value, encode_value, invalid, map_entry, map_str};
use super::ledger::OutcomeRow;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, RawValue, SideKey, SideTable};

/// The outcome ledger's rows as a rule skill writes them: the ledger's own
/// outcome row, which every ledger read decodes, plus its source.
const RULE_OUTCOME: SideTable<(EntityId, String), RuleOutcomeRow, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_OUTCOME);

/// The map key a rule row's source rides under; the outcome row's own reader
/// leaves it alone.
const KEY_SOURCE: &str = "rule_source";

/// The review receipt a rule-skill outcome came from: its id, the row's key,
/// and the card that holds it, so the row finds its receipt again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleOutcomeSource {
    /// The review receipt's id (`health_review:` and 64 hex).
    pub(crate) receipt: String,
    /// The handle of the card that holds it (`health:<subject>:<signal>:<task>`).
    pub(crate) card: String,
}

/// One rule-skill row: the outcome row and its source.
struct RuleOutcomeRow {
    outcome: OutcomeRow,
    source: RuleOutcomeSource,
}

impl RawValue for RuleOutcomeRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let Value::Map(mut row) = decode_value(&self.outcome.to_raw()?)? else {
            return Err(invalid("skill reliability outcome is not a map").into());
        };
        row.push((
            Value::from(KEY_SOURCE),
            Value::Map(vec![
                (
                    Value::from("receipt"),
                    Value::from(self.source.receipt.as_str()),
                ),
                (Value::from("card"), Value::from(self.source.card.as_str())),
            ]),
        ));
        Ok(encode_value(&Value::Map(row))?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let outcome = OutcomeRow::from_raw(bytes)?;
        let value = decode_value(bytes)?;
        let source = map_entry(&value, KEY_SOURCE)
            .and_then(|source| {
                Some(RuleOutcomeSource {
                    receipt: map_str(source, "receipt")?.to_owned(),
                    card: map_str(source, "card")?.to_owned(),
                })
            })
            .ok_or(invalid("rule skill outcome is missing its source"))?;
        Ok(Self { outcome, source })
    }
}

/// Writes one rule-skill outcome of `skill`, keyed by its source's receipt.
/// The newest verdict on a receipt replaces the one before it, so a
/// re-settle or a replay counts once.
///
/// # Errors
///
/// A source with an empty receipt id or card; storage errors.
pub(crate) fn record_rule_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    source: &RuleOutcomeSource,
    win: bool,
    at: u64,
) -> Result<()> {
    if source.receipt.is_empty() || source.card.is_empty() {
        return Err(invalid("a rule skill outcome must cite its receipt"));
    }
    RULE_OUTCOME.put(
        &vault.store,
        txn,
        &(*skill, source.receipt.clone()),
        &RuleOutcomeRow {
            outcome: OutcomeRow { win, at },
            source: source.clone(),
        },
    )
}

/// Withdraws the rule-skill outcome of `skill` that `source` wrote; `true`
/// when one stood. A row its key names from another source stays.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when the row under the receipt names another
/// source; storage errors.
pub(crate) fn withdraw_rule_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    source: &RuleOutcomeSource,
) -> Result<bool> {
    let key = (*skill, source.receipt.clone());
    let Some(row) = RULE_OUTCOME.get(&vault.store, txn, &key)? else {
        return Ok(false);
    };
    if row.source != *source {
        return Err(Error::CorruptedIndex("rule skill outcome source"));
    }
    RULE_OUTCOME.delete(&vault.store, txn, &key)
}

/// Every rule-skill outcome receipt of `skill`, in ledger order: the rows the
/// DEV posterior folds that the projected `skill.reliability` claim never
/// cites, so the optimize brief cites them from here (FIX 10879).
///
/// A row that no longer decodes is skipped with a WARN, never fatal. A row
/// without a rule source is not a rule row and is skipped silently.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn rule_outcome_receipts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<String>> {
    let mut receipts = Vec::new();
    for row in RULE_OUTCOME.iter_raw_from(&vault.store, txn, skill.as_bytes())? {
        let (key, value) = row?;
        let Some((_, receipt)) = <(EntityId, String) as SideKey>::decode_key(&key) else {
            tracing::warn!(
                skill = %skill.to_hex(),
                "a rule skill outcome key is unreadable; it was skipped"
            );
            continue;
        };
        match RuleOutcomeRow::from_raw(&value) {
            Ok(_) => receipts.push(receipt),
            Err(_) if OutcomeRow::from_raw(&value).is_ok() => {}
            Err(error) => {
                tracing::warn!(
                    skill = %skill.to_hex(),
                    receipt = %receipt,
                    ?error,
                    "a rule skill outcome is unreadable; it was skipped"
                );
            }
        }
    }
    Ok(receipts)
}
