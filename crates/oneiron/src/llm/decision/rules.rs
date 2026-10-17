//! The host's rule rows (ARCH-0076 #fit-ask, DEC-0006): a reason the authenticated owner
//! types with an answer lands as a rule row, and the Rule rung answers the next ask of that
//! same question about the same evidence from it. A row is advice, never a grant: it answers
//! one typed question, and every gate after the answer still holds.
//!
//! A row keeps every revision. The owner's next reason on the same question and evidence is
//! its next revision, the owner's revoke stops it answering, and a receipt names the
//! revision that answered as id@revision (ARCH-0040, "a rule row as id@version").

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::ladder::{DecisionCall, DecisionProvider, ProviderDecision, validate_pin};
use super::types::invalid;
use super::{
    AnswerContract, DecisionAnswer, DecisionAsk, DecisionQuestion, DecisionRung, ProviderPin,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains::DECISION_HOST_RULE;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Every revision of every rule row, keyed by the rule's id and its revision.
const RULES: SideTable<(EntityId, u64), HostRule, Named> =
    SideTable::new(&side_table::DECISION_HOST_RULE);

/// The longest reason a rule row keeps, in bytes: the consent confirm's reason bound.
pub const MAX_RULE_REASON_BYTES: usize = 1_024;

/// What the Rule rung reports for the answer a standing row gives: certain of the answer
/// the owner gave (P(yes) 1 or 0 for yes/no, 1 for any other answer).
const RULE_CERTAINTY: f64 = 1.0;

/// One revision of a rule row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    #[serde(with = "super::codec::entity")]
    pub id: EntityId,
    /// From 1.
    pub revision: u32,
    /// The question it answers, pinned whole: a new wording, contract or version is a new
    /// question, and this row does not answer it.
    pub question: DecisionQuestion,
    /// The evidence the ask was about, in the order it was asked.
    #[serde(with = "super::codec::entities")]
    pub evidence: Vec<EntityId>,
    pub answer: DecisionAnswer,
    /// The owner's reason, as typed.
    pub reason: String,
    /// The ask whose answer wrote this revision.
    #[serde(with = "super::codec::entity")]
    pub ask: EntityId,
    pub ask_seq: u64,
    /// The owner who wrote it.
    #[serde(with = "super::codec::entity")]
    pub by: EntityId,
    /// Vault clock seconds when it was written.
    pub written_at: u64,
    /// Vault clock seconds when the owner revoked it; none while it stands.
    pub revoked_at: Option<u64>,
}

/// One revision of one rule row, as a receipt names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuleRef {
    #[serde(with = "super::codec::entity")]
    pub id: EntityId,
    pub revision: u32,
}

impl HostRule {
    #[must_use]
    pub fn rule_ref(&self) -> HostRuleRef {
        HostRuleRef {
            id: self.id,
            revision: self.revision,
        }
    }

    /// The Rule rung's answer from this row.
    fn decision(&self) -> ProviderDecision {
        let probability = match self.answer {
            DecisionAnswer::Noul(false) => 1.0 - RULE_CERTAINTY,
            _ => RULE_CERTAINTY,
        };
        ProviderDecision {
            answer: self.answer.clone(),
            probability: Some(probability),
            paired: None,
            person: None,
            served: None,
        }
    }
}

/// The id of the rule row for `question` asked about `evidence`.
fn rule_id(question: &DecisionQuestion, evidence: &[EntityId]) -> Result<EntityId> {
    let version = question.version.to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(evidence.len() + 2);
    parts.push(question.id.as_bytes());
    parts.push(&version);
    parts.extend(evidence.iter().map(|id| id.as_bytes().as_slice()));
    EntityId::derive(DECISION_HOST_RULE, &parts)
}

/// A reason as a rule row keeps it: trimmed, none when blank, refused past
/// [`MAX_RULE_REASON_BYTES`].
pub(super) fn rule_reason(reason: Option<&str>) -> Result<Option<&str>> {
    let Some(reason) = reason.map(str::trim).filter(|reason| !reason.is_empty()) else {
        return Ok(None);
    };
    if reason.len() > MAX_RULE_REASON_BYTES {
        return Err(invalid("invalid decision rule reason"));
    }
    Ok(Some(reason))
}

impl Vault {
    /// The standing rule row for `question` asked about `evidence`: its latest revision,
    /// unless the owner revoked it.
    pub fn host_rule_for(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<Option<HostRule>> {
        let id = rule_id(question, evidence)?;
        let txn = self.store.env.read_txn()?;
        Ok(self.latest_host_rule_in_txn(&txn, id)?.filter(|row| {
            row.revoked_at.is_none() && row.question == *question && row.evidence == evidence
        }))
    }

    /// One revision of a rule row, as a receipt names it.
    pub fn host_rule(&self, rule: HostRuleRef) -> Result<Option<HostRule>> {
        let txn = self.store.env.read_txn()?;
        RULES.get(&self.store, &txn, &(rule.id, u64::from(rule.revision)))
    }

    /// Every rule row at its latest revision, revoked ones included, in id order.
    pub fn host_rules(&self) -> Result<Vec<HostRule>> {
        let txn = self.store.env.read_txn()?;
        let mut rows: Vec<HostRule> = Vec::new();
        for row in RULES.iter_from(&self.store, &txn, &[])? {
            let (_, row) = row?;
            match rows.last_mut() {
                Some(last) if last.id == row.id => *last = row,
                _ => rows.push(row),
            }
        }
        Ok(rows)
    }

    /// The owner revokes rule `id`: its latest revision stops answering, and the next ask
    /// of its question goes up the ladder again. None when there is no such rule; revoking
    /// a revoked rule returns it as it stands.
    pub fn revoke_host_rule(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<Option<HostRule>> {
        let at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let Some(mut row) = self.latest_host_rule_in_txn(txn, id)? else {
                return Ok(None);
            };
            if row.revoked_at.is_none() {
                row.revoked_at = Some(at);
                RULES.put(&self.store, txn, &(id, u64::from(row.revision)), &row)?;
            }
            Ok(Some(row))
        })
    }

    /// Writes the owner's `reason` for answering `ask` with `answer` as the next revision of
    /// its rule row, in the transaction that keeps the answer. The same answer and reason
    /// on a standing row writes nothing and names that row. An answer found in an image (a
    /// box or a point) writes none: a row binds no image.
    pub(super) fn write_host_rule_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ask: &DecisionAsk,
        answer: &DecisionAnswer,
        reason: &str,
        by: EntityId,
        written_at: u64,
    ) -> Result<Option<HostRuleRef>> {
        if matches!(
            ask.question.contract,
            AnswerContract::Box | AnswerContract::Point
        ) {
            return Ok(None);
        }
        let id = rule_id(&ask.question, &ask.evidence)?;
        let latest = self.latest_host_rule_in_txn(txn, id)?;
        if let Some(row) = latest
            .as_ref()
            .filter(|row| row.revoked_at.is_none() && row.answer == *answer && row.reason == reason)
        {
            return Ok(Some(row.rule_ref()));
        }
        let revision = latest
            .map_or(Some(1), |row| row.revision.checked_add(1))
            .ok_or_else(|| invalid("decision rule revisions exhausted"))?;
        let row = HostRule {
            id,
            revision,
            question: ask.question.clone(),
            evidence: ask.evidence.clone(),
            answer: answer.clone(),
            reason: reason.to_owned(),
            ask: ask.id,
            ask_seq: ask.seq,
            by,
            written_at,
            revoked_at: None,
        };
        RULES.put(&self.store, txn, &(id, u64::from(revision)), &row)?;
        Ok(Some(row.rule_ref()))
    }

    fn latest_host_rule_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<HostRule>> {
        Ok(RULES
            .iter_rev_from(&self.store, txn, id.as_bytes())?
            .next()
            .transpose()?
            .map(|(_, row)| row))
    }
}

/// The host's Rule rung over the vault's rule rows, read on every call, so an owner's
/// reason answers the next ask without a restart and a revoke stops it at once. A question
/// with no standing row has no rule here: it abstains, and the ladder takes it on.
pub struct HostRuleProvider {
    pin: ProviderPin,
    vault: Arc<Vault>,
}

impl HostRuleProvider {
    pub fn new(vault: Arc<Vault>, model: String, version: String) -> Result<Self> {
        let pin = ProviderPin {
            rung: DecisionRung::Rule,
            model,
            version,
        };
        validate_pin(&pin, DecisionRung::Rule)?;
        Ok(Self { pin, vault })
    }

    /// The row standing for `call`. A row binds no image or clip, so a call that reads one
    /// has none.
    fn standing(&self, call: &DecisionCall<'_>) -> Result<Option<HostRule>> {
        if !call.images.is_empty() || !call.audio.is_empty() {
            return Ok(None);
        }
        self.vault.host_rule_for(call.question, call.evidence)
    }
}

impl DecisionProvider for HostRuleProvider {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        Ok(match self.standing(call)? {
            Some(row) => row.decision(),
            None => ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
                served: None,
            },
        })
    }

    fn rule_row(
        &self,
        call: &DecisionCall<'_>,
        decision: &ProviderDecision,
    ) -> Option<HostRuleRef> {
        self.standing(call)
            .ok()
            .flatten()
            .filter(|row| row.answer == decision.answer)
            .map(|row| row.rule_ref())
    }
}
