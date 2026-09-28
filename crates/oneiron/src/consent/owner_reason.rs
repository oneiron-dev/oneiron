//! Owner-authenticated confirm reasons, bounded rule rows, and their derived grants.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::GateDecisionId;

use super::bound::GrantBound;
use super::doors::AuthenticatedOwner;
use super::effect::{ComposedEffect, ConsentDecision};
use super::grant::ConsentReceipt;

mod selection;

use self::selection::{ReasonCandidate, ReasonSelection, select_reason};

/// One owner-reason rule row. Key: grant ref `:` rule decision id.
const RULES: SideTable<RuleKey, RuleRow, Named> =
    SideTable::new(&side_table::CONSENT_OWNER_REASON_RULE);
const MAX_REASON_BYTES: usize = 1024;

/// A host-supplied, authenticated confirm payload. `notice_text` is supplied by
/// the host for localization; engine code contains no fixed user-facing copy.
pub struct OwnerReasonConfirm<'a> {
    pub reason: Option<&'a str>,
    pub notice_text: &'a str,
}

/// What an owner confirmation wrote, including the one-tap undo when a reason
/// created a rule and grant. A reasonless confirmation only approves once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerReasonConfirmation {
    pub receipt: ConsentReceipt,
    pub notice_text: Option<String>,
    pub undo: Option<OwnerReasonUndo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerReasonUndo {
    pub command: String,
    pub grant_ref: String,
    pub rule_decision_id: GateDecisionId,
}

pub const OWNER_REASON_UNDO_COMMAND: &str = "consent.undo_owner_reason";

/// A model's confidence is advice only. A confident answer still needs an
/// active, owner-stamped grant containing the exact required bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonMatchConfidence {
    Confident,
    Unsure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerReasonVerdict {
    Auto {
        rung: crate::llm::decision::DecisionRung,
        reason: String,
        receipt: ConsentReceipt,
    },
    Ask {
        prefill: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRow {
    version: u8,
    grant_ref: String,
    reason: String,
    decision_id: [u8; 16],
    actor: [u8; 16],
    authentication_id: [u8; 16],
    retired: bool,
}

/// [`RULES`]' key: the derived grant's ref, `:`, then the rule's 16-byte decision id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleKey {
    grant_ref: String,
    decision_id: [u8; 16],
}

impl RuleKey {
    /// The key bytes every rule of one grant starts with.
    fn grant_prefix(grant_ref: &str) -> Vec<u8> {
        let mut key = grant_ref.as_bytes().to_vec();
        key.push(b':');
        key
    }
}

impl SideKey for RuleKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::grant_prefix(&self.grant_ref));
        out.extend_from_slice(&self.decision_id);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (head, decision_id) = bytes.split_at_checked(bytes.len().checked_sub(16)?)?;
        Some(Self {
            grant_ref: String::decode_key(head.strip_suffix(b":")?)?,
            decision_id: decision_id.try_into().ok()?,
        })
    }
}

/// A rule row is refused unless its bounds hold and it names its own key.
fn check(key: &RuleKey, row: &RuleRow) -> Result<()> {
    if row.version != 1
        || row.reason.trim().is_empty()
        || row.reason.len() > MAX_REASON_BYTES
        || key.grant_ref != row.grant_ref
        || key.decision_id != row.decision_id
    {
        return Err(Error::CorruptedIndex("owner reason rule"));
    }
    Ok(())
}

/// Any revocation of the derived grant retires its rule in the same transaction.
/// The rule remains for audit and old receipt resolution, but never matches again.
pub(super) fn retire_owner_reason_rules_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
) -> Result<()> {
    let mut rows = Vec::new();
    for entry in RULES.iter_from(store, &*txn, &RuleKey::grant_prefix(grant_ref))? {
        let (key, mut row) = entry?;
        check(&key, &row)?;
        if !row.retired {
            row.retired = true;
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RULES.put(store, txn, &key, &row)?;
    }
    Ok(())
}

impl Vault {
    /// An optional reason on the authenticated confirm. The bound is the
    /// engine-composed requirement, not a class inferred by a model. A reason
    /// mints that exact class/envelope as one standing grant and a rule row in
    /// the same transaction. An unsure re-ask can re-mint its active derived
    /// grant, retiring the predecessor rule. Unrelated active grants cannot
    /// be replaced through this reason door.
    pub fn confirm_owner_reason(
        &self,
        owner: &AuthenticatedOwner,
        effect: &ComposedEffect,
        bound: &GrantBound,
        payload: OwnerReasonConfirm<'_>,
    ) -> Result<OwnerReasonConfirmation> {
        let digest = effect.digest();
        let Some(reason) = payload.reason else {
            return self.with_write_txn(|txn| {
                owner.revalidate_in_txn(self, &*txn)?;
                let receipt = self.approve_once_in_txn(txn, owner, digest)?;
                Ok(OwnerReasonConfirmation {
                    receipt,
                    notice_text: None,
                    undo: None,
                })
            });
        };
        let reason = reason.trim();
        if reason.is_empty()
            || reason.len() > MAX_REASON_BYTES
            || payload.notice_text.trim().is_empty()
        {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "invalid owner reason or notice",
            )));
        }
        if effect.catastrophe().is_some()
            || ![effect.action_requirement(), effect.disclosure_requirement()]
                .into_iter()
                .flatten()
                .any(|required| required == bound)
        {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "reason must bind the exact non-catastrophe effect requirement",
            )));
        }
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let grant_ref = bound.digest().to_hex();
            if let Some(grant) = self.consent_grant_in_txn(&*txn, &grant_ref)?
                && grant.is_active()
            {
                // Only the live rule that derived THIS grant permits an
                // in-moment re-ask. A same-bound independent re-mint retires
                // that rule in the shared mint door, even with the same owner
                // authentication; it cannot be silently replaced here.
                let mut derived = false;
                for entry in
                    RULES.iter_from(&self.store, &*txn, &RuleKey::grant_prefix(&grant_ref))?
                {
                    let (key, rule) = entry?;
                    check(&key, &rule)?;
                    if !rule.retired
                        && rule.actor == *owner.actor().as_bytes()
                        && rule.actor == *grant.owner_stamp.actor.as_bytes()
                        && rule.authentication_id == grant.owner_stamp.decision_id.as_bytes()
                        && grant.grant.bound() == bound
                    {
                        derived = true;
                        break;
                    }
                }
                if !derived {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "reason would replace an unrelated standing grant",
                    )));
                }
            }
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound.clone())?;
            let row = RuleRow {
                version: 1,
                grant_ref: grant_ref.clone(),
                reason: reason.to_owned(),
                decision_id: receipt.decision_id().as_bytes(),
                actor: owner.actor().as_bytes().to_owned(),
                authentication_id: owner.decision_id().as_bytes(),
                retired: false,
            };
            let key = RuleKey {
                grant_ref: grant_ref.clone(),
                decision_id: row.decision_id,
            };
            RULES.put(&self.store, txn, &key, &row)?;
            Ok(OwnerReasonConfirmation {
                undo: Some(OwnerReasonUndo {
                    command: OWNER_REASON_UNDO_COMMAND.to_owned(),
                    grant_ref,
                    rule_decision_id: receipt.decision_id(),
                }),
                receipt,
                notice_text: Some(payload.notice_text.to_owned()),
            })
        })
    }

    /// Retire exactly the rule named by its original confirm and revoke its
    /// derived grant atomically. A stale undo cannot revoke a replacement.
    pub fn undo_owner_reason(
        &self,
        owner: &AuthenticatedOwner,
        action: &OwnerReasonUndo,
    ) -> Result<ConsentReceipt> {
        if action.command != OWNER_REASON_UNDO_COMMAND {
            return Err(Error::Gate(GateError::ConsentGrantNotFound));
        }
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let key = RuleKey {
                grant_ref: action.grant_ref.clone(),
                decision_id: action.rule_decision_id.as_bytes(),
            };
            let row = RULES
                .get(&self.store, &*txn, &key)?
                .ok_or(Error::Gate(GateError::ConsentGrantNotFound))?;
            check(&key, &row)?;
            if row.retired
                || row.decision_id != action.rule_decision_id.as_bytes()
                || row.actor != *owner.actor().as_bytes()
            {
                return Err(Error::Gate(GateError::ConsentGrantNotFound));
            }
            let grant = self
                .consent_grant_in_txn(&*txn, &row.grant_ref)?
                .ok_or(Error::Gate(GateError::ConsentGrantNotFound))?;
            if grant.owner_stamp.decision_id.as_bytes() != row.authentication_id
                || *grant.owner_stamp.actor.as_bytes() != row.actor
            {
                return Err(Error::Gate(GateError::ConsentGrantNotFound));
            }
            if !super::doors::revoke_standing_grant_in_txn(&self.store, txn, &row.grant_ref)? {
                return Err(Error::Gate(GateError::ConsentGrantRevoked));
            }
            let receipt = ConsentReceipt::Revoked {
                decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
                grant_ref: row.grant_ref,
            };
            self.append_consent_receipt_in_txn(txn, owner, &receipt)?;
            Ok(receipt)
        })
    }

    /// Only a live matching rule may answer a confident ask. An unsure match
    /// carries its nearest same-class reason for the host's prefill. No reason
    /// on record asks; the model can neither create nor widen a grant.
    pub fn evaluate_owner_reason(
        &self,
        effect: &ComposedEffect,
        confidence: ReasonMatchConfidence,
    ) -> Result<OwnerReasonVerdict> {
        self.with_write_txn(|txn| {
            let mut rules = Vec::new();
            let mut candidates = Vec::new();
            for entry in RULES.iter_from(&self.store, &*txn, &[])? {
                let (key, rule) = entry?;
                check(&key, &rule)?;
                let Some(grant) = self.consent_grant_in_txn(&*txn, &rule.grant_ref)? else {
                    return Err(Error::CorruptedIndex("owner reason grant"));
                };
                if rule.retired
                    || !grant.is_active()
                    || *grant.owner_stamp.actor.as_bytes() != rule.actor
                    || grant.owner_stamp.decision_id.as_bytes() != rule.authentication_id
                {
                    continue;
                }
                let mut relevant = false;
                for required in [effect.action_requirement(), effect.disclosure_requirement()]
                    .into_iter()
                    .flatten()
                {
                    if let Some(candidate) = ReasonCandidate::new(
                        rules.len(),
                        grant.grant.bound().clone(),
                        required.clone(),
                        rule.decision_id,
                    ) {
                        candidates.push(candidate);
                        relevant = true;
                    }
                }
                if relevant {
                    rules.push(rule);
                }
            }
            let (rule_index, covering) = match select_reason(&candidates) {
                ReasonSelection::Covering(index) => (index, true),
                ReasonSelection::PrefillOnly(index) => (index, false),
                ReasonSelection::None => return Ok(OwnerReasonVerdict::Ask { prefill: None }),
            };
            let rule = &rules[rule_index];
            if !covering {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: Some(rule.reason.clone()),
                });
            }
            if confidence == ReasonMatchConfidence::Unsure || effect.catastrophe().is_some() {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: Some(rule.reason.clone()),
                });
            }
            let grants = self.active_standing_consent_grants_in_txn(&*txn)?;
            if super::effect::evaluate_consent(effect, None, &grants) != ConsentDecision::Auto {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: Some(rule.reason.clone()),
                });
            }
            let receipt = self.record_owner_reason_use_in_txn(
                txn,
                &rule.grant_ref,
                rule.decision_id,
                &rule.reason,
                effect.digest(),
            )?;
            Ok(OwnerReasonVerdict::Auto {
                rung: crate::llm::decision::DecisionRung::Rule,
                reason: rule.reason.clone(),
                receipt,
            })
        })
    }
}
