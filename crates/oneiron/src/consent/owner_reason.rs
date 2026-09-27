//! Owner-authenticated confirm reasons, bounded rule rows, and their derived grants.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::store::GateDecisionId;

use super::bound::{BoundEnvelope, GrantBound};
use super::doors::AuthenticatedOwner;
use super::effect::{ComposedEffect, ConsentDecision};
use super::grant::ConsentReceipt;

const RULE_PREFIX: &[u8] = b"consent.owner_reason.v1:";
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

fn grant_prefix(grant_ref: &str) -> Vec<u8> {
    let mut key = RULE_PREFIX.to_vec();
    key.extend_from_slice(grant_ref.as_bytes());
    key.push(b':');
    key
}

fn key(grant_ref: &str, decision_id: &[u8; 16]) -> Vec<u8> {
    let mut key = grant_prefix(grant_ref);
    key.extend_from_slice(decision_id);
    key
}

fn decode(raw: &[u8], key_bytes: &[u8]) -> Result<RuleRow> {
    let row: RuleRow =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("owner reason rule"))?;
    if row.version != 1
        || row.reason.trim().is_empty()
        || row.reason.len() > MAX_REASON_BYTES
        || key_bytes != key(&row.grant_ref, &row.decision_id)
    {
        return Err(Error::CorruptedIndex("owner reason rule"));
    }
    Ok(row)
}

/// Rank same-class candidates for ASK prefill only, never for authority.
/// The grant's actual containment still decides confident automatic reuse.
fn prefill_proximity(recorded: &GrantBound, required: &GrantBound) -> usize {
    let (selectors, candidate, same_target) = match (recorded.envelope(), required.envelope()) {
        (BoundEnvelope::Action(a), BoundEnvelope::Action(b)) => (
            a.selectors(),
            b.selectors(),
            a.target().is_some() && a.target() == b.target(),
        ),
        (BoundEnvelope::Disclosure(a), BoundEnvelope::Disclosure(b)) => {
            (a.selectors(), b.selectors(), false)
        }
        _ => return 0,
    };
    usize::from(same_target) * 2
        + candidate
            .iter()
            .filter(|selector| selectors.binary_search(selector).is_ok())
            .count()
}

/// Any revocation of the derived grant retires its rule in the same transaction.
/// The rule remains for audit and old receipt resolution, but never matches again.
pub(super) fn retire_owner_reason_rules_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
) -> Result<()> {
    let prefix = grant_prefix(grant_ref);
    let mut rows = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, &prefix)? {
        let (key, raw) = entry?;
        let mut row = decode(&raw, &key)?;
        if !row.retired {
            row.retired = true;
            rows.push((
                key.to_vec(),
                rmp_serde::to_vec_named(&row)
                    .map_err(|_| Error::InvariantViolation("owner reason encoding"))?,
            ));
        }
    }
    for (key, raw) in rows {
        store.vault_meta.put(txn, &key, &raw)?;
    }
    Ok(())
}

impl Vault {
    /// An optional reason on the authenticated confirm. The bound is the
    /// engine-composed requirement, not a class inferred by a model. A reason
    /// mints that exact class/envelope as one standing grant and a rule row in
    /// the same transaction. Reconfirming an active grant is refused so undo
    /// cannot accidentally revoke an unrelated earlier grant.
    pub fn confirm_owner_reason(
        &self,
        owner: &AuthenticatedOwner,
        effect: &ComposedEffect,
        bound: &GrantBound,
        payload: OwnerReasonConfirm<'_>,
    ) -> Result<OwnerReasonConfirmation> {
        let digest = effect.digest();
        let Some(reason) = payload.reason else {
            let receipt = self.approve_once(owner, digest)?;
            return Ok(OwnerReasonConfirmation {
                receipt,
                notice_text: None,
                undo: None,
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
            let grant_ref = bound.digest().to_hex();
            if self
                .consent_grant_in_txn(&*txn, &grant_ref)?
                .is_some_and(|row| row.is_active())
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "reason would replace an active standing grant",
                )));
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
            let encoded = rmp_serde::to_vec_named(&row)
                .map_err(|_| Error::InvariantViolation("owner reason encoding"))?;
            self.store
                .vault_meta
                .put(txn, &key(&grant_ref, &row.decision_id), &encoded)?;
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
            let k = key(&action.grant_ref, &action.rule_decision_id.as_bytes());
            let raw = self
                .store
                .vault_meta
                .get(&*txn, &k)?
                .ok_or(Error::Gate(GateError::ConsentGrantNotFound))?;
            let row = decode(&raw, &k)?;
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
            let required = effect
                .action_requirement()
                .or_else(|| effect.disclosure_requirement());
            let mut nearest: Option<(usize, [u8; 16], String)> = None;
            let mut exact = None;
            for entry in self.store.vault_meta.prefix_iter(&*txn, RULE_PREFIX)? {
                let (k, raw) = entry?;
                let rule = decode(&raw, &k)?;
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
                let Some(required) = required else {
                    continue;
                };
                let bound = grant.grant.bound();
                if bound.contains(required) {
                    exact = Some(rule);
                    break;
                }
                if bound.domain() == required.domain()
                    && bound.subject() == required.subject()
                    && bound.class() == required.class()
                {
                    let score = prefill_proximity(bound, required);
                    if nearest
                        .as_ref()
                        .is_none_or(|(best, id, _)| (score, rule.decision_id) > (*best, *id))
                    {
                        nearest = Some((score, rule.decision_id, rule.reason));
                    }
                }
            }
            let Some(rule) = exact else {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: nearest.map(|(_, _, reason)| reason),
                });
            };
            if confidence == ReasonMatchConfidence::Unsure || effect.catastrophe().is_some() {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: Some(rule.reason),
                });
            }
            let grants = self.active_standing_consent_grants_in_txn(&*txn)?;
            if super::effect::evaluate_consent(effect, None, &grants) != ConsentDecision::Auto {
                return Ok(OwnerReasonVerdict::Ask {
                    prefill: Some(rule.reason),
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
                reason: rule.reason,
                receipt,
            })
        })
    }
}
