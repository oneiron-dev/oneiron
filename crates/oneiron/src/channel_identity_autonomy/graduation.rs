//! Offer-only graduation: scope value, attributed review evidence (agent and owner doors), receipt-backed review validation, and the streak evaluation.

use rmpv::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::write_envelope::WriteActor;

use super::codec::{address, array, id, id_value, key, text, token};
use super::invalid_autonomy;
use super::types::{
    ChannelIdentityAutonomyRung, DEFAULT_GRADUATION_UNCHANGED_STREAK, DraftReviewOutcome,
    GraduationEvidence, GraduationOffer, GraduationScopeKey, PREDICATE_GRADUATION_EVIDENCE,
};

fn scope_value(scope: &GraduationScopeKey) -> Result<Value> {
    if !matches!(scope.verb_class.as_str(), "mail.draft" | "mail.send") {
        return Err(invalid_autonomy());
    }
    if let Some(c) = &scope.counterparty_class {
        token(c)?;
    }
    Ok(Value::Array(vec![
        id_value(scope.actor_ref),
        id_value(scope.identity_ref),
        Value::from(scope.relationship_context.as_str()),
        Value::from(scope.verb_class.clone()),
        scope
            .counterparty_class
            .clone()
            .map_or(Value::Nil, Value::from),
    ]))
}

impl Vault {
    /// Attributed evidence of a persisted outbound review, never caller proof.
    /// Duplicate receipts are rejected; corrections need their own review receipt.
    /// `WriteActor` supplies attribution only, not review authentication.
    pub fn record_graduation_evidence(
        &self,
        evidence: GraduationEvidence,
        actor: &WriteActor,
    ) -> Result<EntityId> {
        if actor.entity_ref() != evidence.scope.actor_ref
            || actor.actor_class() != crate::edge::EdgeActorClass::Agent
        {
            return Err(invalid_autonomy());
        }
        self.record_graduation_evidence_by(evidence, actor.entity_ref(), false)
    }

    /// Owner-attributed review/correction. A caller-asserted Human WriteActor
    /// is not owner authentication and cannot use this exception.
    pub fn record_graduation_evidence_as_owner(
        &self,
        evidence: GraduationEvidence,
        owner: &AuthenticatedOwner,
    ) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        self.record_graduation_evidence_by(evidence, owner.actor(), true)
    }

    fn record_graduation_evidence_by(
        &self,
        evidence: GraduationEvidence,
        writer: EntityId,
        owner_authenticated: bool,
    ) -> Result<EntityId> {
        let scope = scope_value(&evidence.scope)?;
        token(&evidence.receipt_ref)?;
        if evidence.occurred_at > crate::unix_seconds_now() {
            return Err(invalid_autonomy());
        }
        let (task_ref, outcome, distance) = self.validate_graduation_review(&evidence)?;
        let mut txn = self.store.env.write_txn()?;
        if self.autonomy_identity_actor(&txn, evidence.scope.identity_ref)?
            != evidence.scope.actor_ref
        {
            return Err(invalid_autonomy());
        }
        let prefix = key(
            PREDICATE_GRADUATION_EVIDENCE,
            &address("scope", &scope)?.to_hex(),
        );
        let reference = address(
            "evidence",
            &Value::Array(vec![scope, Value::from(evidence.receipt_ref.clone())]),
        )?;
        let mut key = prefix;
        key.extend_from_slice(reference.as_bytes());
        let value = Value::Array(vec![
            Value::from(evidence.receipt_ref),
            Value::from(outcome),
            distance,
            id_value(evidence.scope.actor_ref),
            Value::from(owner_authenticated),
            id_value(task_ref),
        ]);
        if self.store.vault_meta.get(&txn, &key)?.is_some() {
            return Err(invalid_autonomy());
        }
        self.write_autonomy_row(&mut txn, &key, writer, evidence.occurred_at, value)?;
        txn.commit()?;
        Ok(reference)
    }

    // A transport outcome alone is not a draft review. Eligible outbound rows
    // carry an explicit review_outcome and the exact graduation scope fields.
    // Resolve before opening the write txn: the receipt door owns its read txns
    // and send audit receipts are append-only. No actor/time filter may hide an
    // ambiguous receipt id; all durable outbound rows must remain visible.
    fn validate_graduation_review(
        &self,
        evidence: &GraduationEvidence,
    ) -> Result<(EntityId, &'static str, Value)> {
        let scan = self.scan_receipts(
            ReceiptQuery::new(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
                .with_kind(ReceiptKind::Outbound),
        )?;
        // Continuations describe omitted data, not resumable snapshot pages.
        // Without a bounded resume door, neither a missing id nor one visible
        // match proves uniqueness. Reject source AND result truncation.
        if !scan.complete {
            return Err(invalid_autonomy());
        }
        let mut matches = scan
            .records
            .iter()
            .filter(|r| r.receipt_id == evidence.receipt_ref);
        let receipt = matches.next().ok_or_else(invalid_autonomy)?;
        if matches.next().is_some() {
            return Err(invalid_autonomy());
        }
        let field = |key: &str| receipt.fields.get(key).map(String::as_str);
        let task_ref = field(crate::receipt::FIELD_TASK_REF)
            .and_then(|value| EntityId::from_hex(value).ok())
            .ok_or_else(invalid_autonomy)?;
        let (outcome, distance) = match &evidence.outcome {
            DraftReviewOutcome::ApprovedUntouched => ("approved_untouched", None),
            DraftReviewOutcome::ApprovedAmended {
                edit_distance_millis,
            } => ("approved_amended", Some(*edit_distance_millis)),
            DraftReviewOutcome::Rejected => ("rejected", None),
            DraftReviewOutcome::Undone => ("undone", None),
        };
        if receipt.actor.as_deref() != Some(evidence.scope.actor_ref.to_hex().as_str())
            || receipt.occurred_at != evidence.occurred_at
            || field("channel_identity_ref") != Some(evidence.scope.identity_ref.to_hex().as_str())
            || field("relationship_context") != Some(evidence.scope.relationship_context.as_str())
            || field("verb_class") != Some(evidence.scope.verb_class.as_str())
            || field("counterparty_class") != evidence.scope.counterparty_class.as_deref()
            || field("review_outcome") != Some(outcome)
            || field("edit_distance_millis") != distance.map(|d| d.to_string()).as_deref()
        {
            return Err(invalid_autonomy());
        }
        Ok((task_ref, outcome, distance.map_or(Value::Nil, Value::from)))
    }

    /// Pure evaluation: zero selects the pinned default of twelve. The proposal
    /// retains the existing draft volume bound; acceptance must use owner consent.
    /// Each task contributes only its latest `(occurred_at, receipt_ref)` review,
    /// independent of admission order. A later correction replaces its old outcome.
    pub fn evaluate_graduation_offer(
        &self,
        scope: &GraduationScopeKey,
        unchanged_streak: u32,
        now: u64,
    ) -> Result<Option<GraduationOffer>> {
        let threshold = if unchanged_streak == 0 {
            DEFAULT_GRADUATION_UNCHANGED_STREAK
        } else {
            unchanged_streak
        };
        let prefix = key(
            PREDICATE_GRADUATION_EVIDENCE,
            &address("scope", &scope_value(scope)?)?.to_hex(),
        );
        let txn = self.store.env.read_txn()?;
        let now = now.min(crate::unix_seconds_now());
        let mode =
            self.autonomy_mode_in_txn(&txn, scope.identity_ref, scope.relationship_context, now)?;
        if !matches!(
            mode.rung,
            ChannelIdentityAutonomyRung::DraftOnly | ChannelIdentityAutonomyRung::SendWithApproval
        ) || scope.verb_class != "mail.send"
            || self.autonomy_identity_actor(&txn, scope.identity_ref)? != scope.actor_ref
        {
            return Ok(None);
        }
        let state = self.autonomy_state(&txn, mode, now)?;
        let proposed_envelope = state.action_envelope.ok_or_else(invalid_autonomy)?;
        if proposed_envelope.counterparty_class != scope.counterparty_class {
            return Ok(None);
        }
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (key, _) = entry?;
            let (actor, at, value) = self.autonomy_row(&txn, &key)?;
            let v = array(&value, 6)?;
            let task_ref = id(&v[5])?;
            let owner_authenticated = v[4].as_bool().ok_or_else(invalid_autonomy)?;
            if id(&v[3])? != scope.actor_ref || actor != scope.actor_ref && !owner_authenticated {
                return Err(invalid_autonomy());
            }
            if at <= now {
                rows.push((
                    at,
                    text(&v[0])?.to_owned(),
                    text(&v[1])?.to_owned(),
                    task_ref,
                ));
            }
        }
        rows.sort();
        let mut evidence_refs = Vec::new();
        let mut seen_tasks = std::collections::BTreeSet::new();
        for (_, reference, outcome, task_ref) in rows.into_iter().rev() {
            if !seen_tasks.insert(task_ref) {
                continue;
            }
            if outcome != "approved_untouched" {
                break;
            }
            evidence_refs.push(reference);
        }
        let streak = u32::try_from(evidence_refs.len()).map_err(|_| invalid_autonomy())?;
        if streak < threshold {
            return Ok(None);
        }
        evidence_refs.reverse();
        Ok(Some(GraduationOffer {
            scope: scope.clone(),
            evidence_refs,
            proposed_envelope,
            unchanged_streak: streak,
            offered_at: now,
        }))
    }
}
