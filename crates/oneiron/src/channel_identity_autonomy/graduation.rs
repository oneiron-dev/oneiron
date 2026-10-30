//! Offer-only graduation: scope value and its shared ramp scope, attributed review evidence (agent and owner doors), receipt-backed review validation, the streak evaluation against the shared offer policy and owner answers, and the owner's decline doors.

use rmpv::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::consent_graduation::RampScope;
use crate::edit_distance::graduation::{self as shared, SnoozeState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;

use super::codec::{AUTONOMY, address, array, id, id_value, key, text, token};
use super::invalid_autonomy;
use super::types::{
    ChannelIdentityAutonomyRung, DEFAULT_GRADUATION_UNCHANGED_STREAK, DraftReviewOutcome,
    GraduationEvidence, GraduationOffer, GraduationScopeKey, PREDICATE_GRADUATION_EVIDENCE,
};

/// The op-kind prefix of a channel identity's graduation scope in the shared
/// offer machinery, before the scope's verb class.
const RAMP_OP_KIND_PREFIX: &str = "channel_identity.";

impl GraduationScopeKey {
    /// This scope in the shared offer machinery: op kind
    /// `channel_identity.<verb class>`, target class the handle its evidence
    /// rows are keyed under, actor the acting agent. Owner threshold rows, the
    /// answer log (snooze, backoff, manual pin) and the shared unpin door
    /// (`edit_distance::graduation::unpin_scope_as_owner`) name the scope by it.
    pub fn ramp_scope(&self) -> Result<RampScope> {
        RampScope::new(
            format!("{RAMP_OP_KIND_PREFIX}{}", self.verb_class),
            scope_handle(self)?.to_hex(),
            self.actor_ref.to_hex(),
        )
    }
}

/// The handle a scope's evidence rows are keyed under.
fn scope_handle(scope: &GraduationScopeKey) -> Result<EntityId> {
    address("scope", &scope_value(scope)?)
}

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
        self.record_graduation_evidence_by(evidence, actor.entity_ref(), None)
    }

    /// Owner-attributed review/correction. A caller-asserted Human WriteActor
    /// is not owner authentication and cannot use this exception.
    pub fn record_graduation_evidence_as_owner(
        &self,
        evidence: GraduationEvidence,
        owner: &AuthenticatedOwner,
    ) -> Result<EntityId> {
        let actor = self.autonomy_owner(owner)?;
        self.record_graduation_evidence_by(evidence, actor, Some(owner))
    }

    /// `owner` is the proof an owner-attributed review carries: the writing
    /// transaction checks it again, so a revocation that commits first
    /// records nothing.
    fn record_graduation_evidence_by(
        &self,
        evidence: GraduationEvidence,
        writer: EntityId,
        owner: Option<&AuthenticatedOwner>,
    ) -> Result<EntityId> {
        let scope = scope_value(&evidence.scope)?;
        token(&evidence.receipt_ref)?;
        if evidence.occurred_at > self.store.clock.now_recorded_at() {
            return Err(invalid_autonomy());
        }
        let (task_ref, outcome, distance) = self.validate_graduation_review(&evidence)?;
        let mut txn = self.store.env.write_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
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
            Value::from(owner.is_some()),
            id_value(task_ref),
        ]);
        if AUTONOMY.contains(&self.store, &txn, &key)? {
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
    // ambiguous receipt id: the lookup reads every durable outbound row, with
    // no result limit, so the id must name exactly one of them.
    fn validate_graduation_review(
        &self,
        evidence: &GraduationEvidence,
    ) -> Result<(EntityId, &'static str, Value)> {
        let matches = self.outbound_receipts_with_id(&evidence.receipt_ref)?;
        let [receipt] = matches.as_slice() else {
            return Err(invalid_autonomy());
        };
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

    /// Evaluation against the shared offer policy and the owner's answers. The
    /// proposal retains the existing draft volume bound; acceptance must use
    /// owner consent.
    ///
    /// Each task contributes only its latest `(occurred_at, receipt_ref)` review,
    /// independent of admission order; a later correction replaces its old
    /// outcome. The streak is the run of approved-untouched tasks since the
    /// newest correction and since the owner's last decline; the corrections
    /// are every other task. A runtime threshold row governing
    /// [`GraduationScopeKey::ramp_scope`] decides with its streak and posterior
    /// guard. With none, the streak alone meets `unchanged_streak`, and zero
    /// selects the pinned default of twelve. A scope the owner snoozed or
    /// pinned to manual offers nothing until the snooze ends or the pin clears.
    pub fn evaluate_graduation_offer(
        &self,
        scope: &GraduationScopeKey,
        unchanged_streak: u32,
        now: u64,
    ) -> Result<Option<GraduationOffer>> {
        let ramp = scope.ramp_scope()?;
        let recorded_now = self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        self.graduation_offer_in_txn(
            &txn,
            scope,
            &ramp,
            unchanged_streak,
            now.min(recorded_now),
            recorded_now,
        )
    }

    /// The owner's "not now" on a standing identity graduation offer: a row in
    /// the shared answer log on [`GraduationScopeKey::ramp_scope`]. The offer
    /// stays unsurfaced through the owner's policy backoff, a decline past the
    /// end of that ladder pins the scope to manual, and the next offer needs
    /// its streak re-earned after this answer. The writing transaction
    /// re-evaluates `offer` with its own streak as the threshold; an offer
    /// that no longer stands records nothing.
    pub fn decline_channel_identity_graduation_offer(
        &self,
        offer: &GraduationOffer,
        owner: &AuthenticatedOwner,
    ) -> Result<SnoozeState> {
        self.record_channel_identity_offer_decline(offer, owner, false)
    }

    /// The owner's "stop asking" on a standing identity graduation offer: a
    /// manual pin, recorded as
    /// [`Self::decline_channel_identity_graduation_offer`] records a decline.
    /// Only the shared unpin door on [`GraduationScopeKey::ramp_scope`] clears
    /// it.
    pub fn pin_channel_identity_graduation_offer(
        &self,
        offer: &GraduationOffer,
        owner: &AuthenticatedOwner,
    ) -> Result<SnoozeState> {
        self.record_channel_identity_offer_decline(offer, owner, true)
    }

    fn record_channel_identity_offer_decline(
        &self,
        offer: &GraduationOffer,
        owner: &AuthenticatedOwner,
        pin: bool,
    ) -> Result<SnoozeState> {
        self.autonomy_owner(owner)?;
        let ramp = offer.scope.ramp_scope()?;
        let recorded_now = self.store.authorization_now()?;
        let mut txn = self.store.env.write_txn()?;
        if self
            .graduation_offer_in_txn(
                &txn,
                &offer.scope,
                &ramp,
                offer.unchanged_streak,
                recorded_now,
                recorded_now,
            )?
            .is_none()
        {
            return Err(invalid_autonomy());
        }
        let state = shared::record_external_offer_decline_in_txn(
            self,
            &mut txn,
            owner,
            &ramp,
            pin,
            recorded_now,
        )?;
        txn.commit()?;
        Ok(state)
    }

    fn graduation_offer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &GraduationScopeKey,
        ramp: &RampScope,
        unchanged_streak: u32,
        now: u64,
        recorded_now: u64,
    ) -> Result<Option<GraduationOffer>> {
        let prefix = key(
            PREDICATE_GRADUATION_EVIDENCE,
            &scope_handle(scope)?.to_hex(),
        );
        let mode = self.autonomy_mode_in_txn(
            txn,
            scope.identity_ref,
            scope.relationship_context,
            now,
            recorded_now,
        )?;
        if !matches!(
            mode.rung,
            ChannelIdentityAutonomyRung::DraftOnly | ChannelIdentityAutonomyRung::SendWithApproval
        ) || scope.verb_class != "mail.send"
            || self.autonomy_identity_actor(txn, scope.identity_ref)? != scope.actor_ref
            || shared::asks_are_suppressed_in_txn(&self.store, txn, ramp, now)?
        {
            return Ok(None);
        }
        let state = self.autonomy_state(txn, mode, now, recorded_now)?;
        let proposed_envelope = state.action_envelope.ok_or_else(invalid_autonomy)?;
        if proposed_envelope.counterparty_class != scope.counterparty_class {
            return Ok(None);
        }
        let streak_restart = shared::latest_decline_at_in_txn(&self.store, txn, ramp)?;
        let mut rows = Vec::new();
        for (_, row) in AUTONOMY.scan_from(&self.store, txn, &prefix)? {
            let (actor, at, value) = (row.actor, row.at, row.value);
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
        let mut corrections = 0_u32;
        let mut streak_open = true;
        let mut seen_tasks = std::collections::BTreeSet::new();
        for (at, reference, outcome, task_ref) in rows.into_iter().rev() {
            if !seen_tasks.insert(task_ref) {
                continue;
            }
            let untouched = outcome == "approved_untouched";
            if !untouched {
                corrections = corrections.saturating_add(1);
            }
            if streak_open && untouched && streak_restart.is_none_or(|restart| at > restart) {
                evidence_refs.push(reference);
            } else {
                streak_open = false;
            }
        }
        let streak = u32::try_from(evidence_refs.len()).map_err(|_| invalid_autonomy())?;
        let earned = match shared::runtime_graduation_policy_in_txn(&self.store, txn, ramp)? {
            Some(policy) => policy.is_cleared_by(streak, corrections),
            None if unchanged_streak == 0 => streak >= DEFAULT_GRADUATION_UNCHANGED_STREAK,
            None => streak >= unchanged_streak,
        };
        if !earned {
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
