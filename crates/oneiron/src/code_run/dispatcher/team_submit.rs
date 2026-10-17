//! `self.team.submit` (OF-540): a team's leader submits one pinned output of
//! its team for the owner's acceptance review. The host writes one Proposed
//! review claim, the Gate parks it for the owner, and the review binds to the
//! team in the same writer, so the owner's answer settles the team on the
//! inbox's existing path. Only an explicit submit writes a review; nothing is
//! inferred from a run's end or a task's completion. The review stands in the
//! scope the output was recorded under ([`super::team_submit_output`]), never
//! the vault's default.

use std::cell::Cell;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::HostSelfDispatcher;
use super::team_submit_output::output_descriptor_in_txn;
use crate::attempt_queue::AttemptId;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::team_submit::{
    OutputRevision, TEAM_DELIVERABLE_REVIEW_PREDICATE, TeamSubmitAnswer, TeamSubmitInput,
};
use crate::code_run::{SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::team::{
    TeamDeliverableBinding, bind_team_deliverable_in_txn, team_receipt, team_run_binding,
};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EntityId, TimeRange,
};

/// Domain of a review claim's id: one id per (leader, team, output), so a
/// repeat submit finds its first review rather than writing a second.
const TEAM_SUBMIT_REVIEW_ID_DOMAIN: &[u8] = b"oneiron:self-team-submit-review:v1";

/// Longest team ref a team receipt is kept under; a longer one names no team.
const MAX_TEAM_REF_BYTES: usize = 256;

type Submitted = std::result::Result<TeamSubmitAnswer, &'static str>;

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_team_submit(
        &self,
        input: TeamSubmitInput,
    ) -> Result<SelfDispatchOutcome> {
        Ok(match self.team_submit(input)? {
            Ok(answer) => SelfDispatchOutcome::TeamSubmitted(answer),
            Err(code) => SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::Team,
                error: code.to_owned(),
            }),
        })
    }

    fn team_submit(&self, input: TeamSubmitInput) -> Result<Submitted> {
        let Some(leader) = self.agent_parent else {
            return Ok(Err("team_unbound"));
        };
        // A review is a durable record: an off-record run writes none.
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Err("team_off_record"));
        };
        let Some(output) = OutputRevision::parse(&input.output_revision) else {
            return Ok(Err("team_submit_invalid_output"));
        };
        let team = input.team;
        // Early typed refusals. The binder checks the receipt and the leader
        // again in the review's own writer.
        if team.is_empty()
            || team.len() > MAX_TEAM_REF_BYTES
            || team_receipt(vault, &team)?.is_none()
        {
            return Ok(Err("team_submit_unrecorded"));
        }
        let led_prefix = format!("team:{}:", bytes_to_hex_lower(leader.as_bytes()));
        if !team.starts_with(&led_prefix) && team_run_binding(vault, leader, &team)?.is_none() {
            return Ok(Err("team_submit_not_led"));
        }
        // The output as one snapshot reads it: proven, with the scope its own
        // recorded claim carries. The writer reads it again before it writes.
        let descriptor = {
            let rtxn = vault.store.env.read_txn()?;
            match output_descriptor_in_txn(vault, &rtxn, output)? {
                Ok(descriptor) => descriptor,
                Err(code) => return Ok(Err(code)),
            }
        };
        let subject = descriptor.subject();
        let output_revision = output.canonical();
        let review = review_claim_id(leader, &team, &output_revision)?;
        let value = review_value(&team, &output_revision, leader);
        let (envelope, run_group) = self.team_submit_envelope(vault, leader)?;
        // The review takes the output's scope, so it is never wider than
        // what it asks about.
        let candidate = descriptor.scoped(
            ClaimCandidate::new(
                TEAM_DELIVERABLE_REVIEW_PREDICATE,
                ClaimSubject::Entity(subject),
                value.clone(),
                1.0,
            )
            // The review cites the output it asks about, which the landing
            // proves exists in this writer.
            .with_evidence(encode_consolidation_evidence(
                &ConsolidationEvidenceEnvelope {
                    refs: vec![subject],
                    chain: Vec::new(),
                    source_meet: ClaimSource::Generated,
                },
            )),
        );
        let is_review = |body: &ClaimBody| {
            body.predicate == TEAM_DELIVERABLE_REVIEW_PREDICATE
                && body.subject == ClaimSubject::Entity(subject)
                && body.value == value
                && descriptor.scopes(body)
        };
        let now = crate::unix_seconds_now();
        let refusal = Cell::new(None);
        let replay = Cell::new(false);
        let written = vault.put_claim_candidate_with_landing_and_after_apply(
            &review,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            |txn| {
                // The output still stands as it was read, in the same scope.
                // One that changed under the submit is answered as missing.
                let unproven = match output_descriptor_in_txn(vault, txn, output)? {
                    Ok(current) => (current != descriptor).then_some("team_submit_output_missing"),
                    Err(code) => Some(code),
                };
                if unproven.is_some() {
                    refusal.set(unproven);
                    return Err(stopped());
                }
                // A repeat submit of this output finds its first review and
                // never rewrites it. Only a review of this output in its
                // scope replays.
                if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &review)?
                    .is_some()
                {
                    if vault
                        .get_claim_in_txn(txn, &review)
                        .ok()
                        .flatten()
                        .is_some_and(|body| is_review(&body))
                    {
                        replay.set(true);
                    } else {
                        refusal.set(Some("team_submit_id_occupied"));
                    }
                    return Err(stopped());
                }
                Ok(())
            },
            |vault, txn, id| {
                // The review binds only as written, in the output's scope.
                let stored = vault
                    .get_claim_in_txn(txn, id)?
                    .ok_or(Error::EntityNotFound)?;
                if !is_review(&stored)
                    || stored.approval != ClaimApprovalStatus::Proposed
                    || stored.lifecycle != ClaimLifecycleStatus::Active
                {
                    return Err(Error::InvariantViolation(
                        "team submit review stored other than written",
                    ));
                }
                // Proposed is not pending: only the Gate's own owner-review
                // attachment, on this content and in the run's inbox group,
                // puts the review before the owner. An allowing policy, or
                // none, attaches nothing, and the submit writes nothing.
                let attached = match vault.store.pending_gate_consent_in_txn(txn, id)? {
                    Some(pending) => {
                        let (diff_handle, read_frontier_hash) =
                            crate::gate::claim_consent_binding_parts(&vault.store, txn, &stored)?;
                        pending.diff_handle == diff_handle
                            && pending.read_frontier_hash == read_frontier_hash
                            && pending.dreamer_run_id.as_deref() == Some(run_group.as_str())
                    }
                    None => false,
                };
                if !attached {
                    refusal.set(Some("team_submit_unreviewed"));
                    return Err(stopped());
                }
                let binding = TeamDeliverableBinding::acceptance(
                    team.clone(),
                    leader,
                    output_revision.clone(),
                    *id,
                    &stored,
                    now,
                )?;
                bind_team_deliverable_in_txn(vault, txn, &binding)
            },
        );
        let answer = |already_submitted| TeamSubmitAnswer {
            team: team.clone(),
            output_revision: output_revision.clone(),
            review_claim: review.to_hex(),
            already_submitted,
        };
        if replay.get() {
            return Ok(Ok(answer(true)));
        }
        if let Some(code) = refusal.get() {
            return Ok(Err(code));
        }
        written?;
        Ok(Ok(answer(false)))
    }
}

/// The error a landing or after-apply refusal aborts the writer with; the
/// caller answers the refusal it recorded instead.
fn stopped() -> Error {
    Error::InvalidClaimBody("team submit refused in its writer")
}

/// The review's value: what the owner is asked to accept, and whose work it
/// is. The leader is the bound attempt, never the guest's word.
fn review_value(team: &str, output_revision: &str, leader: AttemptId) -> Value {
    Value::Map(vec![
        (Value::from("review"), Value::from("acceptance")),
        (Value::from("team"), Value::from(team)),
        (Value::from("outputRevision"), Value::from(output_revision)),
        (
            Value::from("leader"),
            Value::from(bytes_to_hex_lower(leader.as_bytes())),
        ),
    ])
}

/// The review claim's id: a domain-separated, length-prefixed digest of the
/// leader, the team and the output. A digest that lands on a reserved
/// sentinel is re-salted rather than truncated into one.
fn review_claim_id(leader: AttemptId, team: &str, output_revision: &str) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(TEAM_SUBMIT_REVIEW_ID_DOMAIN);
        hasher.update([salt]);
        for part in [
            leader.as_bytes().as_slice(),
            team.as_bytes(),
            output_revision.as_bytes(),
        ] {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("team submit review id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "team submit review id derivation failed",
    ))
}
