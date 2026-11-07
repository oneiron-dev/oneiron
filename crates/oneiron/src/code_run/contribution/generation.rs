//! A pair's inputs, settled before either fork is paid for, and each
//! fork generated once and kept before it is scored. A fork's call reads
//! the capsule's route prompt from its body just before it is sent, and
//! lends it to that call alone (FIX 6255): a prompt that does not read is
//! no fork, paid for nothing, and is never sent as some other prompt.

use super::super::replay_capsule::{CapsuleRequest, ExposureSlot, ReplayRung};
use super::super::shadow_runner::{ShadowUnavailable, ShadowUnavailableReason};
use super::super::storage::{capsule_request, capsule_route_prompt, store_fork_response};
use super::ancestor::{TargetStep, target_slots};
use super::execution::freeze_program_step;
use super::{
    ContributionForkReceipt, ContributionReplayUnavailable, FORK_RECEIPT_PREFIX, ForkRows,
    ForkScoring, ForkScoringIdentity, ForkTreatment, Outcome, Prepared, Runner, anchor_hash,
    request_hash, without_exposure,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::learning::Anchor;

impl Runner<'_> {
    /// A pair's inputs, settled before either fork is paid for: a knowledge
    /// pair's here, a callable's or a delivery's ([`Self::prepare_caller`],
    /// FIX 3608) once its anchor is one a pair replays.
    pub(super) fn prepare(&self, rows: &ForkRows, step: TargetStep) -> Outcome<Prepared> {
        use ContributionReplayUnavailable as Unavailable;
        // An owner verdict's pair is generated here like any other and
        // judged by the owner (FIX 3609); a world outcome is not replayed.
        if !matches!(
            self.candidate.anchor,
            Anchor::HeldOut | Anchor::Audit { .. } | Anchor::OwnerVerdict
        ) {
            return Ok(Err(Unavailable::AnchorNotReplayable));
        }
        let target = self.candidate.target;
        let capsule = match step {
            TargetStep::Knowledge(Ok(capsule)) => capsule,
            TargetStep::Knowledge(Err(reason)) => return Ok(Err(reason)),
            TargetStep::Caller(caller) => return self.prepare_caller(rows, *caller),
        };
        // An erased capsule's content went with its actor (FIX 6144): none of
        // its rung, exposures or request is read, and the pair is unreadable.
        if capsule.content.actor().is_none() {
            return Ok(Err(Unavailable::Unreadable));
        }
        let Some(binding) = capsule.binding.clone() else {
            return Ok(Err(Unavailable::CapsuleNotFinalized));
        };
        let slots: Vec<&ExposureSlot> = target_slots(&capsule, target);
        let Some(first) = slots.first() else {
            // A target the run was shown only on a browser observation has no
            // span to leave out (FIX 11436).
            let site =
                crate::skill_attribution::site_exposed(self.vault, capsule.run, target.removed())?;
            return Ok(Err(if site {
                Unavailable::SiteObservation
            } else {
                Unavailable::NoExposure
            }));
        };
        if slots.iter().any(|slot| slot.revision != first.revision) {
            return Ok(Err(Unavailable::AmbiguousExposure));
        }
        // The pair is admitted against the target's current record: one that
        // moved on since the step cannot be recorded, and its old body is
        // never rebuilt from the new one.
        let current = self
            .vault
            .get_skill_record(&target.removed())?
            .map(|record| format!("{}@{}", record.skill_id, record.version));
        if current.as_deref() != Some(first.revision.as_str()) {
            return Ok(Err(Unavailable::SkillRevisionMoved));
        }
        let exposure_revision = first.revision.clone();
        let Some(with_skill) = capsule_request(self.vault, &capsule)? else {
            return Ok(Err(
                if matches!(&capsule.request, CapsuleRequest::Kept { erased: true, .. }) {
                    Unavailable::Erased
                } else {
                    Unavailable::Unreadable
                },
            ));
        };
        let Some(without_skill) = without_exposure(&with_skill, &slots) else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let anchor = match self.scorer.resolve(self.vault, self.candidate)? {
            Ok(anchor) => anchor,
            Err(reason) => return Ok(Err(reason)),
        };
        // An engine step's window is frozen once here, before either fork.
        let frozen_program = freeze_program_step(self.vault, &capsule, self.program)?;
        let anchor_scoring = ForkScoringIdentity::of(&anchor)?;
        let anchor_hash = anchor_hash(self.candidate, &anchor_scoring)?;
        if [&rows.with_skill, &rows.without_skill]
            .into_iter()
            .flatten()
            .any(|fork| fork.anchor != anchor_hash || fork.capsule_request != capsule.request_hash)
        {
            return Ok(Err(Unavailable::ForksDiverged));
        }
        Ok(Ok(Prepared {
            with_skill_hash: request_hash(&with_skill)?,
            without_skill_hash: request_hash(&without_skill)?,
            exposure_revision,
            capsule,
            binding,
            with_skill,
            without_skill,
            anchor,
            anchor_scoring,
            anchor_hash,
            frozen_program,
        }))
    }

    /// The fork as stored, else generated now and kept before it is scored.
    /// A fork its writer does not keep is unavailable for that writer's own
    /// reason (FIX 6256): a subject gone now is `Unfinished`, never a
    /// lasting `Unreadable`, so a restore before a later writer cannot make
    /// the stop permanent.
    pub(super) fn generated(
        &self,
        prepared: &Prepared,
        stored: Option<ContributionForkReceipt>,
        treatment: ForkTreatment,
    ) -> Outcome<ContributionForkReceipt> {
        if let Some(fork) = stored {
            return Ok(Ok(fork));
        }
        if !self.clock.decision_may_start() {
            return Ok(Err(ContributionReplayUnavailable::Unfinished));
        }
        let (request, hash) = match treatment {
            ForkTreatment::WithSkill => (&prepared.with_skill, prepared.with_skill_hash),
            ForkTreatment::WithoutSkill => (&prepared.without_skill, prepared.without_skill_hash),
        };
        // The route prompt, read again from its body before the call.
        let rung = match capsule_route_prompt(self.vault, &prepared.capsule)? {
            Ok(prompt) => ReplayRung::of(&prepared.binding, prompt),
            Err(unavailable) => return Ok(Err(prompt_unavailable(&unavailable))),
        };
        let Some(response) = self.model.generate(request, &rung, self.clock)? else {
            return Ok(Err(ContributionReplayUnavailable::ModelUnavailable));
        };
        let capsule = &prepared.capsule;
        // The receipt and path are opaque, not descendants of any target id.
        let receipt_id = bytes_to_hex_lower(&self.vault.store.clock.ulid()?);
        let path_id = bytes_to_hex_lower(&self.vault.store.clock.ulid()?);
        let path = format!("replay/contribution/{path_id}.response.json");
        // Publication and its discoverable erase ownership commit together.
        store_fork_response(
            self.vault,
            capsule,
            &self.pair,
            &self.provenance,
            treatment,
            &path,
            &response,
            |response_ref| ContributionForkReceipt {
                receipt: format!("{FORK_RECEIPT_PREFIX}{receipt_id}"),
                treatment,
                attempt: capsule.attempt,
                lease_generation: capsule.lease_generation,
                step: capsule.step,
                capsule_request: capsule.request_hash,
                request: hash,
                model: prepared.binding.model.clone(),
                route_prompt: prepared.binding.stored_prompt_hash(),
                seed: capsule.seed,
                seed_unsupported: capsule.seed.is_none(),
                response: response_ref,
                response_path: path.clone(),
                response_erased: false,
                anchor: prepared.anchor_hash,
                anchor_scoring: prepared.anchor_scoring,
                scoring: ForkScoring::of(self.candidate),
                execution: None,
                score: None,
                generated_at: crate::unix_seconds_now(),
            },
        )
    }
}

/// Why a pair is unavailable when its capsule's route prompt does not read
/// (FIX 6255): `Erased` once a restore retired its body, `Unreadable` for a
/// prompt withheld, released, marked or no longer its hash.
fn prompt_unavailable(unavailable: &ShadowUnavailable) -> ContributionReplayUnavailable {
    match unavailable.reason {
        ShadowUnavailableReason::SourceErased => ContributionReplayUnavailable::Erased,
        _ => ContributionReplayUnavailable::Unreadable,
    }
}
