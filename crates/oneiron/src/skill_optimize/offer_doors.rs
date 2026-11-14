//! Typed owner doors for the production Coach offer pass and its evidence.
//! No caller supplies a finished offer or a private runner lease.
use serde::{Deserialize, Serialize};

use super::{
    EvalSeat, OfferAnswerRecord, OfferCheck, TrainingOffer, settle_training_offer, training_offer,
    training_offer_checks, training_offers, undo_training_offer_switch, union_source_rows,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::claim::maintenance_kind::COACH_HOST_QUEUE_KIND;
use crate::claim::maintenance_kind::COACH_TRAINING_OFFER_FACET;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::embed::PendingEmbedderBinding;
use crate::federation::{EngineControlActor, EngineControlClass};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// The verb that runs one offer pass now.
pub const OFFER_PASS_RUN_VERB: &str = "vault.coach.training_offers.run";

/// The run verb's refusal of a caller that is neither the live owner nor a
/// holder of the maintenance-cadence class.
fn run_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{OFFER_PASS_RUN_VERB} takes the vault owner's own proof or a live engine.controls.maintenance_cadence grant"
        ),
        &[
            "Call as the owner, or have the owner grant this agent the maintenance-cadence class of engine.controls.",
        ],
    )
}

#[doc(hidden)]
pub use oneiron_verb_wire::skill_optimize::offer_doors::{
    OfferAnswerRequest, OfferPassRef, OfferPassRequest, OfferRef, OfferUndoReceipt, TrainingRunRef,
};

/// Completion is the actual host attempt's terminal state, not the presence
/// of an offer: the skill may choose to raise none.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassResult {
    pub attempt: EntityId,
    pub state: AttemptState,
    pub terminal: bool,
    pub offers: Vec<TrainingOffer>,
}

/// `vault.coach.training_offers.run`'s input: none. The pass reads every
/// served seat's metered receipts, as the nightly pass does; the caller
/// supplies no offer body, skill, seat or lease.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassRunRequest {}

/// Who asked for a run-now pass, as its admission checked them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfferPassCaller {
    /// The vault owner, on its own proof.
    Owner { person: EntityId },
    /// A holder of the maintenance-cadence class of `engine.controls`.
    Holder { actor: EntityId },
}

/// A prerequisite a pass found missing, so it asked no model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferPassPrerequisite {
    /// The host binds no usage meter: no workload to price.
    UsageMeter,
    /// No served seat has a metered call in the evidence window.
    MeteredSeat,
    /// The day's budget of the offer pass is spent: the nightly pass and
    /// every run-now pass draw on one allowance per 24 hours.
    DayBudget,
    /// No Coach seat is served.
    CoachSeat,
    /// No loadable, approved training-offer skill is installed.
    OfferSkill,
    /// No metered seat's model has a priced catalog row and an option.
    PricedOption,
    /// No seat took the Coach's call.
    ModelCall,
}

/// What one offer pass came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "end", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfferPassEnd {
    /// The pass raised at least one offer, at most one per seat.
    Drafted,
    /// The Coach was asked and raised no offer.
    NoOffer,
    /// The pass stopped before it asked the Coach.
    Missing { prerequisite: OfferPassPrerequisite },
}

/// `vault.coach.training_offers.run`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfferPassRunAnswer {
    /// The request's own pass ran on this host: how it ended, and the ids
    /// of the offers its attempt raised. The offers themselves are the
    /// owner's to read and answer (`vault.coach.training_offers.result`).
    Ran {
        attempt: EntityId,
        caller: OfferPassCaller,
        end: OfferPassEnd,
        offers: Vec<EntityId>,
    },
    /// The queue's offer pass was not ready for this host (another pass
    /// holds its lease, or the Coach's line is spent), so none ran for this
    /// request; `vault.coach.training_offers.result` reads its state.
    Waiting { attempt: EntityId },
}

/// What admitting a run-now pass came to.
#[derive(Debug)]
pub enum OfferPassRunAdmission {
    /// The request's own Coach attempt, leased to the host that asked.
    Admitted {
        attempt: Box<DreamerAdmittedAttempt>,
        caller: OfferPassCaller,
    },
    /// The queue's offer pass is not ready for this host now; nothing runs
    /// for this request.
    Waiting { attempt: EntityId },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferListRequest {
    #[serde(default)]
    pub seat: Option<EvalSeat>,
    #[serde(default)]
    pub pending_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferView {
    pub offer: TrainingOffer,
    pub answer: Option<OfferAnswerRecord>,
    pub checks: Vec<OfferCheck>,
    /// The binding's current state, including settled and undone moves.
    /// `None` when this offer staged no embedder binding.
    pub staged: Option<PendingEmbedderBinding>,
}

/// A committed answer beside the embedder binding's current state.
/// The answer stays immutable; the binding is read for each reply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerReply {
    pub answer: OfferAnswerRecord,
    /// Waiting, filling, applied, not applied or undone; `None` when absent.
    pub staged: Option<PendingEmbedderBinding>,
}

impl OfferAnswerReply {
    /// Projects a committed answer; never call from its uncommitted writer.
    ///
    /// # Errors
    /// Storage errors while reading the current binding.
    pub fn current(vault: &Vault, answer: OfferAnswerRecord) -> Result<Self> {
        let staged = vault.embedder_binding_move(&answer.offer)?;
        Ok(Self { answer, staged })
    }
}

/// The rows the offers and checks `views` serve were drafted and checked
/// from (FIX 5482): the union of the sets their snapshots keep, `None` when
/// any is unknown. No view serves no drafted content: a known empty set.
pub fn listed_views(views: &[OfferView]) -> Option<Vec<EntityId>> {
    union_source_rows(views.iter().flat_map(|view| {
        std::iter::once(view.offer.source_rows.as_deref())
            .chain(view.checks.iter().map(|check| check.source_rows.as_deref()))
    }))
}

/// The rows a pass's offers were drafted from (FIX 5482), as
/// [`listed_views`] reads them; a pass with no offer, or no such pass,
/// serves no drafted content.
pub fn listed_pass(pass: Option<&OfferPassResult>) -> Option<Vec<EntityId>> {
    union_source_rows(
        pass.into_iter()
            .flat_map(|pass| &pass.offers)
            .map(|offer| offer.source_rows.as_deref()),
    )
}

pub fn trigger(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: OfferPassRequest,
) -> Result<OfferPassRef> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        // The nightly pass and the public trigger coalesce on the same
        // production facet. Admission stamps it for the Coach, as usual.
        let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
            txn,
            COACH_HOST_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_TRAINING_OFFER_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_TRAINING_OFFER_FACET.into()),
            None,
            now,
        )?;
        let status = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        Ok(OfferPassRef {
            attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
        })
    })
}

/// Admits `actor` for `vault.coach.training_offers.run` and, in the same
/// writer, queues the Coach's offer pass (coalescing with the one queued,
/// as [`trigger`] and the nightly pass do) and admits that very attempt on
/// `admit`'s lease and budget line. The caller is the live owner or a
/// holder of the maintenance-cadence class: running the nightly pass now
/// is a cadence act (engine_controls.rs `MaintenanceCadence`).
///
/// # Errors
///
/// FORBIDDEN for any other caller; storage and queue errors.
pub fn admit_offer_pass_run(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    _input: OfferPassRunRequest,
    admit: AdmitDreamerAttempt,
) -> MemoryResult<OfferPassRunAdmission> {
    let store = DreamerRunnerStore::new(vault);
    let requested_at = admit.now;
    let admission = vault.try_with_write_txn_grouped(|txn| -> MemoryResult<_> {
        let Some((by, owner)) = vault.engine_control_actor_in_txn(
            &*txn,
            actor,
            EngineControlClass::MaintenanceCadence,
        )?
        else {
            return Err(run_refused());
        };
        let caller = if owner {
            OfferPassCaller::Owner { person: by }
        } else {
            OfferPassCaller::Holder { actor: by }
        };
        let queued = match store.enqueue_kind_in_txn(
            txn,
            COACH_HOST_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_TRAINING_OFFER_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_TRAINING_OFFER_FACET.into()),
            None,
            requested_at,
        )? {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        let id = queued.attempt.id;
        let attempt = EntityId::from_bytes(*id.as_bytes())?;
        Ok(
            match store.admit_requested_attempt_in_txn(txn, COACH_HOST_QUEUE_KIND, id, admit)? {
                DreamerAdmissionOutcome::Admitted(admitted) => OfferPassRunAdmission::Admitted {
                    attempt: admitted,
                    caller,
                },
                _ => OfferPassRunAdmission::Waiting { attempt },
            },
        )
    })?;
    vault.store.notify_attempt_observers();
    Ok(admission)
}

/// The offers attempt `id` raised, from the offer rows that name it.
///
/// # Errors
///
/// A store error.
pub fn offers_of_attempt(vault: &Vault, attempt: EntityId) -> Result<Vec<TrainingOffer>> {
    let id = AttemptId::from_bytes(attempt.as_bytes())?;
    Ok(training_offers(vault, None)?
        .into_iter()
        .filter(|(offer, _)| offer.attempt == id)
        .map(|(offer, _)| offer)
        .collect())
}

pub fn result(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPassRef,
) -> Result<Option<OfferPassResult>> {
    owner.revalidate_person(vault)?;
    let id = AttemptId::from_bytes(input.attempt.as_bytes())?;
    let Some(status) = DreamerRunnerStore::new(vault).status(id)? else {
        return Ok(None);
    };
    if status.payload.attempt_type != COACH_TRAINING_OFFER_FACET {
        return Err(Error::InvalidConfig(
            "the attempt is not a Coach offer pass".into(),
        ));
    }
    let offers = training_offers(vault, None)?
        .into_iter()
        .filter(|(offer, _)| offer.attempt == id)
        .map(|(offer, _)| offer)
        .collect();
    Ok(Some(OfferPassResult {
        attempt: input.attempt,
        state: status.attempt.state,
        terminal: status.attempt.state.is_terminal(),
        offers,
    }))
}

pub fn list(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferListRequest,
) -> Result<Vec<OfferView>> {
    owner.revalidate_person(vault)?;
    let pending = if input.pending_only {
        Some(
            super::pending_training_offers(vault)?
                .into_iter()
                .map(|row| row.id)
                .collect::<std::collections::BTreeSet<_>>(),
        )
    } else {
        None
    };
    training_offers(vault, input.seat.as_ref())?
        .into_iter()
        .filter(|(offer, _)| pending.as_ref().is_none_or(|ids| ids.contains(&offer.id)))
        .map(|(offer, answer)| {
            let checks = training_offer_checks(vault, &offer.id)?;
            let staged = vault.embedder_binding_move(&offer.id)?;
            Ok(OfferView {
                offer,
                answer,
                checks,
                staged,
            })
        })
        .collect()
}

pub fn get(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferRef,
) -> Result<Option<OfferView>> {
    owner.revalidate_person(vault)?;
    let Some(offer) = training_offer(vault, &input.offer)? else {
        return Ok(None);
    };
    let answer = training_offers(vault, Some(&offer.seat))?
        .into_iter()
        .find(|(row, _)| row.id == input.offer)
        .and_then(|(_, answer)| answer);
    let checks = training_offer_checks(vault, &input.offer)?;
    let staged = vault.embedder_binding_move(&input.offer)?;
    Ok(Some(OfferView {
        offer,
        answer,
        checks,
        staged,
    }))
}

pub fn answer(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferAnswerRequest,
) -> Result<OfferAnswerReply> {
    let answer = settle_training_offer(
        vault,
        owner,
        &input.offer,
        &input.digest,
        input.answer,
        None,
        vault.now_recorded_at(),
    )?;
    OfferAnswerReply::current(vault, answer)
}

pub fn undo(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferRef,
) -> Result<OfferUndoReceipt> {
    let receipt = undo_training_offer_switch(vault, owner, &input.offer, vault.now_recorded_at())?;
    Ok(OfferUndoReceipt {
        offer: receipt.offer,
        at: receipt.undone.map_or(receipt.at, |undo| undo.at),
        restored_model: receipt.previous.model.as_str().to_owned(),
    })
}

/// Cancels a staged trained embedder swap while its binding still waits or
/// fills (FIX 9459). The staged move is abandoned in the same owner write;
/// an applied swap keeps the existing space-move undo door.
pub fn cancel_training_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TrainingRunRef,
) -> Result<PendingEmbedderBinding> {
    vault.cancel_training_embedder_swap(owner, &input.run)
}
