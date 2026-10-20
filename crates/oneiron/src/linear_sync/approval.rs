//! FIX 6424 part 2a (Engine 10-20 21:0x rulings 1, 2 and 8): the owner's
//! approve-once asks on one Linear mirror mutation, one per actor it speaks
//! for (OF-427).
//!
//! The host scheduler and the TASK revision's verified writer each press
//! their own digest, both over the same operation (its id, the nonce), TASK,
//! linked issue and mirrored fields (CALLS `FIX 6424 Linear dual actor
//! asks`). A held mutation names the actor that held it and that actor's
//! digest on its typed outcome
//! ([`crate::Vault::authorize_linear_effect_outcome`]); the refusals it has
//! always returned keep their variants (the recorded outbound door's names
//! the digest in its message, after its unchanged text). Both asks are
//! composed with the
//! Gate's own composer by each admission's own constructor: the direct
//! admission's by [`crate::Vault::linear_effect_approval_digests`], the
//! recorded outbound door's (whose scheduler asks over its dispatch request)
//! by [`crate::Vault::linear_outbound_door_approval_digests`]. An Allow the
//! other actor did not match spends no press, so the first actor's press
//! still releases the operation once the other is answered.
//!
//! A press an actor's admission spent is kept here, keyed by the operation
//! and its digest, in a writer of its own once that admission committed
//! (CALLS `FIX 6424 pinned Pending proof retention`, `FIX 6424 kept press
//! write failure`): a retry of the same operation, through
//! [`crate::Vault::authorize_linear_effect`] or the recorded outbound door's
//! co-actor admission, reuses it while that actor's own pinned digest is the
//! kept one. A row that does not read, or was not written, leaves the retry
//! on its existing path.

use crate::Vault;
use crate::consent::EffectDigest;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{ApprovalTarget, ExternalEffectGateInput, GateOutcome, PairAdmission};
use crate::linear_sync::{LinearEffectRequest, LinearSyncError, LinearSyncResult};
use crate::outbound::{OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult};
use crate::outbound_chokepoint::CoActorEffect;
use crate::outbound_intent_ledger::{
    AdmittedApproval, IntentLedgerError, keep_press_after_admission,
};
use crate::side_table::{self, Raw, SideTable};
use crate::task_verb::linear_effect_state_in_txn;

/// (operation id, the press's approve-once digest) → the actor's role tag.
const KEPT_PRESS: SideTable<([u8; 32], [u8; 32]), [u8; 1], Raw> =
    SideTable::new(&side_table::LINEAR_EFFECT_APPROVAL);

/// Which of a Linear mirror mutation's two actors an ask is for (OF-427).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearEffectRole {
    /// The host scheduler that sends the mutation.
    Scheduler,
    /// The verified writer of the mirrored TASK revision.
    Writer,
}

impl LinearEffectRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Scheduler => 1,
            Self::Writer => 2,
        }
    }

    /// The role's name: `scheduler` or `writer`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Writer => "writer",
        }
    }
}

/// One actor's approve-once ask on a Linear mirror mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearRoleApproval {
    pub role: LinearEffectRole,
    pub actor: EntityId,
    /// The digest a press for this actor names, 64 lower-hex: the Gate's
    /// own composer over this actor's effect on the operation. Pass it as
    /// the press's `effect_digest`.
    pub approval_digest: Option<String>,
}

/// A Linear mirror mutation the Gate did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearEffectHold {
    /// The actor whose decision held it: the scheduler's when both did.
    pub role: LinearEffectRole,
    pub actor: EntityId,
    /// That actor's recorded decision, `gate:<hex>`.
    pub gate_decision_ref: String,
    /// That decision's outcome: `pending` or `deny`.
    pub gate_outcome: String,
    /// The digest that actor's approve-once press names, while the Gate
    /// holds the mutation for it; `None` for a denial.
    pub approval_digest: Option<String>,
}

/// What [`crate::Vault::authorize_linear_effect_outcome`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinearEffectAdmission {
    /// Both actors were admitted; the scheduler's decision ref.
    Admitted { gate_ref: String },
    /// The Gate did not admit it.
    Held(LinearEffectHold),
}

/// The press `effect`'s actor's admission of `operation_id` spent and kept,
/// as a retry proof for that same effect. `None` for none kept, an effect
/// that pins no target, or a row that does not read.
pub(super) fn kept_press_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    operation_id: [u8; 32],
    effect: &ExternalEffectGateInput,
) -> Option<AdmittedApproval> {
    effect.provenance.approval_target.as_ref()?;
    let digest = crate::gate::external_effect_approval_digest(effect)?;
    KEPT_PRESS
        .contains(&vault.store, txn, &(operation_id, *digest.as_bytes()))
        .ok()?
        .then(|| AdmittedApproval::from_gate(operation_id, digest))
}

/// Keeps the press `role`'s admission of `operation_id` spent.
fn keep_press_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    operation_id: [u8; 32],
    role: LinearEffectRole,
    digest: EffectDigest,
) -> crate::error::Result<()> {
    KEPT_PRESS.put(
        &vault.store,
        txn,
        &(operation_id, *digest.as_bytes()),
        &[role.tag()],
    )
}

/// Keeps each actor's press the pair's committed admission of
/// `operation_id` spent, each in a writer of its own; one that does not
/// write is logged and the admission stands.
///
/// # Errors
/// None while CALLS `FIX 6424 kept press write failure` stands.
pub(super) fn keep_spent_presses(
    vault: &Vault,
    operation_id: [u8; 32],
    spent: [Option<EffectDigest>; 2],
) -> crate::error::Result<()> {
    let [scheduler, writer] = spent;
    let subject = crate::entity_id::bytes_to_hex_lower(&operation_id);
    for (role, digest) in [
        (LinearEffectRole::Scheduler, scheduler),
        (LinearEffectRole::Writer, writer),
    ] {
        if let Some(digest) = digest {
            keep_press_after_admission(vault, &subject, |txn| {
                keep_press_in(vault, txn, operation_id, role, digest)
            })?;
        }
    }
    Ok(())
}

/// The hold a pair that admitted nothing names: its first actor, in role
/// order, whose decision was not an Allow.
pub(super) fn held(
    pair: &PairAdmission,
    actors: [(EntityId, &ExternalEffectGateInput); 2],
) -> LinearEffectHold {
    let index = usize::from(pair.decisions[0].1 == GateOutcome::Allow);
    let (decision_id, outcome) = pair.decisions[index];
    let (actor, effect) = actors[index];
    LinearEffectHold {
        role: if index == 0 {
            LinearEffectRole::Scheduler
        } else {
            LinearEffectRole::Writer
        },
        actor,
        gate_decision_ref: format!("gate:{}", decision_id.to_hex()),
        gate_outcome: outcome.as_str().to_owned(),
        approval_digest: (outcome == GateOutcome::Pending)
            .then(|| ApprovalTarget::held_digest(effect))
            .flatten(),
    }
}

/// The recorded outbound door's co-actor (OF-427): the TASK revision's
/// writer, bound under the admission writer, with the press its earlier
/// admission of this operation kept, and a keeper for the press this
/// admission spends.
pub(crate) fn linear_writer_co_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &LinearEffectRequest,
) -> Result<CoActorEffect, IntentLedgerError> {
    let effect = super::effect::linear_effect_writer_in_txn(vault, txn, request)?;
    let operation_id = request.operation_id;
    let kept_press = kept_press_in(vault, txn, operation_id, &effect);
    Ok(CoActorEffect {
        effect,
        kept_press,
        keep_press: Box::new(
            move |vault: &Vault, txn: &mut heed::RwTxn<'_>, digest: EffectDigest| {
                keep_press_in(vault, txn, operation_id, LinearEffectRole::Writer, digest)
                    .map_err(IntentLedgerError::from)
            },
        ),
    })
}

impl LinearEffectHold {
    /// The hold the recorded outbound door's `result` for `effect` names
    /// (FIX 6424 part 2a): the actor whose decision held the mutation and
    /// the digest its press names, both copied from the result. `None` for a
    /// result the Gate does not hold for a press.
    #[must_use]
    pub fn of_door_result(
        result: &OutboundDispatchResult,
        effect: &LinearEffectRequest,
    ) -> Option<Self> {
        let approval_digest = result.approval_digest.clone()?;
        let actor = result.approval_actor.unwrap_or(effect.scheduler_actor);
        Some(Self {
            role: if actor == effect.scheduler_actor {
                LinearEffectRole::Scheduler
            } else {
                LinearEffectRole::Writer
            },
            actor,
            gate_decision_ref: result.gate_decision_id.clone()?,
            gate_outcome: result.gate_outcome.clone(),
            approval_digest: Some(approval_digest),
        })
    }
}

impl Vault {
    /// FIX 6424 part 2a (CALLS `FIX 6424 Linear dual actor asks`): the
    /// approve-once digests the DIRECT admission's two asks on `request`
    /// name ([`Self::authorize_linear_effect`]), scheduler first, each
    /// composed by the Gate's own constructor over that actor's effect on the
    /// operation, the TASK revision's verified writer read as that admission
    /// reads it. The recorded outbound door's scheduler asks over its
    /// dispatch request instead:
    /// [`Self::linear_outbound_door_approval_digests`]. It records nothing.
    ///
    /// # Errors
    /// [`LinearSyncError::AuthorizationDenied`] when the TASK revision has no
    /// verified writer; a storage failure.
    pub fn linear_effect_approval_digests(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<[LinearRoleApproval; 2]> {
        Ok([
            role_approval(
                LinearEffectRole::Scheduler,
                request.scheduler_actor,
                EdgeActorClass::System,
                request,
            ),
            self.linear_writer_approval(request)?,
        ])
    }

    /// FIX 6424 part 2a (CALLS `FIX 6424 Linear dual actor asks`): the
    /// approve-once digests the recorded outbound door's two asks on one
    /// staged call name, scheduler first. `request` is the dispatch request
    /// that door builds for the call (its target, staged content ref and
    /// logical ref); `effect` the mirror mutation it carries. The scheduler's
    /// is the outbound dispatch's own `LinearDispatch` composer over that
    /// request with `effect`'s mirror facts, frozen as its dispatch freezes
    /// it; the writer's is the co-actor admission's `LinearMirror` effect,
    /// the writer read as that admission reads it. It records nothing.
    ///
    /// # Errors
    /// The request's own refusal at preparation (as
    /// [`crate::outbound::outbound_approve_once_digest`]: an engine failure
    /// as [`LinearSyncError::Store`], any other as
    /// [`LinearSyncError::Transport`]); [`LinearSyncError::AuthorizationDenied`]
    /// when the TASK revision has no verified writer; a storage failure.
    pub fn linear_outbound_door_approval_digests(
        &self,
        request: &OutboundDispatchRequest,
        effect: &LinearEffectRequest,
    ) -> LinearSyncResult<[LinearRoleApproval; 2]> {
        let mut request = request.clone();
        request.linear_mirror = Some(effect.clone());
        let scheduler =
            crate::outbound::outbound_approve_once_digest(self, &request).map_err(|error| {
                match error {
                    OutboundDispatchError::Engine(error) => LinearSyncError::Store(error),
                    other => LinearSyncError::Transport(other.to_string()),
                }
            })?;
        Ok([
            LinearRoleApproval {
                role: LinearEffectRole::Scheduler,
                actor: effect.scheduler_actor,
                approval_digest: scheduler.map(|digest| digest.to_hex()),
            },
            self.linear_writer_approval(effect)?,
        ])
    }

    /// The writer's ask on `request`: the TASK revision's verified writer,
    /// read as both admissions read it, over the `LinearMirror` effect both
    /// build for it.
    fn linear_writer_approval(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<LinearRoleApproval> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let state = linear_effect_state_in_txn(self, &txn, request.task_ref)?;
        let writer = state.writer.ok_or(LinearSyncError::AuthorizationDenied)?;
        let class = EdgeActorClass::try_from_u8(writer.actor_class)
            .ok_or(LinearSyncError::AuthorizationDenied)?;
        Ok(role_approval(
            LinearEffectRole::Writer,
            writer.actor_ref,
            class,
            request,
        ))
    }
}

/// One actor's ask on `request`, by the effect constructor both admissions
/// use for it.
fn role_approval(
    role: LinearEffectRole,
    actor: EntityId,
    class: EdgeActorClass,
    request: &LinearEffectRequest,
) -> LinearRoleApproval {
    LinearRoleApproval {
        role,
        actor,
        approval_digest: ApprovalTarget::held_digest(&super::effect::effect(actor, class, request)),
    }
}
