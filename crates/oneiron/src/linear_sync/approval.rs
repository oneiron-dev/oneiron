//! FIX 6424 part 2a (Engine 10-20 21:0x rulings 1, 2 and 8): the owner's
//! approve-once asks on one Linear mirror mutation, one per actor it speaks
//! for (OF-427).
//!
//! The host scheduler and the TASK revision's verified writer each press
//! their own digest, both over the same operation (its id, the nonce), TASK,
//! linked issue and mirrored fields (CALLS `FIX 6424 Linear dual actor
//! asks`). A held mutation names the actor that held it and that actor's
//! digest; [`crate::Vault::linear_effect_approval_digests`] composes both
//! with the Gate's own composer. An Allow the other actor did not match
//! spends no press, so the first actor's press still releases the operation
//! once the other is answered.
//!
//! A press an actor's admission spent is kept here, keyed by the operation
//! and its digest, in the writer that spends it (CALLS `FIX 6424 pinned
//! Pending proof retention`): a retry of the same operation, through
//! [`crate::Vault::authorize_linear_effect`] or the recorded outbound door's
//! co-actor admission, reuses it while that actor's own pinned digest is the
//! kept one. A row that does not read leaves the retry on its existing path.

use crate::Vault;
use crate::consent::EffectDigest;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{ApprovalTarget, ExternalEffectGateInput, GateOutcome, PairAdmission};
use crate::linear_sync::{LinearEffectRequest, LinearSyncError, LinearSyncResult};
use crate::outbound_chokepoint::CoActorEffect;
use crate::outbound_intent_ledger::{AdmittedApproval, IntentLedgerError};
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

/// Keeps each actor's press the pair's admission of `operation_id` spent.
pub(super) fn keep_spent_presses_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    operation_id: [u8; 32],
    spent: [Option<EffectDigest>; 2],
) -> crate::error::Result<()> {
    let [scheduler, writer] = spent;
    for (role, digest) in [
        (LinearEffectRole::Scheduler, scheduler),
        (LinearEffectRole::Writer, writer),
    ] {
        if let Some(digest) = digest {
            keep_press_in(vault, txn, operation_id, role, digest)?;
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

impl Vault {
    /// FIX 6424 part 2a (CALLS `FIX 6424 Linear dual actor asks`): the
    /// approve-once digests `request`'s two asks name, scheduler first,
    /// each composed by the Gate's own constructor over that actor's effect
    /// on the operation, the TASK revision's verified writer read as
    /// [`Self::authorize_linear_effect`] reads it. It records nothing.
    ///
    /// # Errors
    /// [`LinearSyncError::AuthorizationDenied`] when the TASK revision has no
    /// verified writer; a storage failure.
    pub fn linear_effect_approval_digests(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<[LinearRoleApproval; 2]> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let state = linear_effect_state_in_txn(self, &txn, request.task_ref)?;
        let writer = state.writer.ok_or(LinearSyncError::AuthorizationDenied)?;
        let class = EdgeActorClass::try_from_u8(writer.actor_class)
            .ok_or(LinearSyncError::AuthorizationDenied)?;
        let approval =
            |role: LinearEffectRole, actor: EntityId, class: EdgeActorClass| LinearRoleApproval {
                role,
                actor,
                approval_digest: ApprovalTarget::held_digest(&super::effect::effect(
                    actor, class, request,
                )),
            };
        Ok([
            approval(
                LinearEffectRole::Scheduler,
                request.scheduler_actor,
                EdgeActorClass::System,
            ),
            approval(LinearEffectRole::Writer, writer.actor_ref, class),
        ])
    }
}
