//! Who queued an agent dispatch, and what his request stood on (FIX 11592,
//! ruling 4624(a)). A dispatch a credential caller's request queued keeps
//! the instrument that request was admitted on, as a queued turn action
//! does: the slip, an ask guest's admitted grant (FIX 11688), or a managed
//! vault's attested owner. A child with none of its own keeps its parent's,
//! and a retry keeps the payload it clones. A held request released later
//! keeps the requester it was admitted under (FIX 11691). The in-process
//! host's own work, and maintenance, keeps none and runs as before.
//!
//! Each agent pump checks it again in the write it would claim the try in.
//! Only a positive withdrawal ends the work: the slip, or an ancestor,
//! revoked, the guest's grant withdrawn, the attested owner no longer the
//! vault's live owner, or the requester hard-erased, which leaves an erased
//! marker in place of its standing (FIX 11689). The
//! pump then claims nothing and hands the try to
//! [`AgentDispatcher::end_withdrawn`], which takes the TASK runner's turn
//! first and fails the try for good with that typed reason, through the
//! failure ladder's terminal steps; nothing runs. A read that fails, or
//! standing the host could not judge, is no withdrawal: the
//! try runs as it did. A completed try, or what it produced, is never
//! touched.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, FailAttempt,
};
use crate::authority::{AdmittedTaskGrant, InvocationSlipBinding, ManagedOwnerCheckError};
use crate::error::Result;
use crate::memory::Memory;
use crate::task_verb::highway_runner::{
    RunnerSettle, accept_leased_task_in_txn, report_leased_task_in_txn, runner_report_turn,
};
use crate::{EntityId, Vault};

use super::{AgentDispatchInput, AgentDispatcher};

/// The instrument a queued dispatch's request was admitted on. Never a
/// secret, and it grants nothing: the claim judges it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequesterStanding {
    /// The slip the request was admitted on, with its holder's proof.
    Slip { binding: InvocationSlipBinding },
    /// The vault's owner `holder`, whom its supervisor attested with no
    /// slip: the work stands while the vault records him as its live owner.
    AttestedOwner { holder: EntityId },
    /// An ask guest's grant, admitted for the companion it names (FIX
    /// 11688): the work stands until the owner withdraws the grant.
    TaskGrant { grant: AdmittedTaskGrant },
    /// The requester was hard-erased, and its standing with it (FIX 11689):
    /// the work no longer stands.
    Erased,
}

/// Who queued a dispatch, and what his request stood on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedRequester {
    /// The caller whose request queued the work.
    pub actor: EntityId,
    pub standing: RequesterStanding,
}

/// Why a queued dispatch's requester no longer stands: a positive
/// withdrawal, never a read that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequesterWithdrawn {
    /// The slip the request was admitted on, or an ancestor, was revoked.
    SlipRevoked,
    /// The attested owner is no longer the vault's live owner.
    OwnerNotLive,
    /// The owner withdrew the ask guest's grant the request stood on.
    GrantWithdrawn,
    /// The requester was hard-erased.
    RequesterErased,
}

impl RequesterWithdrawn {
    /// The stable reason the ended try and its TASK record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SlipRevoked => "requester_withdrawn:slip_revoked",
            Self::OwnerNotLive => "requester_withdrawn:owner_not_live",
            Self::GrantWithdrawn => "requester_withdrawn:grant_withdrawn",
            Self::RequesterErased => "requester_withdrawn:requester_erased",
        }
    }
}

impl QueuedRequester {
    /// The requester `memory`'s request queues work under: the one a host
    /// kept for a held request it releases, else the slip its host bound,
    /// the ask guest's grant, or the managed vault's attested owner. `None`
    /// for the in-process host's own surface and any other caller, whose
    /// work stays unmarked.
    pub(crate) fn of_memory(memory: &Memory<'_>) -> Option<Self> {
        if let Some(kept) = memory.kept_requester() {
            return Some(kept.clone());
        }
        if let Some(binding) = memory.invocation_slip() {
            return Some(Self {
                actor: memory.actor(),
                standing: RequesterStanding::Slip {
                    binding: binding.clone(),
                },
            });
        }
        if let Some(grant) = memory.admitted_task_grant() {
            return Some(Self {
                actor: memory.actor(),
                standing: RequesterStanding::TaskGrant { grant },
            });
        }
        memory.attested_owner_holder().map(|holder| Self {
            actor: holder,
            standing: RequesterStanding::AttestedOwner { holder },
        })
    }

    /// Whether this requester's authority was positively withdrawn in
    /// `txn`. A read that fails, or an owner standing the host could not
    /// judge, is `None`: the work runs as before.
    pub(crate) fn withdrawn_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Option<RequesterWithdrawn> {
        match &self.standing {
            RequesterStanding::Slip { binding } => {
                match vault.invocation_slip_revoked_in_txn(txn, binding) {
                    Ok(true) => Some(RequesterWithdrawn::SlipRevoked),
                    Ok(false) => None,
                    Err(error) => {
                        tracing::warn!(%error, "queued requester's slip unread; the try runs");
                        None
                    }
                }
            }
            RequesterStanding::AttestedOwner { holder } => {
                match crate::authority::require_live_managed_owner_in_txn(vault, txn, *holder) {
                    Err(ManagedOwnerCheckError::OwnerNotLive) => {
                        Some(RequesterWithdrawn::OwnerNotLive)
                    }
                    Ok(()) | Err(ManagedOwnerCheckError::Unavailable) => None,
                }
            }
            RequesterStanding::TaskGrant { grant } => {
                match vault.guest_grant_withdrawn_in_txn(txn, &grant.grant()) {
                    Ok(true) => Some(RequesterWithdrawn::GrantWithdrawn),
                    Ok(false) => None,
                    Err(error) => {
                        tracing::warn!(%error, "queued requester's grant unread; the try runs");
                        None
                    }
                }
            }
            RequesterStanding::Erased => Some(RequesterWithdrawn::RequesterErased),
        }
    }

    /// Leaves this requester's standing as the erased marker when `actor`,
    /// hard-erased, is the requester (FIX 11689): the work reads as
    /// withdrawn, by its typed reason. Whether it changed; a marker already
    /// in place changes nothing.
    pub(crate) fn erase_standing_of(&mut self, actor: &EntityId) -> bool {
        if self.actor != *actor || self.standing == RequesterStanding::Erased {
            return false;
        }
        self.standing = RequesterStanding::Erased;
        true
    }
}

impl AgentDispatcher<'_> {
    /// The requester a dispatch keeps: its spawn's own, or else the one its
    /// parent's row keeps. A parent that is no dispatch, or is gone, gives
    /// none.
    pub(super) fn inherited_requester_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        own: Option<QueuedRequester>,
        parent: Option<AttemptId>,
    ) -> Result<Option<QueuedRequester>> {
        if own.is_some() {
            return Ok(own);
        }
        let Some(parent) = parent else {
            return Ok(None);
        };
        Ok(AttemptQueue::new(self.vault)
            .get_in_txn(txn, parent)?
            .and_then(|record| super::codec::record_dispatch_input(&record))
            .and_then(|input| input.requester))
    }

    /// Whether `input`'s requester's authority was positively withdrawn, in
    /// `txn`. `None` for a dispatch no request queued, and for any read
    /// that fails.
    pub(crate) fn requester_withdrawn_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &AgentDispatchInput,
    ) -> Option<RequesterWithdrawn> {
        input
            .requester
            .as_ref()
            .and_then(|requester| requester.withdrawn_in_txn(self.vault, txn))
    }

    /// Ends the queued try `id` a pump found its requester withdrawn for, as
    /// `lease_owner`: the TASK runner's turn taken first (Rule 5), then in a
    /// writer of its own the try is judged again, claimed and taken, its
    /// TASK fails not to be retried, the try fails for good with the typed
    /// reason and its pack receipt, its step receipts go and its spend
    /// lease settles, as the failure ladder's terminal step does. A try
    /// another worker took first, or whose requester stands now, is left as
    /// it is.
    pub(crate) fn end_withdrawn(&self, id: AttemptId, lease_owner: &str, now: u64) -> Result<()> {
        let held = runner_report_turn(self.vault, id)?;
        // The grouped write door, as the ladder's own fail: a TASK this
        // failure settles wakes its peer-result waiters once it commits.
        let ended = self.vault.with_write_txn_grouped(|txn| {
            let Some(row) = AttemptQueue::new(self.vault).get_in_write_txn(&*txn, id)? else {
                return Ok(None);
            };
            if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) {
                return Ok(None);
            }
            let Some(withdrawn) = super::codec::record_dispatch_input(&row)
                .and_then(|input| self.requester_withdrawn_in_txn(&*txn, &input))
            else {
                return Ok(None);
            };
            let ClaimOutcome::Claimed(attempt) = crate::ports::JobQueue::port_job_claim_id(
                self.vault,
                txn,
                id,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now,
                },
            )?
            else {
                return Ok(None);
            };
            accept_leased_task_in_txn(self.vault, txn, &attempt)?;
            let reason = withdrawn.code();
            report_leased_task_in_txn(
                self.vault,
                txn,
                attempt.id,
                RunnerSettle::Failed {
                    error: reason,
                    retryable: false,
                },
                held.as_ref(),
            )?;
            let _failed = crate::ports::JobQueue::port_job_fail(
                self.vault,
                txn,
                FailAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason: reason.to_owned(),
                    now,
                },
            )?;
            crate::dreamer_runner::DreamerRunnerStore::new(self.vault)
                .cleanup_step_receipts_in_txn(txn, attempt.id)?;
            self.settle_child_in_txn(txn, &attempt.id, now)?;
            Ok(Some(attempt))
        })?;
        if let Some(attempt) = ended {
            self.vault.store.notify_attempt_observers();
            self.vault.store.notify_task_updates(
                attempt
                    .task_ref
                    .as_deref()
                    .and_then(|task| EntityId::from_hex(task).ok()),
            );
        }
        Ok(())
    }
}
