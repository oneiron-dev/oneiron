//! Waiting on a world-privacy request (FIX 4706). The request's immutable id
//! is the wait's id: `vault.worlds.privacy.set` answers a proposal or an ask
//! with it as `wait`, and only the actor that opened the request waits on it.
//! A task waits through `wait` (an external wait bound to its step key, the
//! ask waits' own rows and traps); a code run through `wait` or the run's
//! `tasks.wait({request, step_key})`, which parks it on the request's id.
//!
//! Only a holder's terminal answer wakes a wait: applied or declined. A yes
//! collected toward "widen needs every owner" leaves it pending; nothing here
//! answers for a holder, and silence is never a yes. The request's LIVE
//! status is the truth: the commit that settles it signals every external
//! wait bound to it and delivers its terminal state to every run parked on
//! it, as an ask's settlement does, and a park after that commit, or the wake
//! pass after a restart, reads the status again and delivers what is owed.
//! None of it applies the settings again. The wait answers its author the
//! request, its world and where it stands, never the frozen request whole
//! ([`WorldPrivacyWaitResult`]).

use serde::{Deserialize, Serialize};

use crate::code_run::{SelfDurableWait, SelfDurableWaitReason, SelfEffect};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::policy_model::{WorldPrivacyRequest, WorldPrivacyRequestStatus};
use crate::{EntityId, Vault};

use super::{TaskAskHandle, TaskAskStatus, TaskAskWait};

/// What a wait on a world-privacy request answers its author (FIX 4706,
/// redacted by the Engine 10-19 20:0x, CALLS `FIX 4706 wait result`): the
/// request, its world and where it stands, with the outcome's content-free
/// fields. No door shows the author the holders it went to, who said yes,
/// who answered or the credential lineage that opened it, so none is here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldPrivacyWaitResult {
    /// The request's id, as hex: the wait's id.
    pub request_id: String,
    /// The WORLD row, as hex.
    pub world: String,
    pub status: WorldPrivacyWaitStatus,
}

/// Where a waited-on world-privacy request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WorldPrivacyWaitStatus {
    Pending,
    /// A holder's yes applied it: the settings receipt.
    Applied {
        receipt_id: String,
    },
    /// A holder declined it, or cancelled it from its notice.
    Declined,
}

impl WorldPrivacyWaitResult {
    /// `request` as its author's wait reads it.
    fn of(request: &WorldPrivacyRequest) -> Self {
        Self {
            request_id: request.request_id.clone(),
            world: request.world.clone(),
            status: match &request.status {
                WorldPrivacyRequestStatus::Pending => WorldPrivacyWaitStatus::Pending,
                WorldPrivacyRequestStatus::Applied { receipt_id, .. } => {
                    WorldPrivacyWaitStatus::Applied {
                        receipt_id: receipt_id.clone(),
                    }
                }
                WorldPrivacyRequestStatus::Declined { .. } => WorldPrivacyWaitStatus::Declined,
            },
        }
    }
}

/// A wait by any actor but the one that opened the request: the words an
/// ask's own wait refuses with.
const NOT_THE_ASKER: &str = "only the asking actor may wait";

/// Whether a holder applied or declined `request`. A pending one, its
/// collected yeses included, is not settled.
fn settled(request: &WorldPrivacyRequest) -> bool {
    request.status != WorldPrivacyRequestStatus::Pending
}

/// The park a code run's wait on a pending request takes: the request's id
/// is the wait's, and a holder's answer is a human response, never a peer's
/// result.
fn request_park(request: EntityId) -> SelfDurableWait {
    SelfDurableWait {
        wait_id: request,
        effect: SelfEffect::TasksWait,
        reason: SelfDurableWaitReason::HumanInput,
        prompt: None,
    }
}

impl Memory<'_> {
    /// The wait on the world-privacy request `handle` names, in the caller's
    /// verified write; `None` when it names none, so an ask's own wait goes
    /// on. A pending request binds the external wait `step_key` names, or
    /// parks a code run that names none; a settled one answers its terminal
    /// state, consuming a bound wait once.
    ///
    /// # Errors
    /// A bad request for any actor but the request's author.
    pub(super) fn world_privacy_wait_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
        step_key: Option<&str>,
    ) -> MemoryResult<Option<TaskAskWait>> {
        let Some(request) = self
            .vault()
            .world_privacy_request_in_txn(txn, handle.group_ref)?
        else {
            return Ok(None);
        };
        if request.author != self.actor().to_hex() {
            return Err(MemoryError::bad_request(NOT_THE_ASKER));
        }
        let status = if settled(&request) {
            TaskAskStatus::WorldPrivacy(WorldPrivacyWaitResult::of(&request))
        } else {
            TaskAskStatus::Pending { hold: None }
        };
        Ok(Some(match (step_key, status) {
            (Some(step_key), status) => self.bind_external_wait(txn, handle, step_key, status)?,
            (None, TaskAskStatus::WorldPrivacy(request)) => TaskAskWait::WorldPrivacyReady(request),
            (None, _) => TaskAskWait::Park(request_park(handle.group_ref)),
        }))
    }

    /// `tasks.wait({request, step_key})` from a code run: the run's actor's
    /// wait on world-privacy request `request`, its terminal state or the
    /// park on its id. `None` when `request` names no such request.
    ///
    /// # Errors
    /// As [`Self::tasks_wait`].
    pub(crate) fn world_privacy_run_wait(
        &self,
        request: EntityId,
    ) -> MemoryResult<Option<TaskAskWait>> {
        let handle = TaskAskHandle { group_ref: request };
        self.with_verified_actor_write_txn(|txn| self.world_privacy_wait_in(txn, handle, None))
    }
}

/// Settles every wait on `request` in the caller's write, the commit that
/// applied or declined it: each external wait bound to it is signalled, and
/// its terminal state is the reply every run parked on it gets, kept for a
/// run that parks later. A pending request is left as it is.
///
/// # Errors
/// Storage errors, and an external wait row that holds no trap.
pub(crate) fn deliver_world_privacy_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &WorldPrivacyRequest,
) -> crate::Result<()> {
    if !settled(request) {
        return Ok(());
    }
    let id = request.id()?;
    let now_ms = vault.store.clock.now_recorded_at().saturating_mul(1000);
    super::ask_facade::signal_waiters(vault, txn, id, now_ms)
        .map_err(|_| crate::Error::InvariantViolation("a world-privacy wait was not signalled"))?;
    let reply = serde_json::to_value(TaskAskStatus::WorldPrivacy(WorldPrivacyWaitResult::of(
        request,
    )))
    .map_err(|_| crate::Error::InvariantViolation("a world-privacy request is not JSON"))?;
    crate::code_run::deliver_wait_in_txn(vault, txn, id, &reply, now_ms).map(drop)
}

/// [`deliver_world_privacy_wait_in_txn`] for wait `id`, when it names a
/// world-privacy request, read in the caller's write: a run that parks on it
/// after its settling commit gets its reply there.
///
/// # Errors
/// As [`deliver_world_privacy_wait_in_txn`].
pub(crate) fn deliver_world_privacy_wait_for_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> crate::Result<()> {
    match vault.world_privacy_request_in_txn(txn, id)? {
        Some(request) => deliver_world_privacy_wait_in_txn(vault, txn, &request),
        None => Ok(()),
    }
}

/// The wake pass's repair after a restart or a restore: wait `id`, when it
/// names a settled world-privacy request, gets what that settlement owes it,
/// from the request's LIVE status.
///
/// # Errors
/// As [`deliver_world_privacy_wait_in_txn`].
pub(super) fn reconcile_world_privacy_wait(vault: &Vault, id: EntityId) -> crate::Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        vault
            .world_privacy_request_in_txn(&txn, id)?
            .is_some_and(|request| settled(&request))
    };
    if !owed {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| deliver_world_privacy_wait_for_in_txn(vault, txn, id))
}
