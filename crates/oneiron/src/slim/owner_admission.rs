//! The owner's own shed request, `vault.slim.drop_heavy` (FIX 10157): where
//! the automatic shed is refused because more than one outbound step is
//! pending, the owner's request waits for a moment the shed can be decided.
//!
//! Requests take turns per vault in arrival order: one decides at a time,
//! as the transition lock already serializes sheds. The request holding the
//! turn arms a wait, then looks at the journal and residency under the
//! transition lock, revalidating the owner first. While the vault is FULL
//! with more than one step pending it waits, holding no lock, for the next
//! change that could settle it: a committed write (the common write door and
//! the intent ledger's terminal transition), a retired model wait or a
//! residency change. Each wake only says "look again": the next look reads
//! everything afresh. Nothing here times out, polls, counts against a cap or
//! touches an outbound step; only the caller dropping its request ends a
//! wait, and that releases its turn.

use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::public::{SlimDropOutcome, SlimDropReceipt, SlimDropRequest};
use super::{ShedAdmission, ShedBlocker, ShedOutcome, require_positive_wait};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

/// The owner's shed requests on one vault.
#[derive(Debug)]
pub(super) struct OwnerShedLine {
    /// One turn, handed out in the order requests asked for it (tokio's
    /// semaphore is fair).
    turn: Arc<Semaphore>,
    /// Woken by every change that could let the waiting request decide.
    changed: Notify,
}

impl Default for OwnerShedLine {
    fn default() -> Self {
        Self {
            turn: Arc::new(Semaphore::new(1)),
            changed: Notify::new(),
        }
    }
}

/// One look at the vault for an owner's shed that holds its turn. It is
/// blocking work, which the host runs off its async runtime through
/// [`Self::run`]; the turn travels with it, so a caller that stops waiting
/// while a look runs frees the turn only once that look has ended.
pub struct OwnerShedAttempt {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    request: SlimDropRequest,
    /// Whether this request has already waited for a change.
    waited: bool,
    _turn: OwnedSemaphorePermit,
}

/// What one look decided.
pub enum OwnerShedStep {
    /// The request's answer.
    Decided(MemoryResult<SlimDropReceipt>),
    /// More than one outbound step is pending on a FULL vault: the request
    /// keeps its turn and looks again at the next change.
    Waiting(OwnerShedAttempt),
}

impl OwnerShedAttempt {
    /// Revalidates the owner, then decides under the transition lock: the
    /// fixed-order shed for the one pending step, the existing outcome for a
    /// SLIM vault or a refused drop, and, on a FULL vault, a wait while more
    /// than one step is pending. With none pending the answer is the
    /// existing `no_pending_outbound_step` refusal on a first look and
    /// `nothing_pending` once the request has waited: no shed was owed, so
    /// none ran. It says nothing of how any send ended.
    #[must_use]
    pub fn run(self) -> OwnerShedStep {
        match self.decide() {
            Ok(Some(outcome)) => OwnerShedStep::Decided(Ok(SlimDropReceipt {
                process_id: std::process::id(),
                outcome,
            })),
            Ok(None) => OwnerShedStep::Waiting(self),
            Err(error) => OwnerShedStep::Decided(Err(error)),
        }
    }

    fn decide(&self) -> MemoryResult<Option<SlimDropOutcome>> {
        self.owner.revalidate(&self.vault)?;
        let waited_secs = self.request.waited_secs.get();
        require_positive_wait(waited_secs)?;
        let vault = &*self.vault;
        let mut state = vault.slim.lock_state();
        let outcome = match vault.admit_shed(&state)? {
            ShedAdmission::Decided(ShedOutcome::Refused(
                ShedBlocker::MultiplePendingOutboundSteps { .. },
            )) => return Ok(None),
            ShedAdmission::Decided(ShedOutcome::Refused(ShedBlocker::NoPendingOutboundStep))
                if self.waited =>
            {
                return Ok(Some(SlimDropOutcome::NothingPending));
            }
            ShedAdmission::Decided(outcome) => outcome,
            ShedAdmission::Admitted {
                step,
                admitted_residue,
            } => vault.drop_rebuildable_heap(
                &mut state,
                step,
                admitted_residue,
                self.request.cause,
                waited_secs,
                unix_ms_now(),
            )?,
        };
        Ok(Some(SlimDropReceipt::from(outcome).outcome))
    }
}

impl Vault {
    /// The owner's own shed (`vault.slim.drop_heavy`, FIX 10157): waits for
    /// this request's turn, then looks until a look decides, waiting between
    /// looks for the next change ([`OwnerShedAttempt::run`]). `run` is the
    /// host's way to run one look off its async runtime; an error from it
    /// is the request's answer.
    ///
    /// # Errors
    ///
    /// The owner's revalidation, a storage or journal failure, or `run`'s
    /// own error.
    pub async fn shed_rebuildable_heap_as_owner<Run, Ran>(
        self: &Arc<Self>,
        owner: AuthenticatedOwner,
        request: SlimDropRequest,
        run: Run,
    ) -> MemoryResult<SlimDropReceipt>
    where
        Run: Fn(OwnerShedAttempt) -> Ran,
        Ran: Future<Output = MemoryResult<OwnerShedStep>>,
    {
        let line = &self.slim.owner_line;
        // The semaphore is never closed, so this waits for the turn only.
        let turn = Arc::clone(&line.turn)
            .acquire_owned()
            .await
            .map_err(|_| crate::Error::InvalidConfig("owner shed turn closed".to_owned()))?;
        let mut attempt = OwnerShedAttempt {
            vault: Arc::clone(self),
            owner,
            request,
            waited: false,
            _turn: turn,
        };
        loop {
            // Armed before the look, so a change during it is not missed.
            let changed = line.changed.notified();
            let mut changed = std::pin::pin!(changed);
            changed.as_mut().enable();
            match run(attempt).await? {
                OwnerShedStep::Decided(answer) => return answer,
                OwnerShedStep::Waiting(next) => attempt = next,
            }
            changed.await;
            attempt.waited = true;
        }
    }

    /// Wakes the owner's waiting shed to look again (FIX 10157). It returns
    /// nothing, takes no lock a writer or the transition holds and only
    /// wakes; called after a commit, a retired model wait or a residency
    /// change.
    pub(crate) fn wake_owner_shed(&self) {
        self.slim.owner_line.changed.notify_waiters();
    }
}

/// Wall-clock milliseconds for the residue's observability stamps, as a
/// long-wait shed reads them.
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
