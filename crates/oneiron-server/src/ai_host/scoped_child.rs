//! Scoped children at the host (FIX 7507 PR2): the door a scoped child runs
//! behind, the binding of its lent ports to the host's registered adapters,
//! and the host-only enqueue a host queues one through (the Dreamer's, in
//! FIX 7508). PR3 adds what a host lends a parent ([`ReaderParentHost`]):
//! the live clock it runs under and the lease of the attempt it runs as.
//!
//! A scoped child's door is its parent's loan. It admits the child's own
//! lifecycle calls, its reads of what it was lent and its lent ports, each
//! only while its parent actor's authority stands (`scoped_child_authority`:
//! a live person, or a live agent one live Grant of the owner's stands
//! for). It refuses only on that Grant, the job or its route, never on where
//! anyone runs: it reads no caller locality, withholds nothing by
//! destination, and the read child's door (`ReaderChildDoor`) never stands
//! in for it. No tagger or extraction port is registered here; a host
//! registers its own through `McpCodeModeProvider::scoped_child_ports`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::attempt_queue::{AttemptRecord, BorrowedAttemptLease};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, ReaderJob, ReaderJobs, ReaderRunEnd,
    ReaderSpawnReceipt, RunCall, SCOPED_CHILD_PORT_NOT_LENT, SCOPED_CHILD_SERVICE_UNBOUND,
    ScopedChildLoan, ScopedChildPorts, SelfAgentVerbCall, SelfEffect, SpawnHostSeat,
    scoped_child_authority,
};
use oneiron::dreamer_wake::{WakeAttemptContext, WakePassDeadline};
use oneiron::memory::HostWriteOrigin;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EntityId, Vault};

use crate::mcp::McpCodeModeProvider;

/// The door a scoped child's run is bound to: its job, Grant-checked in its
/// vault at every call it admits.
pub(crate) struct ScopedChildDoor {
    vault: Arc<Vault>,
    job: ReaderJob,
}

impl ScopedChildDoor {
    pub(crate) fn new(vault: Arc<Vault>, job: ReaderJob) -> Self {
        Self { vault, job }
    }

    /// The door's Grant check: whether the child's authority stands now
    /// (`scoped_child_authority`). A check that fails to read refuses.
    fn stands(&self) -> Result<(), AgentVerbRefusal> {
        match scoped_child_authority(&self.vault, &self.job) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(code)) => Err(AgentVerbRefusal {
                code: code.to_owned(),
            }),
            Err(error) => {
                tracing::warn!(%error, task = %self.job.task.to_hex(), "a scoped child's authority was not read");
                Err(AgentVerbRefusal {
                    code: "engine_error".to_owned(),
                })
            }
        }
    }
}

impl AgentVerbDoor for ScopedChildDoor {
    /// A lent port runs on its host's adapter (`ScopedChildPorts`), never
    /// through this door.
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: SCOPED_CHILD_PORT_NOT_LENT.to_owned(),
        }))
    }

    /// The child's report, `self.context`, `self.think`, its lent ports
    /// (each checked by name in its dispatcher first) and its reads, while
    /// its authority stands; any other call is the read child's word.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        self.stands()?;
        match call {
            RunCall::RecordedOutput
            | RunCall::Bridge(
                SelfEffect::ReaderReport
                | SelfEffect::Context
                | SelfEffect::Think
                | SelfEffect::AgentVerb,
            ) => Ok(None),
            _ => Err(AgentVerbRefusal {
                code: crate::server::READER_CHILD_READ_ONLY.to_owned(),
            }),
        }
    }

    /// A scoped child reads only what it was lent: its host turn's hooks
    /// read nothing, never a broad lane (FIX 9841).
    fn host_turn_read_key(&self) -> Option<ScopedReadActorKey> {
        None
    }

    /// Nothing is withheld by where anyone runs: a lent input the child's
    /// authority stands for is read, and one it no longer stands for is
    /// refused.
    fn withholds_retained(&self, _: Option<&[EntityId]>) -> Result<bool, AgentVerbRefusal> {
        self.stands().map(|()| false)
    }
}

/// `scoped_child_service_admission` at the runner (FIX 7507): the ports
/// scoped job `job` runs with, its host's registered adapters
/// (`McpCodeModeProvider::scoped_child_ports`), once its authority stands in
/// `vault`. A job whose authority does not stand ends with its refusal, and
/// one that lends a port no adapter serves ends
/// `scoped_child_service_unbound`, before any call: neither ever runs as a
/// read child in its place.
pub(crate) fn scoped_child_service(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    job: &ReaderJob,
) -> Result<Option<Arc<dyn ScopedChildPorts>>, ReaderRunEnd> {
    let Some(spec) = job.scoped_spec() else {
        return Err(ReaderRunEnd::Failed(
            SCOPED_CHILD_SERVICE_UNBOUND.to_owned(),
        ));
    };
    match scoped_child_authority(vault, job) {
        Ok(Ok(())) => {}
        Ok(Err(code)) => return Err(ReaderRunEnd::Failed(code.to_owned())),
        Err(error) => {
            tracing::warn!(%error, task = %job.task.to_hex(), "a scoped child's authority was not read");
            return Err(ReaderRunEnd::Failed(
                "scoped_child_authority_unread".to_owned(),
            ));
        }
    }
    let ports = provider.scoped_child_ports(job);
    if spec.unbound_port(ports.as_deref()).is_some() {
        return Err(ReaderRunEnd::Failed(
            SCOPED_CHILD_SERVICE_UNBOUND.to_owned(),
        ));
    }
    Ok(ports)
}

/// The host-only enqueue of one scoped child (FIX 7507; the Dreamer's
/// consolidation calls it in FIX 7508): the child `loan` lends, queued
/// under `intent_key` on `jobs`, its parent's reader rows on the loan's own
/// route, under `seat`, asked `ask`, at `now_ms`. A loan is only ever the
/// host's ([`ScopedChildLoan::from_parent`]), so no guest call reaches
/// this. The answer's `Err` names why nothing was queued
/// ([`ReaderJobs::spawn_scoped`]).
///
/// # Errors
///
/// The route's own read and write errors.
pub fn enqueue_scoped_child(
    jobs: &ReaderJobs<'_>,
    seat: &SpawnHostSeat,
    loan: &ScopedChildLoan,
    intent_key: &str,
    ask: String,
    now_ms: u64,
) -> oneiron::Result<Result<ReaderSpawnReceipt, &'static str>> {
    jobs.spawn_scoped(seat, loan, intent_key, ask, now_ms)
}

/// The live clock a parent runs under, as its host holds it (FIX 1839): what
/// was left of its wake pass or its decision when it was lent, counted down
/// on the monotonic clock. Never a wall reading and never stored: a first
/// spawn projects it once into its parent row (`reader_parent_deadline`),
/// and the runner bounds the parent's children's model and port work by it
/// beside that row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderParentClock {
    origin: Instant,
    budget_ms: u64,
}

impl ReaderParentClock {
    fn left_from_now(budget_ms: u64) -> Self {
        Self {
            origin: Instant::now(),
            budget_ms,
        }
    }

    /// A wake pass's clock: what is left before its hard ceiling.
    #[must_use]
    pub fn of_wake(deadline: &WakePassDeadline) -> Self {
        Self::left_from_now(deadline.remaining_ms())
    }

    /// A decision's clock: what is left before its answer is due.
    #[must_use]
    pub fn of_decision(deadline: &RetrievalDeadline) -> Self {
        Self::left_from_now(millis(
            deadline
                .answer_at()
                .saturating_duration_since(Instant::now()),
        ))
    }

    /// The earlier of two clocks a parent runs under at once: a decision
    /// inside a wake ends with whichever comes first, and no new window is
    /// made of either.
    #[must_use]
    pub fn earlier(self, other: Self) -> Self {
        if self.remaining_ms() <= other.remaining_ms() {
            self
        } else {
            other
        }
    }

    /// What is left of it now, in milliseconds; zero once it is due.
    #[must_use]
    pub fn remaining_ms(self) -> u64 {
        self.budget_ms.saturating_sub(millis(self.origin.elapsed()))
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// What a host lends a parent run whose children it queues (FIX 7507 PR3):
/// the live clock the parent runs under, the lease of the attempt it runs
/// as, and the loan of a scoped child it queues. The host keeps it; a seat
/// made with it (`ReaderSeats::seat_with_parent`) freezes the clock once and
/// hands the lease's ids, never its payload, to the scoped children queued
/// under it. Without a clock a parent keeps its one window from its first
/// spawn; without a lease its children outlive it, as before.
#[derive(Debug, Clone, Default)]
pub struct ReaderParentHost {
    clock: Option<ReaderParentClock>,
    lease: Option<BorrowedAttemptLease>,
    loan: Option<ScopedChildLoan>,
}

impl ReaderParentHost {
    /// The parent a leased attempt's run is, as the host that holds the
    /// lease lends it: its lease, and no clock. `None` for a record that
    /// holds no lease.
    #[must_use]
    pub fn for_attempt(leased: &AttemptRecord) -> Option<Self> {
        BorrowedAttemptLease::of(leased).map(|lease| Self {
            lease: Some(lease),
            ..Self::default()
        })
    }

    /// This parent under `clock` as well; with one already lent, the
    /// earlier of the two.
    #[must_use]
    pub fn with_clock(mut self, clock: ReaderParentClock) -> Self {
        self.clock = Some(self.clock.map_or(clock, |held| held.earlier(clock)));
        self
    }

    /// The live clock the parent runs under, if its host lent one.
    #[must_use]
    pub const fn clock(&self) -> Option<ReaderParentClock> {
        self.clock
    }

    /// The lease of the attempt the parent runs as, if any.
    #[must_use]
    pub const fn lease(&self) -> Option<&BorrowedAttemptLease> {
        self.lease.as_ref()
    }

    /// The scoped child's loan its host lends with it, if any: the loan
    /// [`enqueue_scoped_child`] queues.
    #[must_use]
    pub const fn loan(&self) -> Option<&ScopedChildLoan> {
        self.loan.as_ref()
    }
}

/// The parent a Dreamer wake attempt lends its scoped child (FIX 7507; FIX
/// 7508's executor calls it with the wake context it already receives):
/// `ctx`'s live wake clock, the lease of `leased`, the attempt the wake
/// runs, and `loan`, made for `run`, borrowing that lease
/// ([`ScopedChildLoan::with_parent_attempt`]) with every port it lends among
/// `parent_ports`, what that attempt itself may call. It assumes no
/// AGENT_DEF dispatch, starts no clock of its own and renews nothing. The
/// answer's `Err` is the loan's refusal: `scoped_child_parent_lease_lost` or
/// `scoped_child_port_exceeds_parent`.
///
/// # Errors
///
/// [`oneiron::Error::InvalidConfig`] when `loan` is not lent from `run` or
/// is another vault's; the queue's own read errors.
pub fn reader_parent_for_wake(
    ctx: &WakeAttemptContext<'_>,
    leased: &AttemptRecord,
    run: EntityId,
    loan: ScopedChildLoan,
    parent_ports: &BTreeSet<String>,
) -> oneiron::Result<Result<ReaderParentHost, &'static str>> {
    if loan.parent_run() != run {
        return Err(oneiron::Error::InvalidConfig(
            "a wake's scoped loan is another run's".to_owned(),
        ));
    }
    let loan = match loan.with_parent_attempt(ctx.vault, leased, parent_ports)? {
        Ok(loan) => loan,
        Err(refused) => return Ok(Err(refused)),
    };
    Ok(Ok(ReaderParentHost {
        clock: Some(ReaderParentClock::of_wake(ctx.deadline)),
        lease: loan.parent_lease().cloned(),
        loan: Some(loan),
    }))
}
