//! Measured admission for authority work (Phase2 A: FIX 7906, 7909, 7911,
//! 7912, 7921, 7922, 7930). A set an owner's signed record carries (custody
//! recipients, checkpoint roots, model routes, mesh addresses and ALPN
//! grants, a machine revision's acknowledged acts) is never refused for its
//! count (Rule 5): past the `authority_record_items` engine row it asks
//! whether everything is okay and is kept whole. Only a codec's own frame
//! bound, the machine's memory and disk floors and the anonymous surface's
//! shedding hold work back.
//!
//! One host hook ([`authority_work_policy`]) holds the wait and whether a
//! crossing only measures. Measuring never waits, so it runs anywhere, a
//! writer transaction included. A turn ([`Vault::admit_authority_work`]) is
//! taken only before a writer opens, only for work past its row, and only
//! when the policy paces: it waits on the vault's one task-work line, never a
//! queue of its own, and a wait that runs out ends typed and named
//! ([`AuthorityWorkWaitExpired`]), never silently.

use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::work_line::{LinePermit, WaitTimedOut};
use crate::{EntityId, Vault};

/// How long authority work past its row waits for a turn, until a host sets
/// its own: the queue default (ARCH-0044), honoring a caller's shorter
/// deadline (CALLS `Phase2 authority work wait`).
pub const AUTHORITY_WORK_WAIT_MS: u64 = 300_000;

/// Whether a crossing only asks and the work goes on at once (CALLS
/// `Phase2 authority work measure only`): no new fixed count, and an engine
/// row is never a permit.
pub const AUTHORITY_WORK_MEASURE_ONLY: bool = true;

/// Whether a new measurement, optional storage or decode check that cannot
/// answer leaves the work on the path it takes today (CALLS `Phase2 new check
/// unknown keeps current`). It never wraps an existing signature or semantic
/// check.
pub(crate) const AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT: bool = true;

/// What the host sets for authority work past its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityWorkPolicy {
    /// The longest a turn waits; a caller's shorter deadline wins.
    pub wait: Duration,
    /// A crossing asks and the work goes on, taking no turn.
    pub measure_only: bool,
}

impl Default for AuthorityWorkPolicy {
    fn default() -> Self {
        Self {
            wait: Duration::from_millis(AUTHORITY_WORK_WAIT_MS),
            measure_only: AUTHORITY_WORK_MEASURE_ONLY,
        }
    }
}

/// The policy a host set, in place of the defaults.
static POLICY: RwLock<Option<AuthorityWorkPolicy>> = RwLock::new(None);

/// The authority work policy in force: the host's, else the defaults.
#[must_use]
pub fn authority_work_policy() -> AuthorityWorkPolicy {
    POLICY
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .unwrap_or_default()
}

/// Sets the authority work policy, in place of any before it.
pub fn set_authority_work_policy(policy: AuthorityWorkPolicy) {
    *POLICY.write().unwrap_or_else(PoisonError::into_inner) = Some(policy);
}

/// A turn that waited past its policy's wait or its caller's deadline:
/// nothing was started, and the reason names the row and the wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityWorkWaitExpired {
    /// The row the work crossed.
    pub row: EngineLimit,
    /// How long it waited.
    pub waited_ms: u64,
    /// Whether the caller's own deadline ended the wait.
    pub caller_deadline: bool,
}

impl std::fmt::Display for AuthorityWorkWaitExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authority work past `{}` waited {} ms for its turn ({}); nothing was written",
            self.row.key(),
            self.waited_ms,
            if self.caller_deadline {
                "the caller's deadline"
            } else {
                "the authority work wait"
            },
        )
    }
}

impl From<AuthorityWorkWaitExpired> for Error {
    fn from(expired: AuthorityWorkWaitExpired) -> Self {
        Self::Refused(expired.to_string())
    }
}

/// One piece of authority work's turn: none for work under its row or under
/// a measure-only policy. Hold it until the writer commits.
#[must_use = "authority work keeps its turn only while it is held"]
pub(crate) struct AuthorityWorkTurn {
    _permit: Option<LinePermit>,
}

/// Measures one authority set of `items` against the `authority_record_items`
/// row: past it the installed port is asked and the bound returned. It never
/// waits and never refuses, so it runs inside a writer too.
pub(crate) fn measure_authority_work(watch: &LimitWatch, items: usize) -> Option<u64> {
    let row = EngineLimit::AuthorityRecordItems;
    let measured = u64::try_from(items).unwrap_or(u64::MAX);
    let bound = watch.bound(row);
    (measured > bound).then(|| {
        watch.crossed(row, bound, measured);
        bound
    })
}

impl Vault {
    /// The turn for authority work carrying `items`, before its writer
    /// opens: measured first, and at once when under the row or measure-only
    /// (today's path never waits, and `key` is not read). Otherwise a turn
    /// on this vault's task-work line in `key`'s place, waiting at most the
    /// policy's wait or until `deadline`, whichever is sooner; one that runs
    /// out is [`AuthorityWorkWaitExpired`]. Never call it holding a write
    /// transaction.
    pub(crate) fn admit_authority_work(
        &self,
        items: usize,
        deadline: Option<Instant>,
        key: impl FnOnce() -> crate::error::Result<EntityId>,
    ) -> crate::error::Result<AuthorityWorkTurn> {
        let crossed = measure_authority_work(self.limit_watch(), items);
        let policy = authority_work_policy();
        if crossed.is_none() || policy.measure_only {
            return Ok(AuthorityWorkTurn { _permit: None });
        }
        let key = key()?;
        let (wait, caller_deadline) =
            match deadline.map(|deadline| deadline.saturating_duration_since(Instant::now())) {
                Some(left) if left < policy.wait => (left, true),
                _ => (policy.wait, false),
            };
        match self.task_work.admit_blocking_for(key, wait) {
            Ok(permit) => Ok(AuthorityWorkTurn {
                _permit: Some(permit),
            }),
            Err(WaitTimedOut) => Err(AuthorityWorkWaitExpired {
                row: EngineLimit::AuthorityRecordItems,
                waited_ms: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                caller_deadline,
            }
            .into()),
        }
    }
}
