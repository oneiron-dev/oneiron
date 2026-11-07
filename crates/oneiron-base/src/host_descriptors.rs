//! The process's one descriptor floor (FIX 5978, FIX 5979, FIX 6299): the
//! line every socket a serving host holds open, and every descriptor and
//! worker thread guests' network work holds, takes its permits from. Every
//! vault this process opens shares it; nothing mints a second one.
//!
//! Until a serving host sets its policy, the line is sized from the machine
//! ([`descriptor_floor`]) and says its crossings only to this process's
//! log: an embedded engine, a CLI run and a test charge it all the same. A
//! serving host holds the policy ([`hold_descriptor_policy`]): its `[limits]
//! max_connections`, its queue wait and where its Connections question is
//! asked. One host's policy stands at a time: a second host borrows the line
//! as it stands, and when the holder lets go the line goes back to the
//! machine's sizing. Permits held through any of it keep their owners: the
//! line is the same.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

pub use oneiron_contracts::host_descriptors::open_file_limit;

use crate::work_line::{LineCrossing, TASK_WORK_WAIT, WorkLine};

/// Half the descriptors this process may open, for sockets; the other half
/// stays for the vault, spools and git children. Raising the open-file limit
/// (`LimitNOFILE=`) raises it.
pub fn descriptor_floor() -> usize {
    let limit = open_file_limit().unwrap_or(8_192);
    usize::try_from(limit / 2).unwrap_or(usize::MAX).max(64)
}

/// The process's descriptor line: one permit for each socket a serving host
/// holds open, and for each descriptor and worker thread a guest's network
/// work holds.
pub fn descriptor_line() -> &'static WorkLine<()> {
    static LINE: OnceLock<WorkLine<()>> = OnceLock::new();
    LINE.get_or_init(|| WorkLine::new(Some(logged()), descriptor_floor(), TASK_WORK_WAIT))
}

/// Where the line's crossings are said while no host's policy stands: this
/// process's log, once per crossing, since no owner's door reads them.
struct LoggedCrossing;

impl LineCrossing for LoggedCrossing {
    fn crossed(&self, epoch: u64, bound: u64, observed: u64) {
        tracing::warn!(
            kind = "descriptor_floor",
            epoch,
            bound,
            observed,
            "work found this process's descriptor floor full; is everything okay?"
        );
    }
}

fn logged() -> Arc<dyn LineCrossing> {
    Arc::new(LoggedCrossing)
}

/// The bound of the host policy that stands, while one does.
static STANDING: Mutex<Option<usize>> = Mutex::new(None);

/// A serving host's hold on the descriptor line's policy. Dropping the one
/// that stands puts the line back to the machine's sizing, its crossings
/// said to this process's log.
#[must_use = "a host's policy stands only while its hold is kept"]
pub struct DescriptorPolicy {
    stands: bool,
}

/// Sets the descriptor line to `bound` permits whose waits end at `wait`,
/// its crossings said to `crossing`, for as long as the returned hold is
/// kept. While another host's policy stands, nothing is set: this host
/// borrows the line as it stands, and a different `bound` is logged, never
/// applied.
pub fn hold_descriptor_policy(
    bound: usize,
    wait: Duration,
    crossing: Arc<dyn LineCrossing>,
) -> DescriptorPolicy {
    let mut standing = STANDING.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(held) = *standing {
        if held != bound {
            tracing::warn!(
                kind = "descriptor_floor",
                standing = held,
                wanted = bound,
                "another host's [limits] max_connections sizes this process's descriptor floor; this host borrows it"
            );
        }
        return DescriptorPolicy { stands: false };
    }
    descriptor_line().configure(bound, wait, Some(crossing));
    *standing = Some(bound);
    DescriptorPolicy { stands: true }
}

impl Drop for DescriptorPolicy {
    fn drop(&mut self) {
        if !self.stands {
            return;
        }
        let mut standing = STANDING.lock().unwrap_or_else(PoisonError::into_inner);
        descriptor_line().configure(descriptor_floor(), TASK_WORK_WAIT, Some(logged()));
        *standing = None;
    }
}
