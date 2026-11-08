//! A vault server's host floor (FIX 5978, FIX 5979, FIX 6299), attached in
//! the server's construction before any worker or guest starts: plain,
//! embedded and managed serving alike.
//!
//! Guests' socket entries and relays take their descriptors and worker
//! threads from the process's descriptor line, the line this server's own
//! sockets wait in ([`super::ConnectionPool::served`]): one ledger. While
//! this server's policy stands, the line holds its `[limits]
//! max_connections` and queue wait, and a crossing asks its Connections
//! question and raises its live pool check, whether a socket waits or a
//! guest's bundle found too little room (FIX 6304). Paused bodies take the
//! server's retained-memory line (FIX 10327). An embedded vault served again
//! attaches its new server's floor in place of the old one's; permits
//! already held keep the lines they came from.

use std::io;
use std::sync::Arc;

use oneiron::code_sandbox::egress::ProcessDescriptorFloor;
use oneiron::host_descriptors::{DescriptorPolicy, hold_descriptor_policy};
use oneiron_container::{HOST_NET_BYTE_FLOOR, HostNetFloor, HostNetPermit, floor_saturated};

use crate::admission::row_crossing;
use crate::byte_line::ByteLine;
use crate::config::LimitsConfig;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// Attaches this server's floor to `vault`, its policy on the process's
/// descriptor line set from `limits`, its crossings asked in `questions`
/// and its guests' paused bytes charged to `retained`.
pub(crate) fn attach_host_floor(
    vault: &oneiron::Vault,
    limits: &LimitsConfig,
    retained: &Arc<ByteLine>,
    questions: &Arc<LimitQuestions>,
) {
    vault.attach_host_net_floor(|| {
        let crossing = row_crossing(LimitRow::Connections, Arc::clone(questions));
        Arc::new(ServedFloor {
            _policy: hold_descriptor_policy(limits.max_connections, limits.queue_wait(), crossing),
            retained: Arc::clone(retained),
            questions: Arc::clone(questions),
        }) as Arc<dyn HostNetFloor>
    });
}

/// The floor a vault server attaches: descriptors and worker threads on the
/// process's descriptor line, paused bytes on the retained-memory line.
struct ServedFloor {
    /// This server's policy on the descriptor line, kept while the floor is.
    _policy: DescriptorPolicy,
    retained: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
}

impl HostNetFloor for ServedFloor {
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        ProcessDescriptorFloor.acquire(fds, workers)
    }

    fn acquire_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
        let held = self
            .retained
            .try_reserve_alone(
                usize::try_from(bytes).unwrap_or(usize::MAX),
                &self.questions,
            )
            .ok_or_else(|| floor_saturated(HOST_NET_BYTE_FLOOR))?;
        Ok(HostNetPermit::new(held))
    }
}
