//! The two mesh protocols a job crosses between the issuer and the node
//! (pass 33, EM-1 = A). A grant is per protocol: the owner grants each with
//! `vault.mesh.set_alpn_grant`, and revoking [`JOB_ALPN`] stops new work
//! while [`JOB_STATUS_ALPN`] still collects the receipts of the jobs it
//! stopped. The messages are oneiron-server's `gpu_execution_node::wire`.

/// Admits new work on a node: `Node`, `Reserve`, `Release`, `Submit`.
pub const JOB_ALPN: &[u8] = b"oneiron/job/1";
/// Serves the keys a node already holds: `Find`, `Status`, `Signal`,
/// `Stop`, `Keys`, `Fetch`, `Ack`.
pub const JOB_STATUS_ALPN: &[u8] = b"oneiron/job-status/1";
