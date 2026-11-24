//! A vault machine that runs pinned workloads for the vault's issuer (pass
//! 33, `33-exec-node/DESIGN.md`): the job protocols' messages ([`wire`])
//! and the node's two mesh services ([`service`]).

#[cfg(feature = "mesh")]
pub mod service;
pub mod wire;

#[cfg(feature = "mesh")]
pub use service::{JobService, JobStatusService};
