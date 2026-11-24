//! A vault machine that runs pinned workloads for the vault's issuer (pass
//! 33, `33-exec-node/DESIGN.md`): the job protocols' messages ([`wire`]),
//! the node's two mesh services ([`service`]), and the issuer's
//! `vault_machine` GPU job connector ([`issuer`]).

pub mod issuer;
#[cfg(feature = "mesh")]
pub mod service;
pub mod wire;

#[cfg(feature = "mesh")]
pub use service::{JobService, JobStatusService};
