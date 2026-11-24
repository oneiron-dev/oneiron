//! Pinned workloads that one of the vault's machines runs for another (pass
//! 33, `33-exec-node/DESIGN.md`): the pin ([`pin`]) the owner approves and
//! the job submit carries, and the two protocol ids it crosses
//! ([`protocol`]). The pin's resource request is general (pass 34,
//! `34-compute-general/DESIGN.md` sections 2.1 and 2.2): its device claims
//! and the placement rule ([`device`]), and what a launch scope can enforce
//! ([`scope_bounds`]).

pub mod device;
pub mod pin;
pub mod protocol;
pub mod scope_bounds;

pub use device::*;
pub use pin::*;
pub use protocol::*;
pub use scope_bounds::*;
