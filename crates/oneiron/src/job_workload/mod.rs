//! Pinned workloads that one of the vault's machines runs for another (pass
//! 33, `33-exec-node/DESIGN.md`): the pin ([`pin`]) the owner approves and
//! the job submit carries, and the two protocol ids it crosses
//! ([`protocol`]).

pub mod pin;
pub mod protocol;

pub use pin::*;
pub use protocol::*;
