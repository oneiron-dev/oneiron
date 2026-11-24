//! Pinned workloads that one of the vault's machines runs for another (pass
//! 33, `33-exec-node/DESIGN.md`): the pin ([`pin`]) the owner approves and
//! the job submit carries.

pub mod pin;

pub use pin::*;
