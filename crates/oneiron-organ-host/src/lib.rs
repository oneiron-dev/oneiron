//! The organ host: the engine side of the open organ protocol
//! (ARCH-0075 section 9, `docengine:organ-host`).
//!
//! An organ runs as its own process and is never compiled into the engine.
//! The host installs it, starts it confined, keeps one warm process per organ,
//! unloads it when idle, restarts it with backoff after a crash and
//! quarantines it after five crashes in ten minutes. Calls book one shared
//! admission budget. Inputs cross as sealed read-only regions, copied out of
//! the vault once per content hash. The host hashes every output itself and
//! writes the receipt. It never writes the vault: the caller lands a proposal
//! through the write gate.
//!
//! Protocol 1.1 lets an organ ask the engine inside a call. The install
//! grant names the asks and their caps, the caller supplies the handlers,
//! and the receipt records every ask. `net.fetch` is the host's own
//! handler: a guarded fetch inside the grant's allowlist.
//!
//! Unix only. The design page is the companion to this crate.
#![cfg(unix)]

mod asks;
mod budget;
mod error;
mod fetch;
mod host;
mod process;
mod receipt;
mod regions;
mod sandbox;
mod slot;
mod spec;

pub use asks::{Answered, AskHandler, AskHandlers, AskRequest};
pub use budget::BudgetConfig;
pub use error::{HostError, Unavailable};
pub use fetch::GuardedFetch;
pub use host::{OrganHost, OrganOutcome, OrganOutput};
pub use receipt::{AskReceipt, CallReceipt, FetchTarget, ReceiptInput, ReceiptOutput, Unanswered};
pub use slot::{OrganState, OrganStatus};
pub use spec::{
    AskGrant, CallClass, FetchGrant, FetchOrigin, HostConfig, LentInput, OrganCall, OrganInput,
    OrganSpec, OrganTier,
};
