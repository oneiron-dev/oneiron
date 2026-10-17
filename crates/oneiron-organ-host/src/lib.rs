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
//! [`seal`] is the engine's seal port over the seal organ.
//!
//! A host that cannot start an organ (a phone, a browser) sends the call to
//! another node of the owner's over the mesh ([`mesh`], OF-575 MESH);
//! [`OrganRouter`] picks where a call runs, and a call no node can run now
//! waits in the vault beside its artifact and says why, until a redrive
//! runs it. Starting and serving organs is Unix only; the router, the mesh
//! client and the types a caller handles build everywhere.

#[cfg(unix)]
mod asks;
mod budget;
mod error;
#[cfg(unix)]
mod fetch;
mod handlers;
#[cfg(unix)]
mod host;
mod landing;
pub mod mesh;
mod outcome;
#[cfg(unix)]
mod pin;
#[cfg(unix)]
mod process;
mod receipt;
#[cfg(unix)]
mod regions;
mod route;
#[cfg(unix)]
mod sandbox;
#[cfg(unix)]
pub mod seal;
#[cfg(unix)]
mod slot;
mod spec;
mod wait;

pub use budget::BudgetConfig;
pub use error::{HostError, Unavailable};
#[cfg(unix)]
pub use fetch::GuardedFetch;
pub use handlers::{Answered, AskHandler, AskHandlers, AskRequest};
#[cfg(unix)]
pub use host::OrganHost;
pub use landing::propose_organ_outputs;
#[cfg(unix)]
pub use mesh::OrganService;
pub use mesh::{ORGAN_ALPN, Offer};
pub use outcome::{OrganOutcome, OrganOutput};
#[cfg(unix)]
pub use pin::{install_pinned_binary, pack_spec};
pub use receipt::{
    AskReceipt, CallReceipt, FetchTarget, ReceiptInput, ReceiptOutput, SignedReceipt, Unanswered,
};
pub use route::{
    NodeWait, OrganNodes, OrganRouter, RanOn, Routed, VaultOrganNodes, can_start_organs,
};
#[cfg(unix)]
pub use slot::{OrganState, OrganStatus};
pub use spec::{
    AskGrant, CallClass, FetchGrant, FetchOrigin, HostConfig, LentInput, OrganCall, OrganInput,
    OrganSpec, OrganTier,
};
pub use wait::{OrganJob, Redrive, Redriven, Submitted};
