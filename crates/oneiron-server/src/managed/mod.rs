//! Managed serve mode: the vault engine as a supervised child process.
//!
//! The engine boots from argv, serves on a socket the supervisor bound, opens
//! its vault from supervisor-delivered credentials, answers control verbs,
//! exports its wake ledger, and exits cleanly on SIGTERM. Every wire type,
//! framing rule and limit comes from [`oneiron_vault_contract`], which both
//! sides of the seam build against; nothing here reshapes them.
//!
//! Three properties hold this module together, and each one is a fail-closed
//! default rather than a convention:
//!
//! - **Off by default.** Managed mode is reachable only through
//!   `--managed-by-hypnos`. Without it, [`crate::commands::serve`] never
//!   enters this module and the unmanaged path is exactly what it was.
//! - **Argv is the whole configuration.** Managed mode never loads settings from
//!   a config file, the `ONEIRON_*` environment (including `ONEIRON_AUTH_SECRET` —
//!   bearer auth is the supervisor's job) or the XDG layers. Explicit privacy
//!   environment settings and `ONEIRON_CONFIG` are refused by presence alone.
//!   Only [`HYPNOS_LISTEN_FD`] supplies an environment value; even dictionary
//!   search roots come from argv rather than the usual `HOME`/`XDG_*` probe.
//! - **The engine schedules nothing.** There is no timer here. Alarms are
//!   pushed by the supervisor over the ctl socket; the ledger tells it when to
//!   push them.
//!
//! Real tenant data needs a probed fscrypt policy and a dedicated per-vault
//! UID owning the directory. Only an explicitly marked synthetic canary may
//! open without those proofs. Organization routing selects one such vault;
//! it never adds cross-vault reads or replaces the vault's membership policy.

mod args;
#[cfg(test)]
mod ctl_shed_tests;
mod host;
mod isolation;
pub mod key_sync;
mod ledger;
mod listener;
pub mod org_routing;
mod peer;
/// Private live previews on a session-owned origin.
pub mod preview;
mod relay;
pub use relay::{IROH_RELAY_REVISION, RelayConfig, run_relay};
mod shed;
pub(crate) use self::peer::UnixPeer;
mod state_serve;
pub(crate) use state_serve::ManagedWidenHolder;
mod vault_gates;
#[cfg(target_os = "linux")]
mod vm_guest;
#[cfg(target_os = "linux")]
mod vm_host;
#[cfg(target_os = "linux")]
mod vm_schedule;
#[cfg(target_os = "linux")]
pub use self::vm_host::{SleepOutcome, VaultVm, VaultVmConfig, VaultVmRun, run_vault_vm};

pub use self::args::{ManagedArgs, ManagedError, NO_FD};
pub use self::key_sync::{
    KeyInvalidation, KeyInvalidationAck, KeyInvalidationKind, account_keys,
    account_keys_from_vault_config, apply_key_invalidation, verdict_lease_from_vault,
};
pub use self::ledger::{LEDGER_REV_KEY, WakeLedger};
pub use self::listener::{
    BoundServeListener, HYPNOS_LISTEN_FD, ManagedCtl, ServeListener, adopt_listen_fd, signal_ready,
};
pub use self::state_serve::{
    ManagedShutdown, ManagedState, ObservedAlarm, ShutdownSignal, WRITES_FROZEN_TAG,
    build_managed_app, final_ledger_push, serve_managed, spawn_sigterm_shutdown,
};
pub(crate) use self::vault_gates::warn_if_reader_table_short;
pub use self::vault_gates::{
    CANARY_MARKER_KEY, CANARY_MARKER_VALUE, DEK_MAC_KEY, check_managed_open_gates,
    open_managed_vault, read_managed_credentials,
};
