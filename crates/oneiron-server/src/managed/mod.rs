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
//! Real tenant data is refused in contract v1. A managed open needs the
//! credential gate AND a synthetic-canary marker, because the isolation this
//! mode would need for real data — an fscrypt policy on the data directory and
//! a dedicated per-vault UID owning it — has no probe in this build. The
//! refusal is the tripwire that keeps the gap visible.

mod args;
mod ledger;
mod listener;
mod state_serve;
mod vault_gates;

pub use self::args::{ManagedArgs, ManagedError};
pub use self::ledger::{LEDGER_REV_KEY, WakeLedger};
pub use self::listener::{
    BoundServeListener, HYPNOS_LISTEN_FD, ManagedCtl, ServeListener, adopt_listen_fd, signal_ready,
};
pub use self::state_serve::{
    ManagedShutdown, ManagedState, ObservedAlarm, ShutdownSignal, WRITES_FROZEN_TAG,
    build_managed_app, final_ledger_push, serve_managed, spawn_sigterm_shutdown,
};
pub use self::vault_gates::{
    CANARY_MARKER_KEY, CANARY_MARKER_VALUE, DEK_MAC_KEY, check_managed_open_gates,
    open_managed_vault, read_managed_credentials,
};
