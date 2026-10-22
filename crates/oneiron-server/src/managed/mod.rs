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
//! - **Argv and one settings file are the whole configuration.** The owner's
//!   feature settings arrive in the one file the supervisor names
//!   (`--settings-file`), refused leaf by leaf where a leaf is the
//!   supervisor's and settled once (`managed::settings`). Managed mode never
//!   loads settings from another config file, the `ONEIRON_*` environment
//!   (including `ONEIRON_AUTH_SECRET` — bearer auth is the supervisor's job)
//!   or the XDG layers. Explicit privacy environment settings and
//!   `ONEIRON_CONFIG` are refused by presence alone. Only [`HYPNOS_LISTEN_FD`]
//!   supplies an environment value; even dictionary search roots come from
//!   argv or the settings file rather than the usual `HOME`/`XDG_*` probe.
//! - **The engine's own timers write only under reap admission.** Its
//!   interval workers (housekeeping, the connector and ladder workers,
//!   embedding and tagging, and the owner's `[backup]` schedule) take the
//!   admission a served write takes for each pass, so a vault frozen for reap
//!   writes nothing from them. Wake alarms are not among them: the supervisor
//!   pushes those over the ctl socket, and the ledger tells it when.
//!
//! Real tenant data needs a probed fscrypt policy and a dedicated per-vault
//! UID owning the directory. Only an explicitly marked synthetic canary may
//! open without those proofs. Organization routing selects one such vault;
//! it never adds cross-vault reads or replaces the vault's membership policy.

mod args;
mod attested_routes;
mod backup_facts;
mod container_dirs;
#[cfg(test)]
mod ctl_shed_tests;
mod host;
mod isolation;
pub mod key_sync;
mod ledger;
mod listener;
pub mod org_routing;
mod owner_recovery;
mod owner_stage;
mod owner_storage;
mod peer;
/// Private live previews on a session-owned origin.
pub mod preview;
mod relay;
/// The relay locker delete this engine executes (FIX 6826).
mod relay_delete;
/// The cold managed restore start mode (`--restore`).
mod restore;
pub(crate) use relay::hold_guard::{
    RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard, RelayDeleteHoldOutcome,
    RelayDeleteTarget,
};
pub(crate) use relay::run_host_relay;
pub use relay::{IROH_RELAY_REVISION, RelayConfig, run_relay};
mod settings;
mod shed;
pub(crate) use self::peer::UnixPeer;
mod state_serve;
pub(crate) use state_serve::{
    ManagedCarrierContext, ManagedIngress, ManagedOwnerHolder, ManagedOwnerSession,
    ManagedWidenHolder,
};
mod vault_gates;
#[cfg(target_os = "linux")]
mod vm_guest;
#[cfg(target_os = "linux")]
mod vm_host;
#[cfg(target_os = "linux")]
mod vm_init;
#[cfg(target_os = "linux")]
mod vm_outbox;
#[cfg(target_os = "linux")]
mod vm_schedule;
#[cfg(target_os = "linux")]
pub use self::vm_host::{
    SleepOutcome, VaultVm, VaultVmConfig, VaultVmInspect, VaultVmRun, VmAnchorHostIo, VmExitWatch,
    VmRestoreFds, VmRestoreHostIo, VmSnapshotCustody, VmSnapshotCustodyUnavailable,
    inspect_vault_vm, run_vault_vm,
};
#[cfg(target_os = "linux")]
pub use self::vm_init::run_vm_init;
#[cfg(target_os = "linux")]
pub use self::vm_outbox::{
    VmOutboxAttachment, VmOutboxHostRoots, read_vm_backup_label, run_vm_outbox,
};

pub use self::args::{ManagedArgs, ManagedError, ManagedStartMode, NO_FD, SettingsRefusal};
pub use self::key_sync::{
    KeyInvalidation, KeyInvalidationAck, KeyInvalidationKind, account_keys,
    account_keys_from_vault_config, apply_key_invalidation, verdict_lease_from_vault,
};
pub use self::ledger::{FrozenReport, LEDGER_REV_KEY, LedgerSnapshot, WakeLedger};
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
