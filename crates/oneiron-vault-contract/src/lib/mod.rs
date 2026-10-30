//! Supervisor ⇄ vault child-process contract: wire types, credential framing,
//! limits. Both sides of the seam build against this crate so framing bugs
//! cannot diverge: the node supervisor (Hypnos) on one side, and every
//! vault-process implementation on the other (the engine's managed serve
//! mode, the conformance stub, or any self-hosted supervisor speaking the
//! same protocol).
//!
//! Versioning: crate SemVer and wire compatibility are separate things. The
//! wire is governed by [`CONTRACT_VERSION`], which stays 3: each change
//! rides it with a build floor at the engine revision it merged in, named in
//! [`CONTRACT_VERSION`]'s docs. A new field is required, with no default and
//! no reader of a record without it kept, so a supervisor reads it only with
//! installed engines at or after its floor. A new ctl request a vault built
//! before it answers as unknown, and an older optional `Ping` field such a
//! vault sends none of reads as unknown, never as support; an absent
//! `Ping.browser` says this engine offers no browser. A new argv flag
//! goes only to an installed engine at or after its floor, since an older one
//! refuses a flag it does not parse. Consumers pin this crate at an exact
//! revision and run cross-repo conformance before moving the pin.

pub mod artifact_origin;
/// The backup handoff: a label's retention pin and the supervisor's
/// root-stage ack (LC backup shipper).
pub mod backup_handoff;
/// The publisher training outbox: offers, controls and receipts (OF-420).
pub mod conversation_training;
mod ctl;
/// The vault's data-key escrow capsules on their way to the registry.
pub mod escrow;
/// The e-sign delivery outbox's completion receipt.
pub mod esign_delivery;
/// Shared lifecycle and host-specific adapters.
pub mod host;
pub mod host_adapters;
mod ledger;
/// The wake ledger's report in bounded pages (FIX 9549).
mod ledger_pages;
mod limits;
mod managed_backup;
mod managed_holder;
mod owner_signing_recovery;
/// Private, lease-bound live process ports.
pub mod preview;
/// The relay locker delete the engine executes, its locker binding and its
/// rechecks (FIX 6826).
pub mod relay_delete;
/// The cold managed restore start mode: its plan, result frames, receipt,
/// status and commit marker (LC FIX 5384/5385).
pub mod restore;
mod secrets;
/// The owner paths a managed vault's settings file names, and their rule.
pub mod settings_paths;
/// The leaves a managed vault's settings file may not set.
pub mod settings_policy;
/// The supervisor's SLIM status read and unslim (FIX 5186).
pub mod slim_control;
/// Account and organization vault bindings with per-vault lifecycle hooks.
pub mod tenancy;
/// The host's vault UID allocation table: its path, file shape and row codec.
pub mod vault_uids;
mod version;
/// The vault-VM wire shared by the guest adapter and the host's VMM driver.
pub mod vm;
/// A vault VM's custody anchor channels: the owner credential's exchange
/// and the proxy to the anchor URL (FIX 6517).
pub mod vm_anchor;
/// A vault VM's outbox carrier: its frames, transfers, acks and members.
pub mod vm_outbox;
/// A vault VM's provision connection: its binding, key frame and reply.
pub mod vm_provision;
/// A vault VM's restore channel: its boot mode, stream records and the
/// commit marker read back (FIX 6584).
pub mod vm_restore;
mod wake;

/// The commitment RECURRENCE vocabulary (CMT-2, ONE-1539).
///
/// Strictly additive and strictly nested: the root [`Schedule`] above is the
/// wake-ledger's one-shot instruction to the supervisor and is untouched, so
/// [`CONTRACT_VERSION`] does not move. This module is the shared *recurrence*
/// vocabulary — one implementation, two consumers (ARCH-0060 [CAL-03]): a
/// commitment series, and an ICS poll cadence expressed as an interval on this
/// same enum rather than as a second recurrence primitive ([CAL-02]).
///
/// Nothing here reaches the wire today. It lives in the contract crate so the
/// vocabulary a vault persists and a supervisor would one day schedule against
/// cannot fork into two spellings.
pub mod commitment;

#[cfg(test)]
mod tests;

pub use self::ctl::{
    BrowserReadiness, BrowserTier, BrowserUnavailableReason, CtlBound, CtlBoundKind, CtlBoundPhase,
    CtlBoundResource, CtlRefusal, CtlRefusalKind, CtlRequest, CtlResponse, CtlResumeOn,
    FacilityNotice, FacilityReason, GUEST_RUNTIME_FACT_ARG, GuestRuntimeFact, LegalHoldsNotProven,
    LegalHoldsWire, ManagedFacility, ManagedReadiness, PingDeletion, REAP_PAUSE_REFUSAL,
    ShedBlockerWire, ShedCause, ShedStatus, TRAINING_PURGE_RECEIPT_PENDING, TRAINING_PURGE_REJECTED,
    TRAINING_PURGE_UNSENT, TrainingPurgeState, TrainingPurgeStateWire,
};
pub use self::ledger::{LedgerAck, LedgerUpdate, ManagedTrainingSetting};
pub use self::ledger_pages::{
    LedgerPage, LedgerPageRequest, LedgerPulledRequest, LedgerReport, LedgerReportAssembly,
    LedgerReportHead,
};
pub use self::limits::{
    CREDENTIALS_LEN, DEK_LEN, MAX_CTL_LINE, MAX_LEDGER_PAGE_ENTRIES, MAX_REASON_TAG, MAX_WAKE_ID,
    READY_BYTE, TOKEN_LEN,
};
pub use self::managed_backup::{
    BackupCoverageWire, CheckpointSignerObservation, CheckpointSignerUnavailable,
    IDLE_REAP_PREPARATION_SECS, IDLE_REAP_SCHEMA_VERSION, IdleBackupFailure, IdleBackupState,
    IdleBackupWire, IdleReapInFlight, IdleReapWire, MANAGED_BACKUP_SCHEMA_VERSION,
    ManagedBackupFacts,
};
pub use self::managed_holder::{
    MANAGED_OWNER_ACTION_HEADER, MANAGED_OWNER_BOUND_HEADERS, MANAGED_PERSON_ACTION_HEADER,
    MANAGED_VOICE_MAX_SKEW_SECS, MANAGED_VOICE_METHOD, MANAGED_VOICE_NONCE_BYTES,
    MANAGED_VOICE_PATH, ManagedOwnerAction, ManagedOwnerHead, ManagedOwnerRequest,
    ManagedOwnerTranscript, ManagedPersonAction, ManagedVoiceBody, ManagedWidenAction,
    embedded_owner_holder_hex, managed_voice_body, managed_voice_nonce,
};
pub use self::owner_signing_recovery::{
    OWNER_SIGNING_CHALLENGE_LEN, OWNER_SIGNING_RECOVERY_OP, OwnerSigningRecovery,
    OwnerSigningRecoveryAck, valid_owner_signing_challenge,
};
pub use self::secrets::{
    Credentials, TokenHex, from_hex, hex, read_credentials, write_credentials,
};
pub use self::version::{CONTRACT_VERSION, SLIM_CONTRACT_VERSION, supports_slim};
pub use self::wake::{
    Schedule, UnixTs, WakeEntry, now_ts, valid_vault_name, validate_wake_entries,
};

// The flat lib.rs module used to provide these names to the sibling test
// module through `use super::*`: the serde derive macros the frozen v1
// schema enums name bare. After the directory split the seam re-imports
// them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use serde::{Deserialize, Serialize};
