//! Supervisor ctl request/response wire types and shed/slim validation.

use serde::{Deserialize, Serialize};

use super::relay_delete::{
    RelayDeleteExecuteWire, RelayDeleteRechecksRequest, RelayDeleteRechecksWire,
    RelayDeleteRequest, RelayLockerBindRequest, RelayLockerBindWire,
};
use super::restore::{
    HostHoldsCursor, HostHoldsSource, HostOrderHoldsExport, ManagedRestoreIdentity, RestoreStatus,
};
use super::slim_control::{SlimResidency, SlimStatusWire, UnslimWire};
use super::wake::validate_wake_fields;
use super::{
    IdleReapWire, LedgerPage, LedgerPageRequest, LedgerPulledRequest, LedgerReportHead,
    ManagedBackupFacts, valid_owner_signing_challenge,
};

/// How a managed vault came up, as every `Ping` reports it.
mod readiness;

pub use self::readiness::{FacilityNotice, FacilityReason, ManagedFacility, ManagedReadiness};

/// How a managed vault's browser stands, as every `Ping` reports it.
mod browser;

pub use self::browser::{
    BrowserReadiness, BrowserTier, BrowserUnavailableReason, GUEST_RUNTIME_FACT_ARG,
    GuestRuntimeFact,
};

/// What every `Ping` says once the vault was deleted (FIX 11710).
mod deletion;

pub use self::deletion::PingDeletion;

/// Wire spelling is pinned to the engine's `slim::ShedCause`; the contract
/// crate must not depend on `oneiron`, so the duplication is deliberate.
/// The vault-side adapter maps with a total function, never a parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedCause {
    LongOutboundWait,
    MemoryPressure,
}

/// Requests the supervisor sends on the vault's ctl socket. One JSON line per
/// connection, one response line back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlRequest {
    PrepareReap,
    ReapAbort,
    /// Fields carry the same bounds as [`WakeEntry`](crate::WakeEntry); vaults must run
    /// [`CtlRequest::validate`] after parsing — deserialization alone does
    /// not enforce the wire limits.
    AlarmDue {
        id: String,
        reason_tag: String,
    },
    Ping,
    /// Appended last. `waited_secs` is the supervisor's own observation of the
    /// wait; the engine validates positivity, never policy.
    ///
    /// `wait_id` (FIX 5186), optional, is the id of the
    /// [`EligibleWaitWire`](crate::slim_control::EligibleWaitWire) a
    /// [`CtlRequest::SlimStatus`] reported. With it the vault sheds only while
    /// the step it would shed still has that live wait, and otherwise refuses
    /// [`WAIT_OBSERVATION_CHANGED`](crate::slim_control::WAIT_OBSERVATION_CHANGED)
    /// before dropping anything. Without it the shed is unguarded, as before.
    /// Build floor: a vault built before it ignores the field and sheds
    /// unguarded, so a supervisor relies on the guard only after that vault's
    /// `Ping` reports `slim_recovery_revision`.
    Shed {
        cause: ShedCause,
        waited_secs: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_id: Option<u64>,
    },
    /// Appended last (TL-5, TRAINING-LINK = C): before an erase destroys the
    /// vault, purge every publisher training scope it ever used. The first
    /// call records the purge; every call answers where it stands
    /// ([`CtlResponse::TrainingPurge`]). A vault frozen for reap refuses it
    /// as it refuses any write.
    TrainingPurge,
    /// Appended last (FIX 5260): an adopted vault proves its owner signing.
    /// `challenge` is [`OWNER_SIGNING_CHALLENGE_LEN`](crate::OWNER_SIGNING_CHALLENGE_LEN)
    /// fresh random bytes as lowercase hex, which the supervisor holds for
    /// this vault's running generation. The vault sends an
    /// [`OwnerSigningRecovery`](crate::OwnerSigningRecovery) proof to the
    /// supervisor socket its ledger pushes go to, then answers
    /// [`CtlResponse::OwnerSigningRecovered`]. It writes nothing and changes
    /// no reap state, so a vault frozen for reap answers it too and stays
    /// frozen. Build floor: it rides v3 with no version move, and a v3 vault
    /// built before it answers it as an unknown request (`Ok { ok: false }`),
    /// which a supervisor reads as not supported.
    RecoverOwnerSigning {
        challenge: String,
    },
    /// Appended last (FIX 6277): how many legal holds stand on the vault,
    /// which a hosted erase asks before it sends a destroy order, removes a
    /// key or deletes a backup ([`CtlResponse::LegalHolds`]). It writes
    /// nothing, so a vault frozen for reap answers it too and stays frozen.
    /// Build floor: it rides v3 with no version move, and a v3 vault built
    /// before it answers it as an unknown request (`Ok { ok: false }`), which
    /// a supervisor reads as not proven: the erase waits.
    LegalHolds,
    /// Appended last (FIX 5186): the vault's residency and the live outbound
    /// wait a `Shed` would park it on ([`CtlResponse::SlimStatus`]). A read:
    /// it changes no residency and resumes nothing, so a vault frozen for
    /// reap answers it too and stays frozen. Build floor: as `Shed.wait_id`.
    SlimStatus,
    /// Appended last (FIX 5186): ends a SLIM episode with logical FULL
    /// residency ([`CtlResponse::Unslim`]), the resume an ordinary inbound
    /// already performs. It rebuilds nothing, schedules no wake, writes no
    /// journal row and neither cancels nor resends an outbound call. It is
    /// not `reap_abort`, and a vault frozen for reap refuses it as it refuses
    /// `shed`, staying frozen. Build floor: as `Shed.wait_id`.
    Unslim,
    /// Appended last (LC FIX 5384/5385): what this process knows of the
    /// cold restore attempt `identity` names ([`CtlResponse::RestoreStatus`]),
    /// for a supervisor that lost the result pipe's last frame. Its
    /// identity's fields ride flat beside `op`; `cursor` is the receipt byte
    /// offset to page from, `null` or absent for its start. A read: it
    /// writes nothing and changes no reap state. Build floor: as the restore
    /// start mode's (`restore`); a v3 vault built before it answers it as an
    /// unknown request (`Ok { ok: false }`), which is never success.
    RestoreStatus {
        #[serde(flatten)]
        identity: ManagedRestoreIdentity,
        #[serde(default)]
        cursor: Option<u64>,
    },
    /// Appended last (Engine 10-20 backup shipper row (a), co-signed with
    /// LC): `prepare_reap` for an idle reap, with one backup before it
    /// ([`CtlResponse::PrepareIdleReap`]). It freezes, drains and exports as
    /// `prepare_reap` does, then reuses the vault's last backup when it
    /// covers the vault as it stands and takes one when it does not, within
    /// [`IDLE_REAP_PREPARATION_SECS`](crate::IDLE_REAP_PREPARATION_SECS) of
    /// the attempt's first call; every call joins that one attempt, and
    /// `reap_abort` drops it. Build floor: it rides v3 with no version move,
    /// and a v3 vault built before it answers it as an unknown request
    /// (`Ok { ok: false }`), which a supervisor reads as not supported and
    /// prepares with `prepare_reap`.
    PrepareIdleReap,
    /// Appended last (FIX 1485): this vault's whole host-order legal hold
    /// family, for the cold restore attempt `identity` names to carry
    /// ([`CtlResponse::HostOrderHolds`],
    /// [`host_holds`](crate::restore::host_holds)). The supervisor asks the
    /// source under its reap freeze, before the control plane's fence;
    /// `source` must name this vault, and `cursor` is the page to read from,
    /// `null` or absent for the first. A read: it writes no hold and changes
    /// no reap state. Build floor: as the restore input's `host_holds`; a v3
    /// vault built before it answers it as an unknown request
    /// (`Ok { ok: false }`), which is never a family. A `cursor` at the
    /// family's end is the confirm (FIX 6820): the supervisor's last call
    /// before it sends the restore input, with the source still frozen,
    /// answered with no bytes while the family is still the cursor's and
    /// `export_changed` once it is not. It has its own build floor
    /// ([`CONTRACT_VERSION`](crate::CONTRACT_VERSION)): a v3 vault built
    /// before it answers a confirm `cursor_invalid`, which confirms nothing.
    HostOrderHolds {
        identity: ManagedRestoreIdentity,
        source: HostHoldsSource,
        #[serde(default)]
        cursor: Option<HostHoldsCursor>,
    },
    /// Appended last (FIX 6826): the engine deletes one relay locker object
    /// of this vault inside its backup-hold writer exclusion
    /// ([`CtlResponse::RelayDeleteExecute`],
    /// [`relay_delete`](crate::relay_delete)). Its fields ride flat beside
    /// `op`. A vault frozen for reap, or stopping, answers it `unknown`
    /// (`not_ready`), never with the typed reap pause. Build floor: proven by
    /// `relay_delete_revision` on `Ping`; a v3 vault built before it answers
    /// it as an unknown request (`Ok { ok: false }`), which deletes nothing.
    RelayDeleteExecute {
        #[serde(flatten)]
        request: RelayDeleteRequest,
    },
    /// Appended last (FIX 6826): a long poll on this vault's relay delete
    /// recheck counter ([`CtlResponse::RelayDeleteRechecks`]). A read: it
    /// writes nothing, and a vault frozen for reap answers it too. Build
    /// floor: as `relay_delete_execute`'s.
    RelayDeleteRechecks {
        #[serde(flatten)]
        request: RelayDeleteRechecksRequest,
    },
    /// Appended last (FIX 6826): the supervisor names this vault's relay
    /// locker objects directory, which the engine opens itself; a rebind
    /// replaces it ([`CtlResponse::RelayLockerBind`]). The supervisor's
    /// alone: its broker never forwards it from a relay. Build floor: as
    /// `relay_delete_execute`'s.
    RelayLockerBind {
        #[serde(flatten)]
        request: RelayLockerBindRequest,
    },
    /// Appended last (FIX 9549): one page of the wake ledger report the
    /// freeze holds, which `prepare_reap` or `prepare_idle_reap` named
    /// ([`CtlResponse::LedgerPage`]). Token-authenticated; a read that
    /// writes nothing, so a vault frozen for reap answers it and stays
    /// frozen. Build floor: the wake ledger pages'.
    LedgerPage {
        #[serde(flatten)]
        request: LedgerPageRequest,
    },
    /// Appended last (FIX 9549): the supervisor holds the frozen report
    /// durably; the vault takes it as delivered and lets it go
    /// (`Ok { ok: true }`). Token-authenticated. Build floor: as
    /// `ledger_page`'s.
    LedgerPulled {
        #[serde(flatten)]
        request: LedgerPulledRequest,
    },
}

impl CtlRequest {
    /// Vault-side reject-not-truncate enforcement: `alarm_due` fields share
    /// the [`WakeEntry`](crate::WakeEntry) bounds; `shed` requires a positive observed wait, not
    /// a policy threshold. Vaults call this immediately after parsing a ctl line.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            CtlRequest::AlarmDue { id, reason_tag } => validate_wake_fields(id, reason_tag)?,
            CtlRequest::Shed { waited_secs, .. } => {
                anyhow::ensure!(*waited_secs > 0, "shed requires a positive waited_secs");
            }
            CtlRequest::RecoverOwnerSigning { challenge } => {
                anyhow::ensure!(
                    valid_owner_signing_challenge(challenge),
                    "recover_owner_signing requires a 64-digit lowercase hex challenge"
                );
            }
            CtlRequest::HostOrderHolds {
                identity, source, ..
            } => {
                anyhow::ensure!(
                    HostOrderHoldsExport::fits(identity, source),
                    "host_order_holds names an attempt and source that leave no room in a line"
                );
            }
            CtlRequest::RelayDeleteExecute { request } => request.validate()?,
            CtlRequest::RelayDeleteRechecks { request } => request.validate()?,
            CtlRequest::RelayLockerBind { request } => request.validate()?,
            CtlRequest::LedgerPage { request } => request.validate()?,
            CtlRequest::LedgerPulled { request } => request.validate()?,
            CtlRequest::PrepareReap
            | CtlRequest::ReapAbort
            | CtlRequest::Ping
            | CtlRequest::TrainingPurge
            | CtlRequest::LegalHolds
            | CtlRequest::SlimStatus
            | CtlRequest::Unslim
            | CtlRequest::RestoreStatus { .. }
            | CtlRequest::PrepareIdleReap => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedStatus {
    Entered,
    AlreadySlim,
    Refused,
}

/// Wire mirror of the engine's `ShedBlocker`. Stringly by design so a newer
/// vault's blocker kind stays displayable by an older supervisor; `detail`
/// is human-facing and bounded by [`MAX_CTL_LINE`](crate::MAX_CTL_LINE) at the framing layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShedBlockerWire {
    pub kind: String,
    pub detail: String,
}

/// What refused a ctl request the vault understood (contract v3). A request
/// that is malformed, over the line cap or failed for another reason still
/// answers `Ok { ok: false }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtlRefusalKind {
    /// The vault is paused for a reap: it takes no write until the reap is
    /// aborted or the vault wakes again.
    WritesFrozen,
}

impl CtlRefusalKind {
    /// The wire spelling, for a log field or another surface's body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WritesFrozen => "writes_frozen",
        }
    }
}

/// The bound a refusal names: its kind, the resource it bounds and the phase
/// it holds in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlBound {
    pub kind: CtlBoundKind,
    pub resource: CtlBoundResource,
    pub phase: CtlBoundPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtlBoundKind {
    /// The service's capacity.
    Capacity,
}

impl CtlBoundKind {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtlBoundResource {
    /// The service's vault lifecycle allocation.
    VaultLifecycleAllocation,
}

impl CtlBoundResource {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultLifecycleAllocation => "vault_lifecycle_allocation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtlBoundPhase {
    /// The phase that prepares a reap.
    ReapPrepare,
}

impl CtlBoundPhase {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReapPrepare => "reap_prepare",
        }
    }
}

/// What lifts a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtlResumeOn {
    /// The supervisor's `reap_abort`.
    ReapAbort,
    /// The vault's next wake.
    Wake,
}

/// A typed ctl refusal (contract v3): what refused, the bound it names,
/// whether it is temporary, what lifts it, and whether the same act works on
/// a self-hosted vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlRefusal {
    pub error: CtlRefusalKind,
    pub bound: CtlBound,
    pub temporary: bool,
    pub resumes_on: [CtlResumeOn; 2],
    pub self_hosted_supported: bool,
}

/// What a vault frozen for reap refuses a write with (K18), on the ctl socket
/// and in its HTTP surface's 503 body alike: a temporary pause under the
/// service's vault lifecycle allocation while it prepares a reap, lifted by
/// `reap_abort` or the vault's next wake. A self-hosted vault has no such
/// limit.
pub const REAP_PAUSE_REFUSAL: CtlRefusal = CtlRefusal {
    error: CtlRefusalKind::WritesFrozen,
    bound: CtlBound {
        kind: CtlBoundKind::Capacity,
        resource: CtlBoundResource::VaultLifecycleAllocation,
        phase: CtlBoundPhase::ReapPrepare,
    },
    temporary: true,
    resumes_on: [CtlResumeOn::ReapAbort, CtlResumeOn::Wake],
    self_hosted_supported: true,
};

/// Why a training purge is pending: it is recorded, and a purge control is
/// not yet written for the node to ship.
pub const TRAINING_PURGE_UNSENT: &str = "purge_unsent";
/// Why a training purge is pending: its controls are written, and the
/// intake's `removed` receipt for one is not in.
pub const TRAINING_PURGE_RECEIPT_PENDING: &str = "receipt_pending";
/// Why a training purge is pending: the intake answered a purge control
/// `rejected`.
pub const TRAINING_PURGE_REJECTED: &str = "purge_rejected";

/// Where a vault's publisher training purge stands (TL-5): one purge
/// control per scope the vault ever used, each riding its own scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingPurgeState {
    /// The vault never used a training scope: nothing to purge.
    NotNeeded,
    /// Recorded, and the intake's `removed` receipt for some purge control
    /// is not in. The erase waits; nothing times it out.
    Pending,
    /// The intake's `removed` receipt for every purge control is in.
    Done,
}

/// The answer to [`CtlRequest::TrainingPurge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingPurgeStateWire {
    pub state: TrainingPurgeState,
    /// Why it is pending: [`TRAINING_PURGE_UNSENT`],
    /// [`TRAINING_PURGE_RECEIPT_PENDING`] or [`TRAINING_PURGE_REJECTED`];
    /// `None` otherwise.
    pub reason: Option<String>,
}

/// The answer to [`CtlRequest::LegalHolds`]: how many legal holds stand on
/// the vault, customer and host order alike, or that the vault could not
/// count them. It names nothing of any hold: no id, matter, scope or reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegalHoldsWire {
    /// Counted: `standing` holds stand, and while any does an erase is
    /// blocked `legal_hold`. 0 means none stands.
    Proven { standing: u64 },
    /// Not counted: a supervisor reads it as it reads an unknown request,
    /// and the erase waits. Never a count of none.
    NotProven { reason: LegalHoldsNotProven },
}

/// Why a vault could not count its standing legal holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldsNotProven {
    /// The process has no open vault to read: it answers ctl before boot.
    VaultNotOpen,
    /// The vault's hold read failed.
    ReadFailed,
}

/// Untagged: variant selection is structural, tried in declaration order.
/// INVARIANT: each variant's required-field set must stay disjoint from every
/// variant above it, and new variants are appended last — otherwise a
/// malformed reply can silently match a later, more permissive variant
/// (e.g. `Ok`). Supervisors that need strict rejection should deserialize the
/// concrete response shape they expect for the request they sent. Tagging
/// this enum is a wire break; the additive SLIM v2 extension keeps it untagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CtlResponse {
    /// `ledger` names the wake ledger report the freeze holds (FIX 9549):
    /// its entries and the training setting at its revision, read page by
    /// page with `ledger_page` ([`LedgerPage`] checks each) and released
    /// with `ledger_pulled`. A reply that carries none matches no variant.
    PrepareReap {
        quiescent: bool,
        ledger: LedgerReportHead,
    },
    /// `readiness` is how the vault came up (contract v3,
    /// [`ManagedReadiness`]); a reply that carries none is no `Ping`.
    /// `browser` is how its browser stands now ([`BrowserReadiness`], FIX
    /// 7670), optional, with a build floor: absent means this engine offers
    /// no browser, as an engine built before the floor sends none, and its
    /// `Ping` is still a `Ping`. A present `browser` carries every key its
    /// state requires; nothing stands in for an absent one.
    /// `managed_backup` is what the vault reports of its backups (Engine
    /// 10-20 row (b), [`ManagedBackupFacts`]), optional. Build floor: it
    /// rides v3 with no version move, and a vault built before it sends
    /// none. A block that does not parse or validate reads as `None` too:
    /// unknown, nothing to pin, and never a failed `Ping`.
    /// `settings_paths_revision` is the revision of the owner-path rule the
    /// vault boots by
    /// ([`SETTINGS_PATHS_REVISION`](crate::settings_paths::SETTINGS_PATHS_REVISION),
    /// FIX 5187), and `artifact_internal_host_revision` that of the internal
    /// authority its artifact origin answers on
    /// ([`ARTIFACT_INTERNAL_HOST_REVISION`](crate::artifact_origin::ARTIFACT_INTERNAL_HOST_REVISION),
    /// FIX 6716). `slim_recovery_revision` is that of the supervisor SLIM
    /// recovery surface
    /// ([`SLIM_RECOVERY_REVISION`](crate::slim_control::SLIM_RECOVERY_REVISION),
    /// FIX 5186): `slim_status`, `unslim` and `Shed.wait_id`.
    /// `vm_outbox_revision` is that of a vault VM's outbox carrier
    /// ([`VM_OUTBOX_WIRE_REVISION`](crate::vm_outbox::VM_OUTBOX_WIRE_REVISION),
    /// FIX 5235), sent only when its storage, its companion and its
    /// attachment to the carrier port are all in place; a node's process
    /// vault sends none. `relay_delete_revision` is that of the relay locker
    /// delete the engine executes
    /// ([`RELAY_DELETE_REVISION`](crate::relay_delete::RELAY_DELETE_REVISION),
    /// FIX 6826), and `engine_instance` this process's boot: 16 random bytes
    /// as 32 lowercase hex, fresh each start, which `relay_delete_execute`
    /// names; one that is not 32 lowercase hex reads as `None`. Each rides v3
    /// with a build floor: a vault built before it sends none, which reads as
    /// unknown, never as revision 1, and so does a value that is not a u32.
    Ping {
        ok: bool,
        vault: String,
        pid: u32,
        contract_version: u32,
        readiness: ManagedReadiness,
        /// Absent: this engine offers no browser.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        browser: Option<BrowserReadiness>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::managed_backup::observed"
        )]
        managed_backup: Option<ManagedBackupFacts>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::version::observed_revision"
        )]
        settings_paths_revision: Option<u32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::version::observed_revision"
        )]
        artifact_internal_host_revision: Option<u32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::version::observed_revision"
        )]
        slim_recovery_revision: Option<u32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::version::observed_revision"
        )]
        vm_outbox_revision: Option<u32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::version::observed_revision"
        )]
        relay_delete_revision: Option<u32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::relay_delete::observed_instance"
        )]
        engine_instance: Option<String>,
        /// Present once the vault's Owners deleted it ([`PingDeletion`]);
        /// absent, it stands (build floor: `CONTRACT_VERSION`'s docs).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deletion::observed"
        )]
        deletion: Option<PingDeletion>,
    },
    Ok {
        ok: bool,
    },
    /// Appended after `Ok`. Required fields {slim, status} are disjoint from every
    /// variant above ({quiescent, ledger},
    /// {ok, vault, pid, contract_version, readiness}, {ok}), preserving the untagged
    /// declaration-order invariant. Do NOT add a required `ok` field here:
    /// it would let the `Ok` variant shadow this one during untagged
    /// matching (unknown fields are ignored, so `Ok { ok }` would accept a
    /// `Slim` line that carried `ok`).
    ///
    /// Out-of-workspace ctl-server mapping specification:
    /// - engine `Entered { dropped, .. }` -> `slim=true`, `status=entered`,
    ///   `reclaimed_bytes=Some(dropped.estimated_reclaimed_bytes)`,
    ///   `dropped_windows=Some(dropped.sync_windows)`, `blocker=None`;
    /// - engine `AlreadySlim` after a selected-identity re-drop -> `slim=true`,
    ///   `status=already_slim`, both fresh numerics `Some(..)`, `blocker=None`;
    /// - engine `AlreadySlim` from the no-identity selection-failure path ->
    ///   `slim=true`, `status=already_slim`, both numerics absent, `blocker=None`;
    /// - engine `Refused(blocker)` -> `status=refused`, both numerics absent,
    ///   `blocker=Some(mapped_blocker)`. For known kinds, `slim=true` iff the kind
    ///   is `already_slim_for_different_step`; the other known blockers report
    ///   `slim=false`. Unknown blocker kinds may report either residency, and
    ///   so may `wait_observation_changed`, a guarded shed's refusal
    ///   (FIX 5186), since the observed wait can end on either side of a shed.
    ///
    /// `slim` always reports residency at return, never whether this call entered it.
    Slim {
        slim: bool,
        status: ShedStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reclaimed_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dropped_windows: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocker: Option<ShedBlockerWire>,
    },
    /// Appended last (contract v3): a request the vault understood and
    /// refused, typed ([`CtlRefusal`]). Its one required field {refused} is
    /// disjoint from every variant above, and it carries no `ok` for the
    /// reason `Slim` carries none.
    Refused {
        refused: CtlRefusal,
    },
    /// Appended last (TL-5): the answer to [`CtlRequest::TrainingPurge`]. Its
    /// one required field {training_purge} is disjoint from every variant
    /// above, and it carries no `ok` for the reason `Slim` carries none.
    TrainingPurge {
        training_purge: TrainingPurgeStateWire,
    },
    /// Appended last (FIX 5260): the answer to
    /// [`CtlRequest::RecoverOwnerSigning`], whether the supervisor acked the
    /// vault's proof. Every failure after the challenge's shape check answers
    /// `false` (no supervisor socket, a proof that timed out, an ack that is
    /// malformed or says no), so the supervisor asks again; only a malformed
    /// challenge answers `Ok { ok: false }`. Its one required field
    /// {owner_signing_recovered} is disjoint from every variant above, and it
    /// carries no `ok` for the reason `Slim` carries none.
    OwnerSigningRecovered {
        owner_signing_recovered: bool,
    },
    /// Appended last (FIX 6277): the answer to [`CtlRequest::LegalHolds`].
    /// Its one required field {legal_holds} is disjoint from every variant
    /// above, and it carries no `ok` for the reason `Slim` carries none.
    LegalHolds {
        legal_holds: LegalHoldsWire,
    },
    /// Appended last (FIX 5186): the answer to [`CtlRequest::SlimStatus`].
    /// Its one required field {slim_status} is disjoint from every variant
    /// above, and it carries no `ok` for the reason `Slim` carries none.
    SlimStatus {
        slim_status: SlimStatusWire,
    },
    /// Appended last (FIX 5186): the answer to [`CtlRequest::Unslim`]. Its
    /// one required field {unslim} is disjoint from every variant above, and
    /// it carries no `ok` for the reason `Slim` carries none.
    Unslim {
        unslim: UnslimWire,
    },
    /// Appended last (LC FIX 5384/5385): the answer to
    /// [`CtlRequest::RestoreStatus`]. Its one required field
    /// {restore_status} is disjoint from every variant above, and it carries
    /// no `ok` for the reason `Slim` carries none. A supervisor parses this
    /// shape alone for the request it sent and runs
    /// [`CtlResponse::validate`]: any other answer is not proven.
    RestoreStatus {
        restore_status: RestoreStatus,
    },
    /// Appended last (Engine 10-20 backup shipper row (a)): the answer to
    /// [`CtlRequest::PrepareIdleReap`] ([`IdleReapWire`]). Its one required
    /// field {idle_reap} is disjoint from every variant above, and it carries
    /// no `ok` for the reason `Slim` carries none. A supervisor parses this
    /// shape alone for the request it sent and runs
    /// [`CtlResponse::validate`]: any other answer is not supported.
    PrepareIdleReap {
        idle_reap: IdleReapWire,
    },
    /// Appended last (FIX 1485): the answer to
    /// [`CtlRequest::HostOrderHolds`] ([`HostOrderHoldsExport`]). Its one
    /// required field {host_order_holds} is disjoint from every variant
    /// above, {idle_reap} included, and it carries no `ok` for the reason
    /// `Slim` carries none. A supervisor parses this shape alone for the
    /// request it sent and runs [`CtlResponse::validate`]: any other answer
    /// is not proven, never an empty family. A confirm's `exported` answer
    /// carries no bytes: it confirms the pages before it and is never an
    /// empty family.
    HostOrderHolds {
        host_order_holds: HostOrderHoldsExport,
    },
    /// Appended last (FIX 6826): the answer to
    /// [`CtlRequest::RelayDeleteExecute`]. Its one required field
    /// {relay_delete_execute} is disjoint from every variant above, and it
    /// carries no `ok` for the reason `Slim` carries none. A relay or its
    /// broker reads this shape alone for the request it sent
    /// ([`decode_execute_answer`](crate::relay_delete::decode_execute_answer)):
    /// any other answer settles nothing.
    RelayDeleteExecute {
        relay_delete_execute: RelayDeleteExecuteWire,
    },
    /// Appended last (FIX 6826): the answer to
    /// [`CtlRequest::RelayDeleteRechecks`]. Its one required field
    /// {relay_delete_rechecks} is disjoint from every variant above, and it
    /// carries no `ok`.
    RelayDeleteRechecks {
        relay_delete_rechecks: RelayDeleteRechecksWire,
    },
    /// Appended last (FIX 6826): the answer to
    /// [`CtlRequest::RelayLockerBind`]. Its one required field
    /// {relay_locker_bind} is disjoint from every variant above, and it
    /// carries no `ok`.
    RelayLockerBind {
        relay_locker_bind: RelayLockerBindWire,
    },
    /// Appended last (FIX 9549): the answer to [`CtlRequest::LedgerPage`].
    /// Its one required field {ledger_page} is disjoint from every variant
    /// above, and it carries no `ok`.
    LedgerPage {
        ledger_page: LedgerPage,
    },
}

impl CtlResponse {
    /// Validate SLIM status, residency, numerics, and blocker combinations,
    /// the shape of `PrepareReap.ledger` and of a `LedgerPage` page, the
    /// residency an `Unslim` left, the shape of a `RestoreStatus` page, of a
    /// `PrepareIdleReap` answer ([`IdleReapWire::validate`]), of a
    /// `HostOrderHolds` page and of the relay delete answers, after parsing.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let CtlResponse::PrepareReap { ledger, .. } = self {
            ledger.validate()?;
        }
        if let CtlResponse::LedgerPage { ledger_page } = self {
            ledger_page.validate()?;
        }
        if let CtlResponse::RestoreStatus { restore_status } = self {
            restore_status.validate()?;
        }
        if let CtlResponse::PrepareIdleReap { idle_reap } = self {
            idle_reap.validate()?;
        }
        if let CtlResponse::HostOrderHolds { host_order_holds } = self {
            host_order_holds.validate()?;
        }
        if let CtlResponse::RelayDeleteExecute {
            relay_delete_execute,
        } = self
        {
            relay_delete_execute.request.validate()?;
        }
        if let CtlResponse::RelayDeleteRechecks {
            relay_delete_rechecks,
        } = self
        {
            relay_delete_rechecks.validate()?;
        }
        if let CtlResponse::RelayLockerBind { relay_locker_bind } = self {
            relay_locker_bind.validate()?;
        }
        if let CtlResponse::Unslim { unslim } = self {
            anyhow::ensure!(
                unslim.residency == SlimResidency::Full,
                "unslim leaves full residency"
            );
        }
        if let CtlResponse::Slim {
            slim,
            status,
            reclaimed_bytes,
            dropped_windows,
            blocker,
        } = self
        {
            match status {
                ShedStatus::Entered => anyhow::ensure!(
                    *slim
                        && reclaimed_bytes.is_some()
                        && dropped_windows.is_some()
                        && blocker.is_none(),
                    "entered SLIM requires slim residency, both numerics, and no blocker"
                ),
                ShedStatus::AlreadySlim => anyhow::ensure!(
                    *slim
                        && (reclaimed_bytes.is_some() == dropped_windows.is_some())
                        && blocker.is_none(),
                    "already_slim SLIM requires slim residency, paired numerics, and no blocker"
                ),
                ShedStatus::Refused => {
                    let blocker = blocker
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("refused SLIM requires a blocker"))?;
                    anyhow::ensure!(
                        reclaimed_bytes.is_none() && dropped_windows.is_none(),
                        "refused SLIM forbids numerics"
                    );
                    let residency_matches = match blocker.kind.as_str() {
                        "no_pending_outbound_step"
                        | "multiple_pending_outbound_steps"
                        | "sync_window_busy" => !*slim,
                        "already_slim_for_different_step" => *slim,
                        _ => true,
                    };
                    anyhow::ensure!(
                        residency_matches,
                        "refused SLIM residency must correlate with blocker kind"
                    );
                }
            }
        }
        Ok(())
    }
}
