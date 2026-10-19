//! Supervisor ctl request/response wire types and shed/slim validation.

use serde::{Deserialize, Serialize};

use super::wake::validate_wake_fields;
use super::{ManagedTrainingSetting, WakeEntry};

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
    /// Fields carry the same bounds as [`WakeEntry`]; vaults must run
    /// [`CtlRequest::validate`] after parsing — deserialization alone does
    /// not enforce the wire limits.
    AlarmDue {
        id: String,
        reason_tag: String,
    },
    Ping,
    /// Appended last. `waited_secs` is the supervisor's own observation of the
    /// wait; the engine validates positivity, never policy.
    Shed {
        cause: ShedCause,
        waited_secs: u64,
    },
}

impl CtlRequest {
    /// Vault-side reject-not-truncate enforcement: `alarm_due` fields share
    /// the [`WakeEntry`] bounds; `shed` requires a positive observed wait, not
    /// a policy threshold. Vaults call this immediately after parsing a ctl line.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            CtlRequest::AlarmDue { id, reason_tag } => validate_wake_fields(id, reason_tag)?,
            CtlRequest::Shed { waited_secs, .. } => {
                anyhow::ensure!(*waited_secs > 0, "shed requires a positive waited_secs");
            }
            CtlRequest::PrepareReap | CtlRequest::ReapAbort | CtlRequest::Ping => {}
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
    /// Supervisors must run [`validate_wake_entries`](crate::validate_wake_entries)
    /// on `next_wake` before trusting it — deserialization alone does not enforce
    /// the wire limits. `training` is the vault's live training setting at
    /// `ledger_rev` (contract v3), shape-checked by [`CtlResponse::validate`];
    /// a reply that carries none matches no variant.
    PrepareReap {
        quiescent: bool,
        ledger_rev: u64,
        next_wake: Vec<WakeEntry>,
        training: ManagedTrainingSetting,
    },
    Ping {
        ok: bool,
        vault: String,
        pid: u32,
        contract_version: u32,
    },
    Ok {
        ok: bool,
    },
    /// Appended after `Ok`. Required fields {slim, status} are disjoint from every
    /// variant above ({quiescent, ledger_rev, next_wake, training},
    /// {ok, vault, pid, contract_version}, {ok}), preserving the untagged
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
    ///   `slim=false`. Unknown blocker kinds may report either residency.
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
}

impl CtlResponse {
    /// Validate SLIM status, residency, numerics, and blocker combinations, and
    /// the shape of `PrepareReap.training`, after parsing. Existing responses
    /// keep their prior validation requirements; `PrepareReap.next_wake` still
    /// uses [`validate_wake_entries`](crate::validate_wake_entries).
    pub fn validate(&self) -> anyhow::Result<()> {
        if let CtlResponse::PrepareReap { training, .. } = self {
            training.validate()?;
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
