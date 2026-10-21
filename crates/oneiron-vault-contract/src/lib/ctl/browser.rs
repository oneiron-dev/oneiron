//! A managed vault's browser readiness (FIX 7670): what every `Ping` says
//! of its `[browser]` guest, and the supervisor's guest runtime fact the
//! engine is spawned with.

use serde::{Deserialize, Serialize};

use crate::UnixTs;

/// The flag that carries the supervisor's [`GuestRuntimeFact`] for the
/// vault's UID, one value per engine spawn. Absent, the supervisor observed
/// none.
pub const GUEST_RUNTIME_FACT_ARG: &str = "--guest-runtime-fact";

/// What the trusted supervisor observed of the guest runtime it provisioned
/// for the vault's UID, in closed names. `GuestRuntimeProvisioned` means the
/// image was imported and the observed preconditions held, never that a
/// guest started; the other eight name the step that did not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestRuntimeFact {
    GuestRuntimeProvisioned,
    GuestRuntimeDisabled,
    GuestRuntimeSubidsConflict,
    GuestRuntimeUsernsUnavailable,
    GuestRuntimeUserspaceMissing,
    GuestRuntimeLimitsUnavailable,
    GuestRuntimeDirsUnavailable,
    GuestRuntimeImageImportFailed,
    GuestRuntimeImageIdMismatch,
}

impl GuestRuntimeFact {
    /// Every fact, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::GuestRuntimeProvisioned,
        Self::GuestRuntimeDisabled,
        Self::GuestRuntimeSubidsConflict,
        Self::GuestRuntimeUsernsUnavailable,
        Self::GuestRuntimeUserspaceMissing,
        Self::GuestRuntimeLimitsUnavailable,
        Self::GuestRuntimeDirsUnavailable,
        Self::GuestRuntimeImageImportFailed,
        Self::GuestRuntimeImageIdMismatch,
    ];

    /// The wire and argv spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestRuntimeProvisioned => "guest_runtime_provisioned",
            Self::GuestRuntimeDisabled => "guest_runtime_disabled",
            Self::GuestRuntimeSubidsConflict => "guest_runtime_subids_conflict",
            Self::GuestRuntimeUsernsUnavailable => "guest_runtime_userns_unavailable",
            Self::GuestRuntimeUserspaceMissing => "guest_runtime_userspace_missing",
            Self::GuestRuntimeLimitsUnavailable => "guest_runtime_limits_unavailable",
            Self::GuestRuntimeDirsUnavailable => "guest_runtime_dirs_unavailable",
            Self::GuestRuntimeImageImportFailed => "guest_runtime_image_import_failed",
            Self::GuestRuntimeImageIdMismatch => "guest_runtime_image_id_mismatch",
        }
    }
}

/// Exactly one of the nine spellings [`GuestRuntimeFact::as_str`] gives,
/// with no alias and no other case.
impl std::str::FromStr for GuestRuntimeFact {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|fact| fact.as_str() == value)
            .ok_or_else(|| format!("{value:?} is not a guest runtime fact"))
    }
}

/// The sandbox a verified browser start ran in: a Firecracker microVM, or
/// the fenced OCI container. A start in no proved sandbox is neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTier {
    Firecracker,
    FencedOci,
}

/// Where the vault's last browser start stopped, by its phase: never an
/// error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserUnavailableReason {
    /// No sandbox could take the guest.
    SandboxUnavailable,
    /// The sandbox did not start the guest.
    GuestStartFailed,
    /// The guest started and the browser driver did not attach to it.
    DriverAttachFailed,
    /// The guest started and its sandbox manifest receipt was not written.
    SessionReceiptFailed,
}

/// How a managed vault's browser stands now, on every `Ping`: what its
/// `[browser]` section declares, and then what its last completed guest
/// start showed. It starts again at each engine spawn and moves only when a
/// start this process makes completes; nothing probes it. No state fails
/// the vault's start or asks for a restart: the vault serves in each, and
/// only its browser acts refuse while it has none.
///
/// `runtime_fact` is the supervisor's [`GuestRuntimeFact`] for this spawn,
/// a required key that is `null` when it observed none. `image` is the
/// configured image, and in `VerifiedStart` the one the guest's manifest
/// names. `last_observed_at` is when that start completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BrowserReadiness {
    /// The vault has no `[browser]` section.
    NotConfigured,
    /// A `[browser]` section with no runtime bound: no guest can start.
    ConfiguredUnbound {
        image: String,
        #[serde(deserialize_with = "Option::deserialize")]
        runtime_fact: Option<GuestRuntimeFact>,
    },
    /// A section with its runtime bound, and no start completed yet. It
    /// declares the binding and proves no start.
    Bound {
        image: String,
        #[serde(deserialize_with = "Option::deserialize")]
        runtime_fact: Option<GuestRuntimeFact>,
    },
    /// The last start ran in a proved sandbox and its browser driver
    /// attached: evidence of that start, not of a seat live now.
    VerifiedStart {
        image: String,
        tier: BrowserTier,
        last_observed_at: UnixTs,
        #[serde(deserialize_with = "Option::deserialize")]
        runtime_fact: Option<GuestRuntimeFact>,
    },
    /// The last start stopped at `reason`.
    Unavailable {
        image: String,
        reason: BrowserUnavailableReason,
        last_observed_at: UnixTs,
        #[serde(deserialize_with = "Option::deserialize")]
        runtime_fact: Option<GuestRuntimeFact>,
    },
}
