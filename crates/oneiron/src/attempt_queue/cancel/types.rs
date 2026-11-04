//! Durable wire types of the ONE-1896 two-rung graceful-cancel protocol.
//!
//! Everything here is persisted inside [`AttemptCancelState`] on an attempt
//! row. The verb inputs and outcomes live in [`super::verbs`], the queue doors
//! in [`super::ops`] and [`super::terminal`].
//!
//! The data types themselves live in [`crate::store::attempt_cancel`]; this
//! module keeps their constants, constructors, predicates and reserve
//! arithmetic, and the force-cancel authority.

use crate::attempt_queue::validate::validate_cancel_actor;
use crate::error::Result;
pub use crate::store::attempt_cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptCancelState,
    AttemptCancellation, AttemptLanding, AttemptLandingReserve, AttemptResumePoint, CancelMode,
    CancelStanding, ForceCancelGrounds, LandingTrigger,
};

/// Share of an attempt's dialed budget held back for LANDING work.
///
/// The dial is a percent of INTEGER budget units, never a float: the reserve is
/// accounting a terminal receipt reports, and a rounded float would make
/// "spent exactly the reserve" untestable.
pub const LANDING_RESERVE_PERCENT: u64 = 10;

/// Largest landing reserve a caller may dial. Past half the budget the
/// "reserve" is the budget and ordinary execution is the exception.
pub const MAX_LANDING_RESERVE_PERCENT: u64 = 50;

/// Refused soft cancel requests after which repeated refusal is an observable
/// pathology rather than a legitimate "not yet".
///
/// Crossing it never changes the attempt's state: only the hard rung
/// ([`AttemptQueue::force_cancel`](crate::attempt_queue::AttemptQueue::force_cancel))
/// can stop a worker that will not land, and this is the signal that says so.
pub const SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD: u32 = 3;

/// Fraction of the lease timeout after which the runtime may WARN a worker to
/// land. Distinct from expiry: the warning asks, expiry forces.
pub const LEASE_LANDING_WARNING_PERCENT: u64 = 80;

/// Actor token reserved for runtime-authored rows.
///
/// Worker- and peer-facing cancel doors refuse it, so a worker cannot author a
/// row that reads as if the runtime wrote it. It matches the run-tree
/// projection's runtime actor so both surfaces name the runtime identically.
pub const ATTEMPT_RUNTIME_ACTOR: &str = "runtime";

impl LandingTrigger {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelRequest => "cancel_request",
            Self::BudgetWarning => "budget_warning",
            Self::LeaseWarning => "lease_warning",
        }
    }
}

impl CancelStanding {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerAgent => "peer_agent",
            Self::Healer => "healer",
            Self::Automation => "automation",
            Self::Authority => "authority",
            Self::None => "none",
        }
    }

    /// Whether this standing may issue a soft `cancel.request`.
    #[must_use]
    pub const fn may_request(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl ForceCancelGrounds {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::LeaseExpiry => "lease_expiry",
            Self::Criticality => "criticality",
            Self::ErasedPayload => "erased_payload",
        }
    }
}

/// Proof that a hard cancellation is AUTHORIZED and runtime-authored.
///
/// The fields AND every constructor are crate-private, deliberately: a public
/// `from_standing(CancelStanding::Authority, actor)` would have been a mint —
/// `CancelStanding` is a public enum any caller can name, so anyone could have
/// declared themselves the authority and chosen the actor the terminal receipt
/// names. The hard rung is therefore reachable only from a path that has
/// ALREADY verified the owner against durable ownership provenance
/// (`Self::owner`, used by the verified `Memory::cancel_force` door) or from a
/// runtime ground the runtime itself establishes (lease expiry, criticality,
/// or a sealed erase/restore continuation).
///
/// Public callers keep the whole soft rung — request, reject, land — and the
/// typed proposal path when they cannot establish authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceCancelAuthority {
    grounds: ForceCancelGrounds,
    actor: String,
}

impl ForceCancelAuthority {
    /// Grants OWNER force authority to an actor the CALLER has already verified
    /// against durable ownership provenance.
    ///
    /// Crate-private: possession of this value is the authorization, so minting
    /// one is exactly the capability that must not be public. The actor is
    /// validated here — before any durable row can be written from it — so a
    /// verified-but-malformed owner identity fails at the door instead of
    /// persisting a receipt no reader can decode.
    pub(crate) fn owner(actor: &str) -> Result<Self> {
        validate_cancel_actor(actor)?;
        Ok(Self {
            grounds: ForceCancelGrounds::Owner,
            actor: actor.to_owned(),
        })
    }

    /// Runtime grounds: the lease expired, so the runtime — not a worker —
    /// authors the terminal receipt.
    pub(crate) fn lease_expiry() -> Self {
        Self {
            grounds: ForceCancelGrounds::LeaseExpiry,
            actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
        }
    }

    /// Runtime grounds: a criticality stop.
    ///
    /// Kept beside its sibling ground even though this build has no criticality
    /// stop wired yet: the ONE-1896 hard rung retains this verified ground,
    /// and deleting the constructor would leave the only way to reach
    /// [`ForceCancelGrounds::Criticality`] as a caller-chosen actor string —
    /// exactly the forgery this type exists to prevent. Exercised by the
    /// crate's cancel tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn criticality() -> Self {
        Self {
            grounds: ForceCancelGrounds::Criticality,
            actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
        }
    }

    /// Scrubs and cancels the accepted hard writer's exact owned BYOA
    /// rows. The authority is minted and consumed before this borrow ends.
    pub(crate) fn erase_actor_payloads_in_txn(
        erase: &mut crate::deletion::ActorErasureWriter<'_, '_>,
    ) -> Result<Vec<(crate::attempt_queue::AttemptId, u32)>> {
        let (vault, wtxn, actor) = erase.parts();
        Self::erase_owned_payloads_in_txn(vault, wtxn, &std::collections::BTreeSet::from([actor]))
    }

    /// Scrubs and cancels the authenticated image writer's owned BYOA
    /// rows. The original borrowed continuation supplies the erase targets;
    /// no cancellation authority leaves this operation.
    pub(crate) fn erase_restored_payloads_in_txn(
        restore: &mut crate::recovery::checkpoint::RestoreActorScrubWriter<'_, '_>,
    ) -> Result<Vec<(crate::attempt_queue::AttemptId, u32)>> {
        let erased = crate::deletion::restore_erased_payload_targets_in_txn(restore)?;
        let (vault, wtxn, _) = restore.parts();
        Self::erase_owned_payloads_in_txn(vault, wtxn, &erased)
    }

    fn erase_owned_payloads_in_txn(
        vault: &crate::Vault,
        wtxn: &mut heed::RwTxn<'_>,
        actors: &std::collections::BTreeSet<crate::EntityId>,
    ) -> Result<Vec<(crate::attempt_queue::AttemptId, u32)>> {
        let owned = crate::attempt_queue::payload_erase::erase_attempt_payload_actors_owned_in_txn(
            &vault.store,
            wtxn,
            actors,
        )?;
        // Every stale payload, archive mark and run reference has been
        // rewritten before native cancellation can replace a queue row.
        let queue = crate::attempt_queue::AttemptQueue::new(vault);
        let now = vault.store.clock.now_recorded_at();
        let mut cancelled = Vec::new();
        for id in owned {
            let authority = Self {
                grounds: ForceCancelGrounds::ErasedPayload,
                actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
            };
            if let super::verbs::ForceCancelOutcome::Cancelled(record) = queue.force_cancel_in_txn(
                wtxn,
                super::verbs::ForceAttemptCancel {
                    id,
                    authority,
                    reason: Some(crate::dispatch_byoa::ERASED_TASK_FAILURE_REASON.to_owned()),
                    now,
                },
            )? {
                cancelled.push((record.id, record.attempt_count));
            }
        }
        Ok(cancelled)
    }

    /// The grounds this authority rests on.
    #[must_use]
    pub const fn grounds(&self) -> ForceCancelGrounds {
        self.grounds
    }

    /// The actor the terminal receipt will name.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

impl AttemptResumePoint {
    /// Builds a resume point with no artifact reference.
    #[must_use]
    pub fn new(marker: impl Into<String>, recorded_at: u64) -> Self {
        Self {
            marker: marker.into(),
            artifact_ref: None,
            recorded_at,
        }
    }

    /// Attaches the durable artifact a successor should read first.
    #[must_use]
    pub fn with_artifact_ref(mut self, artifact_ref: impl Into<String>) -> Self {
        self.artifact_ref = Some(artifact_ref.into());
        self
    }
}

impl CancelMode {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Landed => "landed",
            Self::Forced => "forced",
        }
    }
}

impl AttemptCancellation {
    /// A cancellation row is well-formed when its grounds match its mode: only
    /// a forced stop rests on grounds, and it always does.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        matches!(self.mode, CancelMode::Forced) == self.grounds.is_some()
    }
}

impl AttemptCancelReceiptKind {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftRequested => "soft_requested",
            Self::LandingAccepted => "landing_accepted",
            Self::SoftRejected => "soft_rejected",
            Self::ResumePointRecorded => "resume_point_recorded",
            Self::ReserveSpent => "reserve_spent",
            Self::Landed => "landed",
            Self::ForceCancelled => "force_cancelled",
        }
    }

    /// True for the two rows that SETTLE an attempt. Exactly one of them may
    /// exist on a row, and it is always the last one. No receipt count
    /// refuses, so a long refusal history never leaves it without room.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Landed | Self::ForceCancelled)
    }

    /// True for the two rows that ANSWER one recorded soft request, and which
    /// therefore name it through [`AttemptCancelReceipt::request_sequence`].
    #[must_use]
    pub const fn answers_request(self) -> bool {
        matches!(self, Self::LandingAccepted | Self::SoftRejected)
    }
}

impl AttemptCancelPressure {
    /// True once refusals have crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]. Observability only: it
    /// never terminates anything by itself.
    #[must_use]
    pub const fn is_pathological(&self) -> bool {
        self.rejections >= SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    }
}

impl AttemptLandingReserve {
    /// Dials a reserve as an integer percent of `limit_units`, rounded DOWN so
    /// the reserve can never exceed the budget it is carved from.
    ///
    /// Pure arithmetic: the result carries NO dial mark, so it is the shape a
    /// caller uses to compute an ordinary meter limit, not a durable dial. The
    /// durable one is [`Self::dialed_at_generation`].
    #[must_use]
    pub const fn dialed(limit_units: u64, reserve_percent: u64) -> Self {
        Self {
            limit_units,
            reserve_units: reserve_units_for(limit_units, reserve_percent),
            spent_units: 0,
            dial_generation: None,
        }
    }

    /// The durable dial: the same arithmetic, MARKED with the lease generation
    /// it was applied at so a second dial against that generation is refused.
    #[must_use]
    pub const fn dialed_at_generation(
        limit_units: u64,
        reserve_percent: u64,
        generation: u32,
    ) -> Self {
        Self {
            limit_units,
            reserve_units: reserve_units_for(limit_units, reserve_percent),
            spent_units: 0,
            dial_generation: Some(generation),
        }
    }

    /// True once a dial has been durably applied, whatever it carved.
    #[must_use]
    pub const fn is_dialed(&self) -> bool {
        self.dial_generation.is_some()
    }

    /// The limit an ORDINARY execution meter must be built with: the dialed
    /// total minus the landing reserve.
    #[must_use]
    pub const fn ordinary_limit_units(&self) -> u64 {
        self.limit_units.saturating_sub(self.reserve_units)
    }

    /// Reserve units still available to a landing.
    #[must_use]
    pub const fn remaining_units(&self) -> u64 {
        self.reserve_units.saturating_sub(self.spent_units)
    }

    /// True once the landing has spent everything it was given.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining_units() == 0
    }
}

/// Integer percent of a budget, rounded DOWN, in u128 so the product cannot
/// wrap before the division that brings it back into range.
const fn reserve_units_for(limit_units: u64, reserve_percent: u64) -> u64 {
    ((limit_units as u128 * reserve_percent as u128) / 100) as u64
}
