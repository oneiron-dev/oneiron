//! Prep eligibility checks and exact-wake planning.

use serde::{Deserialize, Serialize};

use super::pack::DEFAULT_PREP_MAX_WORDS;
use crate::entity_id::EntityId;

/// Default lead between the EVENT start and the prep wake: T-45.
pub const DEFAULT_PREP_LEAD_SECS: u64 = 45 * 60;

/// Opaque tag the host echoes back when the prep wake fires.
///
/// Seventeen bytes, so it clears the contract's 64-byte `reason_tag` bound with
/// room to spare.
pub const PREP_WAKE_REASON_TAG: &str = "calendar.prep.t45";

/// The `Schedule` arm every prep wake carries.
///
/// The contract's `Schedule` is tagged `#[serde(tag = "kind", rename_all =
/// "snake_case")]`, so `Schedule::Exact` is the wire token `exact`. CAL plans no
/// window: the fire instant is computed at schedule time and recomputed when the
/// EVENT moves, which leaves the host nothing to jitter.
pub const PREP_WAKE_SCHEDULE_KIND: &str = "exact";

/// Tunables for one vault's prep behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepPolicy {
    /// Seconds before the EVENT start at which the wake fires.
    pub lead_secs: u64,
    /// Ceiling on the assembled pack, counted after ordering.
    pub max_words: usize,
    /// Whether internal-only and solo events need a per-event opt-in.
    pub external_only: bool,
}

impl Default for PrepPolicy {
    fn default() -> Self {
        Self {
            lead_secs: DEFAULT_PREP_LEAD_SECS,
            max_words: DEFAULT_PREP_MAX_WORDS,
            external_only: true,
        }
    }
}

/// The EVENT facts prep eligibility and scoping are decided from.
///
/// Externality, campaign linkage, and commitment linkage are caller-supplied:
/// the engine models attendees as vendor strings on `calendar.attendee` and owns
/// no identity domain, so only the host can say which attendee is outside the
/// house. There is no `VALARM` field, by design — an imported reminder block is
/// not an eligibility signal and cannot become one by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepEvent {
    /// The EVENT this pack is about.
    pub event_ref: EntityId,
    /// Scheduled start, unix seconds UTC.
    pub start_utc: u64,
    /// Scheduled end, unix seconds UTC.
    pub end_utc: u64,
    /// Attendee entities, used as additional assembly seeds.
    pub attendee_refs: Vec<EntityId>,
    /// How many attendees are outside the owner's house.
    pub external_attendee_count: u32,
    /// Whether the EVENT is linked to a campaign.
    pub has_campaign_linkage: bool,
    /// Whether the EVENT is linked to a commitment.
    pub has_commitment_linkage: bool,
    /// Per-event opt-in that arms an internal-only or solo event.
    pub internal_meeting_opt_in: bool,
}

/// Whether this EVENT arms prep at all.
///
/// External-meetings-only is the default: one external attendee, a campaign
/// linkage, or a commitment linkage each arm on their own. An internal-only or
/// solo EVENT arms only on an explicit opt-in — per event via
/// [`PrepEvent::internal_meeting_opt_in`], or vault-wide by clearing
/// [`PrepPolicy::external_only`]. Both are opt-ins; neither is a default.
#[must_use]
pub fn prep_is_eligible(event: &PrepEvent, policy: PrepPolicy) -> bool {
    if event.external_attendee_count > 0
        || event.has_campaign_linkage
        || event.has_commitment_linkage
    {
        return true;
    }
    !policy.external_only || event.internal_meeting_opt_in
}

/// One exact host wake: the three fields of the supervisor wake contract.
///
/// The engine-side image of `oneiron_vault_contract::WakeEntry` with
/// `Schedule::Exact` — see the module note on why the contract type is not
/// named directly at this commit. `at_utc` maps to `Schedule::Exact { at }`;
/// the other two fields map by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepWake {
    /// Stable wake id. Rescheduling reuses it so the host REPLACES the entry.
    pub id: String,
    /// Exact fire instant, unix seconds UTC.
    pub at_utc: u64,
    /// Opaque tag echoed back when the wake fires.
    pub reason_tag: String,
}

/// The stable wake id for one EVENT's prep purpose.
///
/// Stability is the whole point: the host keys its wake table on this id, so
/// recomputing the wake after the EVENT moves replaces the old entry instead of
/// adding a second one. Derived from the EVENT and the purpose tag alone, so two
/// callers that never met agree on it, and it stays inside the contract's
/// 128-byte wake-id bound (17 + 1 + 32 bytes).
#[must_use]
pub fn prep_wake_id(event_ref: &EntityId) -> String {
    format!("{PREP_WAKE_REASON_TAG}:{}", event_ref.to_hex())
}

/// The exact T-45 instant for one EVENT, or `None` when it cannot be
/// represented — an EVENT starting inside the first 45 minutes of the epoch has
/// no lead time, and saturating it to zero would mint a wake in 1970.
pub(super) fn prep_fire_at(event: &PrepEvent, policy: PrepPolicy) -> Option<u64> {
    event.start_utc.checked_sub(policy.lead_secs)
}

/// Plans the T-45 prep wake for one EVENT, or `None` when the EVENT is
/// ineligible or T-45 cannot be represented.
///
/// The engine owns no clock: this only describes the wake the host is asked to
/// deliver. Call it again when the EVENT is rescheduled — with the same
/// [`prep_wake_id`], so the new entry replaces the old one rather than
/// multiplying wakes.
#[must_use]
pub fn plan_prep_wake(wake_id: String, event: &PrepEvent, policy: PrepPolicy) -> Option<PrepWake> {
    if !prep_is_eligible(event, policy) {
        return None;
    }
    let fire_at = prep_fire_at(event, policy)?;
    Some(PrepWake {
        id: wake_id,
        at_utc: fire_at,
        reason_tag: PREP_WAKE_REASON_TAG.to_owned(),
    })
}
