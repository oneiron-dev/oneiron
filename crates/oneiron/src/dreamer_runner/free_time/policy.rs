//! The owner's free-time policy for one agent (FIX 4453): the total budget
//! one cycle may spend, the cycle's clock in an IANA zone, and an optional
//! pinned split between the two kinds. Only the owner sets or clears it,
//! revalidated against this vault in the write, as every owner setting is;
//! the engine stamps the revision, the owner and the time. Neither the
//! agent's words nor a hosted root stand in for the owner.

use serde::{Deserialize, Serialize};

use super::{CLOCK, CYCLE, POLICY};
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Error, Result, Vault};

/// What free time does for an agent the owner set no policy for. Canon is
/// silent on it (ARCH-0005b #free-time): this build opens no cycle without
/// an owner-set budget, and such a resident keeps its nightly dreaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsetFreeTimePolicy {
    /// No cycle, no floor and no free-time spend.
    Disabled,
}

/// The one switch for an agent with no policy (CALLS FIX4453-PR2-DEFAULT,
/// for the owner's pack).
pub const FREE_TIME_WHEN_UNSET: UnsetFreeTimePolicy = UnsetFreeTimePolicy::Disabled;

/// The two owner-facing names of a cycle's one daily clock: one cycle a day
/// either way, at the policy's local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeCadence {
    Daily,
    Nightly,
}

/// When each cycle opens: a local time of day in an IANA zone. A local time
/// a spring-forward gap skips opens no cycle that date; a fall-back fold
/// opens at its earlier instant. Never UTC by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeSchedule {
    pub cadence: FreeTimeCadence,
    /// 0..=23.
    pub hour: u8,
    /// 0..=59.
    pub minute: u8,
    /// An IANA zone, by its canonical name.
    pub zone: String,
}

/// A split the owner pinned: what each kind may spend of the total, as a
/// hard share each. Without one, both kinds draw on one shared total and the
/// agent chooses; no share is a minimum or a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeSplit {
    pub for_human_units: u64,
    pub own_time_units: u64,
}

/// What the owner sets for one agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicyInput {
    /// The most one cycle may spend, in tokens (input plus output).
    pub total_units: u64,
    pub schedule: FreeTimeSchedule,
    #[serde(default)]
    pub pinned_split: Option<FreeTimeSplit>,
    /// When the owner was shown this recurring per-cycle cap and accepted
    /// it, in host milliseconds. Each cycle's root opens under this saved
    /// say-so; the scheduler never claims a showing of its own.
    pub cap_shown_at_ms: u64,
}

/// One agent's free-time policy as the engine keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicy {
    /// The agent definition it is for.
    pub agent: EntityId,
    /// 1 for the first set; each set takes the revision it replaces.
    pub revision: u64,
    pub total_units: u64,
    pub schedule: FreeTimeSchedule,
    pub pinned_split: Option<FreeTimeSplit>,
    pub cap_shown_at_ms: u64,
    /// The owner, as this vault revalidated them in the write.
    pub set_by: EntityId,
    /// Vault clock seconds. No cycle opens at a boundary before this.
    pub set_at: u64,
    /// Where the owner said so. Audit only; no rule reads it.
    pub surface: Option<ActSurface>,
    /// BLAKE3 over the policy it replaced, as JSON (`null` for none).
    pub prior: [u8; 32],
}

/// One agent's policy row as the engine keeps it (FIX 5661): the policy in
/// force, `None` once the owner cleared it, and the witness of every set and
/// clear that led here. A clear keeps the row as its witness, so a home move
/// can prove which of two rows follows the other; what the owner reads is
/// unchanged (a cleared policy reads as none: revision 0, and
/// [`FREE_TIME_WHEN_UNSET`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreeTimePolicyRecord {
    pub(super) policy: Option<FreeTimePolicy>,
    /// One digest per set or clear, oldest first. Each hashes the one before
    /// it with its act, so a record's list is a prefix of the list of every
    /// record that follows it.
    pub(super) acts: Vec<[u8; 32]>,
}

impl FreeTimePolicyRecord {
    /// `previous` with one more act: `by` left `policy` in force for `agent`
    /// at `at` (`None` for a clear).
    fn after(
        previous: Option<Self>,
        agent: EntityId,
        policy: Option<FreeTimePolicy>,
        by: EntityId,
        at: u64,
    ) -> Result<Self> {
        let mut acts = previous.map_or_else(Vec::new, |record| record.acts);
        let act = serde_json::to_vec(&(agent, policy.as_ref(), by, at))
            .map_err(|_| Error::InvariantViolation("free-time policy act encoding"))?;
        let mut witness = blake3::Hasher::new();
        witness.update(b"oneiron:free_time:policy_act:v1");
        witness.update(acts.last().unwrap_or(&[0; 32]));
        witness.update(&act);
        acts.push(*witness.finalize().as_bytes());
        Ok(Self { policy, acts })
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time policy: {reason}"))
}

impl FreeTimePolicyInput {
    fn validate(&self) -> Result<()> {
        if self.total_units == 0 {
            return Err(invalid("the total is more than zero units"));
        }
        if self.schedule.hour > 23 || self.schedule.minute > 59 {
            return Err(invalid("the clock is a time of day"));
        }
        crate::calendar::utc_to_wall(0, &self.schedule.zone)
            .map_err(|_| invalid("the zone is a canonical IANA zone"))?;
        if let Some(split) = self.pinned_split
            && (split.for_human_units == 0
                || split.own_time_units == 0
                || split.for_human_units.checked_add(split.own_time_units)
                    != Some(self.total_units))
        {
            return Err(invalid(
                "a pinned split gives each kind a share and sums to the total",
            ));
        }
        if self.cap_shown_at_ms == 0 {
            return Err(invalid("the owner was shown the recurring cap"));
        }
        Ok(())
    }
}

/// The policy a cycle runs under: the owner's row, else what
/// [`FREE_TIME_WHEN_UNSET`] gives an agent with none.
pub(super) fn effective_policy(row: Option<FreeTimePolicy>) -> Option<FreeTimePolicy> {
    match (row, FREE_TIME_WHEN_UNSET) {
        (Some(policy), _) => Some(policy),
        (None, UnsetFreeTimePolicy::Disabled) => None,
    }
}

/// Whether `resident`'s dreaming at `now` is its free-time cycle's own-time
/// item rather than the nightly child (the FIX 4453 narrowing rule): it holds
/// an owner-set policy, and a cycle actually opened at the boundary `now`
/// falls after (FIX 5662). A boundary the clock passed with no cycle (one
/// that failed to open, an agent that was off) owns nothing, nor does a
/// policy or schedule that does not read: a cycle that did not open never
/// costs the resident its nightly reflection. Every resident without a
/// policy keeps its nightly dreaming exactly as before.
pub(crate) fn free_time_owns_reflection_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
    now: u64,
) -> Result<bool> {
    let Some(policy) = effective_policy(
        POLICY
            .get_lenient(&vault.store, txn, &resident)?
            .and_then(|record| record.policy),
    ) else {
        return Ok(false);
    };
    let boundary = match super::cycle::boundary_at_or_before(&policy.schedule, now) {
        Ok(Some(boundary)) => boundary,
        Ok(None) => return Ok(false),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                agent = %resident.to_hex(),
                "a free-time schedule did not read; the nightly dreaming stays"
            );
            return Ok(false);
        }
    };
    CYCLE.contains(&vault.store, txn, &(resident, boundary))
}

/// BLAKE3 over the policy a write replaces, as JSON.
fn prior_digest(prior: Option<&FreeTimePolicy>) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(&prior)
        .map_err(|_| Error::InvariantViolation("free-time policy act encoding"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// `agent`'s policy row in `txn`, refused unless the revision its policy
/// stands at (0 with none in force) is the one the owner's surface showed.
fn current_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    expected_revision: u64,
) -> Result<Option<FreeTimePolicyRecord>> {
    let record = POLICY.get(&vault.store, txn, &agent)?;
    let revision = record
        .as_ref()
        .and_then(|record| record.policy.as_ref())
        .map_or(0, |policy| policy.revision);
    if revision != expected_revision {
        return Err(Error::ConcurrentWrite(
            "the free-time policy changed; read it again",
        ));
    }
    Ok(record)
}

impl Vault {
    /// The owner's free-time policy for `agent` (FIX 4453); `None` when the
    /// owner set none, which [`FREE_TIME_WHEN_UNSET`] reads as no cycle.
    ///
    /// # Errors
    /// A store read that fails or a row that does not decode.
    pub fn free_time_policy(&self, agent: EntityId) -> Result<Option<FreeTimePolicy>> {
        let txn = self.store.env.read_txn()?;
        Ok(POLICY
            .get(&self.store, &txn, &agent)?
            .and_then(|record| record.policy))
    }

    /// Sets `agent`'s free-time policy as the owner (FIX 4453), replacing
    /// revision `expected_revision` (0 when there is none yet). The owner is
    /// revalidated against this vault in the write; the agent must be an
    /// agent definition. A new policy opens no cycle at a boundary that came
    /// before it: the next boundary is the first.
    ///
    /// # Errors
    /// An invalid input, a proof that does not hold here, an unknown agent,
    /// [`Error::ConcurrentWrite`] for a stale revision, and storage errors.
    pub fn set_free_time_policy(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        agent: EntityId,
        expected_revision: u64,
        input: FreeTimePolicyInput,
    ) -> Result<FreeTimePolicy> {
        input.validate()?;
        let policy = self.with_write_txn_grouped(|txn| {
            let actor =
                crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            self.read_agent_definition_in_txn(txn, &agent)?;
            let record = current_revision_in_txn(self, txn, agent, expected_revision)?;
            let prior = record.as_ref().and_then(|record| record.policy.as_ref());
            let set_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let policy = FreeTimePolicy {
                agent,
                revision: expected_revision
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("free-time policy revision"))?,
                total_units: input.total_units,
                schedule: input.schedule,
                pinned_split: input.pinned_split,
                cap_shown_at_ms: input.cap_shown_at_ms,
                set_by: actor,
                set_at,
                surface,
                prior: prior_digest(prior)?,
            };
            let record =
                FreeTimePolicyRecord::after(record, agent, Some(policy.clone()), actor, set_at)?;
            POLICY.put(&self.store, txn, &agent, &record)?;
            Ok(policy)
        })?;
        // The home's timer arms on the policy's next boundary.
        self.store.notify_proactivity_changes();
        Ok(policy)
    }

    /// Clears `agent`'s free-time policy as the owner (FIX 4453), at
    /// revision `expected_revision`: its open cycle ends now, no new cycle
    /// opens, and the agent goes back to its nightly dreaming. Calls already
    /// made settle normally. Clearing a policy that is not there, at
    /// revision 0, does nothing.
    ///
    /// # Errors
    /// A proof that does not hold here, [`Error::ConcurrentWrite`] for a
    /// stale revision, and storage errors.
    pub fn clear_free_time_policy(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        expected_revision: u64,
    ) -> Result<()> {
        let cleared = self.with_write_txn_grouped(|txn| {
            let actor =
                crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            let record = match current_revision_in_txn(self, txn, agent, expected_revision)? {
                Some(record) if record.policy.is_some() => record,
                _ => return Ok(false),
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            // The row stays as the witness of this clear (FIX 5661), with no
            // policy in force.
            let record = FreeTimePolicyRecord::after(Some(record), agent, None, actor, now)?;
            POLICY.put(&self.store, txn, &agent, &record)?;
            super::cycle::close_open_cycle_in_txn(self, txn, agent, now)?;
            // The clock goes with the policy: a later policy starts at its
            // own first boundary, and until then the agent dreams nightly.
            CLOCK.delete(&self.store, txn, &agent)?;
            Ok(true)
        })?;
        if cleared {
            self.store.notify_proactivity_changes();
        }
        Ok(())
    }
}
