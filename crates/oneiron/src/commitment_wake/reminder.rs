//! Served reminder delivery for commitment wakes (OF-187): the owner's
//! reminder route, the planner the server installs, and the reminder text a
//! channel sink sends.
//!
//! Canon picks no default channel (ARCH-0046): the planner sends a promise's
//! reminder only where the vault already says the obligor can be reached. The
//! owner's own promises go to the route the owner set; a third party's go over
//! the native route our identities already share with that person. A promise
//! an agent owes, or one with no route, proposes nothing. Every proposal is
//! still `Proposed` and waits for the owner's run approval.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::commitment::{CommitmentObligorKind, CommitmentRecord, CommitmentStatus};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::OutboundScheduleContext;
use crate::side_table::{self, Named, SideTable};

use super::wake_event::{CommitmentWakeEvent, CommitmentWakePhase, validate_wake_string};
use super::wake_proposal::{CommitmentWakeProposalDraft, CommitmentWakeProposalPlanner};

/// The owner's reminder route. Key: ().
const REMINDER_ROUTE: SideTable<(), CommitmentReminderRoute, Named> =
    SideTable::new(&side_table::COMMITMENT_REMINDER_ROUTE);

/// Every reminder's content ref starts with this; the rest names the instance,
/// the phase and the instant it is owed, so the text is a pure function of it.
pub const COMMITMENT_REMINDER_CONTENT_PREFIX: &str = "commitment-reminder:v1:";
/// The verb a reminder to a third party travels as.
const NUDGE_VERB: &str = "send";
/// The longest promise text a reminder quotes.
const MAX_QUOTED_PROMISE_CHARS: usize = 400;

/// Where the owner's own commitment reminders go, and the owner's civil clock.
///
/// `utc_offset_minutes` (with `iana_timezone` as its label) is frozen on every
/// approved reminder, so the delivery window can read the owner's local time;
/// without it an interrupt-class reminder holds under a window claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentReminderRoute {
    pub channel: String,
    pub verb: String,
    pub target: String,
    #[serde(default)]
    pub utc_offset_minutes: Option<i16>,
    #[serde(default)]
    pub iana_timezone: Option<String>,
}

impl CommitmentReminderRoute {
    fn validate(&self) -> Result<()> {
        validate_wake_string(&self.channel, "reminder route channel is invalid")?;
        validate_wake_string(&self.verb, "reminder route verb is invalid")?;
        validate_wake_string(&self.target, "reminder route target is invalid")?;
        if self.iana_timezone.is_some() && self.utc_offset_minutes.is_none() {
            return Err(Error::InvalidClaimBody(
                "reminder route timezone needs its UTC offset",
            ));
        }
        if self
            .utc_offset_minutes
            .is_some_and(|offset| !(-840..=840).contains(&offset))
        {
            return Err(Error::InvalidClaimBody(
                "reminder route UTC offset must be in -840..=840",
            ));
        }
        if self.iana_timezone.as_deref().is_some_and(|label| {
            label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
        }) {
            return Err(Error::InvalidClaimBody(
                "reminder route timezone label is invalid",
            ));
        }
        Ok(())
    }

    /// The clock an approved reminder freezes on its send.
    #[must_use]
    pub fn schedule_context(&self) -> OutboundScheduleContext {
        OutboundScheduleContext {
            utc_offset_minutes: self.utc_offset_minutes,
            iana_timezone: self.iana_timezone.clone(),
            ..OutboundScheduleContext::default()
        }
    }
}

impl Vault {
    /// The owner's reminder route, when one is set.
    pub fn commitment_reminder_route(&self) -> Result<Option<CommitmentReminderRoute>> {
        let txn = self.store.env.read_txn()?;
        REMINDER_ROUTE.get(&self.store, &txn, &())
    }

    /// Sets (or, with `None`, clears) where the owner's reminders go. Only the
    /// authenticated owner sets it; it changes no reminder already approved.
    pub fn set_commitment_reminder_route(
        &self,
        owner: &AuthenticatedOwner,
        route: Option<&CommitmentReminderRoute>,
    ) -> Result<()> {
        if let Some(route) = route {
            route.validate()?;
        }
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            match route {
                Some(route) => REMINDER_ROUTE.put(&self.store, txn, &(), route),
                None => REMINDER_ROUTE.delete(&self.store, txn, &()).map(|_| ()),
            }
        })
    }

    /// The text a channel sends for a reminder content ref, `Ok(None)` when
    /// the ref is not a reminder's. The promise must still be open: a reminder
    /// for a kept or released promise is refused, not sent.
    pub fn commitment_reminder_text(&self, content_ref: &str) -> Result<Option<String>> {
        let Some(reminder) = ReminderRef::parse(content_ref) else {
            return Ok(None);
        };
        let record = self
            .get_commitment_claim(&reminder.instance_id)?
            .ok_or(Error::InvalidClaimBody("reminder's commitment is gone"))?;
        if record.status != CommitmentStatus::Open {
            return Err(Error::InvalidClaimBody(
                "reminder's commitment is no longer open",
            ));
        }
        let offset = self
            .commitment_reminder_route()?
            .and_then(|route| route.utc_offset_minutes);
        Ok(Some(reminder_text(&record, &reminder, offset)))
    }
}

/// A parsed reminder content ref.
struct ReminderRef {
    instance_id: EntityId,
    phase: CommitmentWakePhase,
    due_at: u64,
}

impl ReminderRef {
    fn content_ref(event: &CommitmentWakeEvent) -> String {
        format!(
            "{COMMITMENT_REMINDER_CONTENT_PREFIX}{}:{}:{}",
            event.instance_id.to_hex(),
            event.phase.as_str(),
            event.due_at
        )
    }

    fn parse(content_ref: &str) -> Option<Self> {
        let rest = content_ref.strip_prefix(COMMITMENT_REMINDER_CONTENT_PREFIX)?;
        let mut parts = rest.split(':');
        let instance_id = EntityId::from_hex(parts.next()?).ok()?;
        let phase = CommitmentWakePhase::parse(parts.next()?)?;
        let due_at = parts.next()?.parse().ok()?;
        parts.next().is_none().then_some(Self {
            instance_id,
            phase,
            due_at,
        })
    }
}

fn reminder_text(record: &CommitmentRecord, reminder: &ReminderRef, offset: Option<i16>) -> String {
    let promise: String = record
        .content
        .text
        .trim()
        .chars()
        .take(MAX_QUOTED_PROMISE_CHARS)
        .collect();
    let when = civil_time(reminder.due_at, offset);
    match reminder.phase {
        CommitmentWakePhase::Lead => format!("Reminder: {promise} (due {when})."),
        CommitmentWakePhase::Due => format!("Due now: {promise} (due {when})."),
    }
}

/// `due_at` in the owner's civil time when the route carries an offset, else UTC.
fn civil_time(due_at: u64, offset: Option<i16>) -> String {
    let Some(utc) = i64::try_from(due_at)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
    else {
        return format!("at {due_at}");
    };
    let minutes = i32::from(offset.unwrap_or(0));
    match chrono::FixedOffset::east_opt(minutes * 60) {
        Some(zone) if minutes != 0 => {
            let sign = if minutes < 0 { '-' } else { '+' };
            format!(
                "{} UTC{sign}{:02}:{:02}",
                utc.with_timezone(&zone).format("%a %d %b %Y %H:%M"),
                minutes.unsigned_abs() / 60,
                minutes.unsigned_abs() % 60
            )
        }
        _ => format!("{} UTC", utc.format("%a %d %b %Y %H:%M")),
    }
}

/// The planner the server installs: a reminder goes where the vault already
/// says the obligor is reached, and nowhere else.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommitmentReminderPlanner;

impl CommitmentWakeProposalPlanner for CommitmentReminderPlanner {
    fn plan(
        &mut self,
        _event: &CommitmentWakeEvent,
        _commitment: &CommitmentRecord,
    ) -> Result<CommitmentWakeProposalDraft> {
        Err(Error::InvalidClaimBody(
            "the reminder planner routes through the vault",
        ))
    }

    fn plan_in_vault(
        &mut self,
        vault: &Vault,
        event: &CommitmentWakeEvent,
        commitment: &CommitmentRecord,
    ) -> Result<Option<CommitmentWakeProposalDraft>> {
        let (verb, channel, target) = match commitment.obligor.kind {
            CommitmentObligorKind::Owner => match vault.commitment_reminder_route()? {
                Some(route) => (route.verb, route.channel, route.target),
                None => return Ok(None),
            },
            CommitmentObligorKind::ThirdParty => {
                match crate::human_task::resolve_native_human_route(
                    vault,
                    commitment.obligor.entity_ref,
                ) {
                    Ok(route) => (NUDGE_VERB.to_owned(), route.channel, route.target),
                    Err(error) => {
                        tracing::info!(%error, "no native route for a commitment nudge");
                        return Ok(None);
                    }
                }
            }
            // A promise an agent owes is the agent's to keep in its own turn,
            // not a message to send.
            CommitmentObligorKind::Agent => return Ok(None),
        };
        Ok(Some(CommitmentWakeProposalDraft {
            verb,
            channel,
            target,
            on_behalf_of: None,
            content_ref: Some(ReminderRef::content_ref(event)),
            dedupe_key: None,
        }))
    }
}

/// The schedule clock approved reminders freeze: the owner's, when set.
pub(super) fn reminder_schedule_context(vault: &Vault) -> OutboundScheduleContext {
    vault
        .commitment_reminder_route()
        .ok()
        .flatten()
        .map(|route| route.schedule_context())
        .unwrap_or_default()
}
