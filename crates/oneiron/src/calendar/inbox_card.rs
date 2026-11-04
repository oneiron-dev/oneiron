//! Meeting cards in the owners' INBOX (FIX 12004): the prep pack a meeting
//! earns at T-45, the check-in that follows its end, and that check-in's one
//! morning re-ask.
//!
//! The engine owns no clock. The host runs [`run_calendar_card_pass`] on the
//! elected home node, the proof [`run_due_home_node_prep_with_sources`] asks
//! of it, and the
//! pass is the cards' only writer. Each card is one row keyed by its EVENT and
//! kind: a re-run for the same EVENT and start finds its row and adds nothing,
//! and a moved meeting's new card replaces the old one.
//!
//! A prep pack is still built from live vault rows when its wake fires. The
//! row keeps only the lens the owners were shown, and a wake that found
//! nothing to say keeps no lens at all. The INBOX reads the rows
//! (`calendar_inbox_items`) and rechecks each against the live EVENT: a prep
//! card stands until its meeting moves, is cancelled or ends, and a check-in
//! until an outcome is recorded or the EVENT is cancelled.
//!
//! Silence is unknown, never a no-show: an unanswered check-in is asked once
//! more on the owner's next local morning
//! ([`plan_check_in_re_ask`](super::plan_check_in_re_ask)), then rests. An
//! answer or a dismissal before then cancels the re-ask.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::claims::CalendarStatus;
use super::outcome::{
    CheckInCardModel, CheckInCopy, DueOutcomeCheckIn, MeetingClassSignals,
    OUTCOME_CHECK_IN_REASON_TAG, build_check_in_lens, check_in_is_still_due, current_outcome_in,
    current_status_in, outcome_grace_secs,
};
use super::prep::{
    PrepEvent, PrepHomeNodeJob, PrepLensCopy, PrepPolicy, live_prep_event, plan_check_in_re_ask,
    prep_wake_id, run_due_home_node_prep_with_sources,
};
use crate::agent_inbox_lens::{
    AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
    agent_inbox_row_done_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::lens::GeneratedLens;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::task_verb::sdk::AgentVerb;
use crate::vault::Vault;

/// Key: (EVENT, card kind token).
const CARDS: SideTable<(EntityId, String), CalendarInboxCard, Named> =
    SideTable::new(&side_table::CALENDAR_INBOX_CARD);

/// How late a check-in the host has not yet asked is still asked, and how
/// long a rested check-in stays in the INBOX after its re-ask: a host that was
/// down for a day still asks, and a year of imported past meetings is never
/// asked at once.
pub const CHECK_IN_CATCH_UP_SECS: u64 = 86_400;

/// Where a prep card sorts: an update, above a digest.
const PREP_INBOX_IMPACT: u16 = 50;
/// Where a check-in sorts: a question waiting on the owner, with the other
/// rows that wait on a read.
const CHECK_IN_INBOX_IMPACT: u16 = 100;
/// EVENT ids one page of the pass reads.
const EVENT_PAGE: usize = 256;

/// Which card a row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarCardKind {
    /// The T-45 prep pack.
    Prep,
    /// The check-in after the meeting's end and grace.
    CheckIn,
}

impl CalendarCardKind {
    /// Stable token: the row key's kind and the INBOX handle's prefix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prep => "meeting_prep",
            Self::CheckIn => "meeting_check_in",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token {
            "meeting_prep" => Some(Self::Prep),
            "meeting_check_in" => Some(Self::CheckIn),
            _ => None,
        }
    }
}

/// Where a check-in's one morning re-ask stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckInReAsk {
    /// Asked again at `at`, unless an answer or a dismissal comes first.
    Planned { at: u64 },
    /// Asked again at `at`; never asked a third time.
    Asked { at: u64 },
    /// Dismissed before its morning, found so at `at`; never asked again.
    Cancelled { at: u64 },
}

impl CheckInReAsk {
    /// When the re-ask settled; `None` while it is still planned.
    const fn settled_at(self) -> Option<u64> {
        match self {
            Self::Planned { .. } => None,
            Self::Asked { at } | Self::Cancelled { at } => Some(at),
        }
    }
}

/// One meeting card as the pass delivered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInboxCard {
    pub kind: CalendarCardKind,
    pub event_ref: EntityId,
    /// The EVENT's start the card was built for, unix seconds UTC.
    pub scheduled_start_utc: u64,
    /// The EVENT's end the card was built for, unix seconds UTC.
    pub scheduled_end_utc: u64,
    /// When the card was first delivered.
    pub delivered_at: u64,
    /// When the card was last put in front of the owners: its delivery, or
    /// its re-ask. The INBOX row's time.
    pub asked_at: u64,
    /// The card as delivered. `None` on a prep wake that fired and found
    /// nothing to say, or whose meeting was cancelled since: the wake ran,
    /// and the owners are shown nothing.
    pub lens: Option<GeneratedLens>,
    /// Every vault row the delivered lens copied, the EVENT itself excluded:
    /// the prep pack's cited rows. Empty on a check-in, which copies none,
    /// and on a card with no lens.
    pub source_refs: BTreeSet<EntityId>,
    /// A check-in's one morning re-ask; `None` on a prep card.
    pub re_ask: Option<CheckInReAsk>,
}

impl CalendarInboxCard {
    /// The INBOX handle: kind, EVENT and start, so a moved meeting's card is
    /// a new row and a read mark on the old one never closes it.
    #[must_use]
    pub fn item_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_str(),
            self.event_ref.to_hex(),
            self.scheduled_start_utc
        )
    }
}

/// Every word the pass puts on a card: the host's copy. Engine Rust holds no
/// product prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarCardCopy {
    pub prep: PrepLensCopy,
    pub check_in: CheckInCopy,
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CalendarCardPass {
    /// Prep cards delivered with a pack.
    pub prepped: usize,
    /// Check-ins asked for the first time.
    pub asked: usize,
    /// Check-ins asked once more on their morning.
    pub re_asked: usize,
    /// Shown cards taken out: the meeting moved, was cancelled, went or
    /// ended, an outcome landed, or a rested check-in's day passed.
    pub withdrawn: usize,
    /// EVENTs whose card failed this pass; the next pass tries them again.
    pub failed: usize,
}

/// Runs one pass at `now`: settles the cards already delivered, then
/// delivers each prep pack and check-in that has come due.
///
/// The host calls this on the elected home node only. A prep wake fires
/// once per EVENT start, between T-45 and the start. A check-in is asked once
/// the EVENT's end and the vault's grace have passed, at most
/// [`CHECK_IN_CATCH_UP_SECS`] late, and its re-ask is planned on the owner's
/// clock: the zone or offset of the owner's reminder route, else UTC.
///
/// One EVENT whose card fails is counted and logged by its error kind, and
/// the pass goes on to the others.
///
/// # Errors
///
/// Storage errors from reading the cards, the grace policy or the EVENT
/// index propagate; the next pass takes up what this one did not reach.
pub fn run_calendar_card_pass(
    vault: &Vault,
    now: u64,
    copy: &CalendarCardCopy,
) -> Result<CalendarCardPass> {
    let mut run = CardRun {
        vault,
        now,
        copy,
        report: CalendarCardPass::default(),
    };
    let cards = {
        let rtxn = vault.store.env.read_txn()?;
        CARDS.scan(&vault.store, &rtxn)?
    };
    for (key, card) in cards {
        let event_ref = card.event_ref;
        let settled = run.revisit(&key, card);
        run.tally(settled, event_ref);
    }
    let policy = PrepPolicy::default();
    let grace = outcome_grace_secs(vault)?;
    let mut after: Option<EntityId> = None;
    loop {
        let ids = vault.entities_by_type_page(ENTITY_TYPE_EVENT, after.as_ref(), EVENT_PAGE)?;
        let Some(last) = ids.last().copied() else {
            break;
        };
        for (event_ref, start, end) in event_spans(vault, &ids)? {
            if let Some(fire_at) = start.checked_sub(policy.lead_secs)
                && fire_at <= now
                && now < start
            {
                let delivered = run.deliver_prep(event_ref, start, end, fire_at);
                run.tally(delivered, event_ref);
            }
            let due_at = end.saturating_add(grace);
            if due_at <= now && now - due_at <= CHECK_IN_CATCH_UP_SECS {
                let delivered = run.deliver_check_in(event_ref, start, end);
                run.tally(delivered, event_ref);
            }
        }
        if ids.len() < EVENT_PAGE {
            break;
        }
        after = Some(last);
    }
    Ok(run.report)
}

/// The meeting rows of the INBOX: each delivered card with a lens that still
/// stands, addressed to the vault's owners on no identity. A prep card is an
/// update; a check-in waits on its answer, so an answer or a cancellation
/// takes it away at once.
pub(crate) fn calendar_inbox_items(vault: &Vault) -> Result<Vec<AgentInboxLensItem>> {
    let rtxn = vault.store.env.read_txn()?;
    let cards = CARDS.scan(&vault.store, &rtxn)?;
    if cards.is_empty() {
        return Ok(Vec::new());
    }
    let owners = match crate::policy_model::owners_in_txn(vault, &rtxn) {
        Ok(owners) => owners,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "meeting card owners not read; meeting rows left out"
            );
            return Ok(Vec::new());
        }
    };
    let Some(actor_ref) = owners.first().copied() else {
        return Ok(Vec::new());
    };
    let now = vault.now_recorded_at();
    let mut items = Vec::new();
    for (_, card) in cards {
        if card.lens.is_none() || !card_stands_in_txn(vault, &rtxn, &card, now)? {
            continue;
        }
        let (kind, impact) = match card.kind {
            CalendarCardKind::Prep => (AgentInboxItemKind::CoordinationUpdate, PREP_INBOX_IMPACT),
            CalendarCardKind::CheckIn => {
                (AgentInboxItemKind::ApprovalRequired, CHECK_IN_INBOX_IMPACT)
            }
        };
        items.push(AgentInboxLensItem {
            item_id: card.item_id(),
            kind,
            thread_ref: None,
            identity_ref: None,
            actor_ref,
            facet_ref: None,
            participants: owners
                .iter()
                .map(|owner| AgentInboxParticipant {
                    identity_ref: None,
                    actor_ref: *owner,
                })
                .collect(),
            impact: InboxImpact(impact),
            occurred_at: card.asked_at,
            receipt_ref: None,
            payload_ref: Some(card.event_ref.to_hex()),
            concern: None,
            diary_review: None,
            sender: None,
            widening: None,
        });
    }
    Ok(items)
}

/// The lens the meeting row `item_id` carries, as delivered; `None` for a row
/// that is no meeting card, or whose card a moved meeting has replaced.
pub(crate) fn calendar_inbox_card_lens(
    vault: &Vault,
    item_id: &str,
) -> Result<Option<GeneratedLens>> {
    let mut parts = item_id.splitn(3, ':');
    let (Some(kind), Some(event), Some(start)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(None);
    };
    let Some(kind) = CalendarCardKind::from_token(kind) else {
        return Ok(None);
    };
    let (Ok(event_ref), Ok(start)) = (EntityId::from_hex(event), start.parse::<u64>()) else {
        return Ok(None);
    };
    Ok(read_card(vault, &card_key(event_ref, kind))?
        .filter(|card| card.scheduled_start_utc == start)
        .and_then(|card| card.lens))
}

/// One pass's clock, copy and tally.
struct CardRun<'a> {
    vault: &'a Vault,
    now: u64,
    copy: &'a CalendarCardCopy,
    report: CalendarCardPass,
}

impl CardRun<'_> {
    /// Counts and logs one EVENT's failed card; the pass goes on.
    fn tally(&mut self, result: Result<()>, event_ref: EntityId) {
        if let Err(error) = result {
            self.report.failed += 1;
            tracing::warn!(
                kind = ?error.kind(),
                event = %event_ref.to_hex(),
                "meeting card failed; the next pass retries it"
            );
        }
    }

    /// Settles one delivered card against the live EVENT.
    fn revisit(&mut self, key: &(EntityId, String), card: CalendarInboxCard) -> Result<()> {
        match card.kind {
            CalendarCardKind::Prep => self.revisit_prep(key, card),
            CalendarCardKind::CheckIn => self.revisit_check_in(key, card),
        }
    }

    /// A prep card leaves once its meeting has ended, moved or gone; a
    /// cancelled meeting's card keeps its row, so the wake never fires again
    /// for that start, and shows nothing.
    fn revisit_prep(
        &mut self,
        key: &(EntityId, String),
        mut card: CalendarInboxCard,
    ) -> Result<()> {
        let rtxn = self.vault.store.env.read_txn()?;
        let start = live_start_in_txn(self.vault, &rtxn, &card.event_ref)?;
        let cancelled = cancelled_in_txn(self.vault, &rtxn, &card.event_ref)?;
        drop(rtxn);
        if self.now > card.scheduled_end_utc || start != Some(card.scheduled_start_utc) {
            let shown = card.lens.is_some();
            return self.withdraw(key, shown);
        }
        if cancelled && card.lens.take().is_some() {
            card.source_refs.clear();
            self.report.withdrawn += 1;
            return write_card(self.vault, key, &card);
        }
        Ok(())
    }

    /// A check-in leaves once it is no longer due; its planned re-ask runs
    /// once its morning has come, unless an owner dismissed the card first;
    /// a rested check-in leaves a day after its re-ask settled.
    fn revisit_check_in(
        &mut self,
        key: &(EntityId, String),
        mut card: CalendarInboxCard,
    ) -> Result<()> {
        let still_due = match live_prep_event(self.vault, card.event_ref)? {
            Some(event) if event.start_utc == card.scheduled_start_utc => {
                check_in_is_still_due(self.vault, &due_check_in(&event))?
            }
            _ => false,
        };
        if !still_due {
            return self.withdraw(key, true);
        }
        match card.re_ask {
            Some(CheckInReAsk::Planned { at }) if at <= self.now => {
                if self.dismissed(&card)? {
                    card.re_ask = Some(CheckInReAsk::Cancelled { at: self.now });
                } else {
                    card.lens = Some(check_in_lens(
                        card.event_ref,
                        card.scheduled_start_utc,
                        &self.copy.check_in,
                    )?);
                    card.asked_at = self.now;
                    card.re_ask = Some(CheckInReAsk::Asked { at: self.now });
                    self.report.re_asked += 1;
                }
                write_card(self.vault, key, &card)
            }
            Some(re_ask)
                if re_ask
                    .settled_at()
                    .is_some_and(|at| self.now.saturating_sub(at) > CHECK_IN_CATCH_UP_SECS) =>
            {
                self.withdraw(key, true)
            }
            _ => Ok(()),
        }
    }

    /// Fires the prep wake for one EVENT start, once: the pack is built from
    /// live rows now, and the row records the wake even when the pack is
    /// empty.
    fn deliver_prep(
        &mut self,
        event_ref: EntityId,
        start: u64,
        end: u64,
        fire_at: u64,
    ) -> Result<()> {
        let key = card_key(event_ref, CalendarCardKind::Prep);
        if read_card(self.vault, &key)?.is_some_and(|card| card.scheduled_start_utc == start) {
            return Ok(());
        }
        let job = PrepHomeNodeJob {
            event_ref: event_ref.to_hex(),
            scheduled_for: fire_at,
            wake_id: prep_wake_id(&event_ref),
        };
        let delivered = run_due_home_node_prep_with_sources(
            self.vault,
            &job,
            self.now,
            PrepPolicy::default(),
            &self.copy.prep,
        )?;
        let (lens, source_refs) =
            delivered.map_or((None, BTreeSet::new()), |(lens, refs)| (Some(lens), refs));
        let prepped = lens.is_some();
        write_card(
            self.vault,
            &key,
            &CalendarInboxCard {
                kind: CalendarCardKind::Prep,
                event_ref,
                scheduled_start_utc: start,
                scheduled_end_utc: end,
                delivered_at: self.now,
                asked_at: self.now,
                lens,
                source_refs,
                re_ask: None,
            },
        )?;
        if prepped {
            self.report.prepped += 1;
        }
        Ok(())
    }

    /// Asks the check-in for one EVENT start, once, when it is still due,
    /// and plans its morning re-ask.
    fn deliver_check_in(&mut self, event_ref: EntityId, start: u64, end: u64) -> Result<()> {
        let key = card_key(event_ref, CalendarCardKind::CheckIn);
        if read_card(self.vault, &key)?.is_some_and(|card| card.scheduled_start_utc == start) {
            return Ok(());
        }
        let Some(event) = live_prep_event(self.vault, event_ref)? else {
            return Ok(());
        };
        if !check_in_is_still_due(self.vault, &due_check_in(&event))? {
            return Ok(());
        }
        let lens = check_in_lens(event_ref, start, &self.copy.check_in)?;
        let re_ask_at = re_ask_at(self.vault, self.now)?;
        write_card(
            self.vault,
            &key,
            &CalendarInboxCard {
                kind: CalendarCardKind::CheckIn,
                event_ref,
                scheduled_start_utc: start,
                scheduled_end_utc: end,
                delivered_at: self.now,
                asked_at: self.now,
                lens: Some(lens),
                source_refs: BTreeSet::new(),
                re_ask: Some(CheckInReAsk::Planned { at: re_ask_at }),
            },
        )?;
        self.report.asked += 1;
        Ok(())
    }

    /// Whether an owner closed the card's row since it was last asked.
    fn dismissed(&self, card: &CalendarInboxCard) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        let item_id = card.item_id();
        for owner in crate::policy_model::owners_in_txn(self.vault, &rtxn)? {
            if agent_inbox_row_done_in_txn(self.vault, &rtxn, owner, &item_id, card.asked_at)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Deletes one card; `shown` counts it as withdrawn from the INBOX.
    fn withdraw(&mut self, key: &(EntityId, String), shown: bool) -> Result<()> {
        let vault = self.vault;
        vault.with_write_txn(|wtxn| CARDS.delete(&vault.store, wtxn, key))?;
        if shown {
            self.report.withdrawn += 1;
        }
        Ok(())
    }
}

/// Whether `card` still stands at `now`: its EVENT is live, starts when the
/// card says and is not cancelled; a prep card's meeting has not ended, and
/// a check-in has no recorded outcome.
fn card_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &CalendarInboxCard,
    now: u64,
) -> Result<bool> {
    if live_start_in_txn(vault, txn, &card.event_ref)? != Some(card.scheduled_start_utc)
        || cancelled_in_txn(vault, txn, &card.event_ref)?
    {
        return Ok(false);
    }
    Ok(match card.kind {
        CalendarCardKind::Prep => now <= card.scheduled_end_utc,
        CalendarCardKind::CheckIn => current_outcome_in(vault, txn, &card.event_ref)?.is_none(),
    })
}

/// Each EVENT's id, start and end among `ids`, read in one snapshot.
fn event_spans(vault: &Vault, ids: &[EntityId]) -> Result<Vec<(EntityId, u64, u64)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut spans = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(header) = vault.entity_header_in_txn(&rtxn, id)? else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_EVENT {
            continue;
        }
        let start = header.occurred_start.min(header.occurred_end);
        let end = header.occurred_start.max(header.occurred_end);
        spans.push((*id, start, end));
    }
    Ok(spans)
}

/// The live EVENT's start; `None` when it is gone, is no EVENT, or is a
/// deleted shell.
fn live_start_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<u64>> {
    let Some(header) = vault.entity_header_in_txn(txn, event_ref)? else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_EVENT || vault.is_deleted_shell_in_txn(txn, event_ref)? {
        return Ok(None);
    }
    Ok(Some(header.occurred_start.min(header.occurred_end)))
}

/// Whether the EVENT's current `calendar.status` says cancelled.
fn cancelled_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, event_ref: &EntityId) -> Result<bool> {
    Ok(current_status_in(vault, txn, event_ref)?
        .is_some_and(|status| status.status == CalendarStatus::Cancelled))
}

/// The due check-in for an EVENT as it stands, its meeting class re-read.
fn due_check_in(event: &PrepEvent) -> DueOutcomeCheckIn {
    DueOutcomeCheckIn {
        wake_id: format!("{OUTCOME_CHECK_IN_REASON_TAG}:{}", event.event_ref.to_hex()),
        event_ref: event.event_ref,
        scheduled_start_utc: event.start_utc,
        signals: MeetingClassSignals {
            external_attendee_count: event.external_attendee_count,
            has_campaign_linkage: event.has_campaign_linkage,
            has_commitment_linkage: event.has_commitment_linkage,
            internal_meeting_opt_in: event.internal_meeting_opt_in,
        },
    }
}

/// The check-in card: its answers ride the check-in answer verb and its
/// recording drop the transcript ingest verb.
fn check_in_lens(event_ref: EntityId, start: u64, copy: &CheckInCopy) -> Result<GeneratedLens> {
    build_check_in_lens(
        &CheckInCardModel {
            event_ref,
            scheduled_start_utc: start,
            answer_action_id: AgentVerb::VaultCalendarCheckInAnswer.as_str().to_owned(),
            recording_upload_action_id: AgentVerb::VaultCalendarTranscriptIngest
                .as_str()
                .to_owned(),
        },
        copy,
    )
}

/// The morning re-ask for a check-in asked at `asked_at`, on the owner's
/// clock: the reminder route's zone or offset, else UTC.
fn re_ask_at(vault: &Vault, asked_at: u64) -> Result<u64> {
    let route = vault.commitment_reminder_route()?;
    Ok(plan_check_in_re_ask(asked_at, |at| {
        route
            .as_ref()
            .and_then(|route| route.utc_offset_minutes_at(at))
            .unwrap_or(0)
    }))
}

fn card_key(event_ref: EntityId, kind: CalendarCardKind) -> (EntityId, String) {
    (event_ref, kind.as_str().to_owned())
}

fn read_card(vault: &Vault, key: &(EntityId, String)) -> Result<Option<CalendarInboxCard>> {
    let rtxn = vault.store.env.read_txn()?;
    CARDS.get(&vault.store, &rtxn, key)
}

fn write_card(vault: &Vault, key: &(EntityId, String), card: &CalendarInboxCard) -> Result<()> {
    vault.with_write_txn(|wtxn| CARDS.put(&vault.store, wtxn, key, card))
}

/// Drops the meeting cards an erased row reached: every card keyed by it as
/// the EVENT, and every card whose delivered lens copied it. Cards are few,
/// so the source scan reads the whole table.
pub(crate) fn erase_inbox_cards_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    CARDS.delete_from(store, txn, id.as_bytes())?;
    let doomed = CARDS
        .scan(store, &*txn)?
        .into_iter()
        .filter(|(_, card)| card.source_refs.contains(id))
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    for key in doomed {
        CARDS.delete(store, txn, &key)?;
    }
    Ok(())
}
