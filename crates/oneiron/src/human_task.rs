//! Human-assigned TASK follow-up and the identity-bound human response signal
//! (ONE-1708).
//!
//! ARCH-0067 §6: humans are first-class TASK assignees. A human-assigned TASK
//! gets **no job realization** — Dreamer follow-up (track / remind / digest /
//! escalate) instead — and durable workflows wait on humans exactly as on
//! agents, through the existing C9 trap.
//!
//! Two pieces of durable state live here, and neither is authoritative:
//!
//! * the **follow-up cursor**, derived scheduler state keyed by `task_ref`.
//!   The authoritative, synced facts stay on the TASK entity
//!   (`assignee` / `status` / `started_at`); this cursor only remembers WHERE
//!   the nudging got to, and is rebuildable from live human-assigned TASK rows
//!   after a migration or home-node change.
//! * the **wait binding**, the device-local row that lets an inbound human
//!   response find the trap parked on it. Claim-ACT mechanics: it never syncs.
//!
//! Nothing here extends OF-327. Reminders, digests and escalations are
//! ordinary connector `send` intents scheduled through the existing outbound
//! chokepoint, sharing ONE-1699's `(task_ref, stage)` idempotency namespace so
//! one task can never double-notify across follow-up families.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::ChannelIdentityState;
use crate::comm::{CommClaim, CommClaimValue, PREDICATE_COMM_REACHABLE_VIA};
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::facade::OutboundDraftInput;
use crate::llm::{DreamerTrapKind, TrapRef, send_trap_signal};
use crate::outbound::outbound_verb_contract;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::task_verb::{
    task_create_owner, task_follow_up_dedupe_key, task_human_assignee, task_is_terminal,
};
use crate::Vault;

/// Schema version of the persisted follow-up cursor.
pub const HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION: u8 = 1;

const HUMAN_TASK_FOLLOWUP_KEY_PREFIX: &[u8] = b"human_task.followup.v1\0";
const HUMAN_TASK_WAIT_KEY_PREFIX: &[u8] = b"human_task.wait.v1\0";
/// Records which response event already produced a signal for one wait, so a
/// re-delivered response returns the first signal instead of re-driving the
/// trap state machine.
const HUMAN_TASK_WAIT_SIGNAL_KEY_PREFIX: &[u8] = b"human_task.wait.signal.v1\0";

/// Repeatable follow-up stage tokens. The generation rides INSIDE the token
/// (ONE-1699's namespace is `(task_ref, stage)`), so an intentionally repeated
/// escalation gets a fresh idempotency key while a restart-driven replay of the
/// same generation collapses.
pub const HUMAN_FOLLOWUP_STAGE_REMINDER: &str = "human_reminder";
pub const HUMAN_FOLLOWUP_STAGE_DIGEST: &str = "human_digest";
pub const HUMAN_FOLLOWUP_STAGE_ESCALATION: &str = "human_escalation";

/// The one outbound verb follow-up uses. `remind`/`digest`/`escalate` are NOT
/// outbound verbs and are never minted: the connector manifest decides what a
/// channel can do, and follow-up is an ordinary send.
const HUMAN_FOLLOWUP_VERB: &str = "send";

/// Quiet interval before the first direct nudge.
const REMINDER_AFTER_SECONDS: u64 = 24 * 60 * 60;
/// Interval from the reminder to the open-loop digest entry.
const DIGEST_AFTER_SECONDS: u64 = 3 * 24 * 60 * 60;
/// Interval from the digest to escalation, and between escalations.
const ESCALATION_AFTER_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Bound on one wake-pass follow-up drive.
const FOLLOWUP_WAKE_LIMIT: usize = 64;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_TASK_REF: &str = "task_ref";
const KEY_ASSIGNEE_REF: &str = "assignee_ref";
const KEY_STAGE: &str = "stage";
const KEY_STAGE_GENERATION: &str = "stage_generation";
const KEY_NEXT_DUE_AT: &str = "next_due_at";
const KEY_REMINDERS_SENT: &str = "reminders_sent";
const KEY_LAST_RECEIPT_REF: &str = "last_receipt_ref";
const KEY_COMPLETED_AT: &str = "completed_at";
const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";
const KEY_STEP_HASH: &str = "step_hash";
const KEY_SIGNAL_REF: &str = "signal_ref";
const KEY_SURFACE_EVENT_REF: &str = "surface_event_ref";
/// Synced-truth address field on a comm-owned PERSON body.
const KEY_PARTY_KEY: &str = "party_key";

/// Typed failure surface for native-human routing and response signalling.
///
/// A rejected assignee is refused in its own name — never degraded into a
/// Dreamer fallback, and never routed out through a marketplace pack.
#[derive(Debug, thiserror::Error)]
pub enum HumanTaskError {
    #[error(transparent)]
    Engine(#[from] Error),
    /// The assignee resolves to something that is not a PERSON.
    #[error("task assignee is not a person")]
    NotAPerson,
    /// A known person the vault has no native route to. Deliberately distinct
    /// from `NotAPerson`: the TASK fact stays legible either way, but only this
    /// one says "we know who, we just cannot reach them here".
    #[error("known person is not currently reachable through a native route")]
    NotNativelyReachable,
    /// The response did not come from the bound person, task, or step.
    #[error("human response does not match its wait binding")]
    UnboundResponse,
}

pub type HumanTaskResult<T> = std::result::Result<T, HumanTaskError>;

/// Where one human-assigned TASK's nudging has got to.
///
/// `Tracking` is the resting state; the three `*Due` stages are what the
/// driver has ALREADY done, and `Completed` closes the cursor. There is
/// deliberately no failure stage: a held, degraded or suppressed delivery is an
/// outbound receipt outcome, not a follow-up state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanFollowupStage {
    Tracking,
    ReminderDue,
    DigestDue,
    EscalationDue,
    Completed,
}

impl HumanFollowupStage {
    /// Stable storage token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tracking => "tracking",
            Self::ReminderDue => "reminder_due",
            Self::DigestDue => "digest_due",
            Self::EscalationDue => "escalation_due",
            Self::Completed => "completed",
        }
    }

    fn from_token(token: &str) -> Result<Self> {
        match token {
            "tracking" => Ok(Self::Tracking),
            "reminder_due" => Ok(Self::ReminderDue),
            "digest_due" => Ok(Self::DigestDue),
            "escalation_due" => Ok(Self::EscalationDue),
            "completed" => Ok(Self::Completed),
            _ => Err(Error::CorruptedIndex("human_task.followup stage")),
        }
    }

    /// What running this stage's due work produces: the stage reached and the
    /// outbound family it notifies through. `Completed` and a not-yet-due
    /// `Tracking` produce nothing.
    const fn advance(self) -> Option<(Self, &'static str, u64)> {
        match self {
            Self::Tracking => Some((
                Self::ReminderDue,
                HUMAN_FOLLOWUP_STAGE_REMINDER,
                DIGEST_AFTER_SECONDS,
            )),
            Self::ReminderDue => Some((
                Self::DigestDue,
                HUMAN_FOLLOWUP_STAGE_DIGEST,
                ESCALATION_AFTER_SECONDS,
            )),
            // Escalation repeats: the Dreamer keeps surfacing an unresolved
            // human loop rather than silently giving up on it.
            Self::DigestDue | Self::EscalationDue => Some((
                Self::EscalationDue,
                HUMAN_FOLLOWUP_STAGE_ESCALATION,
                ESCALATION_AFTER_SECONDS,
            )),
            Self::Completed => None,
        }
    }
}

/// The native route one reminder travels: OUR sending identity on a channel the
/// person is known to be reachable on, plus their address on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHumanRoute {
    pub person_ref: EntityId,
    pub channel_identity_ref: EntityId,
    pub channel: String,
    pub target: String,
    pub counterparty_ref: Option<String>,
}

/// Durable, rebuildable follow-up cursor for one human-assigned TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanTaskFollowupRecord {
    pub schema_version: u8,
    pub task_ref: EntityId,
    pub assignee_ref: EntityId,
    pub stage: HumanFollowupStage,
    pub stage_generation: u32,
    pub next_due_at: Option<u64>,
    pub reminders_sent: u32,
    pub last_receipt_ref: Option<String>,
    pub completed_at: Option<u64>,
}

/// Device-local binding from one human-assigned TASK to the trap parked on the
/// person's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanTaskWaitBinding {
    pub task_ref: EntityId,
    pub assignee_ref: EntityId,
    pub trap_claim_id: EntityId,
    pub step_hash: [u8; 32],
}

/// One identity-stamped inbound response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanResponseSignal {
    pub task_ref: EntityId,
    pub responder_ref: EntityId,
    pub surface_event_ref: EntityId,
    pub occurred_at: u64,
}

/// What one due follow-up actually scheduled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanFollowupDispatch {
    pub task_ref: EntityId,
    pub assignee_ref: EntityId,
    pub stage: HumanFollowupStage,
    /// `(task_ref, stage)` namespace token, generation included.
    pub stage_token: String,
    pub intent_ref: String,
    /// Outbound schedule outcome, verbatim from the OF-327 receipt.
    pub outcome: String,
}

// ── native-human resolution ─────────────────────────────────────────────────

/// Resolves a native human assignee to the route a follow-up would travel.
///
/// Native means the vault ALREADY knows them: a PERSON with an effective
/// `comm.reachable_via` fact, one of our own active channel identities on that
/// channel, and a live counterparty contact for their address. No pack is
/// installed, no MACHINE assignee is synthesized, and an unknown person is
/// never quietly routed through an external marketplace — the outside-human
/// path is EF-311's and stays out of this engine surface.
pub fn resolve_native_human_route(
    vault: &Vault,
    person_ref: EntityId,
) -> HumanTaskResult<NativeHumanRoute> {
    if vault.get_entity_type(&person_ref)? != Some(ENTITY_TYPE_PERSON) {
        return Err(HumanTaskError::NotAPerson);
    }
    let now = crate::unix_seconds_now();
    let Some(party_key) = comm_party_key(vault, person_ref)? else {
        return Err(HumanTaskError::NotNativelyReachable);
    };

    for channel in reachable_channel_classes(vault, person_ref, now)? {
        // A channel the connector manifest does not serve is not a route,
        // however reachable the person is on it.
        if outbound_verb_contract(&channel, HUMAN_FOLLOWUP_VERB).is_err() {
            continue;
        }
        for channel_identity_ref in vault.entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)? {
            let Some(identity) = vault.get_channel_identity(&channel_identity_ref)? else {
                continue;
            };
            if identity.channel != channel || identity.state != ChannelIdentityState::Active {
                continue;
            }
            let Some((_, contact)) =
                vault.find_counterparty_contact(&channel_identity_ref, &party_key)?
            else {
                continue;
            };
            if contact.status != CounterpartyContactStatus::Active || contact.opt_out.is_some() {
                continue;
            }
            return Ok(NativeHumanRoute {
                person_ref,
                channel_identity_ref,
                channel,
                target: contact.counterparty.clone(),
                counterparty_ref: Some(contact.counterparty),
            });
        }
    }
    Err(HumanTaskError::NotNativelyReachable)
}

/// The comm-owned PERSON's `party_key` — the address the identity plane already
/// knows this person by. Absent means the PERSON was minted by some other
/// surface and carries no communication address.
fn comm_party_key(vault: &Vault, person_ref: EntityId) -> Result<Option<String>> {
    let Some(raw) = vault.get_raw(&person_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let Ok(value) = rmpv::decode::read_value(&mut std::io::Cursor::new(
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )) else {
        return Ok(None);
    };
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    Ok(entries.into_iter().find_map(|(key, value)| {
        (key.as_str() == Some(KEY_PARTY_KEY))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    }))
}

/// Channel classes this person is standing-reachable on, deterministically
/// ordered so one vault always picks the same route.
fn reachable_channel_classes(
    vault: &Vault,
    person_ref: EntityId,
    now: u64,
) -> Result<Vec<String>> {
    let mut classes = BTreeSet::new();
    for claim_ref in vault.claims_for_subject(&person_ref)? {
        let Some(body) = vault.get_claim(&claim_ref)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_REACHABLE_VIA {
            continue;
        }
        let Ok(claim) = CommClaim::from_claim_body(&body) else {
            continue;
        };
        if !claim.is_effective_at(now) {
            continue;
        }
        if let CommClaimValue::ReachableVia {
            channel_class,
            reachable: true,
            ..
        } = claim.value
        {
            classes.insert(channel_class);
        }
    }
    Ok(classes.into_iter().collect())
}

// ── follow-up cursor ────────────────────────────────────────────────────────

/// Opens the follow-up cursor for one human-assigned TASK, inside the SAME
/// transaction that persists the TASK. A cursor write that fails rolls the
/// create back rather than leaving a human task nothing is tracking.
///
/// Re-registering an existing cursor is a no-op: the create path is idempotent
/// on its dedupe key, and a rebuild must not rewind live nudging state.
pub(crate) fn register_human_followup_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    assignee_ref: EntityId,
    now: u64,
) -> Result<()> {
    if followup_record_in_txn(vault, &*wtxn, task_ref)?.is_some() {
        return Ok(());
    }
    put_followup_record_in_txn(
        vault,
        wtxn,
        &HumanTaskFollowupRecord {
            schema_version: HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION,
            task_ref,
            assignee_ref,
            stage: HumanFollowupStage::Tracking,
            stage_generation: 0,
            next_due_at: Some(now.saturating_add(REMINDER_AFTER_SECONDS)),
            reminders_sent: 0,
            last_receipt_ref: None,
            completed_at: None,
        },
    )
}

/// The follow-up cursor for one TASK, if this replica holds one.
pub fn human_followup_record(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskFollowupRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    followup_record_in_txn(vault, &rtxn, task_ref)
}

/// Every follow-up cursor on this replica, task order.
pub fn human_followup_records(vault: &Vault) -> Result<Vec<HumanTaskFollowupRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, HUMAN_TASK_FOLLOWUP_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        records.push(decode_followup_record(raw.as_ref())?);
    }
    Ok(records)
}

/// Drives the human follow-up cursors: no job, no queue row, no closed-string
/// Dreamer attempt kind — just the maintenance the Dreamer owes an open human
/// loop.
pub struct HumanTaskFollowupDriver<'a> {
    vault: &'a Vault,
}

impl<'a> HumanTaskFollowupDriver<'a> {
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    /// Runs every follow-up whose cursor is due at `now`, up to `limit`.
    ///
    /// Ordering is deliberate and mirrors ONE-1699's expiry sweep: the outbound
    /// is scheduled FIRST and the cursor advances after. A crash in between
    /// leaves the cursor un-advanced, the next pass re-drives the same
    /// `(task_ref, stage)` key, and the outbound chokepoint's idempotency
    /// coalesces the retry — so a restart re-runs the stage rather than nagging
    /// the person twice.
    pub fn run_due(&self, now: u64, limit: usize) -> Result<Vec<HumanFollowupDispatch>> {
        let mut dispatched = Vec::new();
        for record in self.due_records(now, limit)? {
            // A settled TASK closes its own loop: the authoritative synced fact
            // wins over anything the local cursor believed.
            if task_is_terminal(self.vault, record.task_ref)? {
                self.complete(&record, now)?;
                continue;
            }
            let Some((next_stage, family, interval)) = record.stage.advance() else {
                continue;
            };
            let stage_token = format!("{family}:{}", record.stage_generation);
            let Some(dispatch) = self.schedule(&record, next_stage, &stage_token)? else {
                continue;
            };
            self.advance(&record, next_stage, interval, now, &dispatch.intent_ref)?;
            dispatched.push(dispatch);
        }
        Ok(dispatched)
    }

    /// Re-derives missing cursors from live human-assigned TASK rows. The
    /// cursor is derived scheduler state, so a migration or home-node change
    /// that loses it costs nothing but a re-walk — no registry byte, no second
    /// synced truth.
    pub fn rebuild_cursors(&self, now: u64) -> Result<usize> {
        let mut rebuilt = 0;
        for task_ref in self.vault.entities_by_type(ENTITY_TYPE_TASK)? {
            // One malformed body must not wedge the rebuild for every other
            // human task — the same degrade `tasks.check` already applies.
            let Ok(Some(actor_ref)) = task_human_assignee(self.vault, task_ref) else {
                continue;
            };
            if human_followup_record(self.vault, task_ref)?.is_some() {
                continue;
            }
            self.vault.with_write_txn(|wtxn| {
                register_human_followup_in_txn(self.vault, wtxn, task_ref, actor_ref, now)
            })?;
            rebuilt += 1;
        }
        Ok(rebuilt)
    }

    fn due_records(&self, now: u64, limit: usize) -> Result<Vec<HumanTaskFollowupRecord>> {
        Ok(human_followup_records(self.vault)?
            .into_iter()
            .filter(|record| {
                record.stage != HumanFollowupStage::Completed
                    && record.next_due_at.is_some_and(|due| due <= now)
            })
            .take(limit)
            .collect())
    }

    /// Schedules one follow-up notification through the OF-327 chokepoint.
    ///
    /// The acting identity is the TASK's create owner — the same actor whose
    /// ceiling admitted the create — so the gate, budget and delivery-window
    /// pipeline decide delivery exactly as they would for any other send this
    /// actor makes. A task whose owner or route no longer resolves degrades to
    /// a skip: one unreachable row must not wedge the sweep for every other.
    fn schedule(
        &self,
        record: &HumanTaskFollowupRecord,
        stage: HumanFollowupStage,
        stage_token: &str,
    ) -> Result<Option<HumanFollowupDispatch>> {
        let Some(owner_ref) = task_create_owner(self.vault, record.task_ref)? else {
            return Ok(None);
        };
        let Ok(route) = resolve_native_human_route(self.vault, record.assignee_ref) else {
            return Ok(None);
        };
        let key = task_follow_up_dedupe_key(record.task_ref, stage_token);
        let facade = self
            .vault
            .memory_facade(owner_ref, EdgeActorClass::Agent);
        let Ok(receipt) = facade.schedule_outbound(&OutboundDraftInput {
            verb: HUMAN_FOLLOWUP_VERB.to_owned(),
            channel: route.channel.clone(),
            target: route.target.clone(),
            on_behalf_of: None,
            // Outbound copy renders from the typed TASK, never from prose
            // assembled here.
            content_ref: Some(record.task_ref.to_hex()),
            idempotency_key: Some(key.clone()),
            dedupe_key: Some(key),
            trigger: "commitment_timer_wake".to_owned(),
            trigger_ref: record.task_ref.to_hex(),
            job_ref: None,
            occurred_at: None,
        }) else {
            return Ok(None);
        };
        Ok(Some(HumanFollowupDispatch {
            task_ref: record.task_ref,
            assignee_ref: record.assignee_ref,
            stage,
            stage_token: stage_token.to_owned(),
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
        }))
    }

    fn advance(
        &self,
        record: &HumanTaskFollowupRecord,
        stage: HumanFollowupStage,
        interval: u64,
        now: u64,
        intent_ref: &str,
    ) -> Result<()> {
        let reminders_sent = record.reminders_sent.saturating_add(1);
        // The generation advances only where repetition is intentional, so a
        // reminder and its digest keep distinct stable keys while successive
        // escalations do not collapse onto one another.
        let stage_generation = if stage == HumanFollowupStage::EscalationDue {
            record.stage_generation.saturating_add(1)
        } else {
            record.stage_generation
        };
        let next = HumanTaskFollowupRecord {
            stage,
            stage_generation,
            next_due_at: Some(now.saturating_add(interval)),
            reminders_sent,
            last_receipt_ref: Some(intent_ref.to_owned()),
            ..record.clone()
        };
        self.vault
            .with_write_txn(|wtxn| put_followup_record_in_txn(self.vault, wtxn, &next))
    }

    fn complete(&self, record: &HumanTaskFollowupRecord, now: u64) -> Result<()> {
        let next = HumanTaskFollowupRecord {
            stage: HumanFollowupStage::Completed,
            next_due_at: None,
            completed_at: Some(now),
            ..record.clone()
        };
        self.vault
            .with_write_txn(|wtxn| put_followup_record_in_txn(self.vault, wtxn, &next))
    }
}

/// Closes one follow-up cursor because the person answered or the TASK settled.
pub fn close_human_followup(vault: &Vault, task_ref: EntityId, now: u64) -> Result<bool> {
    let Some(record) = human_followup_record(vault, task_ref)? else {
        return Ok(false);
    };
    if record.stage == HumanFollowupStage::Completed {
        return Ok(false);
    }
    HumanTaskFollowupDriver::new(vault).complete(&record, now)?;
    Ok(true)
}

/// Drives every due human follow-up on one Dreamer wake pass.
pub(crate) fn run_human_followups_on_wake(vault: &Vault, now: u64) -> Result<usize> {
    HumanTaskFollowupDriver::new(vault)
        .run_due(now, FOLLOWUP_WAKE_LIMIT)
        .map(|dispatched| dispatched.len())
}

// ── C9 wait binding + identity-bound response signal ────────────────────────

/// Binds one parked step to the person expected to answer it.
///
/// The binding lands BEFORE the trap is registered as waiting, deliberately: a
/// crash in between leaves a locatable binding on a `created` trap, which the
/// signal path still accepts (signal-before-wait), whereas the reverse order
/// would leave a waiting trap nothing could find.
pub fn bind_human_wait(
    vault: &Vault,
    task_ref: EntityId,
    assignee_ref: EntityId,
    trap: &TrapRef,
) -> HumanTaskResult<HumanTaskWaitBinding> {
    if trap.kind != DreamerTrapKind::HumanResponse {
        return Err(HumanTaskError::UnboundResponse);
    }
    let binding = HumanTaskWaitBinding {
        task_ref,
        assignee_ref,
        trap_claim_id: trap.trap_claim_id,
        step_hash: trap.step_hash,
    };
    vault.with_write_txn(|wtxn| put_wait_binding_in_txn(vault, wtxn, &binding))?;
    Ok(binding)
}

/// The wait binding for one TASK, if a step on this device is parked on it.
pub fn human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, wait_binding_key(task_ref).as_slice())?
    else {
        return Ok(None);
    };
    decode_wait_binding(raw.as_ref()).map(Some)
}

/// Sends the resume signal for one identity-stamped human response.
///
/// Every mismatch is refused without touching the trap: a response from the
/// wrong actor, for a different task, or against a stale step hash signals
/// nothing. Re-delivery of the SAME response returns the first signal instead
/// of re-driving the state machine; `consume_trap_signal` remains the atomic
/// consume/resume door, so the parked attempt resumes exactly once.
pub fn signal_human_response(
    vault: &Vault,
    binding: &HumanTaskWaitBinding,
    signal: &HumanResponseSignal,
) -> HumanTaskResult<EntityId> {
    if signal.responder_ref != binding.assignee_ref || signal.task_ref != binding.task_ref {
        return Err(HumanTaskError::UnboundResponse);
    }
    // The caller-supplied binding is a convenience handle; the DEVICE-LOCAL row
    // is the authority, so a forged or stale binding cannot signal.
    let stored = human_wait_binding(vault, binding.task_ref)?
        .ok_or(HumanTaskError::UnboundResponse)?;
    if stored != *binding {
        return Err(HumanTaskError::UnboundResponse);
    }
    if let Some((signal_ref, surface_event_ref)) = wait_signal_marker(vault, stored.trap_claim_id)?
    {
        if surface_event_ref == signal.surface_event_ref {
            return Ok(signal_ref);
        }
        // A DIFFERENT event arriving after the trap already signalled has
        // nothing left to wake.
        return Err(HumanTaskError::UnboundResponse);
    }
    let signal_ref = send_trap_signal(
        vault,
        &stored.trap_claim_id,
        stored.step_hash,
        signal.occurred_at,
    )?;
    vault.with_write_txn(|wtxn| {
        put_wait_signal_marker_in_txn(
            vault,
            wtxn,
            stored.trap_claim_id,
            signal_ref,
            signal.surface_event_ref,
        )
    })?;
    Ok(signal_ref)
}

/// Retires the wait binding once its trap has been consumed.
pub fn release_human_wait(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    let Some(binding) = human_wait_binding(vault, task_ref)? else {
        return Ok(false);
    };
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .delete(wtxn, wait_binding_key(task_ref).as_slice())?;
        vault
            .store
            .vault_meta
            .delete(wtxn, wait_signal_key(binding.trap_claim_id).as_slice())?;
        Ok(())
    })?;
    Ok(true)
}

// ── storage ─────────────────────────────────────────────────────────────────

fn prefixed_key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + id.as_bytes().len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn followup_key(task_ref: EntityId) -> Vec<u8> {
    prefixed_key(HUMAN_TASK_FOLLOWUP_KEY_PREFIX, task_ref)
}

fn wait_binding_key(task_ref: EntityId) -> Vec<u8> {
    prefixed_key(HUMAN_TASK_WAIT_KEY_PREFIX, task_ref)
}

fn wait_signal_key(trap_claim_id: EntityId) -> Vec<u8> {
    prefixed_key(HUMAN_TASK_WAIT_SIGNAL_KEY_PREFIX, trap_claim_id)
}

fn encoded(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .expect("writing msgpack into a Vec is infallible");
    bytes
}

fn entity_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn optional_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn field<'v>(entries: &'v [(Value, Value)], key: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

fn decode_map(raw: &[u8], what: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(what))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(what)),
    }
}

fn decode_entity(entries: &[(Value, Value)], key: &str, what: &'static str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(Error::CorruptedIndex(what));
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(what))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(what))
}

fn decode_u64(entries: &[(Value, Value)], key: &str, what: &'static str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(what))
}

fn put_followup_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &HumanTaskFollowupRecord,
) -> Result<()> {
    let body = encoded(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(record.schema_version),
        ),
        (Value::from(KEY_TASK_REF), entity_value(record.task_ref)),
        (
            Value::from(KEY_ASSIGNEE_REF),
            entity_value(record.assignee_ref),
        ),
        (Value::from(KEY_STAGE), Value::from(record.stage.as_str())),
        (
            Value::from(KEY_STAGE_GENERATION),
            Value::from(record.stage_generation),
        ),
        (
            Value::from(KEY_NEXT_DUE_AT),
            optional_u64_value(record.next_due_at),
        ),
        (
            Value::from(KEY_REMINDERS_SENT),
            Value::from(record.reminders_sent),
        ),
        (
            Value::from(KEY_LAST_RECEIPT_REF),
            optional_str_value(record.last_receipt_ref.as_deref()),
        ),
        (
            Value::from(KEY_COMPLETED_AT),
            optional_u64_value(record.completed_at),
        ),
    ]);
    vault
        .store
        .vault_meta
        .put(wtxn, followup_key(record.task_ref).as_slice(), &body)?;
    Ok(())
}

fn followup_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<HumanTaskFollowupRecord>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, followup_key(task_ref).as_slice())?
    else {
        return Ok(None);
    };
    decode_followup_record(raw.as_ref()).map(Some)
}

fn decode_followup_record(raw: &[u8]) -> Result<HumanTaskFollowupRecord> {
    const WHAT: &str = "human_task.followup row";
    let entries = decode_map(raw, WHAT)?;
    let schema_version = u8::try_from(decode_u64(&entries, KEY_SCHEMA_VERSION, WHAT)?)
        .map_err(|_| Error::CorruptedIndex(WHAT))?;
    if schema_version != HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex(WHAT));
    }
    let stage = field(&entries, KEY_STAGE)
        .and_then(Value::as_str)
        .ok_or(Error::CorruptedIndex(WHAT))
        .and_then(HumanFollowupStage::from_token)?;
    Ok(HumanTaskFollowupRecord {
        schema_version,
        task_ref: decode_entity(&entries, KEY_TASK_REF, WHAT)?,
        assignee_ref: decode_entity(&entries, KEY_ASSIGNEE_REF, WHAT)?,
        stage,
        stage_generation: u32::try_from(decode_u64(&entries, KEY_STAGE_GENERATION, WHAT)?)
            .map_err(|_| Error::CorruptedIndex(WHAT))?,
        next_due_at: field(&entries, KEY_NEXT_DUE_AT).and_then(Value::as_u64),
        reminders_sent: u32::try_from(decode_u64(&entries, KEY_REMINDERS_SENT, WHAT)?)
            .map_err(|_| Error::CorruptedIndex(WHAT))?,
        last_receipt_ref: field(&entries, KEY_LAST_RECEIPT_REF)
            .and_then(Value::as_str)
            .map(str::to_owned),
        completed_at: field(&entries, KEY_COMPLETED_AT).and_then(Value::as_u64),
    })
}

fn put_wait_binding_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &HumanTaskWaitBinding,
) -> Result<()> {
    let body = encoded(vec![
        (Value::from(KEY_TASK_REF), entity_value(binding.task_ref)),
        (
            Value::from(KEY_ASSIGNEE_REF),
            entity_value(binding.assignee_ref),
        ),
        (
            Value::from(KEY_TRAP_CLAIM_ID),
            entity_value(binding.trap_claim_id),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(binding.step_hash.to_vec()),
        ),
    ]);
    vault
        .store
        .vault_meta
        .put(wtxn, wait_binding_key(binding.task_ref).as_slice(), &body)?;
    Ok(())
}

fn decode_wait_binding(raw: &[u8]) -> Result<HumanTaskWaitBinding> {
    const WHAT: &str = "human_task.wait row";
    let entries = decode_map(raw, WHAT)?;
    let Some(Value::Binary(step_hash)) = field(&entries, KEY_STEP_HASH) else {
        return Err(Error::CorruptedIndex(WHAT));
    };
    let step_hash: [u8; 32] = step_hash
        .as_slice()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(WHAT))?;
    Ok(HumanTaskWaitBinding {
        task_ref: decode_entity(&entries, KEY_TASK_REF, WHAT)?,
        assignee_ref: decode_entity(&entries, KEY_ASSIGNEE_REF, WHAT)?,
        trap_claim_id: decode_entity(&entries, KEY_TRAP_CLAIM_ID, WHAT)?,
        step_hash,
    })
}

fn put_wait_signal_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap_claim_id: EntityId,
    signal_ref: EntityId,
    surface_event_ref: EntityId,
) -> Result<()> {
    let body = encoded(vec![
        (Value::from(KEY_SIGNAL_REF), entity_value(signal_ref)),
        (
            Value::from(KEY_SURFACE_EVENT_REF),
            entity_value(surface_event_ref),
        ),
    ]);
    vault
        .store
        .vault_meta
        .put(wtxn, wait_signal_key(trap_claim_id).as_slice(), &body)?;
    Ok(())
}

fn wait_signal_marker(
    vault: &Vault,
    trap_claim_id: EntityId,
) -> Result<Option<(EntityId, EntityId)>> {
    const WHAT: &str = "human_task.wait.signal row";
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, wait_signal_key(trap_claim_id).as_slice())?
    else {
        return Ok(None);
    };
    let entries = decode_map(raw.as_ref(), WHAT)?;
    Ok(Some((
        decode_entity(&entries, KEY_SIGNAL_REF, WHAT)?,
        decode_entity(&entries, KEY_SURFACE_EVENT_REF, WHAT)?,
    )))
}

#[cfg(test)]
mod tests;
