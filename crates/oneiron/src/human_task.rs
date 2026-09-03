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

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::ChannelIdentityState;
use crate::comm::{
    CommClaim, CommClaimValue, PREDICATE_COMM_OPT_OUT, PREDICATE_COMM_REACHABLE_VIA,
};
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{DREAMER_TRAP_PREDICATE, DreamerTrapKind, TrapRef, send_trap_signal};
use crate::memory::OutboundDraftInput;
use crate::outbound::outbound_verb_contract;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::task_verb::{
    task_create_owner, task_follow_up_dedupe_key, task_human_assignee, task_is_terminal,
};

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
/// Page size for the bounded TASK walk in [`HumanTaskFollowupDriver::rebuild_cursors`].
const REBUILD_PAGE: usize = 256;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_TASK_REF: &str = "task_ref";
const KEY_ASSIGNEE_REF: &str = "assignee_ref";
const KEY_STAGE: &str = "stage";
const KEY_STAGE_GENERATION: &str = "stage_generation";
const KEY_NEXT_DUE_AT: &str = "next_due_at";
const KEY_REMINDERS_SENT: &str = "reminders_sent";
const KEY_LAST_RECEIPT_REF: &str = "last_receipt_ref";
const KEY_COMPLETED_AT: &str = "completed_at";
const KEY_RESPONDER_REF: &str = "responder_ref";
const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";
const KEY_STEP_HASH: &str = "step_hash";
const KEY_IS_ACTIVE: &str = "is_active";
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
    /// OUR sending identity on this channel — the auditable half of the route.
    pub channel_identity_ref: EntityId,
    pub channel: String,
    /// The person's address on that channel, straight off the contact row.
    pub target: String,
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
    pub responder_ref: EntityId,
    pub trap_claim_id: EntityId,
    pub step_hash: [u8; 32],
    /// The persisted authorization bit. Release writes an inactive tombstone so
    /// an old in-memory handle cannot revive a consumed wait.
    pub is_active: bool,
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
/// Native means the vault ALREADY knows them. The POSITIVE fact is the pair
/// that only an existing relationship can produce: one of our own ACTIVE
/// channel identities, plus a live counterparty contact on it for this
/// person's address. The `comm.*` standing state is read as a VETO over that
/// pair — an opt-out, or an explicit `comm.reachable_via: false`, removes the
/// channel. That direction is deliberate: consent facts must be able to take a
/// route away without being able to invent one.
///
/// No pack is installed, no MACHINE assignee is synthesized, and an unknown
/// person is never quietly routed through an external marketplace — the
/// outside-human path is EF-311's and stays out of this engine surface.
pub fn resolve_native_human_route(
    vault: &Vault,
    person_ref: EntityId,
) -> HumanTaskResult<NativeHumanRoute> {
    if vault.get_entity_type(&person_ref)? != Some(ENTITY_TYPE_PERSON) {
        return Err(HumanTaskError::NotAPerson);
    }
    let Some(party_key) = comm_party_key(vault, person_ref)? else {
        return Err(HumanTaskError::NotNativelyReachable);
    };
    let vetoed = vetoed_channel_classes(vault, person_ref, crate::unix_seconds_now())?;

    for channel_identity_ref in vault.entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)? {
        let Some(identity) = vault.get_channel_identity(&channel_identity_ref)? else {
            continue;
        };
        if identity.state != ChannelIdentityState::Active || vetoed.contains(&identity.channel) {
            continue;
        }
        // A channel the connector manifest does not serve is not a route,
        // however well connected the person is on it.
        if outbound_verb_contract(&identity.channel, HUMAN_FOLLOWUP_VERB).is_err() {
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
            channel: identity.channel,
            target: contact.counterparty,
        });
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

/// Channel classes this person's standing `comm.*` state takes off the table:
/// an active opt-out, or an explicit "not reachable here".
fn vetoed_channel_classes(
    vault: &Vault,
    person_ref: EntityId,
    now: u64,
) -> Result<BTreeSet<String>> {
    let mut vetoed = BTreeSet::new();
    for claim_ref in vault.claims_for_subject(&person_ref)? {
        let Some(body) = vault.get_claim(&claim_ref)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_REACHABLE_VIA
            && body.predicate != PREDICATE_COMM_OPT_OUT
        {
            continue;
        }
        // A malformed comm row must not silently WIDEN reachability, so a
        // decode failure vetoes nothing but is never read as consent either —
        // it simply cannot contribute, and the positive fact still has to
        // stand on its own.
        let Ok(claim) = CommClaim::from_claim_body(&body) else {
            continue;
        };
        if !claim.is_effective_at(now) {
            continue;
        }
        match claim.value {
            CommClaimValue::OptOut { channel_class, .. }
            | CommClaimValue::ReachableVia {
                channel_class,
                reachable: false,
                ..
            } => {
                vetoed.insert(channel_class);
            }
            CommClaimValue::ReachableVia { .. }
            | CommClaimValue::LastTouch { .. }
            | CommClaimValue::ThreadMember { .. } => {}
        }
    }
    Ok(vetoed)
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
    ///
    /// It walks TASK ids through the bounded page primitive rather than the
    /// capped `entities_by_type` query: this is a recovery path over EVERY task
    /// a vault has ever held, which is exactly the shape that overflows one.
    pub fn rebuild_cursors(&self, now: u64) -> Result<usize> {
        let mut rebuilt = 0;
        let mut cursor: Option<EntityId> = None;
        loop {
            let page = self.vault.entities_by_type_page(
                ENTITY_TYPE_TASK,
                cursor.as_ref(),
                REBUILD_PAGE,
            )?;
            let exhausted = page.len() < REBUILD_PAGE;
            cursor = page.last().copied();
            for task_ref in page {
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
            if exhausted {
                break;
            }
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
        let facade = self.vault.memory(owner_ref, EdgeActorClass::Agent);
        let Ok(receipt) = facade.schedule_outbound(&OutboundDraftInput {
            verb: HUMAN_FOLLOWUP_VERB.to_owned(),
            channel: route.channel,
            target: route.target,
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

/// Drives every due human follow-up on one Dreamer wake pass.
pub(crate) fn run_human_followups_on_wake(vault: &Vault, now: u64) -> Result<()> {
    HumanTaskFollowupDriver::new(vault)
        .run_due(now, FOLLOWUP_WAKE_LIMIT)
        .map(|_| ())
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
    responder_ref: EntityId,
    trap: &TrapRef,
) -> HumanTaskResult<HumanTaskWaitBinding> {
    if trap.kind != DreamerTrapKind::HumanResponse {
        return Err(HumanTaskError::UnboundResponse);
    }
    let binding = HumanTaskWaitBinding {
        task_ref,
        responder_ref,
        trap_claim_id: trap.trap_claim_id,
        step_hash: trap.step_hash,
        is_active: true,
    };
    vault.with_write_txn(|wtxn| put_wait_binding_in_txn(vault, wtxn, &binding))?;
    Ok(binding)
}

/// The active wait binding for one TASK, if a step on this device is parked on it.
pub fn human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    Ok(stored_human_wait_binding(vault, task_ref)?.filter(|binding| binding.is_active))
}

fn stored_human_wait_binding(
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
    caller_identity: EntityId,
    signal: &HumanResponseSignal,
) -> HumanTaskResult<EntityId> {
    // The caller-supplied binding is a convenience handle; the DEVICE-LOCAL row
    // is the authority, so a forged, inactive, or stale binding cannot signal.
    let stored = stored_human_wait_binding(vault, binding.task_ref)?
        .ok_or(HumanTaskError::UnboundResponse)?;
    if !stored.is_active || !binding.is_active || stored != *binding {
        return Err(HumanTaskError::UnboundResponse);
    }
    // `signal.responder_ref` is payload. Only the independently authenticated
    // caller identity is an authority, and both must name the persisted responder.
    if caller_identity != stored.responder_ref
        || signal.responder_ref != caller_identity
        || signal.task_ref != stored.task_ref
    {
        return Err(HumanTaskError::UnboundResponse);
    }
    require_persisted_human_response_trap(vault, &stored)?;
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

fn require_persisted_human_response_trap(
    vault: &Vault,
    binding: &HumanTaskWaitBinding,
) -> HumanTaskResult<()> {
    let body = vault
        .get_claim(&binding.trap_claim_id)?
        .ok_or(HumanTaskError::UnboundResponse)?;
    if body.predicate != DREAMER_TRAP_PREDICATE {
        return Err(HumanTaskError::UnboundResponse);
    }
    let Value::Map(entries) = &body.value else {
        return Err(HumanTaskError::UnboundResponse);
    };
    let mut persisted_kind = None;
    for (key, value) in entries {
        if key.as_str() != Some("trap_kind") {
            continue;
        }
        if persisted_kind.replace(value.as_str()).is_some() {
            return Err(HumanTaskError::UnboundResponse);
        }
    }
    if persisted_kind.flatten() != Some(DreamerTrapKind::HumanResponse.as_str()) {
        return Err(HumanTaskError::UnboundResponse);
    }
    Ok(())
}

/// Retires the wait binding once its trap has been consumed.
pub fn release_human_wait(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    let Some(binding) = stored_human_wait_binding(vault, task_ref)? else {
        return Ok(false);
    };
    if !binding.is_active {
        return Ok(false);
    }
    let retired = HumanTaskWaitBinding {
        is_active: false,
        ..binding
    };
    vault.with_write_txn(|wtxn| {
        put_wait_binding_in_txn(vault, wtxn, &retired)?;
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
            Value::from(KEY_RESPONDER_REF),
            entity_value(binding.responder_ref),
        ),
        (
            Value::from(KEY_TRAP_CLAIM_ID),
            entity_value(binding.trap_claim_id),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(binding.step_hash.to_vec()),
        ),
        (Value::from(KEY_IS_ACTIVE), Value::from(binding.is_active)),
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
    let Some(Value::Boolean(is_active)) = field(&entries, KEY_IS_ACTIVE) else {
        return Err(Error::CorruptedIndex(WHAT));
    };
    Ok(HumanTaskWaitBinding {
        task_ref: decode_entity(&entries, KEY_TASK_REF, WHAT)?,
        responder_ref: decode_entity(&entries, KEY_RESPONDER_REF, WHAT)?,
        trap_claim_id: decode_entity(&entries, KEY_TRAP_CLAIM_ID, WHAT)?,
        step_hash,
        is_active: *is_active,
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
mod tests {
    use super::*;

    use crate::attempt_queue::AttemptQueue;
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
    };
    use crate::comm::{
        CommClaimValue, record_comm_inbound_stop, resolve_or_create_comm_party, run_comm_projector,
    };
    use crate::config::VaultConfig;
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::dreamer_runner::{
        DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
    };
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::llm::{
        DurableStepContext, TrapRef, consume_trap_signal, open_trap, trap_for_durable_wait,
        trap_park_owner,
    };
    use crate::registry::ENTITY_TYPE_TURN;
    use crate::task_verb::{
        TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition,
    };
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;

    const NOW: u64 = 1_772_600_000;
    const HUMAN_ADDRESS: &str = "alice@example.test";
    const OWN_ADDRESS: &str = "assistant@example.test";
    const STEP_HASH: [u8; 32] = [0x71; 32];

    struct HumanFixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        /// The first-party connector actor — the one identity the default
        /// policy manifest grants an Auto ceiling, so the create effects.
        /// Pinned (`0xE1`), so it is constructed explicitly rather than through
        /// the band-asserting generic helper.
        owner: EntityId,
        person: EntityId,
    }

    impl HumanFixture {
        fn open() -> Self {
            Self::open_with_grant(true)
        }

        fn open_with_grant(granted: bool) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
            let (owner, person) = seed_human_vault(&vault, granted);
            Self {
                _dir: dir,
                vault,
                owner,
                person,
            }
        }

        fn create_human_task(&self) -> EntityId {
            self.vault
                .memory(self.owner, EdgeActorClass::Agent)
                .tasks_create(
                    &TaskCreateSpec::new(Value::from("ask the person"), None, None, Some(NOW))
                        .with_assignee(TaskAssignee::Human {
                            actor_ref: self.person,
                        }),
                )
                .expect("human create effects")
                .task_ref
                .expect("an effected create mints one TASK")
        }

        fn cursor(&self, task_ref: EntityId) -> HumanTaskFollowupRecord {
            human_followup_record(&self.vault, task_ref)
                .expect("read cursor")
                .expect("a human task always has a cursor")
        }

        fn rewind_to(&self, record: &HumanTaskFollowupRecord, stage: HumanFollowupStage, due: u64) {
            let rewound = HumanTaskFollowupRecord {
                stage,
                next_due_at: Some(due),
                ..record.clone()
            };
            self.vault
                .with_write_txn(|wtxn| put_followup_record_in_txn(&self.vault, wtxn, &rewound))
                .expect("rewind cursor");
        }

        /// Scheduled connector sends carrying one exact idempotency key. This is
        /// the OUTBOUND effect count — what a duplicate wake must not double.
        fn scheduled_sends(&self, key: &str) -> usize {
            self.vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .into_iter()
                .filter(|task_ref| {
                    self.vault
                        .connector_send_task(task_ref)
                        .ok()
                        .flatten()
                        .is_some_and(|send| send.intent.idempotency_key.as_deref() == Some(key))
                })
                .count()
        }
    }

    /// Seeds one vault with the first-party owner and a person the vault
    /// ALREADY knows: a comm party (so the PERSON row carries its address),
    /// standing-reachable on a connected channel we hold an active sending
    /// identity and a live counterparty contact on.
    fn seed_human_vault(vault: &Vault, granted: bool) -> (EntityId, EntityId) {
        let owner = EntityId::from_bytes([0xE1; 16]).expect("first-party connector actor id");
        put_person(vault, owner);
        if granted {
            vault
                .mint_standing_outbound_grant(
                    &crate::test_util::entity(0x7B),
                    &GrantMintIntent {
                        principal_ref: owner.to_hex(),
                        origin_component_id: "tasks".to_owned(),
                        origin_action_id: "human.followup".to_owned(),
                        origin_receipt_ref: None,
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: HUMAN_FOLLOWUP_VERB.to_owned(),
                        },
                    },
                    NOW,
                )
                .expect("mint outbound grant");
        }
        let person = resolve_or_create_comm_party(vault, HUMAN_ADDRESS).expect("comm party");
        let identity_ref = active_email_identity(vault);
        vault
            .create_counterparty_contact(
                &crate::test_util::entity(0x7D),
                &CounterpartyContactRecord::user_introduction(identity_ref, HUMAN_ADDRESS, NOW)
                    .expect("contact record"),
            )
            .expect("create counterparty contact");
        (owner, person)
    }

    fn put_person(vault: &Vault, id: EntityId) {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )
            .expect("put actor");
    }

    fn active_email_identity(vault: &Vault) -> EntityId {
        let identity_ref = crate::test_util::entity(0x7C);
        vault
            .create_channel_identity(
                &identity_ref,
                &ChannelIdentity::requested(
                    "email",
                    OWN_ADDRESS,
                    SelfHeldShape::DedicatedAddress,
                    ChannelIdentityBinding::vault(1),
                    NOW,
                ),
            )
            .expect("create channel identity");
        vault
            .transition_channel_identity(
                &identity_ref,
                ChannelIdentityState::PendingFulfillment,
                Some(ChannelIdentityFulfillment::Api),
                NOW,
                None,
            )
            .expect("enter fulfillment");
        vault
            .transition_channel_identity(
                &identity_ref,
                ChannelIdentityState::Active,
                None,
                NOW,
                None,
            )
            .expect("activate the identity");
        identity_ref
    }

    /// Parks one step on a human answer and returns everything the resume path
    /// needs. The trap kind comes from the REAL mapping, so a regression in
    /// `trap_for_durable_wait` shows up here rather than silently parking a
    /// human wait as a consent trap.
    fn park_on_human(
        fixture: &HumanFixture,
        task_ref: EntityId,
        step_hash: [u8; 32],
    ) -> (
        crate::attempt_queue::AttemptId,
        TrapRef,
        HumanTaskWaitBinding,
    ) {
        let runner = DreamerRunnerStore::new(&fixture.vault);
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = runner
            .enqueue(EnqueueDreamerAttempt {
                attempt_type: "human-workflow-step".to_owned(),
                input: Value::from("step"),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("human-run".to_owned()),
                now: NOW,
            })
            .expect("enqueue the workflow step");
        let attempt_id = status.attempt.id;
        let ctx = DurableStepContext {
            vault: &fixture.vault,
            attempt_id,
            run_id: Some("human-run".to_owned()),
            envelope_actor: WriteActor::new(fixture.owner, EdgeActorClass::Agent),
            subject: fixture.person,
            pinned_config: None,
            deadline: None,
            now_ms: NOW,
        };
        let kind = trap_for_durable_wait(&human_input_wait(task_ref), step_hash);
        let trap = open_trap(&fixture.vault, &ctx, kind, step_hash, "human response")
            .expect("open the human trap");
        runner
            .park_attempt(ParkDreamerAttempt {
                attempt_id,
                reason: "human response".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: NOW,
            })
            .expect("park the suspended step");
        // Binding first, THEN the trap's own wait registration: a crash between
        // the two leaves a locatable binding on a `created` trap, which the
        // signal path still accepts.
        let binding = bind_human_wait(&fixture.vault, task_ref, fixture.person, &trap)
            .expect("bind the human wait");
        crate::llm::register_wait(&fixture.vault, &trap, NOW).expect("register the wait");
        (attempt_id, trap, binding)
    }

    /// The durable wait a workflow step raises when it asks a PERSON. Built
    /// exactly as the C9 dispatcher builds it, so the mapping under test is the
    /// production one.
    fn human_input_wait(task_ref: EntityId) -> crate::code_run::SelfDurableWait {
        crate::code_run::SelfDurableWait {
            wait_id: task_ref,
            effect: crate::code_run::SelfEffect::AskHuman,
            reason: crate::code_run::SelfDurableWaitReason::HumanInput,
            prompt: None,
        }
    }

    fn response(fixture: &HumanFixture, task_ref: EntityId, seed: u8) -> HumanResponseSignal {
        HumanResponseSignal {
            task_ref,
            responder_ref: fixture.person,
            surface_event_ref: crate::test_util::entity(seed),
            occurred_at: NOW + 10,
        }
    }

    fn open_test_trap(
        fixture: &HumanFixture,
        kind: DreamerTrapKind,
        step_hash: [u8; 32],
    ) -> TrapRef {
        let runner = DreamerRunnerStore::new(&fixture.vault);
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = runner
            .enqueue(EnqueueDreamerAttempt {
                attempt_type: "human-workflow-step".to_owned(),
                input: Value::from("step"),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("human-run".to_owned()),
                now: NOW,
            })
            .expect("enqueue the workflow step");
        let ctx = DurableStepContext {
            vault: &fixture.vault,
            attempt_id: status.attempt.id,
            run_id: Some("human-run".to_owned()),
            envelope_actor: WriteActor::new(fixture.owner, EdgeActorClass::Agent),
            subject: fixture.person,
            pinned_config: None,
            deadline: None,
            now_ms: NOW,
        };
        open_trap(&fixture.vault, &ctx, kind, step_hash, "human response").expect("open test trap")
    }

    // ── native-human resolution ─────────────────────────────────────────────

    /// A PERSON with an effective `comm.reachable_via` fact, one of our active
    /// channel identities on that channel, and a live contact IS a native
    /// route — no pack, no marketplace, no synthesized machine assignee.
    #[test]
    fn native_route_resolves_a_vault_known_person() {
        let fixture = HumanFixture::open();
        let route = resolve_native_human_route(&fixture.vault, fixture.person)
            .expect("a connected person is natively reachable");

        assert_eq!(route.person_ref, fixture.person);
        assert_eq!(route.channel, "email");
        assert_eq!(route.target, HUMAN_ADDRESS);
        assert_eq!(
            route.channel_identity_ref,
            crate::test_util::entity(0x7C),
            "the route names OUR sending identity, not the recipient"
        );
    }

    /// Every rejection keeps its own name: a non-person is not "unreachable",
    /// and a known-but-unreachable person is not "missing".
    #[test]
    fn unreachable_and_non_person_assignees_get_distinct_typed_errors() {
        let fixture = HumanFixture::open();
        let stranger = crate::test_util::entity(0x7E);
        put_person(&fixture.vault, stranger);
        let turn_ref = crate::test_util::entity(0x7F);
        fixture
            .vault
            .put_entity(
                &turn_ref,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"turn",
            )
            .expect("put turn");

        assert!(matches!(
            resolve_native_human_route(&fixture.vault, stranger),
            Err(HumanTaskError::NotNativelyReachable)
        ));
        assert!(matches!(
            resolve_native_human_route(&fixture.vault, turn_ref),
            Err(HumanTaskError::NotAPerson)
        ));
    }

    /// Standing `comm.*` state VETOES a route it can never invent. Both vetoes
    /// are exercised on the same connected person: the production STOP path
    /// (inbound event -> projector -> `comm.opt_out`), and the explicit
    /// `comm.reachable_via: false` fact, which is validated but has no
    /// projector rule yet and so is written directly.
    ///
    /// Writing comm standing state trips the gate's criticality floor under a
    /// live policy manifest, so these run on the legacy-manifest test vault —
    /// the resolver is the subject here, not the create ceiling.
    #[test]
    fn standing_comm_state_vetoes_an_otherwise_live_route() {
        for veto in ["opt_out", "not_reachable"] {
            let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
            let person = resolve_or_create_comm_party(&vault, HUMAN_ADDRESS).expect("comm party");
            let identity_ref = active_email_identity(&vault);
            vault
                .create_counterparty_contact(
                    &crate::test_util::entity(0x7D),
                    &CounterpartyContactRecord::user_introduction(identity_ref, HUMAN_ADDRESS, NOW)
                        .expect("contact record"),
                )
                .expect("create counterparty contact");
            assert!(
                resolve_native_human_route(&vault, person).is_ok(),
                "{veto}: the route is live before the veto"
            );

            if veto == "opt_out" {
                record_comm_inbound_stop(&vault, HUMAN_ADDRESS, "email", NOW)
                    .expect("record the STOP");
                run_comm_projector(&vault).expect("project the STOP into standing state");
            } else {
                vault
                    .put_claim(
                        &EntityId::now(),
                        &CommClaimValue::ReachableVia {
                            party_ref: person,
                            channel_class: "email".to_owned(),
                            reachable: false,
                        }
                        .claim_body(),
                        TimeRange { start: 1, end: 1 },
                        1,
                    )
                    .expect("record unreachability");
            }

            assert!(
                matches!(
                    resolve_native_human_route(&vault, person),
                    Err(HumanTaskError::NotNativelyReachable)
                ),
                "{veto}: the veto takes the channel away"
            );
        }
    }

    /// A revoked contact is not a route: the relationship that made the person
    /// natively reachable is the thing that ended.
    #[test]
    fn a_revoked_contact_removes_the_route() {
        let fixture = HumanFixture::open();
        assert!(resolve_native_human_route(&fixture.vault, fixture.person).is_ok());

        fixture
            .vault
            .revoke_counterparty_contact(&crate::test_util::entity(0x7D), NOW + 1)
            .expect("revoke the contact");

        assert!(matches!(
            resolve_native_human_route(&fixture.vault, fixture.person),
            Err(HumanTaskError::NotNativelyReachable)
        ));
    }

    // ── follow-up cursor ────────────────────────────────────────────────────

    /// The create opens the cursor and nothing else: the person is tracked, and
    /// no queue row anywhere carries this task's backlink.
    #[test]
    fn human_create_opens_a_tracking_cursor_and_no_attempt() {
        let fixture = HumanFixture::open();
        let receipt = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Agent)
            .tasks_create(
                &TaskCreateSpec::new(Value::from("ask the person"), None, None, Some(NOW))
                    .with_assignee(TaskAssignee::Human {
                        actor_ref: fixture.person,
                    }),
            )
            .expect("human create effects");
        let task_ref = receipt.task_ref.expect("an effected create mints one TASK");
        let cursor = fixture.cursor(task_ref);

        assert!(receipt.effected);
        assert_eq!(
            receipt.route,
            Some(crate::task_verb::TaskRouteOutcome::HumanFollowup {
                actor_ref: fixture.person
            })
        );
        assert_eq!(
            receipt
                .route
                .and_then(crate::task_verb::TaskRouteOutcome::local_attempt),
            None,
            "a person is not a worker"
        );
        assert_eq!(cursor.stage, HumanFollowupStage::Tracking);
        assert_eq!(cursor.assignee_ref, fixture.person);
        assert_eq!(cursor.reminders_sent, 0);
        assert_eq!(
            cursor.next_due_at,
            Some(NOW + REMINDER_AFTER_SECONDS),
            "tracking rests until the first nudge is due"
        );
        assert_eq!(
            AttemptQueue::new(&fixture.vault)
                .list()
                .expect("list")
                .len(),
            0
        );
    }

    /// A cursor that is not yet due is not work. The driver must not nudge a
    /// person the moment their task is created.
    #[test]
    fn a_cursor_before_its_due_time_dispatches_nothing() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();

        let dispatched = HumanTaskFollowupDriver::new(&fixture.vault)
            .run_due(NOW + 1, 8)
            .expect("run due");

        assert!(dispatched.is_empty());
        assert_eq!(fixture.cursor(task_ref).stage, HumanFollowupStage::Tracking);
    }

    /// The ladder walks track → remind → digest → escalate, and only the
    /// repeatable stage advances its generation.
    #[test]
    fn followup_walks_the_ladder_and_only_escalation_regenerates() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let driver = HumanTaskFollowupDriver::new(&fixture.vault);
        let mut seen = Vec::new();

        for _ in 0..4 {
            let due = fixture
                .cursor(task_ref)
                .next_due_at
                .expect("an open loop is always due later");
            let dispatched = driver.run_due(due, 8).expect("run due");
            assert_eq!(dispatched.len(), 1);
            assert_eq!(dispatched[0].task_ref, task_ref);
            assert_eq!(dispatched[0].stage, fixture.cursor(task_ref).stage);
            seen.push(dispatched[0].stage_token.clone());
        }

        assert_eq!(
            seen,
            vec![
                "human_reminder:0".to_owned(),
                "human_digest:0".to_owned(),
                "human_escalation:0".to_owned(),
                "human_escalation:1".to_owned(),
            ],
            "the generation rides inside the stage token, and only where \
             repetition is intentional"
        );
        let cursor = fixture.cursor(task_ref);
        assert_eq!(cursor.stage, HumanFollowupStage::EscalationDue);
        assert_eq!(cursor.reminders_sent, 4);
        assert!(cursor.last_receipt_ref.is_some());
    }

    /// The crash window between "outbound scheduled" and "cursor advanced":
    /// the next pass re-drives the SAME `(task_ref, stage)` key, and the shared
    /// follow-up namespace collapses it onto one outbound effect.
    #[test]
    fn a_replayed_stage_collapses_onto_one_outbound_effect() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let driver = HumanTaskFollowupDriver::new(&fixture.vault);
        let due = NOW + REMINDER_AFTER_SECONDS;
        let key = task_follow_up_dedupe_key(task_ref, "human_reminder:0");

        let first = driver.run_due(due, 8).expect("first pass");
        // Exactly the state a crash after the schedule would leave behind.
        fixture.rewind_to(&fixture.cursor(task_ref), HumanFollowupStage::Tracking, due);
        let replay = driver.run_due(due, 8).expect("replayed pass");

        assert_eq!(first.len(), 1);
        assert_eq!(replay.len(), 1);
        assert_eq!(first[0].stage_token, replay[0].stage_token);
        assert_eq!(first[0].intent_ref, replay[0].intent_ref);
        assert_eq!(
            fixture.scheduled_sends(&key),
            1,
            "a replayed stage re-notifies nobody"
        );
    }

    /// The ONE-1699 expiry stage and the ONE-1708 human stages share one
    /// namespace, so two follow-up families can never collide on one task.
    #[test]
    fn human_stages_share_the_one_follow_up_namespace() {
        let task_ref = crate::test_util::entity(0x6A);
        let reminder = task_follow_up_dedupe_key(task_ref, "human_reminder:0");

        assert!(reminder.starts_with("tasks.followup.v1:"));
        assert_ne!(
            reminder,
            task_follow_up_dedupe_key(
                task_ref,
                crate::task_verb::TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED
            )
        );
        assert_ne!(
            reminder,
            task_follow_up_dedupe_key(task_ref, "human_reminder:1")
        );
    }

    /// A delivery the pipeline declines to push is an outbound RECEIPT outcome.
    /// The cursor has no failure state to move into and must not invent one:
    /// it advances exactly as it would on a clean send.
    #[test]
    fn a_declined_delivery_stays_a_receipt_outcome_and_never_fails_the_cursor() {
        // No standing outbound grant: the gate declines, which is precisely the
        // "held / degraded / suppressed" family ARCH-0046 O3 receipts.
        let fixture = HumanFixture::open_with_grant(false);
        let task_ref = fixture.create_human_task();

        let dispatched = HumanTaskFollowupDriver::new(&fixture.vault)
            .run_due(NOW + REMINDER_AFTER_SECONDS, 8)
            .expect("run due");
        let cursor = fixture.cursor(task_ref);

        assert_eq!(dispatched.len(), 1);
        assert_ne!(
            dispatched[0].outcome, "delivered_to_channel",
            "the pipeline declined this one"
        );
        assert_eq!(cursor.stage, HumanFollowupStage::ReminderDue);
        assert_eq!(cursor.completed_at, None);
        assert_eq!(
            cursor.last_receipt_ref.as_deref(),
            Some(dispatched[0].intent_ref.as_str())
        );
    }

    /// The authoritative synced fact closes the loop: once the TASK settles,
    /// the cursor completes and the nudging stops for good.
    #[test]
    fn a_settled_task_completes_its_cursor_and_stops_nudging() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let result_ref = crate::test_util::entity(0x6B);
        fixture
            .vault
            .put_entity(
                &result_ref,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"answer",
            )
            .expect("put result");
        fixture
            .vault
            .memory(fixture.person, EdgeActorClass::Agent)
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: NOW + 5,
                },
            )
            .expect("the person's answer settles the task");

        let driver = HumanTaskFollowupDriver::new(&fixture.vault);
        let at = NOW + REMINDER_AFTER_SECONDS;
        let dispatched = driver.run_due(at, 8).expect("run due");
        let cursor = fixture.cursor(task_ref);

        assert!(dispatched.is_empty());
        assert_eq!(cursor.stage, HumanFollowupStage::Completed);
        assert_eq!(cursor.completed_at, Some(at));
        assert_eq!(cursor.next_due_at, None);
        assert!(
            driver
                .run_due(at + ESCALATION_AFTER_SECONDS, 8)
                .expect("later pass")
                .is_empty()
        );
    }

    /// The cursor is derived scheduler state: losing it costs a re-walk of the
    /// synced TASK facts, never a second truth or a registry byte.
    #[test]
    fn a_lost_cursor_rebuilds_from_the_synced_task_fact() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        fixture
            .vault
            .with_write_txn(|wtxn| {
                fixture
                    .vault
                    .store
                    .vault_meta
                    .delete(wtxn, followup_key(task_ref).as_slice())?;
                Ok(())
            })
            .expect("drop the cursor");
        assert!(
            human_followup_record(&fixture.vault, task_ref)
                .expect("read cursor")
                .is_none()
        );

        let rebuilt = HumanTaskFollowupDriver::new(&fixture.vault)
            .rebuild_cursors(NOW + 1)
            .expect("rebuild");

        assert_eq!(rebuilt, 1);
        assert_eq!(fixture.cursor(task_ref).assignee_ref, fixture.person);
        assert_eq!(
            HumanTaskFollowupDriver::new(&fixture.vault)
                .rebuild_cursors(NOW + 2)
                .expect("second rebuild"),
            0,
            "a rebuild never rewinds live nudging state"
        );
    }

    /// Only human-assigned tasks get a cursor. A dreamer task is realized by a
    /// job and has nothing to follow up on — and a rebuild walking every TASK
    /// row must not invent one for it.
    #[test]
    fn non_human_lanes_get_no_cursor() {
        let fixture = HumanFixture::open();
        let human_task = fixture.create_human_task();
        let dreamer_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec::new(
                Value::from("ordinary"),
                None,
                None,
                Some(NOW),
            ))
            .expect("dreamer create")
            .task_ref
            .expect("task ref");

        assert!(
            human_followup_record(&fixture.vault, dreamer_task)
                .expect("read cursor")
                .is_none()
        );
        assert_eq!(
            human_followup_records(&fixture.vault)
                .expect("all cursors")
                .into_iter()
                .map(|record| record.task_ref)
                .collect::<Vec<_>>(),
            vec![human_task]
        );
        assert_eq!(
            HumanTaskFollowupDriver::new(&fixture.vault)
                .rebuild_cursors(NOW + 1)
                .expect("rebuild"),
            0,
            "a rebuild invents no cursor for a realized lane"
        );
    }

    // ── C9 wait binding + response signal ───────────────────────────────────

    /// `HumanInput` is the only wait that maps to the human trap; the consent
    /// flavors keep theirs.
    #[test]
    fn only_human_input_maps_to_the_human_response_trap() {
        use crate::code_run::{SelfDurableWait, SelfDurableWaitReason, SelfEffect};

        let kind = |reason| {
            trap_for_durable_wait(
                &SelfDurableWait {
                    wait_id: crate::test_util::entity(0x8F),
                    effect: SelfEffect::AskHuman,
                    reason,
                    prompt: None,
                },
                STEP_HASH,
            )
        };

        assert_eq!(
            kind(SelfDurableWaitReason::HumanInput),
            DreamerTrapKind::HumanResponse
        );
        assert_eq!(
            kind(SelfDurableWaitReason::DestructiveEffect),
            DreamerTrapKind::Consent
        );
        assert_eq!(
            kind(SelfDurableWaitReason::OutboundEffect),
            DreamerTrapKind::Consent
        );
        assert_eq!(
            kind(SelfDurableWaitReason::PeerResult),
            DreamerTrapKind::PeerResult
        );
    }

    #[test]
    fn ask_human_dispatch_binds_the_real_task_at_wait_mint_time() {
        use crate::code_run::{
            HostSelfDispatcher, SelfAskHumanCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
        };

        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let trap = open_test_trap(&fixture, DreamerTrapKind::HumanResponse, STEP_HASH);
        let dispatcher = HostSelfDispatcher::for_human_task(
            &fixture.vault,
            WriteActor::new(fixture.owner, EdgeActorClass::Agent),
            "human-task-run",
            task_ref,
            trap,
        )
        .expect("bind dispatcher to the human task");

        let outcome = dispatcher
            .dispatch(SelfCall::AskHuman(SelfAskHumanCall::new(
                "Please answer this task",
            )))
            .expect("dispatch self.ask_human");
        let SelfDispatchOutcome::DurableWait(wait) = outcome else {
            panic!("self.ask_human must mint a durable wait");
        };

        assert_eq!(wait.wait_id, task_ref);
        assert_eq!(
            human_wait_binding(&fixture.vault, task_ref).expect("read wait binding"),
            Some(HumanTaskWaitBinding {
                task_ref,
                responder_ref: fixture.person,
                trap_claim_id: trap.trap_claim_id,
                step_hash: trap.step_hash,
                is_active: true,
            })
        );
    }

    /// The bound person's answer resumes the parked branch exactly once.
    #[test]
    fn the_bound_person_resumes_the_parked_step() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        let runner = DreamerRunnerStore::new(&fixture.vault);

        assert!(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_some(),
            "the step is suspended before the response"
        );
        signal_human_response(
            &fixture.vault,
            &binding,
            fixture.person,
            &response(&fixture, task_ref, 0x6C),
        )
        .expect("the bound person may signal");
        let resumed = consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 11)
            .expect("consume resumes the branch");

        assert_eq!(resumed, attempt_id);
        assert!(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_none()
        );
    }

    /// A response from the wrong actor, for a different task, or against a
    /// stale step hash signals NOTHING — and leaves the step parked.
    #[test]
    fn wrong_responder_task_or_step_hash_never_signals() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (attempt_id, _trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        let runner = DreamerRunnerStore::new(&fixture.vault);
        let other_person = crate::test_util::entity(0x6D);
        put_person(&fixture.vault, other_person);

        let wrong_responder = HumanResponseSignal {
            responder_ref: other_person,
            ..response(&fixture, task_ref, 0x6E)
        };
        let wrong_task = HumanResponseSignal {
            task_ref: crate::test_util::entity(0x6F),
            ..response(&fixture, task_ref, 0x7A)
        };
        let stale_step = HumanTaskWaitBinding {
            step_hash: [0x99; 32],
            ..binding
        };

        for (case, error) in [
            (
                "wrong responder",
                signal_human_response(&fixture.vault, &binding, fixture.person, &wrong_responder),
            ),
            (
                "wrong task",
                signal_human_response(&fixture.vault, &binding, fixture.person, &wrong_task),
            ),
            (
                "stale step hash",
                signal_human_response(
                    &fixture.vault,
                    &stale_step,
                    fixture.person,
                    &response(&fixture, task_ref, 0x8A),
                ),
            ),
        ] {
            assert!(
                matches!(error, Err(HumanTaskError::UnboundResponse)),
                "{case} must be refused"
            );
        }
        assert!(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_some(),
            "no refused response may resume the branch"
        );
    }

    #[test]
    fn forged_caller_identity_cannot_signal_a_bound_human_wait() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (_, _, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        let intruder = crate::test_util::entity(0x91);
        put_person(&fixture.vault, intruder);
        let signal = response(&fixture, task_ref, 0x92);

        let error = signal_human_response(&fixture.vault, &binding, intruder, &signal)
            .expect_err("a forged caller token must not signal");

        assert!(matches!(error, HumanTaskError::UnboundResponse));
        assert!(
            wait_signal_marker(&fixture.vault, binding.trap_claim_id)
                .expect("read signal marker")
                .is_none(),
            "the payload's responder field cannot substitute for verified caller identity"
        );
    }

    #[test]
    fn inactive_persisted_binding_cannot_signal() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (_, _, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        assert!(release_human_wait(&fixture.vault, task_ref).expect("release wait"));
        let stored = stored_human_wait_binding(&fixture.vault, task_ref)
            .expect("read retired binding")
            .expect("release persists a tombstone");

        assert!(!stored.is_active);
        assert!(matches!(
            signal_human_response(
                &fixture.vault,
                &binding,
                fixture.person,
                &response(&fixture, task_ref, 0x93),
            ),
            Err(HumanTaskError::UnboundResponse)
        ));
    }

    /// Re-delivery of the SAME response is idempotent, and the trap consumes
    /// once: the second consume finds no sent signal to absorb.
    #[test]
    fn duplicate_delivery_of_one_response_resumes_once() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        let runner = DreamerRunnerStore::new(&fixture.vault);
        let signal = response(&fixture, task_ref, 0x8B);

        let first = signal_human_response(&fixture.vault, &binding, fixture.person, &signal)
            .expect("first");
        let replay = signal_human_response(&fixture.vault, &binding, fixture.person, &signal)
            .expect("replay");

        assert_eq!(first, replay, "a re-delivered response returns its signal");
        assert_eq!(
            consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 11).expect("consume"),
            attempt_id
        );
        assert!(consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 12).is_err());
        assert!(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_none()
        );
    }

    /// For ANY interleaving of foreign, duplicate and valid response events the
    /// bound branch resumes at most once, and never before the first valid one.
    #[test]
    fn any_response_sequence_resumes_at_most_once_and_never_early() {
        #[derive(Clone, Copy)]
        enum Event {
            Foreign,
            Valid,
            Duplicate,
        }
        let sequences: [&[Event]; 6] = [
            &[Event::Foreign, Event::Foreign],
            &[Event::Valid],
            &[Event::Valid, Event::Duplicate],
            &[Event::Duplicate, Event::Valid, Event::Duplicate],
            &[Event::Foreign, Event::Valid, Event::Foreign],
            &[Event::Valid, Event::Valid, Event::Duplicate, Event::Foreign],
        ];

        for (index, sequence) in sequences.iter().enumerate() {
            let fixture = HumanFixture::open();
            let task_ref = fixture.create_human_task();
            let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
            let runner = DreamerRunnerStore::new(&fixture.vault);
            let foreign_person = crate::test_util::entity(0x8C);
            put_person(&fixture.vault, foreign_person);
            let valid = response(&fixture, task_ref, 0x8D);
            let mut resumes = 0;
            let mut seen_valid = false;

            for event in sequence.iter().copied() {
                let signalled = match event {
                    Event::Foreign => signal_human_response(
                        &fixture.vault,
                        &binding,
                        foreign_person,
                        &HumanResponseSignal {
                            responder_ref: foreign_person,
                            ..valid
                        },
                    )
                    .is_ok(),
                    Event::Valid | Event::Duplicate => {
                        signal_human_response(&fixture.vault, &binding, fixture.person, &valid)
                            .is_ok()
                    }
                };
                if matches!(event, Event::Valid | Event::Duplicate) && signalled {
                    seen_valid = true;
                }
                assert!(
                    !signalled || seen_valid,
                    "sequence {index}: only a valid response may signal"
                );
                if consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 20).is_ok() {
                    resumes += 1;
                    assert!(
                        seen_valid,
                        "sequence {index}: resumed before a valid response"
                    );
                }
            }

            assert!(resumes <= 1, "sequence {index}: resumed {resumes} times");
            assert_eq!(
                resumes,
                usize::from(seen_valid),
                "sequence {index}: a valid response resumes exactly once"
            );
            assert_eq!(
                runner
                    .parked_attempt(attempt_id)
                    .expect("read parked row")
                    .is_some(),
                !seen_valid
            );
        }
    }

    /// A wait may only bind to a trap opened for a human answer.
    #[test]
    fn a_non_human_trap_cannot_carry_a_human_wait() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let (_, trap, _) = park_on_human(&fixture, task_ref, STEP_HASH);
        let consent_trap = TrapRef {
            kind: DreamerTrapKind::Consent,
            ..trap
        };

        assert!(matches!(
            bind_human_wait(&fixture.vault, task_ref, fixture.person, &consent_trap),
            Err(HumanTaskError::UnboundResponse)
        ));
    }

    #[test]
    fn signal_refuses_a_binding_over_a_persisted_non_human_trap() {
        let fixture = HumanFixture::open();
        let task_ref = fixture.create_human_task();
        let consent_trap = open_test_trap(&fixture, DreamerTrapKind::Consent, STEP_HASH);
        let forged_human_ref = TrapRef {
            kind: DreamerTrapKind::HumanResponse,
            ..consent_trap
        };
        let binding = bind_human_wait(&fixture.vault, task_ref, fixture.person, &forged_human_ref)
            .expect("the forged handle passes the caller-side kind check");

        let error = signal_human_response(
            &fixture.vault,
            &binding,
            fixture.person,
            &response(&fixture, task_ref, 0x70),
        )
        .expect_err("the persisted consent trap must refuse a human response");

        assert!(matches!(error, HumanTaskError::UnboundResponse));
    }

    /// Both durable halves survive a REAL restart — the vault is dropped and
    /// reopened, so only what LMDB persisted can carry them across — and the
    /// answer that arrives afterwards resumes the ORIGINAL branch.
    #[test]
    fn parked_wait_and_cursor_survive_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (task_ref, person, attempt_id, trap, binding) = {
            let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
            let (owner, person) = seed_human_vault(&vault, true);
            let fixture = HumanFixture {
                _dir: tempfile::tempdir().expect("placeholder tempdir"),
                vault,
                owner,
                person,
            };
            let task_ref = fixture.create_human_task();
            let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
            (task_ref, person, attempt_id, trap, binding)
        };

        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen vault");
        let runner = DreamerRunnerStore::new(&vault);
        let cursor = human_followup_record(&vault, task_ref)
            .expect("read cursor")
            .expect("the cursor survives reopen");

        assert_eq!(cursor.stage, HumanFollowupStage::Tracking);
        assert_eq!(
            human_wait_binding(&vault, task_ref).expect("read binding"),
            Some(binding)
        );
        assert!(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_some()
        );

        signal_human_response(
            &vault,
            &binding,
            person,
            &HumanResponseSignal {
                task_ref,
                responder_ref: person,
                surface_event_ref: crate::test_util::entity(0x8E),
                occurred_at: NOW + 30,
            },
        )
        .expect("the person answers after the restart");

        assert_eq!(
            consume_trap_signal(&vault, &runner, &trap, NOW + 31).expect("consume"),
            attempt_id
        );
        assert!(release_human_wait(&vault, task_ref).expect("release"));
        assert!(
            human_wait_binding(&vault, task_ref)
                .expect("read binding")
                .is_none()
        );
    }
}
