//! Native-human routing, follow-up cursor lifecycle and the wake driver.

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
use crate::error::Result;
use crate::memory::OutboundDraftInput;
use crate::outbound::outbound_verb_contract;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::task_verb::{
    task_create_owner, task_follow_up_dedupe_key, task_human_assignee, task_is_terminal,
};

use super::model::{
    FOLLOWUP_WAKE_LIMIT, HUMAN_FOLLOWUP_VERB, HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION,
    HumanFollowupDispatch, HumanFollowupStage, HumanTaskError, HumanTaskFollowupRecord,
    HumanTaskResult, NativeHumanRoute, REBUILD_PAGE, REMINDER_AFTER_SECONDS,
};
use super::storage::{
    HUMAN_TASK_FOLLOWUP_KEY_PREFIX, KEY_PARTY_KEY, decode_followup_record, followup_record_in_txn,
    put_followup_record_in_txn,
};

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

// ── follow-up cursor ────────────────────────────────────────────────────────

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
            CommClaimValue::OptOut {
                channel_class: Some(channel_class),
                ..
            }
            | CommClaimValue::ReachableVia {
                channel_class,
                reachable: false,
                ..
            } => {
                vetoed.insert(channel_class);
            }
            // ONE-1752 fan-out only. This helper answers a PER-CLASS question,
            // and neither a party-wide (channel-less) opt-out nor a send
            // override names a class, so neither contributes a row here. Every
            // channel-scoped opt-out head vetoes exactly as before.
            CommClaimValue::OptOut { .. }
            | CommClaimValue::SendOverride { .. }
            | CommClaimValue::ReachableVia { .. }
            | CommClaimValue::LastTouch { .. }
            | CommClaimValue::ThreadMember { .. } => {}
        }
    }
    Ok(vetoed)
}

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
