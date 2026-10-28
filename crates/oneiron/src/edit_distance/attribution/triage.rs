//! The triage packet a persistent failure mints, and the one owner-inbox
//! escalation that carries it (ARCH-0056 §5 "Persistent failure → the triage
//! packet", r5; FIX 7825).
//!
//! The packet is refs, never copied text: the failing receipts and their Δ
//! refs, the AgentDefinition behind them, the skills at the version each run
//! loaded, the executor stamps, and what changed last across those receipts.
//! [`TriagePacket`] is its stable JSON shape, so it can be handed as it is to
//! any debugging agent; the fix rides the normal propose lane.
//!
//! One escalation per subject, scope and signal: an Ask NOTIFICATION in each
//! live owner's inbox, keyed by all four, so the row is its own
//! open-escalation record. A re-trigger rewrites that row's packet and puts
//! it back in front of an owner who had cleared it; the same trigger again
//! writes nothing, and a row its owner deleted stays deleted.
//!
//! Routing by publisher (r5): the packet names its artifact's publisher, and
//! every packet reaches the owner's inbox. A shipped artifact's issue
//! signature is not emitted here: the ED-08 signature door needs a
//! registered model stack and a numbered artifact version, which these
//! receipts do not carry.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::cells::charges_subject;
use super::evidence_judge::amendment_judgments_in_txn;
use super::stored::{EVIDENCE, EVIDENCE_ROW_LABEL, hex_entity};
use super::taxonomy::AmendmentJudgment;
use super::worsening::outcomes_in_txn;
use crate::Vault;
use crate::claim::ClaimSource;
use crate::edit_distance::delta::amendment_recorded_in_txn;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_NOTIFICATION};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Producer name of a worsening escalation.
const NOTIFICATION_PRODUCER_WORSENING: &str = "edit_distance.worsening";

/// Newest failing receipts a packet cites. Canon pins no bound; sixteen
/// keeps one packet one inbox row.
const MAX_TRIAGE_RECEIPTS: usize = 16;

/// Which worsening fired, with the numbers it fired on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorseningSignal {
    /// The `learning.edit_cost` cell's mean rose past the spread its earlier
    /// head held.
    #[serde(rename_all = "camelCase")]
    EditCostClimbing {
        /// The head the climb is measured from.
        previous_head: String,
        previous_mean: f64,
        previous_spread: f64,
        /// The head now.
        current_head: String,
        current_mean: f64,
        current_spread: f64,
    },
    /// The subject's newest outcomes in the scope were rejected `length`
    /// times in a row, the newest on receipt `newest`.
    #[serde(rename_all = "camelCase")]
    RejectionRun { length: u32, newest: String },
    /// The reliability floor contract's open quarantine proposal: the skill's
    /// posterior lower bound fell under the floor.
    #[serde(rename_all = "camelCase")]
    ReliabilityFloor {
        proposal: String,
        /// The executor whose cell crossed; `None` for the skill-wide check.
        executor: Option<String>,
        lower_bound: f32,
        floor: f32,
        crossed_at: u64,
    },
}

impl WorseningSignal {
    /// The signal's stable token, one part of its escalation's key.
    const fn token(&self) -> &'static str {
        match self {
            Self::EditCostClimbing { .. } => "edit_cost_climbing",
            Self::RejectionRun { .. } => "rejection_run",
            Self::ReliabilityFloor { .. } => "reliability_floor",
        }
    }

    /// What fired it: the head now, the newest rejected receipt, or the
    /// proposal. A re-trigger names another.
    fn trigger(&self) -> &str {
        match self {
            Self::EditCostClimbing { current_head, .. } => current_head.as_str(),
            Self::RejectionRun { newest, .. } => newest.as_str(),
            Self::ReliabilityFloor { proposal, .. } => proposal.as_str(),
        }
    }
}

/// What the subject of a packet is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageSubject {
    /// A SKILL a `skill_defect` share charged.
    Skill,
    /// An actor an `execution_lapse` share charged.
    Actor,
}

/// Who published the subject (ARCH-0056 r5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPublisher {
    /// Owner-authored, or made in the vault: the owner fixes it.
    Owner,
    /// A shipped or system artifact: an imported skill, or a seeded `sys.*`
    /// agent definition.
    Shipped,
}

/// One failing receipt, as refs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageReceipt {
    /// The judged receipt.
    pub receipt: String,
    /// The key of its Δ in the side-ledger
    /// ([`amendment_delta`](crate::edit_distance::delta::amendment_delta)
    /// reads it); `None` when none is recorded, as for a rejection.
    pub delta_ref: Option<String>,
    pub rejected: bool,
    /// The judgment's edit mass.
    pub d_norm: f32,
    pub at: u64,
    /// The terminal pack receipt of the attempt the proposal came from.
    pub attempt: Option<String>,
    /// The drafting executor at revision; `None` when unknown.
    pub executor: Option<String>,
    /// The judge revision the judgment stands on; `None` for the rule tier.
    pub judge: Option<String>,
    /// The skill the run loaded, at version.
    pub skill: Option<SkillAtVersion>,
}

/// A skill at a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAtVersion {
    /// The SKILL entity.
    pub skill: String,
    /// Its stable name.
    pub skill_id: String,
    pub version: String,
    /// Whether the version was read through the attempt's pack receipt, its
    /// pinned revision where the manifest pinned one; `false` is the record
    /// as it stands now.
    pub via_attempt: bool,
}

/// An AgentDefinition behind the failing runs: the system-prompt ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDefinitionRef {
    /// The AGENT_DEF entity.
    pub definition: String,
    pub agent_id: String,
    /// Its version as it stands now; the runs may have used an earlier one.
    pub version: String,
    /// The seeded `sys.*` id of a shipped definition.
    pub logical_id: Option<String>,
}

/// One value that changed between two failing receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentChange {
    /// The first receipt with the new value.
    pub receipt: String,
    pub before: String,
    pub after: String,
    pub at: u64,
}

/// What changed last across the failing receipts in the learning window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentChanges {
    /// Where the window starts: one learning half-life before the packet.
    pub window_from: u64,
    /// The last skill revision, as `skill_id@version`.
    pub skill_revision: Option<RecentChange>,
    /// The last executor change.
    pub executor: Option<RecentChange>,
}

/// The triage packet one worsening escalation carries (ARCH-0056 §5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriagePacket {
    /// The signal that fired and its numbers.
    pub signal: WorseningSignal,
    /// The skill or actor it is about.
    pub subject: String,
    pub subject_kind: TriageSubject,
    /// The consent scope the failing receipts share.
    pub scope: String,
    pub publisher: ArtifactPublisher,
    /// The newest failing receipts, oldest first: the judged receipts in this
    /// scope that charge the subject or left an amended or rejected outcome
    /// on its cells.
    pub receipts: Vec<TriageReceipt>,
    pub agent_definitions: Vec<AgentDefinitionRef>,
    /// Each skill at each version the receipts name.
    pub skills: Vec<SkillAtVersion>,
    /// Each executor stamp the receipts name.
    pub executors: Vec<String>,
    pub recent_changes: RecentChanges,
    /// When the outcome that fired it landed.
    pub at: u64,
}

/// The packet `signal` mints for `subject` in `scope` at `at`, read from the
/// judgment ledger, the subject's cells and the records they name in `txn`.
///
/// # Errors
///
/// Storage errors; an undecodable row.
pub(super) fn packet_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    subject_kind: TriageSubject,
    scope: &str,
    at: u64,
    signal: WorseningSignal,
) -> Result<TriagePacket> {
    // A count-only outcome charges nobody, yet it is the subject's failure.
    let marked: BTreeSet<String> = outcomes_in_txn(vault, txn, &subject, scope)?
        .into_iter()
        .filter(|outcome| outcome.failed())
        .map(|outcome| outcome.receipt)
        .collect();
    let mut failing: Vec<AmendmentJudgment> = amendment_judgments_in_txn(vault, txn)?
        .into_iter()
        .map(|(row, _)| row)
        .filter(|row| {
            row.scope == scope
                && (charges_subject(row, &subject) || marked.contains(&row.receipt_id))
        })
        .collect();
    failing.sort_by(|a, b| (a.at, &a.receipt_id).cmp(&(b.at, &b.receipt_id)));
    let skip = failing.len().saturating_sub(MAX_TRIAGE_RECEIPTS);
    let mut actors = Vec::new();
    if subject_kind == TriageSubject::Actor {
        actors.push(subject);
    }
    let mut receipts = Vec::new();
    for row in failing.into_iter().skip(skip) {
        let evidence = EVIDENCE.get(&vault.store, txn, &row.receipt_id)?;
        let mut skill = (subject_kind == TriageSubject::Skill).then_some(subject);
        if let Some(evidence) = &evidence {
            let actor = hex_entity(&evidence.actor, EVIDENCE_ROW_LABEL)?;
            if !actors.contains(&actor) {
                actors.push(actor);
            }
            if skill.is_none()
                && let Some(named) = evidence.skill.as_deref()
            {
                skill = Some(hex_entity(named, EVIDENCE_ROW_LABEL)?);
            }
        }
        let skill = match skill {
            Some(skill) => {
                skill_at_version_in_txn(vault, txn, skill, row.attempt_receipt.as_deref())?
            }
            None => None,
        };
        receipts.push(TriageReceipt {
            delta_ref: amendment_recorded_in_txn(vault, txn, &row.receipt_id)?
                .then(|| row.receipt_id.clone()),
            receipt: row.receipt_id,
            rejected: row.rejected,
            d_norm: row.d_norm,
            at: row.at,
            attempt: row.attempt_receipt,
            executor: row.executor,
            judge: row.judge,
            skill,
        });
    }
    let mut agent_definitions = Vec::new();
    for actor in &actors {
        agent_definitions.extend(agent_definition_in_txn(vault, txn, actor)?);
    }
    let publisher = publisher_in_txn(vault, txn, subject, subject_kind, &agent_definitions)?;
    let mut skills: Vec<SkillAtVersion> = Vec::new();
    let mut executors: Vec<String> = Vec::new();
    for receipt in &receipts {
        if let Some(skill) = &receipt.skill
            && !skills.contains(skill)
        {
            skills.push(skill.clone());
        }
        if let Some(executor) = &receipt.executor
            && !executors.contains(executor)
        {
            executors.push(executor.clone());
        }
    }
    let half_life = crate::learning::project::window_in_txn(vault, txn)?.half_life;
    let recent_changes = recent_changes(&receipts, at.saturating_sub(half_life));
    Ok(TriagePacket {
        signal,
        subject: subject.to_hex(),
        subject_kind,
        scope: scope.to_owned(),
        publisher,
        receipts,
        agent_definitions,
        skills,
        executors,
        recent_changes,
        at,
    })
}

/// Raises or brings up to date `packet`'s escalation in each live owner's
/// inbox, in the caller's write. A row already carrying this trigger is left
/// as it is; one carrying an earlier trigger takes this packet and comes back
/// unseen for its owner.
///
/// # Errors
///
/// Storage errors; a packet that does not encode.
pub(super) fn escalate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    packet: &TriagePacket,
) -> Result<()> {
    let detail = serde_json::to_string(packet)
        .map_err(|_| Error::InvariantViolation("triage packet encode"))?;
    let mut subject_refs = Vec::new();
    for reference in std::iter::once(&packet.subject)
        .chain(
            packet
                .agent_definitions
                .iter()
                .map(|agent| &agent.definition),
        )
        .chain(packet.skills.iter().map(|skill| &skill.skill))
    {
        let id = EntityId::from_hex(reference)?;
        if !subject_refs.contains(&id) {
            subject_refs.push(id);
        }
    }
    for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
        let owner_ref = owner.to_hex();
        let event = NotificationEvent {
            kind: NotificationKind::Ask,
            source: NotificationSource {
                producer: NOTIFICATION_PRODUCER_WORSENING.to_owned(),
                // The scope goes last: it is the one part that may hold a
                // separator.
                event: format!(
                    "{}:{}:{owner_ref}:{}",
                    packet.signal.token(),
                    packet.subject,
                    packet.scope
                ),
                result: Some(packet.subject.clone()),
                detail: Some(detail.clone()),
                ..NotificationSource::default()
            },
            subject_refs: subject_refs.clone(),
            recipient: Some(owner),
            created_at: packet.at,
            origin_conversation: None,
        };
        let id = vault.record_notification_in_txn(txn, &event)?;
        // A deleted escalation stays deleted.
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*txn, &id)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let held = body
            .source
            .detail
            .as_deref()
            .and_then(|held| serde_json::from_str::<TriagePacket>(held).ok());
        if held.is_some_and(|held| held.signal.trigger() == packet.signal.trigger()) {
            continue;
        }
        body.source.detail = Some(detail.clone());
        body.subject_refs = subject_refs.iter().map(EntityId::to_hex).collect();
        body.seen_by.remove(&owner_ref);
        body.acked_by.remove(&owner_ref);
        vault.put_notification_in_txn(txn, &id, &body)?;
    }
    Ok(())
}

/// The triage packet the worsening escalation `id` carries; `None` when `id`
/// is not a live worsening escalation.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a packet that does not
/// decode.
pub fn triage_packet(vault: &Vault, id: &EntityId) -> Result<Option<TriagePacket>> {
    let txn = vault.store.env.read_txn()?;
    let LiveEntityRow::Live { entity_type, body } = live_entity_row_in_txn(&vault.store, &txn, id)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_NOTIFICATION {
        return Ok(None);
    }
    let body = decode_notification_body(&body)?;
    if body.source.producer != NOTIFICATION_PRODUCER_WORSENING {
        return Ok(None);
    }
    body.source
        .detail
        .as_deref()
        .map(|packet| {
            serde_json::from_str(packet).map_err(|_| Error::CorruptedIndex("triage packet"))
        })
        .transpose()
}

/// `skill` at the version the run behind `attempt` loaded, or as it stands
/// when no attempt names one; `None` once the skill is gone.
fn skill_at_version_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    attempt: Option<&str>,
) -> Result<Option<SkillAtVersion>> {
    let at_version = |record: crate::skill::SkillRecord, via_attempt| SkillAtVersion {
        skill: skill.to_hex(),
        skill_id: record.skill_id,
        version: record.version,
        via_attempt,
    };
    if let Some(attempt) = attempt
        && let Some(receipt) =
            crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
        && let Some(record) =
            crate::skill::receipt_skill_record_in_txn(vault, txn, &receipt, &skill)?
    {
        return Ok(Some(at_version(record, true)));
    }
    Ok(vault
        .get_skill_record_in_txn(txn, &skill)?
        .map(|record| at_version(record, false)))
}

/// `actor`'s AgentDefinition, when it is a live AGENT_DEF.
fn agent_definition_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Option<AgentDefinitionRef>> {
    let LiveEntityRow::Live { entity_type, body } =
        live_entity_row_in_txn(&vault.store, txn, actor)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_AGENT_DEF {
        return Ok(None);
    }
    let definition = crate::agent_def::decode_agent_definition(&body)?;
    Ok(Some(AgentDefinitionRef {
        definition: actor.to_hex(),
        agent_id: definition.agent_id,
        version: definition.version,
        logical_id: definition.logical_id,
    }))
}

/// Who published `subject`: an imported skill, or a seeded agent definition,
/// is shipped; anything else is the owner's.
fn publisher_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    subject_kind: TriageSubject,
    agent_definitions: &[AgentDefinitionRef],
) -> Result<ArtifactPublisher> {
    let shipped = match subject_kind {
        TriageSubject::Skill => vault
            .get_skill_record_in_txn(txn, &subject)?
            .is_some_and(|record| record.source == ClaimSource::Imported),
        TriageSubject::Actor => {
            let subject = subject.to_hex();
            agent_definitions
                .iter()
                .any(|agent| agent.definition == subject && agent.logical_id.is_some())
        }
    };
    Ok(if shipped {
        ArtifactPublisher::Shipped
    } else {
        ArtifactPublisher::Owner
    })
}

/// The last skill revision and the last executor change across `receipts`
/// from `window_from` on.
fn recent_changes(receipts: &[TriageReceipt], window_from: u64) -> RecentChanges {
    let window: Vec<&TriageReceipt> = receipts
        .iter()
        .filter(|receipt| receipt.at >= window_from)
        .collect();
    RecentChanges {
        window_from,
        skill_revision: last_change(&window, |receipt| {
            receipt.skill.as_ref().map(|skill| {
                (
                    skill.skill.clone(),
                    format!("{}@{}", skill.skill_id, skill.version),
                )
            })
        }),
        executor: last_change(&window, |receipt| {
            receipt
                .executor
                .clone()
                .map(|executor| (String::new(), executor))
        }),
    }
}

/// The newest point where a keyed value differs from the one the receipt
/// before it held under the same key.
fn last_change(
    window: &[&TriageReceipt],
    value: impl Fn(&TriageReceipt) -> Option<(String, String)>,
) -> Option<RecentChange> {
    let mut held: BTreeMap<String, String> = BTreeMap::new();
    let mut change = None;
    for receipt in window {
        let Some((key, now)) = value(receipt) else {
            continue;
        };
        if let Some(before) = held.get(&key)
            && *before != now
        {
            change = Some(RecentChange {
                receipt: receipt.receipt.clone(),
                before: before.clone(),
                after: now.clone(),
                at: receipt.at,
            });
        }
        held.insert(key, now);
    }
    change
}
