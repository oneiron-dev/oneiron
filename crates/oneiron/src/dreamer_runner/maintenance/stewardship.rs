//! Relationship stewardship (ARCH-0026, Forward and relationships). The owner
//! names the people to keep in touch with and how long a quiet stretch may
//! run. Each night the facet reads what the vault holds about each person as
//! the Dreamer, under its relationship grants, and a rule whose person has
//! gone quiet past its period lands one Proposed reach-out. The reach-out
//! cites the newest record read, or the person when the vault holds none yet,
//! and the proactivity digest carries it to the owner. No tie strength is
//! scored: the quiet stretch is the only signal, and the rule says how long.
//!
//! A rule with a draft route also lets the host draft the follow-up through
//! the representation seam ([`Vault::stewardship_draft_requests`] →
//! [`Vault::schedule_stewardship_draft`]). The draft is a proposal the owner
//! approves before any send; nothing here sends.
use super::proposals;
use super::representation::{
    RepresentationKind, RepresentationPlanner, RepresentationRequest, RepresentationSourceRef,
};
use super::{MAINTENANCE_QUEUE_KIND, invalid};
use crate::claim::{PointRead, ScopedRead, ScopedReadActorKey, claim_evidence_admissible};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId, Result, Vault,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STEWARDSHIP_FACET: &str = "dreamer.stewardship";
/// The Proposed reach-out one due rule lands, its subject the rule's person.
pub const STEWARDSHIP_PREDICATE: &str = "dreamer.stewardship.reach_out";
const RULES: SideTable<(), StewardshipRules, LegacyJson> =
    SideTable::new(&side_table::DREAMER_STEWARDSHIP_RULES);
/// Reach-outs a host draft was scheduled for, with when.
const DRAFTED: SideTable<EntityId, u64, side_table::Raw> =
    SideTable::new(&side_table::DREAMER_STEWARDSHIP_DRAFTED);
const MAX_RULES: usize = 256;
/// The newest records about a person one draft cites.
const DRAFT_EVIDENCE: usize = 8;
const READ_CHUNK: usize = 256;

/// The owner's keep-in-touch rules, set whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StewardshipRules {
    /// The owner who set the rules; a draft speaks in their voice.
    #[serde(with = "crate::serialize::entity_ref")]
    pub owner: EntityId,
    pub rules: Vec<StewardshipRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StewardshipRule {
    /// The owner's own stable name for the rule, unique in the set.
    pub id: String,
    /// The PERSON to keep in touch with.
    #[serde(with = "crate::serialize::entity_ref")]
    pub person: EntityId,
    /// The longest quiet stretch, in seconds, before the rule falls due.
    pub every_secs: u64,
    /// When the rule was first set; the engine stamps it. A person the vault
    /// holds no record of yet falls due one period after it.
    #[serde(default)]
    pub since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<StewardshipDraftRoute>,
}

/// Where a drafted follow-up would go, and how the owner wants it written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StewardshipDraftRoute {
    pub verb: String,
    pub channel: String,
    pub target: String,
    /// The owner's own stated claims the draft's voice follows.
    pub voice: Vec<RepresentationSourceRef>,
    /// The owner's drafting instruction, handed to the host's model as is.
    pub instruction: String,
}

/// One pending reach-out the host may draft a follow-up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardshipDraftRequest {
    /// The reach-out proposal the draft follows up.
    pub proposal: EntityId,
    /// The owner's drafting instruction.
    pub instruction: String,
    pub request: RepresentationRequest,
}

fn bad_text(text: &str, max: usize) -> bool {
    text.trim().is_empty() || text.len() > max || text.chars().any(char::is_control)
}

impl StewardshipRule {
    fn validate(&self) -> Result<()> {
        if bad_text(&self.id, 128) || self.every_secs == 0 {
            return Err(invalid());
        }
        if let Some(route) = &self.draft {
            if [&route.verb, &route.channel, &route.target]
                .into_iter()
                .any(|text| bad_text(text, 2048))
                || route.voice.is_empty()
                || route.voice.len() > 8
                || route.instruction.trim().is_empty()
                || route.instruction.len() > 8192
            {
                return Err(invalid());
            }
            crate::outbound::outbound_verb_contract(&route.channel, &route.verb)
                .map_err(|_| invalid())?;
        }
        Ok(())
    }
}

impl Vault {
    pub fn stewardship_rules(&self) -> Result<Option<StewardshipRules>> {
        let txn = self.store.env.read_txn()?;
        RULES.get(&self.store, &txn, &())
    }

    /// Replaces the owner's whole rule set. A rule kept under its id and
    /// person keeps its `since`; a new one starts now.
    pub fn set_stewardship_rules(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        mut rules: Vec<StewardshipRule>,
        now: u64,
    ) -> Result<StewardshipRules> {
        if rules.len() > MAX_RULES {
            return Err(invalid());
        }
        let mut ids = BTreeSet::new();
        for rule in &rules {
            rule.validate()?;
            if !ids.insert(rule.id.clone()) {
                return Err(invalid());
            }
        }
        self.with_write_txn_grouped(|txn| {
            let actor = super::validate_owner_in_txn(self, txn, owner)?;
            let held = RULES.get(&self.store, &*txn, &())?;
            for rule in &mut rules {
                if !matches!(
                    crate::vault::live_entity_row_in_txn(&self.store, &*txn, &rule.person)?,
                    crate::vault::LiveEntityRow::Live {
                        entity_type: crate::registry::ENTITY_TYPE_PERSON,
                        ..
                    }
                ) {
                    return Err(invalid());
                }
                rule.since = held
                    .as_ref()
                    .and_then(|held| {
                        held.rules
                            .iter()
                            .find(|kept| kept.id == rule.id && kept.person == rule.person)
                    })
                    .map_or(now, |kept| kept.since);
            }
            let mut row = StewardshipRules {
                owner: actor,
                rules,
            };
            // The rule set as the side-row wall keeps it is the one handed back.
            RULES.admit(self, txn, &(), &mut row)?;
            RULES.put(&self.store, txn, &(), &row)?;
            Ok(row)
        })
    }

    /// Pending reach-outs whose rule has a draft route and no draft yet, at
    /// most `limit`. A reach-out the vault holds no record to cite for has
    /// nothing to ground a draft in and is left to the owner.
    pub fn stewardship_draft_requests(&self, limit: usize) -> Result<Vec<StewardshipDraftRequest>> {
        let Some(rules) = self.stewardship_rules()? else {
            return Ok(Vec::new());
        };
        if rules.rules.iter().all(|rule| rule.draft.is_none()) {
            return Ok(Vec::new());
        }
        let authority = self.dreamer_authority()?.entity_ref();
        let pending: Vec<EntityId> = {
            let txn = self.store.env.read_txn()?;
            let mut pending = Vec::new();
            for row in
                crate::claim::PENDING_PRODUCER.iter_from(&self.store, &txn, authority.as_bytes())?
            {
                let ((_, id), _) = row?;
                pending.push(id);
            }
            pending
        };
        let reader = dreamer_reader(self)?;
        let mut requests = Vec::new();
        for id in pending {
            if requests.len() >= limit {
                break;
            }
            if let Some(request) = draft_request(self, &reader, &rules, authority, id)? {
                requests.push(request);
            }
        }
        Ok(requests)
    }

    /// Schedules the host's draft for one reach-out through the
    /// representation seam, once. The request is derived again here, so a
    /// reach-out the owner resolved or a rule they removed meanwhile drafts
    /// nothing.
    pub fn schedule_stewardship_draft(
        &self,
        proposal: EntityId,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let rules = self.stewardship_rules()?.ok_or_else(invalid)?;
        let authority = self.dreamer_authority()?.entity_ref();
        let request = draft_request(self, &dreamer_reader(self)?, &rules, authority, proposal)?
            .ok_or_else(invalid)?;
        let outcome = self.schedule_representation(&request.request, planner, now)?;
        self.with_write_txn_grouped(|txn| DRAFTED.put(&self.store, txn, &proposal, &now))?;
        Ok(outcome)
    }
}

impl DreamerRunnerStore<'_> {
    /// The nightly stewardship pass, one per wake key, only while the owner
    /// has rules.
    pub(super) fn enqueue_stewardship_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        if RULES
            .get(&self.vault.store, &*txn, &())?
            .is_none_or(|row| row.rules.is_empty())
        {
            return Ok(());
        }
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: STEWARDSHIP_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{STEWARDSHIP_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )?;
        Ok(())
    }
}

/// Lands one reach-out per due rule. A rule stays due on the same newest
/// record, and its reach-out is content-keyed, so a replayed night lands
/// nothing twice; a new record about the person starts a new stretch.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    let Some(rules) = vault.stewardship_rules()? else {
        return Ok(());
    };
    let reader = dreamer_reader(vault)?;
    let mut due = Vec::new();
    for rule in &rules.rules {
        let newest = recent(vault, &reader, rule.person, 1)?.into_iter().next();
        let quiet_since = newest.map_or(rule.since, |(_, at)| at);
        let due_at = quiet_since.saturating_add(rule.every_secs);
        if now < due_at {
            continue;
        }
        let value = serde_json::json!({
            "rule": rule.id,
            "last_record": newest.map(|(claim, _)| claim.to_hex()),
            "quiet_since": quiet_since,
            "due_at": due_at,
        });
        let evidence = newest.map_or(rule.person, |(claim, _)| claim);
        due.push((rule.person, value, evidence));
    }
    if due.is_empty() {
        return Ok(());
    }
    let envelope =
        proposals::run_tray_envelope(vault, STEWARDSHIP_FACET, attempt.status.attempt.id)?;
    vault.with_write_txn_grouped(|txn| {
        for (person, value, evidence) in &due {
            proposals::emit_in_txn(
                vault,
                txn,
                *person,
                STEWARDSHIP_PREDICATE,
                value,
                &[*evidence],
                &envelope,
                now,
            )?;
        }
        Ok(())
    })
}

/// The Dreamer's read: a relationship's rows and private rows pass only on
/// its own live grants.
fn dreamer_reader(vault: &Vault) -> Result<ScopedRead<'_>> {
    let actor = vault.dreamer_authority()?.entity_ref();
    Ok(vault.scoped_read(
        ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
            .ok_or_else(invalid)?
            .require_relationship_grants(Some(actor)),
    ))
}

/// The newest records about `person` the Dreamer reads and may cite, newest
/// first, each with when it happened. The Dreamer's own claims are not a
/// record of the person.
fn recent(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    person: EntityId,
    limit: usize,
) -> Result<Vec<(EntityId, u64)>> {
    let ids = vault.claims_for_subject(&person)?;
    let mut found = Vec::new();
    for chunk in ids.chunks(READ_CHUNK) {
        let reads: Vec<PointRead<'_>> = chunk.iter().map(|id| PointRead::id(*id)).collect();
        for row in reader.read(&reads, None)?.value.into_iter().flatten() {
            let Some(bytes) = row.body.as_deref() else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(bytes, true)?;
            if body.predicate.starts_with("dreamer.")
                || body.stale
                || body.lifecycle != ClaimLifecycleStatus::Active
                || !claim_evidence_admissible(&body)
                || !vault.claim_consolidation_eligible(
                    &row.id,
                    crate::gate::ConsolidationReader::RepresentationSource,
                )?
            {
                continue;
            }
            found.push((row.id, row.occurred.end));
        }
    }
    found.sort_by_key(|&(id, at)| (std::cmp::Reverse(at), id));
    found.truncate(limit);
    Ok(found)
}

/// The draft request one pending claim makes, when it is a live reach-out
/// of the Dreamer's whose rule routes drafts and that has no draft yet.
fn draft_request(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    rules: &StewardshipRules,
    authority: EntityId,
    proposal: EntityId,
) -> Result<Option<StewardshipDraftRequest>> {
    {
        let txn = vault.store.env.read_txn()?;
        if DRAFTED.contains(&vault.store, &txn, &proposal)? {
            return Ok(None);
        }
    }
    let Some(body) = vault.get_claim(&proposal)? else {
        return Ok(None);
    };
    if body.predicate != STEWARDSHIP_PREDICATE
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.source != Some(ClaimSource::Generated)
        || body.stale
        || crate::claim::session_claim_producer(&body) != Some(authority)
    {
        return Ok(None);
    }
    let ClaimSubject::Entity(person) = body.subject else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(body.value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let Some(rule) = rules
        .rules
        .iter()
        .find(|rule| rule.person == person && value["rule"].as_str() == Some(rule.id.as_str()))
    else {
        return Ok(None);
    };
    let Some(route) = &rule.draft else {
        return Ok(None);
    };
    let evidence: Vec<RepresentationSourceRef> = recent(vault, reader, person, DRAFT_EVIDENCE)?
        .into_iter()
        .map(|(claim, _)| RepresentationSourceRef { claim })
        .collect();
    if evidence.is_empty() {
        return Ok(None);
    }
    Ok(Some(StewardshipDraftRequest {
        proposal,
        instruction: route.instruction.clone(),
        request: RepresentationRequest {
            owner: rules.owner,
            kind: RepresentationKind::FollowUp,
            verb: route.verb.clone(),
            channel: route.channel.clone(),
            target: route.target.clone(),
            evidence,
            voice: route.voice.clone(),
        },
    }))
}
