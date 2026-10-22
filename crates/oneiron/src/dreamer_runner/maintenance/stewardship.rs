//! Relationship stewardship (ARCH-0026, Forward and relationships). The owner
//! names the people to keep in touch with and how long a quiet stretch may
//! run. Each night the facet reads what the vault holds about each person as
//! the Dreamer, under its relationship grants, and a rule whose person has
//! gone quiet past its period lands one reach-out. The reach-out applies at
//! once (OF-023): it lands Auto with a receipt the owner reverts, and the
//! inbox's finding notice tells them; a reach-out the Gate parks waits in the
//! run tray as before. The quiet stretch runs from the person's last touch:
//! the newer of the newest record read about them and the newest contact
//! with them (a `comm.last_touch` head the Dreamer reads). The reach-out
//! cites whichever that is, or the person when the vault holds neither yet.
//! No tie strength is scored: the quiet stretch is the only signal, and the
//! rule says how long.
//!
//! A rule with a draft route also lets the host draft the follow-up through
//! the representation seam ([`Vault::stewardship_draft_page`] →
//! [`Vault::schedule_stewardship_draft`]). A draft whose rule the owner
//! edited while it was written is stale, and the host drafts again at once
//! against the current rule ([`Vault::stewardship_draft_request`], FIX
//! 6079). The draft is saved at once for the owner's send review, and only
//! their approval at `/v1/owner/representation/approve` schedules a send;
//! nothing here sends.
//! Reverting the reach-out withdraws the plans drafted from it, and each
//! plan's own applied row closes with it.
use super::applied::{self, MaintenanceInverse, MaintenanceRevert};
use super::proposals;
use super::representation::{
    RepresentationKind, RepresentationPlanner, RepresentationRequest, RepresentationSourceRef,
};
use super::{MAINTENANCE_QUEUE_KIND, invalid};
use crate::claim::{PointRead, ScopedRead, ScopedReadActorKey, claim_evidence_admissible};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Result, Vault, WriteActor,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STEWARDSHIP_FACET: &str = "dreamer.stewardship";
/// The reach-out one due rule lands, its subject the rule's person.
pub const STEWARDSHIP_PREDICATE: &str = "dreamer.stewardship.reach_out";
const RULES: SideTable<(), StewardshipRules, LegacyJson> =
    SideTable::new(&side_table::DREAMER_STEWARDSHIP_RULES);
/// Reach-outs a host draft was scheduled for, with when.
const DRAFTED: SideTable<EntityId, u64, side_table::Raw> =
    SideTable::new(&side_table::DREAMER_STEWARDSHIP_DRAFTED);
/// Rows one read takes: a traversal unit, never a cap on what is read.
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

/// One standing reach-out the host may draft a follow-up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardshipDraftRequest {
    /// The reach-out the draft follows up.
    pub proposal: EntityId,
    /// The owner's drafting instruction.
    pub instruction: String,
    pub request: RepresentationRequest,
    /// The reach-out's revision the draft is pinned to.
    revision: [u8; 32],
}

/// One page of [`Vault::stewardship_draft_page`]: the draft requests one
/// traversal unit of the reach-out index makes, and where the next starts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StewardshipDraftPage {
    /// The page's standing reach-outs with a draft route and no draft yet,
    /// in reach-out id order.
    pub drafts: Vec<StewardshipDraftRequest>,
    /// The last reach-out this page read, to read the next page after;
    /// `None` once the index is read to its end.
    pub next: Option<EntityId>,
}

/// What scheduling a host's draft came to.
#[derive(Debug, Clone, PartialEq)]
pub enum StewardshipDraftOutcome {
    /// The draft's plan is queued and its reach-out marked drafted.
    Scheduled(EnqueueDreamerAttemptOutcome),
    /// The request the draft was written for no longer stands as it was
    /// (FIX 6079): the owner edited its rule, the reach-out moved or went,
    /// or it was drafted meanwhile. Its text is not used; the host drafts
    /// again against [`Vault::stewardship_draft_request`], when there is one.
    Stale,
}

fn bad_text(text: &str) -> bool {
    text.trim().is_empty() || text.chars().any(char::is_control)
}

/// Measures a rule set where the owner sets it against the `[limits]` rows
/// (OF-520): its rules, the most voice sources one route names, and its
/// longest id, route or instruction. Past one the vault's port asks, and the
/// set is kept whole.
fn measure_rules(vault: &Vault, rules: &[StewardshipRule]) {
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, rules.len() as u64);
    let mut voices: usize = 0;
    let mut longest: usize = 0;
    for rule in rules {
        longest = longest.max(rule.id.len());
        let Some(route) = &rule.draft else {
            continue;
        };
        voices = voices.max(route.voice.len());
        for text in [&route.verb, &route.channel, &route.target] {
            longest = longest.max(text.len());
        }
        longest = longest.max(route.instruction.len());
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, voices as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}

impl StewardshipRule {
    fn validate(&self) -> Result<()> {
        if bad_text(&self.id) || self.every_secs == 0 {
            return Err(invalid());
        }
        if let Some(route) = &self.draft {
            if [&route.verb, &route.channel, &route.target]
                .into_iter()
                .any(|text| bad_text(text))
                || route.voice.is_empty()
                || route.instruction.trim().is_empty()
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
        let mut ids = BTreeSet::new();
        for rule in &rules {
            rule.validate()?;
            if !ids.insert(rule.id.clone()) {
                return Err(invalid());
            }
        }
        measure_rules(self, &rules);
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

    /// One page of the standing reach-outs whose rule has a draft route and
    /// no draft yet, read after the reach-out `after`: each one applied and
    /// not reverted, or held for the owner and not declined. A page is a
    /// traversal unit, never a cap: the host follows
    /// [`StewardshipDraftPage::next`] until it is `None`, so every due draft
    /// is read. A reach-out the vault holds no record to cite for has
    /// nothing to ground a draft in and is left to the owner.
    pub fn stewardship_draft_page(&self, after: Option<EntityId>) -> Result<StewardshipDraftPage> {
        let Some(rules) = self.stewardship_rules()? else {
            return Ok(StewardshipDraftPage::default());
        };
        if rules.rules.iter().all(|rule| rule.draft.is_none()) {
            return Ok(StewardshipDraftPage::default());
        }
        let authority = self.dreamer_authority()?.entity_ref();
        let reader = dreamer_reader(self)?;
        let page = {
            let txn = self.store.env.read_txn()?;
            crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.store,
                &txn,
                STEWARDSHIP_PREDICATE,
                after,
                READ_CHUNK,
            )?
        };
        // A short page is the index's end.
        let next = if page.len() < READ_CHUNK {
            None
        } else {
            page.last().copied()
        };
        let mut drafts = Vec::new();
        for id in page {
            if let Some(request) = draft_request(self, &reader, &rules, authority, id)? {
                drafts.push(request);
            }
        }
        Ok(StewardshipDraftPage { drafts, next })
    }

    /// The draft request the reach-out `proposal` makes now, when it is a
    /// standing reach-out of the Dreamer's whose rule routes drafts and that
    /// has no draft yet: what a host drafts again against once its draft
    /// went stale (FIX 6079).
    pub fn stewardship_draft_request(
        &self,
        proposal: EntityId,
    ) -> Result<Option<StewardshipDraftRequest>> {
        let Some(rules) = self.stewardship_rules()? else {
            return Ok(None);
        };
        let authority = self.dreamer_authority()?.entity_ref();
        draft_request(self, &dreamer_reader(self)?, &rules, authority, proposal)
    }

    /// Schedules the host's draft of `draft`, the request it was written
    /// for, through the representation seam, once. The plan is that
    /// request's, never one derived again: its reach-out must still stand
    /// undrafted at its revision and its rule still route it exactly,
    /// checked before the planner and again in the writer, or the draft is
    /// [`StewardshipDraftOutcome::Stale`] and schedules nothing (FIX 6079),
    /// so text written under an old rule never goes out under a new one. A
    /// reach-out the owner reverted or declined, or a rule they removed, is
    /// stale too. The queued draft carries the reach-out and lands only
    /// while it still stands. The planner, its checks and the stored draft
    /// run outside any writer; the plan's row, its queued landing and the
    /// reach-out's draft mark then commit in one write (FIX 1000), so a
    /// crash between them drafts nothing twice.
    pub fn schedule_stewardship_draft(
        &self,
        draft: &StewardshipDraftRequest,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<StewardshipDraftOutcome> {
        let authority = self.dreamer_authority()?.entity_ref();
        {
            let txn = self.store.env.read_txn()?;
            if !still_drafts_in_txn(self, &txn, authority, draft)? {
                return Ok(StewardshipDraftOutcome::Stale);
            }
        }
        let plan =
            self.prepare_follow_up(&draft.request, draft.proposal, draft.revision, planner)?;
        self.with_write_txn_grouped(|txn| {
            // The writer's own snapshot: still undrafted, the reach-out still
            // stands at the drafted revision, and its rule still routes this
            // draft.
            if !still_drafts_in_txn(self, &*txn, authority, draft)? {
                return Ok(StewardshipDraftOutcome::Stale);
            }
            let outcome = plan.enqueue_in_txn(self, txn, now)?;
            DRAFTED.put(&self.store, txn, &draft.proposal, &now)?;
            Ok(StewardshipDraftOutcome::Scheduled(outcome))
        })
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

/// Lands one reach-out per due rule, applied at once. A rule stays due on the
/// same last touch, and its reach-out is content-keyed, so a replayed night
/// lands nothing twice and a reverted reach-out never lands again; a new
/// record about the person, or a newer contact with them, starts a new
/// stretch.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    let Some(rules) = vault.stewardship_rules()? else {
        return Ok(());
    };
    let reader = dreamer_reader(vault)?;
    let mut due = Vec::new();
    for rule in &rules.rules {
        let newest = last_touch(vault, &reader, rule.person, now)?;
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
    proposals::land(
        vault,
        STEWARDSHIP_FACET,
        attempt.status.attempt.id,
        |landing| {
            vault.with_write_txn_grouped(|txn| {
                for (person, value, evidence) in &due {
                    landing.land_in_txn(
                        vault,
                        txn,
                        &proposals::Finding {
                            subject: *person,
                            predicate: STEWARDSHIP_PREDICATE,
                            value,
                            evidence: &[*evidence],
                        },
                        now,
                        |_| Ok(MaintenanceInverse::ReachOut),
                    )?;
                }
                Ok(())
            })
        },
    )
}

/// The owner's revert of one applied reach-out, beside its retraction: its
/// draft marker goes and each follow-up plan drafted from it is withdrawn,
/// so a draft still queued lands nothing and a plan not yet sent never
/// sends. Each withdrawn plan's applied row is closed in this transaction,
/// naming the reach-out (FIX 3329). A message already sent cannot be unsent.
pub(super) fn revert_reach_out_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: WriteActor,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let reach_out = out.target.finding().ok_or_else(invalid)?;
    DRAFTED.delete(&vault.store, txn, &reach_out)?;
    super::representation::withdraw_follow_ups_in_txn(vault, txn, reach_out, owner, now, out)
}

/// A reach-out of the Dreamer's that still stands, with the revision a
/// follow-up pins: live, not stale, and applied at once and not reverted,
/// or held for the owner and not declined. The revision is its body with
/// the approval set aside, so the owner's approval of a held one moves
/// nothing while a retraction or any rewrite does.
pub(super) fn standing_reach_out_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    id: EntityId,
) -> Result<Option<(ClaimBody, [u8; 32])>> {
    let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
        return Ok(None);
    };
    let standing = match body.approval {
        ClaimApprovalStatus::Auto => applied::standing_in_txn(vault, txn, id)?,
        ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Approved => true,
        _ => false,
    };
    if !standing
        || body.predicate != STEWARDSHIP_PREDICATE
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.source != Some(ClaimSource::Generated)
        || body.stale
        || crate::claim::session_claim_producer(&body) != Some(authority)
    {
        return Ok(None);
    }
    let revision = super::representation::review_revision(&body)?;
    Ok(Some((body, revision)))
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

/// Every record about `person` the Dreamer reads and may cite, newest first,
/// each with when it happened. The Dreamer's own claims are not a record of
/// the person. With `text_only`, a record whose value is not text (a
/// `comm.last_touch` head's map, say) or whose text is blank is passed over:
/// a draft cites text alone, and the representation loader refuses any other
/// source.
fn recent(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    person: EntityId,
    text_only: bool,
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
                || (text_only
                    && body
                        .value
                        .as_str()
                        .is_none_or(|text| text.trim().is_empty()))
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
    Ok(found)
}

/// The person's newest message-level contact the Dreamer reads (FIX 998):
/// each effective, standing `comm.last_touch` head about them, the newest by
/// its contact's own time, with the head that says so for evidence. It reads
/// through the Dreamer's relationship-granted read alone, never the raw
/// contact cache.
fn last_contact(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    person: EntityId,
    now: u64,
) -> Result<Option<(EntityId, u64)>> {
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
            if body.predicate != crate::comm::PREDICATE_COMM_LAST_TOUCH {
                continue;
            }
            // A head that does not read as a contact record is none.
            let Ok(claim) = crate::comm::CommClaim::from_claim_body(&body) else {
                continue;
            };
            if let crate::comm::CommClaimValue::LastTouch {
                party_ref,
                occurred_at,
                ..
            } = claim.value
                && party_ref == person
                && claim.is_standing()
                && claim.is_effective_at(now)
            {
                found.push((row.id, occurred_at));
            }
        }
    }
    Ok(found
        .into_iter()
        .min_by_key(|&(id, at)| (std::cmp::Reverse(at), id)))
}

/// The person's last touch (FIX 998): the newer of the newest record about
/// them and their newest message-level contact, with the claim that says so.
/// With no contact history the newest record stands alone, as before; on a
/// tie it is the record.
fn last_touch(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    person: EntityId,
    now: u64,
) -> Result<Option<(EntityId, u64)>> {
    // The newest record alone: a pick by time, not a cap on what is read.
    let record = recent(vault, reader, person, false)?.into_iter().next();
    let contact = last_contact(vault, reader, person, now)?;
    Ok(contact.into_iter().chain(record).max_by_key(|&(_, at)| at))
}

/// The person and draft route the owner's rules name for the reach-out
/// `body`, when its rule still routes drafts.
fn draft_route<'a>(
    rules: &'a StewardshipRules,
    body: &ClaimBody,
) -> Result<Option<(EntityId, &'a StewardshipDraftRoute)>> {
    let ClaimSubject::Entity(person) = body.subject else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(body.value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    Ok(rules
        .rules
        .iter()
        .find(|rule| rule.person == person && value["rule"].as_str() == Some(rule.id.as_str()))
        .and_then(|rule| rule.draft.as_ref())
        .map(|route| (person, route)))
}

impl StewardshipDraftRequest {
    /// Whether this request, read after `stale` went stale, is the owner's
    /// rule or the reach-out really moved (FIX 6079): its revision or its
    /// exact route differs. The evidence it cites may differ either way.
    #[must_use]
    pub fn moved_from(&self, stale: &Self) -> bool {
        self.revision != stale.revision
            || self.request.owner != stale.request.owner
            || self.instruction != stale.instruction
            || self.request.verb != stale.request.verb
            || self.request.channel != stale.request.channel
            || self.request.target != stale.request.target
            || self.request.voice != stale.request.voice
    }

    /// Whether `route`, in rules set by `owner`, still drafts this request:
    /// its voice is some of the route's, at least one, as a draft written
    /// over the voice samples one model was sent records only those (FIX
    /// 9447).
    fn drafted_by(&self, owner: EntityId, route: &StewardshipDraftRoute) -> bool {
        self.request.owner == owner
            && self.instruction == route.instruction
            && self.request.verb == route.verb
            && self.request.channel == route.channel
            && self.request.target == route.target
            && !self.request.voice.is_empty()
            && self
                .request
                .voice
                .iter()
                .all(|voice| route.voice.contains(voice))
    }
}

/// Whether `draft` still drafts as it was requested, read in `txn` (FIX
/// 1000, 6079): its reach-out undrafted and still standing at its revision,
/// and the owner's rules still routing it exactly.
fn still_drafts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    draft: &StewardshipDraftRequest,
) -> Result<bool> {
    if DRAFTED.contains(&vault.store, txn, &draft.proposal)? {
        return Ok(false);
    }
    let Some((body, revision)) = standing_reach_out_in_txn(vault, txn, authority, draft.proposal)?
    else {
        return Ok(false);
    };
    let Some(rules) = RULES.get(&vault.store, txn, &())? else {
        return Ok(false);
    };
    Ok(revision == draft.revision
        && draft_route(&rules, &body)?
            .is_some_and(|(_, route)| draft.drafted_by(rules.owner, route)))
}

/// The draft request one claim makes, when it is a standing reach-out of
/// the Dreamer's whose rule routes drafts and that has no draft yet.
fn draft_request(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    rules: &StewardshipRules,
    authority: EntityId,
    proposal: EntityId,
) -> Result<Option<StewardshipDraftRequest>> {
    let (body, revision) = {
        let txn = vault.store.env.read_txn()?;
        if DRAFTED.contains(&vault.store, &txn, &proposal)? {
            return Ok(None);
        }
        match standing_reach_out_in_txn(vault, &txn, authority, proposal)? {
            Some(standing) => standing,
            None => return Ok(None),
        }
    };
    let Some((person, route)) = draft_route(rules, &body)? else {
        return Ok(None);
    };
    // Every eligible text record about the person, newest first. One the
    // route names as voice is cited there: the loader reads a source once.
    let evidence: Vec<RepresentationSourceRef> = recent(vault, reader, person, true)?
        .into_iter()
        .filter(|(claim, _)| !route.voice.iter().any(|voice| voice.claim == *claim))
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
        revision,
    }))
}
