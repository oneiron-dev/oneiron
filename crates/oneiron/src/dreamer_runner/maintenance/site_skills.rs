//! The Coach's site skills (CUA E8b, FIX 7606): each night, fixed code
//! reads the same solved-run evidence, coverage and live site programs the
//! browser-programs facet reads, and distils one site skill per site and
//! caller scope. No model call, skill or browser.
//!
//! A candidate is a site-skill folder (`SKILL.md` plus `site.json`, no
//! `programs/` dir) with explicit origins and routes, traps, and its
//! programs named by workflow id. There is no second copy of any program's
//! steps. Filed bytes are shared-safe and caller-literal-free; the scope
//! only partitions the trigger and the finding's cited evidence.
//!
//! Each candidate lands in one write as a born-Proposed, Candidate Native
//! skill with its stored package, plus one Proposed finding citing the
//! skill and the source evidence. A Candidate is inert: it waits on the
//! ordinary skill gate like any other birth, and the Coach never admits,
//! activates or queues anything for it. On a content-hash duplicate the
//! pass points at the existing skill and files no second entity. On the
//! Coach's own earlier site filing it files the next Candidate revision,
//! with the predecessor cited; a foreign holder still wins with only a
//! collision finding and no cursor advance.
//!
//! The pass owns its own (site, scope) cursor and fingerprint domain. It
//! never marks a group clean, never marks a program seen, and never queues
//! an admission job: E8's lifecycle is untouched.

mod distill;

use std::collections::BTreeMap;

use distill::{DistillInputs, SiteSkillCandidate};
use serde::{Deserialize, Serialize};

use super::coach::COACH_SITE_SKILLS_FACET;
use super::proposals;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::browser_library::{
    DirtySolvedGroup, RetiredWorkflow, SolvedRunEvidence, SolvedRunScope, WorkflowRecord,
    WorkflowResolution, all_solved_groups, resolve_workflow_in_txn, retired_workflows,
    site_workflows, solved_group_coverage, solved_runs_in_group,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ScopedRead, ScopedReadActorKey};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::ErrorKind;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::side_table::{self, Named, SideTable};
use crate::skill::{
    SkillContentHash, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
    decode_skill_record, is_legacy_opaque_skill_body, resident_of,
};
use crate::skill_hub::{SkillPackageFormat, package_from_source};
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;

/// The predicate a site-skill finding is filed under.
pub const COACH_SITE_SKILLS_PREDICATE: &str = "coach.site_skills.proposal";

/// What one site-skills pass read and filed.
#[derive(Debug, Clone, Default)]
pub struct CoachSiteSkillsReport {
    /// Site-and-scope units read.
    pub sites: usize,
    /// Skills landed.
    pub skills_created: usize,
    /// Units whose bytes an existing skill already holds.
    pub skills_dup: usize,
    /// Findings filed.
    pub findings: usize,
    /// Diagnostics among them, and units reported only.
    pub diagnostics: usize,
    /// Units with a row the Coach could not read.
    pub withheld: usize,
    /// Units whose write rolled back, and why.
    pub errors: Vec<String>,
}

impl Vault {
    /// One `coach.site_skills` pass under its leased attempt: every solved
    /// group's evidence, grouped by site and caller scope, distilled into
    /// at most one candidate folder each, landed in one write per site.
    /// A write that fails rolls back and is reported; the pass goes on.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's Coach attempt, and storage errors
    /// reading the indexes.
    pub fn run_coach_site_skills(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<CoachSiteSkillsReport> {
        self.require_coach_attempt(attempt, COACH_SITE_SKILLS_FACET)?;
        let envelope =
            proposals::run_tray_envelope(self, COACH_SITE_SKILLS_FACET, attempt.status.attempt.id)?;
        let coach = self.coach_authority()?.entity_ref();
        let key = ScopedReadActorKey::with_actor_class(coach.to_hex(), "system")
            .ok_or_else(|| Error::InvalidConfig("invalid Coach read key".into()))?
            .require_relationship_grants(Some(coach));
        let read = self.scoped_read(key);
        let mut pass = Pass {
            vault: self,
            read: &read,
            coach,
            envelope: &envelope,
            now,
            report: CoachSiteSkillsReport::default(),
            live: BTreeMap::new(),
            retired: BTreeMap::new(),
        };
        let mut groups = Vec::new();
        let mut after = None;
        loop {
            let page = all_solved_groups(self, after.as_ref())?;
            groups.extend(page.items);
            let Some(next) = page.next else { break };
            after = Some(next);
        }
        let mut units: BTreeMap<(String, [u8; 32]), Vec<DirtySolvedGroup>> = BTreeMap::new();
        for group in groups {
            let scope = scope_digest(&group.key.scope);
            units
                .entry((group.key.group.site.clone(), scope))
                .or_default()
                .push(group);
        }
        for ((site, scope), groups) in &units {
            if let Err(error) = pass.unit(site, *scope, groups) {
                pass.report.errors.push(format!("site {site}: {error}"));
            }
        }
        Ok(pass.report)
    }
}

/// The last site-skill filing for one (site, scope): its content
/// fingerprint, the skill entities it filed or pointed at, and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoachSiteSkillSeen {
    fingerprint: [u8; 32],
    filed_ids: Vec<EntityId>,
    at: u64,
}

/// This facet's own cursor. Key: the site's hash, then the scope's digest.
const SEEN: SideTable<([u8; 32], [u8; 32]), CoachSiteSkillSeen, Named> =
    SideTable::new(&side_table::COACH_SITE_SKILL_SEEN);

/// The domain the cursor's site hash is keyed in.
const SITE_HASH_DOMAIN: &[u8] = b"oneiron:coach-site-skill-site:v1";

/// The domain the cursor's scope digest is keyed in.
const SCOPE_DIGEST_DOMAIN: &[u8] = b"oneiron:coach-site-skill-scope:v1";

/// The cursor key half for a site.
fn site_hash(site: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SITE_HASH_DOMAIN);
    hasher.update(site.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The cursor key half for a caller scope: the actor, its class, and the
/// exact credential digest it was admitted on, when it presented one.
fn scope_digest(scope: &SolvedRunScope) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCOPE_DIGEST_DOMAIN);
    hasher.update(scope.actor.as_bytes());
    hasher.update(&[scope.actor_class]);
    match scope.authority {
        Some(authority) => {
            hasher.update(&[1]);
            hasher.update(&authority);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// One pass's reader, finding envelope, tally and per-site program cache.
struct Pass<'a> {
    vault: &'a Vault,
    read: &'a ScopedRead<'a>,
    coach: EntityId,
    envelope: &'a WriteEnvelope,
    now: u64,
    report: CoachSiteSkillsReport,
    live: BTreeMap<String, Vec<WorkflowRecord>>,
    retired: BTreeMap<String, Vec<RetiredWorkflow>>,
}

/// One site-and-scope unit's assembled inputs, ready to distil and commit.
struct Unit {
    site: String,
    hash: [u8; 32],
    scope: [u8; 32],
    evidence: Vec<SolvedRunEvidence>,
    live: Vec<WorkflowRecord>,
    retired: Vec<RetiredWorkflow>,
    covered_groups: usize,
}

/// What one unit's write did.
enum CommitOutcome {
    /// The cursor already names the fingerprint.
    Seen,
    /// A source the Coach read is no longer readable.
    Withheld,
    /// Nothing to name and no failures left at commit.
    Empty,
    /// The bytes already have a holder; the finding points at it.
    Dup,
    /// A foreign holder already has the skill id; the hub wins.
    Collision,
    /// A skill, its package and the finding landed.
    Created,
    /// A next-revision skill, its package and the finding landed.
    Revised,
}

impl Pass<'_> {
    /// One site-and-scope unit: its evidence and live programs distilled
    /// into at most one candidate, landed in one write.
    fn unit(&mut self, site: &str, scope: [u8; 32], groups: &[DirtySolvedGroup]) -> Result<()> {
        let hash = site_hash(site);
        let live = self.live_site(site)?;
        let retired = self.retired_site(site)?;
        let mut evidence = Vec::new();
        let mut withheld = false;
        let mut covered_groups = 0;
        for group in groups {
            let (mut rows, page_withheld, covered) = match self.drain(group) {
                Ok(drained) => drained,
                Err(error) => {
                    let digest = bytes_to_hex_lower(&group.digest);
                    self.report.errors.push(format!("group {digest}: {error}"));
                    return Ok(());
                }
            };
            evidence.append(&mut rows);
            withheld |= page_withheld;
            covered_groups += usize::from(covered);
        }
        self.report.sites += 1;
        if withheld {
            self.report.withheld += 1;
            return Ok(());
        }
        let unit = Unit {
            site: site.to_owned(),
            hash,
            scope,
            evidence,
            live,
            retired,
            covered_groups,
        };
        if unit.live.is_empty() && failures_of(&unit.live, &unit.retired) == 0 {
            self.report.diagnostics += 1;
            return Ok(());
        }
        let (candidate, render_diagnostics) = distill::distill(&DistillInputs {
            site: &unit.site,
            evidence: &unit.evidence,
            live: &unit.live,
            retired: &unit.retired,
            covered_groups: unit.covered_groups,
        })?;
        let Some(candidate) = candidate else {
            self.report.diagnostics += render_diagnostics.len().max(1);
            return Ok(());
        };
        if self.seen_fingerprint(&unit)? == Some(candidate.fingerprint) {
            return Ok(());
        }
        self.report.diagnostics += render_diagnostics.len();
        self.commit(&unit)
    }

    /// Every page of `group`'s evidence the Coach reads, whether a page
    /// withheld a row, and whether a live program covers the group.
    fn drain(&mut self, group: &DirtySolvedGroup) -> Result<(Vec<SolvedRunEvidence>, bool, bool)> {
        let mut evidence = Vec::new();
        let mut withheld = false;
        let mut after = None;
        loop {
            let page = solved_runs_in_group(self.read, &group.key, after.as_ref())?;
            withheld |= page.receipt.suppressed_count > 0;
            evidence.extend(page.value.items);
            let Some(next) = page.value.next else { break };
            after = Some(next);
        }
        let covered = !solved_group_coverage(self.vault, &group.digest)?.is_empty();
        Ok((evidence, withheld, covered))
    }

    /// The site's live programs, read once per pass.
    fn live_site(&mut self, site: &str) -> Result<Vec<WorkflowRecord>> {
        if let Some(records) = self.live.get(site) {
            return Ok(records.clone());
        }
        let records = site_workflows(self.vault, site, None, None)?;
        self.live.insert(site.to_owned(), records.clone());
        Ok(records)
    }

    /// The site's retired programs, read once per pass.
    fn retired_site(&mut self, site: &str) -> Result<Vec<RetiredWorkflow>> {
        if let Some(traces) = self.retired.get(site) {
            return Ok(traces.clone());
        }
        let traces = retired_workflows(self.vault, site)?;
        self.retired.insert(site.to_owned(), traces.clone());
        Ok(traces)
    }

    /// The fingerprint the cursor holds for the unit, if one filed before.
    fn seen_fingerprint(&self, unit: &Unit) -> Result<Option<[u8; 32]>> {
        let rtxn = self.vault.store.env.read_txn()?;
        Ok(SEEN
            .get(&self.vault.store, &rtxn, &(unit.hash, unit.scope))?
            .map(|seen| seen.fingerprint))
    }

    /// The unit's one transaction: re-check readability and the cursor,
    /// keep each named workflow only while it is live (dropping retired,
    /// missing or mid-pass-successor rows with a diagnostic), then
    /// content-hash dedup and the landing. A duplicate points at the
    /// existing skill; an id collision files nothing. The cursor advances
    /// only on a landing or a duplicate.
    fn commit(&mut self, unit: &Unit) -> Result<()> {
        let (vault, read, coach, envelope, now) =
            (self.vault, self.read, self.coach, self.envelope, self.now);
        let outcome = vault.with_write_txn_grouped(|txn| {
            let mut ordered: Vec<&SolvedRunEvidence> = unit.evidence.iter().collect();
            ordered.sort_by_key(|source| (source.run_id, source.id));
            let sources: Vec<EntityId> = ordered.iter().map(|source| source.id).collect();
            let policy = read.live_policy_manifest_in(txn)?;
            for id in &sources {
                if !read.is_entity_readable_with_policy_in(txn, &policy, id)? {
                    return Ok(CommitOutcome::Withheld);
                }
            }
            let by_id: BTreeMap<EntityId, &WorkflowRecord> =
                unit.live.iter().map(|record| (record.id, record)).collect();
            let mut resolved = Vec::new();
            let mut commit_diagnostics = Vec::new();
            for record in &unit.live {
                match resolve_workflow_in_txn(vault, txn, &record.id)? {
                    WorkflowResolution::Active { id } => match by_id.get(&id) {
                        Some(record) => resolved.push((*record).clone()),
                        None => commit_diagnostics.push(format!(
                            "{} names a program filed mid-pass; dropped",
                            record.id.to_hex()
                        )),
                    },
                    WorkflowResolution::Retired { .. } => commit_diagnostics.push(format!(
                        "{} retired with no live successor; dropped",
                        record.id.to_hex()
                    )),
                    WorkflowResolution::Missing => commit_diagnostics
                        .push(format!("{} is filed no more; dropped", record.id.to_hex())),
                }
            }
            if resolved.is_empty() && failures_of(&resolved, &unit.retired) == 0 {
                return Ok(CommitOutcome::Empty);
            }
            let (candidate, _) = distill::distill(&DistillInputs {
                site: &unit.site,
                evidence: &unit.evidence,
                live: &resolved,
                retired: &unit.retired,
                covered_groups: unit.covered_groups,
            })?;
            let Some(candidate) = candidate else {
                return Ok(CommitOutcome::Empty);
            };
            if SEEN
                .get(&vault.store, txn, &(unit.hash, unit.scope))?
                .is_some_and(|seen| seen.fingerprint == candidate.fingerprint)
            {
                return Ok(CommitOutcome::Seen);
            }
            let content_hash = canonical_skill_tree_hash(
                candidate
                    .files
                    .iter()
                    .map(|file| (file.path.as_str(), file.content.as_slice())),
            )?;
            if let Some(existing) = vault.skill_entity_for_content_hash_in_txn(txn, content_hash)? {
                let mut cites = Vec::with_capacity(sources.len() + 1);
                cites.push(existing);
                cites.extend(sources.iter().copied());
                let value =
                    distill::finding_value(&candidate, &existing.to_hex(), &commit_diagnostics);
                let _finding = proposals::emit_in_txn(
                    vault,
                    txn,
                    coach,
                    COACH_SITE_SKILLS_PREDICATE,
                    &value,
                    &cites,
                    envelope,
                    now,
                )?;
                SEEN.put(
                    &vault.store,
                    txn,
                    &(unit.hash, unit.scope),
                    &CoachSiteSkillSeen {
                        fingerprint: candidate.fingerprint,
                        filed_ids: vec![existing],
                        at: now,
                    },
                )?;
                return Ok(CommitOutcome::Dup);
            }
            let mut own = Vec::new();
            let mut foreign = Vec::new();
            for (id, record) in skill_holders_in_txn(vault, txn, &candidate.skill_id)? {
                if is_own_site_revision(&record, &unit.site)? {
                    own.push((id, record));
                } else {
                    foreign.push((id, record));
                }
            }
            if let Some((holder, _)) = foreign.first() {
                let value = distill::collision_value(&candidate, &holder.to_hex());
                let mut cites = Vec::with_capacity(sources.len() + 1);
                cites.push(*holder);
                cites.extend(sources.iter().copied());
                let _finding = proposals::emit_in_txn(
                    vault,
                    txn,
                    coach,
                    COACH_SITE_SKILLS_PREDICATE,
                    &value,
                    &cites,
                    envelope,
                    now,
                )?;
                // A foreign collision retries after the holder changes; the
                // content-addressed finding dedups, so no cursor advance.
                return Ok(CommitOutcome::Collision);
            }
            let seen = SEEN.get(&vault.store, txn, &(unit.hash, unit.scope))?;
            let cursor = seen
                .as_ref()
                .and_then(|seen| seen.filed_ids.last())
                .copied();
            let predecessor =
                match cursor.and_then(|cursor| own.iter().find(|(id, _)| *id == cursor)) {
                    Some((id, record)) => Some((*id, record.clone())),
                    None => own.iter().max_by_key(|(id, _)| *id).cloned(),
                };
            let id = vault.store.clock.entity_id()?;
            let (version, outcome) = if predecessor.is_some() {
                (
                    distill::revision_version(content_hash),
                    CommitOutcome::Revised,
                )
            } else {
                (
                    distill::SITE_SKILL_VERSION.to_owned(),
                    CommitOutcome::Created,
                )
            };
            let record = skill_record(&candidate, content_hash, &version, predecessor.as_ref());
            let package =
                package_from_source(&record, candidate.files.clone(), SkillPackageFormat::Native)?;
            vault.put_skill_record_in_txn(
                txn,
                &id,
                &record,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            vault.persist_hub_package_in_txn(txn, &id, &package)?;
            let mut cites = Vec::with_capacity(sources.len() + 2);
            cites.push(id);
            if let Some((predecessor, _)) = &predecessor {
                cites.push(*predecessor);
            }
            cites.extend(sources.iter().copied());
            let value = match &predecessor {
                Some((predecessor, _)) => distill::revision_value(
                    &candidate,
                    &id.to_hex(),
                    &predecessor.to_hex(),
                    &commit_diagnostics,
                ),
                None => distill::finding_value(&candidate, &id.to_hex(), &commit_diagnostics),
            };
            let _finding = proposals::emit_in_txn(
                vault,
                txn,
                coach,
                COACH_SITE_SKILLS_PREDICATE,
                &value,
                &cites,
                envelope,
                now,
            )?;
            SEEN.put(
                &vault.store,
                txn,
                &(unit.hash, unit.scope),
                &CoachSiteSkillSeen {
                    fingerprint: candidate.fingerprint,
                    filed_ids: vec![id],
                    at: now,
                },
            )?;
            Ok(outcome)
        })?;
        let report = &mut self.report;
        match outcome {
            CommitOutcome::Seen => {}
            CommitOutcome::Withheld => report.withheld += 1,
            CommitOutcome::Empty => report.diagnostics += 1,
            CommitOutcome::Dup => {
                report.skills_dup += 1;
                report.findings += 1;
            }
            CommitOutcome::Collision => {
                report.diagnostics += 1;
                report.findings += 1;
            }
            CommitOutcome::Created | CommitOutcome::Revised => {
                report.skills_created += 1;
                report.findings += 1;
            }
        }
        Ok(())
    }
}

/// The site's failure events across its live and retired programs.
fn failures_of(live: &[WorkflowRecord], retired: &[RetiredWorkflow]) -> u64 {
    live.iter()
        .map(|record| u64::from(record.failures))
        .sum::<u64>()
        .saturating_add(
            retired
                .iter()
                .map(|trace| u64::from(trace.record.failures))
                .sum::<u64>(),
        )
}

/// The born-Proposed, Candidate record a landing files: Generated on the
/// Dreamer-distill road, knowledge role, no dependencies. A revision keeps
/// the same skill id and cites its predecessor, without changing that row.
fn skill_record(
    candidate: &SiteSkillCandidate,
    content_hash: SkillContentHash,
    version: &str,
    predecessor: Option<&(EntityId, SkillRecord)>,
) -> SkillRecord {
    let mut provenance = vec![
        (Value::from("birth"), Value::from("dreamer_distill")),
        (Value::from("site"), Value::from(candidate.site.as_str())),
    ];
    if let Some((id, prior)) = predecessor {
        provenance.push((Value::from("merge_of"), Value::from(id.to_hex())));
        provenance.push((
            Value::from("prev_version"),
            Value::from(prior.version.as_str()),
        ));
    }
    SkillRecord::new(
        candidate.skill_id.clone(),
        distill::description_for_site(&candidate.site),
        version,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated).mean(),
        true,
        false,
        Vec::new(),
        Value::Map(provenance),
    )
    .with_content_hash(content_hash)
    .with_role(SkillRole::Knowledge, None)
}

/// At most this many skill rows the id-collision scan reads before it
/// refuses, like the content-hash index walk.
const MAX_SKILL_HOLDER_SCAN_ENTRIES: usize = 100_000;

/// The skill entities holding `skill_id`: a vault-wide scan that skips
/// tombstones, legacy opaque bodies and superseded history. Stale and
/// quarantined holders remain foreign collision blockers.
fn skill_holders_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill_id: &str,
) -> Result<Vec<(EntityId, SkillRecord)>> {
    let mut holders = Vec::new();
    for (scanned, entry) in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_SKILL, None)?
        .enumerate()
    {
        if scanned >= MAX_SKILL_HOLDER_SCAN_ENTRIES {
            return Err(Error::IndexOverflow("skill_holder_for_skill_id"));
        }
        let id = entry?;
        if crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &id)?.deleted {
            continue;
        }
        let raw = vault
            .get_raw_in(txn, &id)?
            .ok_or(Error::CorruptedIndex("skill type index"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill type index"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let record = match decode_skill_record(body) {
            Ok(record) => record,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && is_legacy_opaque_skill_body(body) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if record.skill_id == skill_id && record.lifecycle_status != SkillLifecycle::Superseded {
            holders.push((id, record));
        }
    }
    Ok(holders)
}

/// Whether a current holder is this Coach's own filing for `site`, rather
/// than a hub, user, fork, resident or different-site holder (FIX 7606).
fn is_own_site_revision(record: &SkillRecord, site: &str) -> Result<bool> {
    if !matches!(
        record.lifecycle_status,
        SkillLifecycle::Candidate | SkillLifecycle::Active
    ) || record.source != ClaimSource::Generated
        || !record.generated
        || record.human_authored
        || record.role != SkillRole::Knowledge
        || record.forked_from.is_some()
        || resident_of(record)?.is_some()
    {
        return Ok(false);
    }
    let Value::Map(provenance) = &record.provenance else {
        return Ok(false);
    };
    let birth = provenance.iter().any(|(key, value)| {
        key.as_str() == Some("birth") && value.as_str() == Some("dreamer_distill")
    });
    let same_site = provenance
        .iter()
        .any(|(key, value)| key.as_str() == Some("site") && value.as_str() == Some(site));
    Ok(birth && same_site)
}
