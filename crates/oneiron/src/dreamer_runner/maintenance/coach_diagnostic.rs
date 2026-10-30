//! The Coach's diagnosis of a model finding's issue (OF-418 L3; ARCH-0066 §4, §6). An Issues
//! run asks each waiting issue the route question a blocked report is asked, over the finding,
//! the producer its recorded links prove and what its window recorded of the cause (OF-418
//! L10), as untrusted data. The producer is the engine's: a [`ProducerTarget`] is bound only
//! from recorded links and never named by a model, and a finding whose links prove none is
//! `Unknown`, and its issue asks which producer to fix. A `skill_edit` heal drafts by target:
//! a revision of the skill as a gated candidate, or a [`ProducerFixDraft`] of a policy
//! manifest or a config, a suggested delta filed for the owner and never applied. Prompt,
//! environment and person routes stay route-only. The proposal, its oversight count and the
//! issue's settled marker land in one commit; a failed decision waits for the next run, and
//! its third failure goes to a person. Whether a repair took effect is read here too
//! ([`issue_effective_revision`]), from exact refs of the producer's revision in force.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::coach::COACH_ISSUES_FACET;
use super::coach_heal::{HealRoute, ISSUE_RETRIES, IssueOutcome, IssuesPass};
use super::coach_repair::{SkillRepairDraft, land_skill_repair_in_txn, run_target};
use super::proposals;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL};
use crate::self_heal::HealContextSeed;
use crate::self_heal::blocked_reports;
use crate::self_heal::issue_evidence::WindowJudgment;
use crate::self_heal::issue_work::{self, DiagnosticIssue};
use crate::skill::SkillLifecycle;
use crate::store::{RetrievalRunId, RetrievalRunRecord};
use crate::{EntityId, Error, Result, Vault};

/// Predicate of a proposed heal for a model finding's issue (OF-418 L3).
pub const COACH_DIAGNOSTIC_PROPOSAL_PREDICATE: &str = "coach.diagnostic.proposal";
/// Predicate of a proposed resolution of a model finding's issue, for the owner to confirm
/// (OF-418 L3).
pub const COACH_ISSUE_RESOLUTION_PREDICATE: &str = "coach.issue.resolution";
/// The owner of the config a retrieval run records it ran under: its replay inputs' `config`.
pub const RETRIEVAL_REPLAY_CONFIG: &str = "retrieval.replay_config";
/// What an issue asks when no recorded link proves its producer.
const UNBOUND_QUESTION: &str = "No recorded link proves which skill, policy manifest or config \
    produced this finding. Which producer should be fixed, if any?";

/// What produced a model finding, as its recorded links prove it (OF-418 L3). The engine binds
/// it, a model never names it, and a finding whose links prove no single producer is
/// [`Self::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProducerTarget {
    /// The one active skill the one attempt the finding links loaded.
    Skill {
        /// The skill.
        skill: EntityId,
        /// Its version when the finding was filed: the base a revision is drafted against.
        version: String,
        /// The linked attempt, whose dispatched agent a revision binds to.
        attempt: EntityId,
    },
    /// The one live policy manifest the finding links.
    PolicyManifest {
        /// The manifest.
        manifest: EntityId,
        /// blake3 of its stored body when the finding was filed: the base a fix is against. The
        /// row's header is not hashed, so a rewrite of the same body keeps the revision, as its
        /// trust does (FIX 7344).
        revision: [u8; 32],
    },
    /// The config every run of the finding recorded it ran under, the same one each time.
    Config {
        /// Whose config it is: [`RETRIEVAL_REPLAY_CONFIG`].
        owner: String,
        /// blake3 of the recorded config: the base a fix is against.
        digest: [u8; 32],
    },
    /// No recorded link proves one producer.
    Unknown,
}

impl ProducerTarget {
    /// The base revision a fix of it is drafted against; `None` for [`Self::Unknown`].
    #[must_use]
    pub fn base_revision(&self) -> Option<String> {
        match self {
            Self::Skill { version, .. } => Some(version.clone()),
            Self::PolicyManifest { revision, .. } => Some(bytes_to_hex_lower(revision)),
            Self::Config { digest, .. } => Some(bytes_to_hex_lower(digest)),
            Self::Unknown => None,
        }
    }

    /// The target as a proposal, a question's state or a draft reads it, engine-authored.
    #[must_use]
    pub fn value(&self) -> serde_json::Value {
        match self {
            Self::Skill {
                skill,
                version,
                attempt,
            } => json!({
                "kind": "skill",
                "skill": skill.to_hex(),
                "base_revision": version,
                "attempt": attempt.to_hex(),
            }),
            Self::PolicyManifest { manifest, revision } => json!({
                "kind": "policy_manifest",
                "manifest": manifest.to_hex(),
                "base_revision": bytes_to_hex_lower(revision),
            }),
            Self::Config { owner, digest } => json!({
                "kind": "config",
                "owner": owner,
                "base_revision": bytes_to_hex_lower(digest),
            }),
            Self::Unknown => json!({ "kind": "unknown" }),
        }
    }

    /// Which producer it is, whatever its revision: the bytes a recurrence is keyed by. A
    /// skill is its stable `skill_id` and resident, read from its record, so a supersession
    /// keeps its key; a manifest is its id; a config is its owner. `None` for
    /// [`Self::Unknown`] and for a skill whose record no longer reads: neither names one.
    pub(crate) fn identity(&self, vault: &Vault) -> Result<Option<Vec<u8>>> {
        Ok(match self {
            Self::Skill { skill, .. } => {
                let Some(record) = vault.get_skill_record(skill)? else {
                    return Ok(None);
                };
                let mut bytes = b"skill\0".to_vec();
                bytes.extend_from_slice(&(record.skill_id.len() as u64).to_be_bytes());
                bytes.extend_from_slice(record.skill_id.as_bytes());
                if let Some(resident) = crate::skill::resident_of(&record)? {
                    bytes.extend_from_slice(resident.as_bytes());
                }
                Some(bytes)
            }
            Self::PolicyManifest { manifest, .. } => Some(
                [
                    b"policy_manifest\0".as_slice(),
                    manifest.as_bytes().as_slice(),
                ]
                .concat(),
            ),
            Self::Config { owner, .. } => Some([b"config\0".as_slice(), owner.as_bytes()].concat()),
            Self::Unknown => None,
        })
    }
}

/// A drafted fix of a policy-manifest or config producer (OF-418 L3): a suggested delta
/// against the exact target and base revision it was asked about, with why. It is filed
/// inside a proposed claim for the owner and never applied: nothing here applies a manifest
/// or a config.
#[derive(Debug, Clone, PartialEq)]
pub struct ProducerFixDraft {
    /// The target the author was asked about, as it was given.
    pub target: ProducerTarget,
    /// The base revision the delta is against, as [`ProducerTarget::base_revision`] gave it.
    pub base_revision: String,
    /// The proposed manifest or config delta, a JSON object; `None` when the author declines.
    pub delta: Option<serde_json::Value>,
    /// Why the evidence supports the delta, or why it supports none.
    pub rationale: String,
}

/// The recorded links a finding carries to what produced it (OF-418 L3).
pub(crate) struct ProducerLinks {
    /// The attempts it links.
    pub(crate) attempts: Vec<AttemptId>,
    /// The policy manifests it links.
    pub(crate) manifests: Vec<EntityId>,
}

/// The producer a finding's recorded links prove (OF-418 L3), under one binding rule: the one
/// active skill the one linked attempt loaded, by the heal's own ruled rule; else the one
/// linked live policy manifest, at its stored row's digest; else the config every run of
/// `runs` recorded it ran under, when each recorded the same one; else `Unknown`. A result is
/// never taken for its producer, and nothing is guessed.
pub(crate) fn bind_producer(
    vault: &Vault,
    runs: &[RetrievalRunRecord],
    links: &ProducerLinks,
) -> Result<ProducerTarget> {
    if let [attempt] = links.attempts.as_slice()
        && let Some(skill) = run_target(vault, *attempt)?
        && let Some(record) = vault.get_skill_record(&skill)?
    {
        return Ok(ProducerTarget::Skill {
            skill,
            version: record.version,
            attempt: EntityId::from_bytes(*attempt.as_bytes())?,
        });
    }
    if let [manifest] = links.manifests.as_slice()
        && let Some(raw) = vault.get_raw(manifest)?
        && EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
        && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
    {
        return Ok(ProducerTarget::PolicyManifest {
            manifest: *manifest,
            revision: *blake3::hash(body).as_bytes(),
        });
    }
    let mut configs = runs
        .iter()
        .map(|run| run.replay_inputs.as_ref().map(|inputs| &inputs.config));
    if let Some(Some(first)) = configs.next()
        && !first.is_null()
        && configs.all(|config| config == Some(first))
    {
        let bytes = serde_json::to_vec(first)
            .map_err(|_| Error::InvariantViolation("retrieval replay config encode"))?;
        return Ok(ProducerTarget::Config {
            owner: RETRIEVAL_REPLAY_CONFIG.to_owned(),
            digest: *blake3::hash(&bytes).as_bytes(),
        });
    }
    Ok(ProducerTarget::Unknown)
}

impl Vault {
    /// One waiting model issue of an Issues run, asked and filed under `pass` (OF-418 L3):
    /// the route question over the finding, its bound producer and what its window recorded
    /// of the cause, then, on `skill_edit`, its draft by target, filed as one proposed heal
    /// with its oversight count and settled marker. A failed decision waits for the next run,
    /// and its third failure goes to a person. An issue already settled files nothing.
    pub(super) fn coach_diagnostic_issue(
        &self,
        pass: &IssuesPass<'_, '_>,
        issue_id: EntityId,
        issue: &DiagnosticIssue,
    ) -> Result<IssueOutcome> {
        let runs = window_runs(self, issue)?;
        // OF-418 L10: what the finding's window recorded of its cause, beside it.
        let cause = self.heal_evidence_context(
            pass.decisions.principal,
            HealContextSeed::RetrievalWindow(&runs),
        );
        let evidence = [issue.diagnostic];
        let gate_decisions: Vec<String> = issue
            .gate_decisions
            .iter()
            .map(|id| bytes_to_hex_lower(id.as_slice()))
            .collect();
        let state = json!({
            "about": "model_diagnostic",
            "tier": issue.tier,
            "family": issue.family,
            "class": issue.class,
            "runs": issue.windows.len(),
            "runs_read": runs.len(),
            "gate_decisions": gate_decisions,
            "producer": issue.producer.value(),
            "untrusted_cause_context": cause.value(),
        });
        let (route, decided) = match pass.decisions.route(b"diagnostic", &evidence, &state) {
            Ok(Some(route)) => (route, "ladder"),
            Ok(None) => (HealRoute::Person, "abstained"),
            Err(_) if issue.retries.saturating_add(1) < ISSUE_RETRIES => {
                issue_work::defer_diagnostic_issue(self, &issue_id)?;
                return Ok(IssueOutcome::Deferred);
            }
            Err(_) => (HealRoute::Person, "unanswered"),
        };
        let mut repair = None;
        let mut producer_fix = serde_json::Value::Null;
        if route == HealRoute::SkillEdit {
            match &issue.producer {
                ProducerTarget::Skill { .. } => {
                    repair = Some(self.draft_coach_diagnostic_repair(
                        issue,
                        cause,
                        pass.author,
                        pass.attempt,
                        pass.now,
                    )?);
                }
                ProducerTarget::PolicyManifest { .. } | ProducerTarget::Config { .. } => {
                    let drafted = pass.author.draft_producer_fix(&issue.producer, &cause);
                    producer_fix = producer_fix_value(self, &issue.producer, drafted);
                }
                ProducerTarget::Unknown => {}
            }
        }
        let question =
            matches!(issue.producer, ProducerTarget::Unknown).then_some(UNBOUND_QUESTION);
        let windows: Vec<_> = issue
            .windows
            .iter()
            .map(|window| {
                json!({
                    "run": bytes_to_hex_lower(&window.run),
                    "replay": bytes_to_hex_lower(&window.replay),
                })
            })
            .collect();
        let mut value = json!({
            "issue": issue_id.to_hex(),
            "diagnostic": issue.diagnostic.to_hex(),
            "tier": issue.tier,
            "family": issue.family,
            "class": issue.class,
            "recipe_revision": bytes_to_hex_lower(&issue.recipe_revision),
            "context_digest": bytes_to_hex_lower(&issue.context_digest),
            "source_pins": issue.source_pins,
            "windows": windows,
            "gate_decisions": gate_decisions,
            "producer": issue.producer.value(),
            "route": route.as_str(),
            "decided": decided,
        });
        value["coordinate"] = json!({
            "content_hash": bytes_to_hex_lower(&issue.coordinate),
            "run": issue.run_ref,
        });
        value["decisions"] = serde_json::to_value(&issue.decisions).unwrap_or_default();
        value["recurrence_of"] = json!(issue.recurrence_of.map(|id| id.to_hex()));
        value["repair"] = json!(repair.as_ref().map(SkillRepairDraft::value));
        value["producer_fix"] = producer_fix;
        value["question"] = json!(question);
        let now = pass.now;
        let filed = self.with_write_txn_grouped(|txn| {
            if blocked_reports::settled_in_txn(self, &*txn, &issue_id)?.is_some() {
                return Ok(false);
            }
            if let Some(repair) = &repair
                && let Some(stale) = land_skill_repair_in_txn(
                    self,
                    txn,
                    repair,
                    COACH_ISSUES_FACET,
                    pass.attempt,
                    now,
                )?
            {
                value["repair"] = stale;
            }
            let proposal = proposals::emit_in_txn(
                self,
                txn,
                pass.subject,
                COACH_DIAGNOSTIC_PROPOSAL_PREDICATE,
                &value,
                &evidence,
                pass.envelope,
                now,
            )?;
            crate::failure_ladder::oversight::proposed_in_txn(self, txn, &issue_id.to_hex(), now)?;
            crate::failure_ladder::oversight::routed_in_txn(self, txn, &issue_id.to_hex(), now)?;
            blocked_reports::record_issue_settled_in_txn(self, txn, &issue_id, proposal, now)?;
            Ok(true)
        })?;
        Ok(if filed {
            IssueOutcome::Filed
        } else {
            IssueOutcome::Nothing
        })
    }
}

/// The finding's window as it reads now, oldest first: each run whose record still replays to
/// the hash it was graded at. A run gone or changed is left out, and the cause context marks
/// what it could not read; neither refuses the issue.
fn window_runs(vault: &Vault, issue: &DiagnosticIssue) -> Result<Vec<RetrievalRunRecord>> {
    let mut runs = Vec::with_capacity(issue.windows.len());
    for window in &issue.windows {
        let Some(run) = vault
            .store
            .retrieval_run(RetrievalRunId::from_bytes(window.run))?
        else {
            continue;
        };
        if rmp_serde::to_vec_named(&run)
            .is_ok_and(|bytes| *blake3::hash(&bytes).as_bytes() == window.replay)
        {
            runs.push(run);
        }
    }
    Ok(runs)
}

/// A drafted producer fix as the proposal carries it (OF-418 L3): the delta against the exact
/// target and base it was asked about, or its decline, whole and measured; or, for a failed
/// author or a draft about another target or base, what was skipped and why.
fn producer_fix_value(
    vault: &Vault,
    target: &ProducerTarget,
    drafted: Result<ProducerFixDraft>,
) -> serde_json::Value {
    let skipped = |why: &str| json!({ "target": target.value(), "skipped": why });
    let Ok(draft) = drafted else {
        return skipped("author_failed");
    };
    if draft.target != *target
        || target.base_revision().as_deref() != Some(draft.base_revision.as_str())
        || draft.rationale.trim().is_empty()
        || draft.delta.as_ref().is_some_and(|delta| !delta.is_object())
    {
        return skipped("unusable_draft");
    }
    // The draft goes whole: past `limits.maintenance_text_bytes` it asks.
    let delta = draft
        .delta
        .as_ref()
        .and_then(|delta| serde_json::to_vec(delta).ok())
        .map_or(0, |bytes| bytes.len());
    let _ = vault.measure_limit(
        EngineLimit::MaintenanceTextBytes,
        delta.max(draft.rationale.len()) as u64,
    );
    match draft.delta {
        Some(delta) => json!({
            "target": target.value(),
            "base_revision": draft.base_revision,
            "delta": delta,
            "rationale": draft.rationale,
        }),
        None => json!({
            "target": target.value(),
            "base_revision": draft.base_revision,
            "declined": draft.rationale,
        }),
    }
}

/// What proves a producer's revision in force (OF-418 L3), kept whole in an issue's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EffectProof {
    /// The skill's admitted head, reached from the base revision through its succession.
    Skill {
        /// The head revision, active and loading as canon.
        head: EntityId,
        /// Its version.
        version: String,
        /// The revisions after the base, oldest first, ending at the head.
        succession: Vec<EntityId>,
        /// When the head superseded its predecessor; `None` for a base revised in place.
        superseded_at: Option<u64>,
    },
    /// The manifest's row while the resolved policy reads it, trusted.
    PolicyManifest {
        /// The manifest.
        manifest: EntityId,
        /// blake3 of its stored row.
        revision: [u8; 32],
        /// Every trusted manifest the resolution reads, by id and row digest.
        trusted_contributors: Vec<(EntityId, [u8; 32])>,
    },
    /// The config the newest unbroken streak of an issue's windows recorded, each run's
    /// record the owner's receipt of the config it ran under.
    Config {
        /// Whose config it is.
        owner: String,
        /// blake3 of the recorded config.
        digest: [u8; 32],
        /// The first run of that streak.
        first_run: [u8; 16],
        /// When it started.
        first_started_at: u64,
    },
}

impl EffectProof {
    /// The proof as a resolution's value reads it, engine-authored.
    pub(crate) fn value(&self) -> serde_json::Value {
        match self {
            Self::Skill {
                head,
                version,
                succession,
                superseded_at,
            } => json!({
                "kind": "skill",
                "head": head.to_hex(),
                "version": version,
                "succession": succession.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                "superseded_at": superseded_at,
            }),
            Self::PolicyManifest {
                manifest,
                revision,
                trusted_contributors,
            } => json!({
                "kind": "policy_manifest",
                "manifest": manifest.to_hex(),
                "revision": bytes_to_hex_lower(revision),
                "trusted_contributors": trusted_contributors
                    .iter()
                    .map(|(id, digest)| json!({
                        "manifest": id.to_hex(),
                        "revision": bytes_to_hex_lower(digest),
                    }))
                    .collect::<Vec<_>>(),
            }),
            Self::Config {
                owner,
                digest,
                first_run,
                first_started_at,
            } => json!({
                "kind": "config",
                "owner": owner,
                "revision": bytes_to_hex_lower(digest),
                "first_run": bytes_to_hex_lower(first_run),
                "first_started_at": first_started_at,
            }),
        }
    }
}

/// The revision of a producer in force now, as [`issue_effective_revision`] proves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectiveRevision {
    /// In force at `revision`, spelled as [`ProducerTarget::base_revision`] spells it.
    InForce {
        /// The revision.
        revision: String,
        /// The first second a record stamps it in force from; `None` when no record stamps
        /// when it took effect.
        from: Option<u64>,
        /// The exact refs that prove it.
        proof: EffectProof,
    },
    /// Nothing proves which revision is in force: an issue on it stays unresolved.
    Unknown,
}

/// The revision of `producer` in force now (OF-418 L3), joined from exact refs on `txn`, never
/// from a drafted candidate: a skill's admitted head through its recorded succession from the
/// base revision, stamped by the supersession; a policy manifest's row while the resolved
/// policy is not fail-closed and reads it, trusted and contributing; a config's digest as the
/// newest unbroken streak of `windows` recorded it, each run's record the owner's receipt, in
/// force from that streak's first run. `Unknown` when no ref proves one.
pub(crate) fn issue_effective_revision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    producer: &ProducerTarget,
    windows: &[&WindowJudgment],
) -> Result<EffectiveRevision> {
    match producer {
        ProducerTarget::Skill { skill, .. } => skill_in_force(vault, txn, *skill),
        ProducerTarget::PolicyManifest { manifest, .. } => manifest_in_force(vault, txn, *manifest),
        ProducerTarget::Config { owner, .. } => Ok(config_in_force(owner, windows)),
        ProducerTarget::Unknown => Ok(EffectiveRevision::Unknown),
    }
}

/// The skill revision in force for `base`: the base itself while it loads as canon; else the
/// head its `Supersedes` succession reaches, when that head loads as canon as the same skill
/// of the same resident, stamped from the second after the head superseded its predecessor.
fn skill_in_force(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    base: EntityId,
) -> Result<EffectiveRevision> {
    let Some(record) = vault.get_skill_record_in_txn(txn, &base)? else {
        return Ok(EffectiveRevision::Unknown);
    };
    if record.lifecycle_status.loads_as_canon() {
        return Ok(EffectiveRevision::InForce {
            proof: EffectProof::Skill {
                head: base,
                version: record.version.clone(),
                succession: Vec::new(),
                superseded_at: None,
            },
            revision: record.version,
            from: None,
        });
    }
    if record.lifecycle_status != SkillLifecycle::Superseded {
        return Ok(EffectiveRevision::Unknown);
    }
    let mut head = base;
    let mut seen = BTreeSet::from([base]);
    let mut succession = Vec::new();
    let mut superseded_at = None;
    loop {
        let newer = vault.filtered_edge_peers(
            txn,
            EdgeDirection::In,
            &head,
            EdgeKind::Supersedes,
            Some(ENTITY_TYPE_SKILL),
        )?;
        // Admitted succession is linear; the least id settles a fork in it.
        let Some(next) = newer.into_iter().filter(|id| !seen.contains(id)).min() else {
            break;
        };
        superseded_at = vault
            .store
            .port_edge_get(txn, &next, EdgeKind::Supersedes, &head)?
            .map(|edge| edge.created_at);
        seen.insert(next);
        succession.push(next);
        head = next;
    }
    let Some(stamp) = superseded_at else {
        return Ok(EffectiveRevision::Unknown);
    };
    let Some(current) = vault.get_skill_record_in_txn(txn, &head)? else {
        return Ok(EffectiveRevision::Unknown);
    };
    if !current.lifecycle_status.loads_as_canon()
        || current.skill_id != record.skill_id
        || crate::skill::resident_of(&current)? != crate::skill::resident_of(&record)?
    {
        return Ok(EffectiveRevision::Unknown);
    }
    Ok(EffectiveRevision::InForce {
        revision: current.version.clone(),
        from: Some(stamp.saturating_add(1)),
        proof: EffectProof::Skill {
            head,
            version: current.version,
            succession,
            superseded_at: Some(stamp),
        },
    })
}

/// The manifest's row in force: present, read by a resolved policy that is not fail-closed,
/// and among its contributors, trusted; each revision its body's digest (FIX 7344). It is in
/// force from the second this vault first trusted that body, which a rewrite of the same body
/// keeps (FIX 10936); the row's own time moves with any such rewrite, so it is never read. A
/// stamp with no time (the bootstrap seed's) counts from the pass that first proves it.
fn manifest_in_force(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    manifest: EntityId,
) -> Result<EffectiveRevision> {
    let Some(raw) = vault.get_raw_in(txn, &manifest)? else {
        return Ok(EffectiveRevision::Unknown);
    };
    if crate::gate::resolve_policy_manifest(&vault.store, txn)?
        .diagnostics
        .is_fail_closed()
    {
        return Ok(EffectiveRevision::Unknown);
    }
    let contributors = crate::gate::policy_manifest_contributors(&vault.store, txn)?;
    // Every contributor is read: past its threshold row the read asks and reads on.
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, contributors.len() as u64);
    let mut trusted_contributors = Vec::new();
    for id in &contributors {
        let Some(row) = vault.get_raw_in(txn, id)? else {
            continue;
        };
        let Some(body) = row.get(ENTITY_METADATA_HEADER_LEN..) else {
            continue;
        };
        if crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, id, body)? {
            trusted_contributors.push((*id, *blake3::hash(body).as_bytes()));
        }
    }
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(EffectiveRevision::Unknown);
    };
    let revision = *blake3::hash(body).as_bytes();
    if !trusted_contributors.contains(&(manifest, revision)) {
        return Ok(EffectiveRevision::Unknown);
    }
    let from = crate::gate::manifest_authenticity::manifest_trusted_at(
        &vault.store,
        txn,
        &manifest,
        body,
    )?;
    Ok(EffectiveRevision::InForce {
        revision: bytes_to_hex_lower(&revision),
        from,
        proof: EffectProof::PolicyManifest {
            manifest,
            revision,
            trusted_contributors,
        },
    })
}

/// The config of `owner` in force by its receipts: the digest the newest of `windows` recorded,
/// from the first run of the unbroken streak of windows that recorded it. Windows whose runs
/// disagree or record none bind no config and read as nothing here.
fn config_in_force(owner: &str, windows: &[&WindowJudgment]) -> EffectiveRevision {
    let mut recorded: Vec<(u64, [u8; 16], [u8; 32])> = windows
        .iter()
        .filter_map(|window| match &window.producer {
            ProducerTarget::Config { owner: by, digest } if by == owner => window
                .runs
                .first()
                .map(|run| (run.started_at, run.run, *digest)),
            _ => None,
        })
        .collect();
    recorded.sort_unstable();
    let Some(&(_, _, newest)) = recorded.last() else {
        return EffectiveRevision::Unknown;
    };
    let start = recorded
        .iter()
        .rposition(|(.., digest)| *digest != newest)
        .map_or(0, |before| before + 1);
    let Some(&(first_started_at, first_run, _)) = recorded.get(start) else {
        return EffectiveRevision::Unknown;
    };
    EffectiveRevision::InForce {
        revision: bytes_to_hex_lower(&newest),
        from: Some(first_started_at),
        proof: EffectProof::Config {
            owner: owner.to_owned(),
            digest: newest,
            first_run,
            first_started_at,
        },
    }
}
