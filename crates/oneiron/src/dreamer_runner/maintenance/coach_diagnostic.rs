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
//! its third failure goes to a person.
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::coach::COACH_ISSUES_FACET;
use super::coach_heal::{HealRoute, ISSUE_RETRIES, IssueOutcome, IssuesPass};
use super::coach_repair::{SkillRepairDraft, land_skill_repair_in_txn, run_target};
use super::proposals;
use crate::attempt_queue::AttemptId;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::self_heal::HealContextSeed;
use crate::self_heal::blocked_reports;
use crate::self_heal::issue_work::{self, DiagnosticIssue};
use crate::store::{RetrievalRunId, RetrievalRunRecord};
use crate::{EntityId, Error, Result, Vault};

/// Predicate of a proposed heal for a model finding's issue (OF-418 L3).
pub const COACH_DIAGNOSTIC_PROPOSAL_PREDICATE: &str = "coach.diagnostic.proposal";
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
        /// blake3 of its stored row when the finding was filed: the base a fix is against.
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

    /// Which producer it is, whatever its revision: the bytes a recurrence is keyed by.
    /// `None` for [`Self::Unknown`], which names no producer.
    pub(crate) fn identity(&self) -> Option<Vec<u8>> {
        match self {
            Self::Skill { skill, .. } => {
                Some([b"skill\0".as_slice(), skill.as_bytes().as_slice()].concat())
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
        }
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
    {
        return Ok(ProducerTarget::PolicyManifest {
            manifest: *manifest,
            revision: *blake3::hash(&raw).as_bytes(),
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
