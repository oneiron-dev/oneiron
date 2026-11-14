//! The engine side of the reference-model test: one real vault that takes
//! each generated [`Step`] through the public calls a host makes, and reads
//! its state back through other doors into an [`Observed`] that the
//! [`VaultModel`] invariants judge.
//!
//! The acts:
//! - the owner's claim write, `Memory::claim_upsert`, and an agent's
//!   proposal, `Memory::claim_propose`, under the owner's read-and-propose
//!   grant (`Vault::grant_foreign_principal`);
//! - the owner's settlement: `claim_review_as_owner`, then
//!   `claim_settle_as_owner` with that review's id;
//! - identity merge (read-through) and split, `Vault::apply_identity_topology_op`;
//! - the owner's user delete, `Memory::safe_delete`;
//! - a restart: the vault is dropped and opened again on the same directory,
//!   clock and keystore, and the owner proves itself again.
//!
//! The design (verdict 52, section 5 item 1) names `verbs::invoke`. Merge and
//! split are host-only on the embedded handle, and settlement takes the id
//! of the owner's review, so this step calls the typed public doors the
//! regression tests of both defects call (`claim_settle_supersession.rs`,
//! `split_reads_through_merges.rs`).
//!
//! The reads, never the acting call's reply: each claim's stored body
//! (`Vault::get_claim`: approval, lifecycle, end time and the scope axes),
//! its `Supersedes` edge, its tombstone (`Vault::is_deleted_shell`), and the
//! topology readers `Vault::claims_assigned_to` and
//! `Vault::claims_remaining_on_origin`. Membership reads keep only the
//! claims the steps wrote: claims the engine writes itself are outside the
//! model.
//!
//! Not observed in this step: what each actor's read returns
//! ([`Observed::visible`]) and the held-claims view ([`Observed::held`]),
//! which no engine reader states.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    ReassignmentEntry, ReassignmentMap, ReassignmentTarget, SplitOp, SurvivorshipPlan,
};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    SafeDeleteReason, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault,
};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

use crate::clock::{FAKE_EPOCH, FakeClock};
use crate::model::generator::{Step, sequence};
use crate::model::{
    Aud, ClaimKey, Ent, Observed, Outcome, QKey, Question, Status, Universe, VaultModel,
};

/// The predicate each model question slot binds. Each is a single-valued
/// `profile.` predicate, which the default policy rates `normal`: the
/// owner's write lands standing and replaces the question's head
/// (ARCH-0044 S3).
pub const QUESTION_PREDICATES: [&str; 3] = ["profile.name", "profile.city", "profile.note"];

/// The model's persons are PERSON rows `[PERSON_ID_BASE + n; 16]`.
const PERSON_ID_BASE: u8 = 0x61;

/// When every person and claim of the fixture becomes valid.
const BORN: TimeRange = TimeRange {
    start: 100,
    end: 100,
};

/// The fixture host's root secret: a fixed test value, so every open
/// derives the same host issuer and the rooted vault recognises its host.
const HOST_ISSUER_SECRET: &[u8] = b"oneiron-testkit reference-model host";

/// A supersedes edge to a claim the steps never wrote, or more than one.
const UNKNOWN_CLAIM: ClaimKey = ClaimKey(0);

/// A real vault holding the model's universe, and the engine id of each
/// model claim.
pub struct EngineVault {
    /// `None` only while a restart reopens it.
    vault: Option<Vault>,
    clock: FakeClock,
    keystore: Arc<MemoryKeystore>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    agents: Vec<EntityId>,
    persons: Vec<EntityId>,
    /// The facet each audience's claims are written in: `[private, shared]`.
    facets: Vec<EntityId>,
    claims: BTreeMap<ClaimKey, EntityId>,
    questions: BTreeMap<ClaimKey, Question>,
    /// Each claim's scope axes as first read back after its write.
    birth_axes: BTreeMap<ClaimKey, String>,
    /// Dropped last, after the vault.
    directory: tempfile::TempDir,
}

impl EngineVault {
    /// A fresh vault holding `universe`: the owner, one agent definition per
    /// model agent, created by the owner and holding the owner's
    /// read-and-propose grant, one PERSON per model entity, and two
    /// audiences. `Aud(0)` is a facet the owner creates, which only
    /// the owner writes in; `Aud(1)` is the vault's default facet, where the
    /// agents propose.
    pub fn new(universe: &Universe) -> Result<Self, String> {
        if universe.audiences != 2 || usize::from(universe.predicates) > QUESTION_PREDICATES.len() {
            return Err(format!(
                "the engine fixture binds two audiences and at most {} predicates",
                QUESTION_PREDICATES.len()
            ));
        }
        let directory = tempfile::tempdir().map_err(|error| format!("vault dir: {error}"))?;
        let clock = FakeClock::at(FAKE_EPOCH);
        let keystore = Arc::new(MemoryKeystore::new());
        let vault = open(&directory, &clock, &keystore)?;
        eprintln!("## PF-OPEN {}", fd_census(directory.path()));
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| format!("the embedded owner: {error:?}"))?;
        let owner_proof = authenticate(&vault, owner)?;
        let mut agents = Vec::new();
        for n in 0..universe.agents {
            // The owner creates the agent through the owner's create door,
            // which stamps the owner as its creator, so the owner's later
            // correction supersedes the agent's approved claim. A bare
            // PERSON holding a Grant is no agent of the owner's: the engine
            // refuses that correction and keeps the claim for review.
            let agent = clock
                .store_clock()
                .entity_id()
                .map_err(|error| format!("agent {n} id: {error:?}"))?;
            create_agent_definition_as(
                &vault,
                &owner_proof,
                AgentDefinitionCreateRequest {
                    agent_def_ref: agent,
                    definition: serde_json::from_value(json!({
                        "agent_id": format!("model-agent-{n}"),
                        "desc": "A reference-model agent",
                        "version": "1.0.0",
                        "ceiling": "auto",
                        "enabled": true,
                    }))
                    .map_err(|error| format!("agent {n} definition: {error}"))?,
                },
            )
            .map_err(|error| format!("the owner creates agent {n}: {error:?}"))?;
            vault
                .grant_foreign_principal(&owner_proof, &agent.to_hex())
                .map_err(|error| format!("the owner grants agent {n}: {error:?}"))?;
            agents.push(agent);
        }
        let mut persons = Vec::new();
        for n in 0..universe.persons {
            let person = EntityId::from_bytes([PERSON_ID_BASE + n; 16])
                .map_err(|error| format!("person {n} id: {error:?}"))?;
            vault
                .put_entity(
                    &person,
                    ENTITY_TYPE_PERSON,
                    BORN,
                    BORN.start,
                    b"model person",
                )
                .map_err(|error| format!("person {n}: {error:?}"))?;
            persons.push(person);
        }
        let private = vault
            .create_facet(
                &owner_proof,
                owner,
                "model-private-audience",
                vault.now_recorded_at(),
            )
            .map_err(|error| format!("the private audience's facet: {error:?}"))?;
        let shared = vault
            .default_facet()
            .map_err(|error| format!("the default facet: {error:?}"))?;
        Ok(Self {
            vault: Some(vault),
            clock,
            keystore,
            owner,
            owner_proof,
            agents,
            persons,
            facets: vec![private, shared],
            claims: BTreeMap::new(),
            questions: BTreeMap::new(),
            birth_axes: BTreeMap::new(),
            directory,
        })
    }

    /// Applies `step` through the engine's public calls, then moves the clock
    /// one second. An error names the call that failed and its answer.
    pub fn apply(&mut self, step: &Step) -> Result<(), String> {
        let result = match step {
            Step::OwnerWrite {
                claim,
                subject,
                question,
                value,
                aud,
            } => self.write(None, *claim, *subject, *question, *value, *aud),
            Step::AgentPropose {
                agent,
                claim,
                subject,
                question,
                value,
                aud,
            } => self.write(Some(*agent), *claim, *subject, *question, *value, *aud),
            Step::OwnerApprove { claim } => self.settle(*claim, ClaimSettleDecision::Approve),
            Step::OwnerReject { claim } => self.settle(*claim, ClaimSettleDecision::Reject),
            Step::Merge { sources, survivor } => self.merge(sources, *survivor),
            Step::Split {
                entity,
                heads,
                assign,
            } => self.split(*entity, heads, assign),
            Step::Delete { claim } => self.delete(*claim),
            Step::Restart => self.restart(),
        };
        self.clock.advance(1);
        result
    }

    fn vault(&self) -> Result<&Vault, String> {
        self.vault
            .as_ref()
            .ok_or_else(|| "the vault is closed".to_owned())
    }

    fn person(&self, entity: Ent) -> Result<EntityId, String> {
        self.persons
            .get(usize::from(entity.0))
            .copied()
            .ok_or_else(|| format!("no person for {entity:?}"))
    }

    fn claim(&self, claim: ClaimKey) -> Result<EntityId, String> {
        self.claims
            .get(&claim)
            .copied()
            .ok_or_else(|| format!("no engine claim for {claim:?}"))
    }

    /// The owner's write (`agent` None) or an agent's proposal of one answer
    /// to one question in one audience.
    fn write(
        &mut self,
        agent: Option<u8>,
        claim: ClaimKey,
        subject: Ent,
        question: QKey,
        value: u32,
        aud: Aud,
    ) -> Result<(), String> {
        let predicate = QUESTION_PREDICATES
            .get(usize::from(question.0))
            .ok_or_else(|| format!("no predicate for {question:?}"))?;
        let facet = self
            .facets
            .get(usize::from(aud.0))
            .ok_or_else(|| format!("no facet for {aud:?}"))?;
        let input = ClaimInput {
            id: None,
            predicate: (*predicate).to_owned(),
            subject_ref: self.person(subject)?.to_hex(),
            value: json!(format!("model answer {value}")),
            confidence: 1.0,
            confidence_details: None,
            source: if agent.is_some() {
                "inferred"
            } else {
                "user_stated"
            }
            .to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": facet.to_hex() })),
            valid_from: Some(BORN.start),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        let vault = self.vault()?;
        let receipt = match agent {
            None => vault
                .memory(self.owner, EdgeActorClass::Human)
                .claim_upsert(&input)
                .map_err(|error| format!("the owner's claim_upsert: {error:?}"))?,
            Some(n) => {
                let agent = self
                    .agents
                    .get(usize::from(n))
                    .ok_or_else(|| format!("no agent {n}"))?;
                vault
                    .memory(*agent, EdgeActorClass::Agent)
                    .claim_propose(&input)
                    .map_err(|error| format!("agent {n}'s claim_propose: {error:?}"))?
            }
        };
        let id = resolve_entity_ref(vault, &receipt.claim_short_id)
            .map_err(|error| format!("resolve {}: {error:?}", receipt.claim_short_id))?;
        if let Ok(Some(body)) = vault.get_claim(&id) {
            self.birth_axes.insert(claim, scope_axes(&body));
        }
        self.claims.insert(claim, id);
        self.questions.insert(
            claim,
            Question {
                subject,
                predicate: question,
                audience: aud,
            },
        );
        Ok(())
    }

    /// The owner reviews the proposal, then settles it with that review.
    fn settle(&self, claim: ClaimKey, decision: ClaimSettleDecision) -> Result<(), String> {
        let id = self.claim(claim)?;
        let owner = self.vault()?.memory(self.owner, EdgeActorClass::Human);
        let review = owner
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .map_err(|error| format!("claim_review_as_owner: {error:?}"))?;
        owner
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision,
                    grant_ref: None,
                },
            )
            .map_err(|error| format!("claim_settle_as_owner: {error:?}"))?;
        Ok(())
    }

    fn merge(&self, sources: &[Ent], survivor: Ent) -> Result<(), String> {
        let sources = sources
            .iter()
            .map(|source| self.person(*source))
            .collect::<Result<Vec<_>, _>>()?;
        self.topology(&IdentityTopologyOp::Merge(MergeOp {
            sources,
            survivor: self.person(survivor)?,
            evidence: evidence(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }))
    }

    fn split(&self, entity: Ent, heads: &[Ent], assign: &[(ClaimKey, Ent)]) -> Result<(), String> {
        let heads = heads
            .iter()
            .map(|head| self.person(*head))
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = Vec::new();
        for (claim, head) in assign {
            entries.push(ReassignmentEntry {
                item: ClaimSubject::Entity(self.claim(*claim)?),
                target: ReassignmentTarget::Head(self.person(*head)?),
            });
        }
        self.topology(&IdentityTopologyOp::Split(SplitOp {
            entity: self.person(entity)?,
            heads,
            reassignment: ReassignmentMap { entries },
            evidence: evidence(),
        }))
    }

    fn topology(&self, op: &IdentityTopologyOp) -> Result<(), String> {
        let write = IdentityOpWrite::auto(ClaimSource::Inferred);
        match self
            .vault()?
            .apply_identity_topology_op(op, &write, self.clock.now())
        {
            Ok(IdentityOpOutcome::Applied { .. }) => Ok(()),
            Ok(other) => Err(format!("the identity op did not apply: {other:?}")),
            Err(error) => Err(format!("apply_identity_topology_op: {error:?}")),
        }
    }

    fn delete(&self, claim: ClaimKey) -> Result<(), String> {
        let id = self.claim(claim)?;
        self.vault()?
            .memory(self.owner, EdgeActorClass::Human)
            .safe_delete(&id.to_hex(), SafeDeleteReason::UserDelete)
            .map_err(|error| format!("the owner's safe_delete: {error:?}"))?;
        Ok(())
    }

    /// Drops the vault and opens it again: same directory, clock and
    /// keystore. The owner is the same actor and proves itself again.
    fn restart(&mut self) -> Result<(), String> {
        drop(self.vault.take());
        let after_drop = fd_census(self.directory.path());
        let vault = open(&self.directory, &self.clock, &self.keystore)?;
        eprintln!(
            "## PF-RESTART after_drop {after_drop} after_open {}",
            fd_census(self.directory.path())
        );
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| format!("the embedded owner after the restart: {error:?}"))?;
        if owner != self.owner {
            return Err(format!(
                "the owner changed across the restart: {} then {}",
                self.owner.to_hex(),
                owner.to_hex()
            ));
        }
        self.owner_proof = authenticate(&vault, owner)?;
        self.vault = Some(vault);
        Ok(())
    }

    /// The engine's state read back, keyed by the model's ids: every claim's
    /// status, supersedes link and audience, each question's standing heads,
    /// the live claims, every entity's assigned claims and the remaining
    /// claims of every entity not merged into another (`model` names the
    /// entities and their merges).
    pub fn observe(&self, model: &VaultModel) -> Result<Observed, String> {
        let vault = self.vault()?;
        let mut observed = Observed::default();
        let mut live = Vec::new();
        let mut live_ids = BTreeSet::new();
        for question in self.questions.values() {
            observed.standing_heads.entry(*question).or_default();
        }
        for (&key, id) in &self.claims {
            let deleted = vault
                .is_deleted_shell(id)
                .map_err(|error| format!("is_deleted_shell {key:?}: {error:?}"))?;
            if deleted {
                observed.statuses.insert(key, Some(Status::Deleted));
                continue;
            }
            // A read error is an invalid row, as an absent one is.
            let Ok(Some(body)) = vault.get_claim(id) else {
                observed.statuses.insert(key, None);
                continue;
            };
            let status = status_of(&body);
            observed.statuses.insert(key, status);
            observed
                .supersedes
                .insert(key, self.supersedes_of(vault, id)?);
            observed.audience.insert(key, self.audience_of(key, &body));
            if status == Some(Status::Standing)
                && let Some(question) = self.questions.get(&key)
            {
                observed
                    .standing_heads
                    .entry(*question)
                    .or_default()
                    .push(key);
            }
            live.push(key);
            live_ids.insert(*id);
        }
        observed.live = Some(live);
        for (entity, state) in model.entities() {
            let person = self.person(*entity)?;
            let assigned = vault
                .claims_assigned_to(&person)
                .map_err(|error| format!("claims_assigned_to {entity:?}: {error:?}"))?;
            observed
                .assigned
                .insert(*entity, self.model_keys(&assigned, &live_ids));
            if state.merged_into.is_none() {
                let remaining = vault
                    .claims_remaining_on_origin(&person)
                    .map_err(|error| format!("claims_remaining_on_origin {entity:?}: {error:?}"))?;
                observed
                    .remaining
                    .insert(*entity, self.model_keys(&remaining, &live_ids));
            }
        }
        Ok(observed)
    }

    /// The claim `id` supersedes, by its `Supersedes` edge.
    fn supersedes_of(&self, vault: &Vault, id: &EntityId) -> Result<Option<ClaimKey>, String> {
        let targets = vault
            .targets(id, EdgeKind::Supersedes, None)
            .map_err(|error| format!("supersedes edges of {}: {error:?}", id.to_hex()))?;
        Ok(match targets.as_slice() {
            [] => None,
            [target] => Some(
                self.claims
                    .iter()
                    .find(|(_, claim)| *claim == target)
                    .map_or(UNKNOWN_CLAIM, |(key, _)| *key),
            ),
            _ => Some(UNKNOWN_CLAIM),
        })
    }

    /// The claim's audience while it keeps its audience's facet and the
    /// scope axes it was written with; [`Aud::ABSENT`] once either changed.
    fn audience_of(&self, key: ClaimKey, body: &ClaimBody) -> Aud {
        let Some(question) = self.questions.get(&key) else {
            return Aud::ABSENT;
        };
        let facet = self.facets.get(usize::from(question.audience.0));
        if facet == Some(&body.scope_facet) && self.birth_axes.get(&key) == Some(&scope_axes(body))
        {
            question.audience
        } else {
            Aud::ABSENT
        }
    }

    /// The model ids of the live claims among `ids`, sorted. Claims the
    /// steps never wrote are left out.
    fn model_keys(&self, ids: &[EntityId], live_ids: &BTreeSet<EntityId>) -> Vec<ClaimKey> {
        let mut keys = Vec::new();
        for (key, id) in &self.claims {
            if live_ids.contains(id) {
                // A claim the engine names twice counts twice: I1 fails on it.
                keys.extend(ids.iter().filter(|seen| *seen == id).map(|_| *key));
            }
        }
        keys.sort_unstable();
        keys
    }
}

/// PAGE-FULL probe (lane branch only): the process's open descriptors on
/// files under `dir`, by path relative to it, and the process's thread count.
pub fn fd_census(dir: &std::path::Path) -> String {
    let root = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    if let Ok(relative) = target.strip_prefix(&root) {
                        *counts.entry(format!("/{}", relative.display())).or_default() += 1;
                    }
                }
            }
        }
        Err(error) => return format!("fds=unavailable({error})"),
    }
    let threads = std::fs::read_dir("/proc/self/task").map_or(0, Iterator::count);
    format!("fds={counts:?} threads={threads}")
}

fn open(
    directory: &tempfile::TempDir,
    clock: &FakeClock,
    keystore: &Arc<MemoryKeystore>,
) -> Result<Vault, String> {
    let mut config = clock.vault_config();
    config.map_size = 64 * 1024 * 1024;
    let vault =
        Vault::open(directory.path(), config).map_err(|error| format!("open: {error:?}"))?;
    // A host loads this install's signing keys from its keystore after each
    // open; merge, split and delete sign with them.
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(keystore));
    vault
        .prepare_install_signing()
        .map_err(|error| format!("this install's signing keys: {error:?}"))?;
    // As a served vault is: rooted under its host, which binds the embedded
    // owner as `human`, with the engine's machine signers and a live profile
    // of this install. Each call after the first open only reuses the root,
    // retains the signers and finds the profile standing.
    let issuer = HostSlipIssuer::from_secret(HOST_ISSUER_SECRET)
        .map_err(|error| format!("the host issuer: {error:?}"))?;
    vault
        .ensure_host_root_slip(&issuer)
        .map_err(|error| format!("the host root: {error:?}"))?;
    vault
        .provision_engine_machine_identities(&issuer)
        .map_err(|error| format!("the engine machine signers: {error:?}"))?;
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(|error| format!("this install's machine profile: {error:?}"))?;
    Ok(vault)
}

/// The local host attests its own owner.
fn authenticate(vault: &Vault, owner: EntityId) -> Result<AuthenticatedOwner, String> {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .map_err(|error| format!("the owner's proof: {error:?}"))
}

fn evidence() -> IdentityOpEvidence {
    IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "reference-model step".to_owned(),
    }
}

/// The model status a stored claim reads as: standing is approved or auto,
/// active, open and not stale; superseded is closed with an end time.
/// Anything else is no model status (`None`).
fn status_of(body: &ClaimBody) -> Option<Status> {
    let open = body.valid_to.is_none();
    match (&body.approval, &body.lifecycle) {
        (ClaimApprovalStatus::Rejected, _) => Some(Status::Rejected),
        (ClaimApprovalStatus::Proposed, ClaimLifecycleStatus::Active) if open => {
            Some(Status::Proposed)
        }
        (
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        ) if open && !body.stale => Some(Status::Standing),
        (
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Superseded,
        ) if !open => Some(Status::Superseded),
        _ => None,
    }
}

/// The stored scope axes besides the facet: world, relationship set,
/// project and the scope object.
fn scope_axes(body: &ClaimBody) -> String {
    format!(
        "world {:?} relationship {:?} project {} scope {:?}",
        body.world,
        body.rel,
        body.scope_project.to_hex(),
        body.scope
    )
}

/// What [`check_seeds`] found: the first divergence of each seed that had
/// one, and how many steps of each kind the sequences held.
#[derive(Debug, Default)]
pub struct SeedReport {
    pub divergences: Vec<String>,
    pub steps: BTreeMap<&'static str, usize>,
}

impl SeedReport {
    /// How many steps of `kind` (a [`step_kind`] name) the sequences held.
    pub fn count(&self, kind: &str) -> usize {
        self.steps.get(kind).copied().unwrap_or_default()
    }
}

/// The name of a step's kind in a [`SeedReport`].
pub fn step_kind(step: &Step) -> &'static str {
    match step {
        Step::OwnerWrite { .. } => "owner_write",
        Step::AgentPropose { .. } => "agent_propose",
        Step::OwnerApprove { .. } => "owner_approve",
        Step::OwnerReject { .. } => "owner_reject",
        Step::Merge { .. } => "merge",
        Step::Split { .. } => "split",
        Step::Delete { .. } => "delete",
        Step::Restart => "restart",
    }
}

/// Runs the sequence of each seed in `seeds`, `len` steps over `universe`,
/// against the model and a fresh engine vault.
pub fn check_seeds(seeds: Range<u64>, len: usize, universe: &Universe) -> SeedReport {
    let mut report = SeedReport::default();
    for seed in seeds {
        let steps = sequence(seed, len, universe);
        for step in &steps {
            *report.steps.entry(step_kind(step)).or_default() += 1;
        }
        if let Err(divergence) = check_sequence(seed, &steps, universe) {
            report.divergences.push(divergence);
        }
    }
    report
}

/// Applies `steps` to the model and to a fresh engine vault, and checks
/// I1, I2 and I3 after each step. The error names the seed, the step and
/// the first invariant the engine broke, or the engine call that failed.
pub fn check_sequence(seed: u64, steps: &[Step], universe: &Universe) -> Result<(), String> {
    let mut model = VaultModel::new(universe);
    let mut engine =
        EngineVault::new(universe).map_err(|error| format!("seed {seed} setup: {error}"))?;
    for (index, step) in steps.iter().enumerate() {
        let at = || format!("seed {seed} step {index} {step:?}");
        let outcome = step.apply(&mut model);
        if outcome != Outcome::Applied {
            return Err(format!("{}: the model did not apply it: {outcome:?}", at()));
        }
        engine.apply(step).map_err(|error| {
            format!(
                "{}: the engine refused it: {error} [PF-CENSUS {}]",
                at(),
                fd_census(engine.directory.path())
            )
        })?;
        let observed = engine
            .observe(&model)
            .map_err(|error| format!("{}: read back: {error}", at()))?;
        model
            .i1_counts_conserve(&observed)
            .and_then(|()| model.i2_one_live_version(&observed))
            .and_then(|()| model.i3_no_audience_widens(&observed))
            .map_err(|violation| {
                format!("{}: {} {}", at(), violation.invariant, violation.message)
            })?;
    }
    Ok(())
}
