//! The world-scoped arm's pack vault: a rooted vault with a second world, a
//! corpus's records written as the owner's claims in the base world or that
//! world, and an agent whose one Grant reads the base world. It is
//! `crates/oneiron/tests/world_scope_bm25_hidden_postings.rs`'s fixture,
//! built from public items and the `test-support` doors (no test doors).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, CommitOutcome, ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_ruler::pack::{Corpus, LoadedPack};
use sha2::Digest;

use crate::scorecard::ScorecardFailure;
use crate::scorecard::run::{MAP_SIZE, pack_time};

/// The claim predicate of every record: one PERSON subject per record keeps
/// its single-valued key apart from every other record's.
const PREDICATE: &str = "profile.preference";

/// Sensitivity band 0, Public: the world axis alone keeps the second world's
/// claims from the agent.
const PUBLIC_BAND: u8 = 0;

/// Claims committed per atomic batch.
const CLAIM_BATCH: usize = 256;

/// The id domains of a record's claim and of its PERSON subject.
const CLAIM_DOMAIN: &[u8] = b"oneiron-bench.scorecard.world-scoped.claim\0";
const SUBJECT_DOMAIN: &[u8] = b"oneiron-bench.scorecard.world-scoped.subject\0";

/// The agent's request challenge and its pairing binding key seed.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:scorecard-world-scoped";
const BINDING_SEED: u8 = 0x77;

/// The agent's pairing link lifetime: it is paired after the corpus lands.
const PAIRING_TTL_SECS: u64 = 3_600;

/// One corpus's pack vault, its owner and its base-world agent.
pub(super) struct AgentVault {
    /// The vault; dropped before its directory.
    vault: Vault,
    /// The vault's directory, removed on drop.
    _dir: tempfile::TempDir,
    /// The test host root that rooted the vault.
    issuer: HostSlipIssuer,
    /// The embedded owner.
    owner: EntityId,
    /// The owner's host-authenticated proof.
    owner_proof: AuthenticatedOwner,
    /// The world the agent's Grant leaves out.
    second_world: EntityId,
    /// The agent the Grant names.
    agent: EntityId,
}

/// A record's mapped id and whether it sits in the second world.
pub(super) struct Placed {
    /// The pack record id.
    pub(super) record_id: String,
    /// True when the record's claim sits in the second world.
    pub(super) hidden: bool,
}

/// Map a store error to a run failure naming the step.
fn failed<E: std::fmt::Display>(step: &'static str) -> impl FnOnce(E) -> ScorecardFailure {
    move |error| ScorecardFailure::Run(format!("{step} failed: {error}"))
}

/// A record's id in `domain`: the first 16 bytes of sha256(domain || record id).
fn derived_id(domain: &[u8], record_id: &str) -> Result<EntityId, ScorecardFailure> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    hasher.update(record_id.as_bytes());
    let digest = hasher.finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(raw)
        .map_err(|error| ScorecardFailure::Run(format!("record {record_id} id failed: {error}")))
}

/// One record's claim input: the owner's Public claim in `world`.
fn claim_input(
    id: EntityId,
    subject: EntityId,
    world: EntityId,
    facet: &str,
    text: &str,
    moment: u64,
) -> ScopedClaimInput {
    ScopedClaimInput {
        id: Some(id.to_hex()),
        predicate: PREDICATE.to_owned(),
        subject_ref: subject.to_hex(),
        value: serde_json::Value::String(text.to_owned()),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        scope: ClaimScope {
            world_id: world.to_hex(),
            scope_facet_id: facet.to_owned(),
            scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
            scope_project_id: default_project_id().to_hex(),
        }
        .into(),
        sensitivity: Some(PUBLIC_BAND),
        evidence_turn_refs: Vec::new(),
        valid_from: None,
        valid_to: None,
        occurred_at: Some(moment),
        learned_at: Some(moment),
        salience: None,
    }
}

impl AgentVault {
    /// Open a fresh rooted vault whose second world is created at `created_at`
    /// (the corpus's earliest session), and mint the agent its base-world
    /// read Grant before any pairing, so no default Grant can name it first.
    pub(super) fn open(created_at: u64) -> Result<Self, ScorecardFailure> {
        let dir = tempfile::tempdir().map_err(failed("pack vault tempdir"))?;
        let mut config = VaultConfig::device();
        config.map_size = MAP_SIZE;
        let vault = Vault::open(dir.path(), config).map_err(failed("pack vault open"))?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .map_err(failed("serving install profile"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(failed("embedded owner"))?;
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .map_err(failed("host owner binding"))?;
        // The bench is the host: it authenticated its own fixture owner.
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .map_err(failed("owner authentication"))?;
        let second_world = vault
            .create_world(
                &owner_proof,
                "World the agent's Grant leaves out",
                created_at,
            )
            .map_err(failed("second world"))?;
        let agent = EntityId::now();
        create_agent_definition_as(
            &vault,
            &owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(serde_json::json!({
                    "agent_id": "scorecard_world_scoped_reader",
                    "desc": "World-scoped scorecard reader",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .map_err(failed("agent definition"))?,
            },
        )
        .map_err(failed("agent definition"))?;
        let mut authority_scope = Scope::top();
        authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &vault,
            &owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .map_err(failed("base-world Grant"))?;
        if !minted.grant.confers {
            return Err(ScorecardFailure::Run(
                "the agent's base-world Grant confers nothing".to_owned(),
            ));
        }
        Ok(Self {
            vault,
            _dir: dir,
            issuer,
            owner,
            owner_proof,
            second_world,
            agent,
        })
    }

    /// The pack vault.
    pub(super) fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Write every record of `corpus` as the owner's Public claim, its text
    /// the claim's string value (indexed as the claim lands): a record in
    /// `hidden` in the second world, any other in the base world. Each claim
    /// has its own PERSON subject. Returns the claim ids.
    pub(super) fn ingest(
        &self,
        loaded: &LoadedPack,
        corpus: &Corpus,
        ordinal_of: &BTreeMap<&str, usize>,
        hidden: &BTreeSet<String>,
    ) -> Result<BTreeMap<EntityId, Placed>, ScorecardFailure> {
        let facet = self
            .vault
            .default_facet()
            .map_err(failed("owner default facet"))?
            .to_hex();
        let subject_body = rmp_serde::to_vec_named(&BTreeMap::from([("name", "Scorecard reader")]))
            .map_err(failed("subject body"))?;
        let mut placed: BTreeMap<EntityId, Placed> = BTreeMap::new();
        let mut subjects = self.vault.batch();
        let mut claims: Vec<ScopedClaimInput> = Vec::with_capacity(CLAIM_BATCH);
        for session in &corpus.sessions {
            let moment = pack_time(&session.time).map_err(ScorecardFailure::Input)?;
            for record_id in &session.record_ids {
                let Some(ordinal) = ordinal_of.get(record_id.as_str()).copied() else {
                    let corpus_id = &corpus.corpus_id;
                    return Err(ScorecardFailure::Run(format!(
                        "corpus {corpus_id} names a record outside the pack: {record_id}"
                    )));
                };
                let id = derived_id(CLAIM_DOMAIN, record_id)?;
                if let Some(first) = placed.get(&id) {
                    if first.record_id != *record_id {
                        let first = &first.record_id;
                        return Err(ScorecardFailure::Run(format!(
                            "record id hash collision: {first} and {record_id}"
                        )));
                    }
                    continue;
                }
                let in_second_world = hidden.contains(record_id);
                placed.insert(
                    id,
                    Placed {
                        record_id: record_id.clone(),
                        hidden: in_second_world,
                    },
                );
                let subject = derived_id(SUBJECT_DOMAIN, record_id)?;
                let at = TimeRange {
                    start: moment,
                    end: moment,
                };
                subjects = subjects.put(&subject, ENTITY_TYPE_PERSON, at, moment, &subject_body);
                let world = if in_second_world {
                    self.second_world
                } else {
                    base_world_id()
                };
                let text = &loaded.slice.records[ordinal].text;
                claims.push(claim_input(id, subject, world, &facet, text, moment));
                if claims.len() >= CLAIM_BATCH {
                    subjects.commit().map_err(failed("subject batch"))?;
                    subjects = self.vault.batch();
                    self.commit_claims(&claims)?;
                    claims.clear();
                }
            }
        }
        if !claims.is_empty() {
            subjects.commit().map_err(failed("subject batch"))?;
            self.commit_claims(&claims)?;
        }
        Ok(placed)
    }

    /// Commit `claims` as one atomic owner-authored batch; a refused element
    /// fails the run.
    fn commit_claims(&self, claims: &[ScopedClaimInput]) -> Result<(), ScorecardFailure> {
        let outcomes = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof)
            .commit_scoped(claims, false)
            .map_err(failed("claim batch"))?;
        if outcomes.len() != claims.len() {
            let (asked, answered) = (claims.len(), outcomes.len());
            return Err(ScorecardFailure::Run(format!(
                "claim batch answered {answered} outcomes for {asked} claims"
            )));
        }
        for outcome in &outcomes {
            if let CommitOutcome::Refused { refusal, .. } = outcome {
                return Err(ScorecardFailure::Run(format!(
                    "claim batch refused: {refusal:?}"
                )));
            }
        }
        Ok(())
    }

    /// Pair the agent and prove possession of its credential: only the verbs
    /// axis narrows the pairing, so the base-world Grant is the world ceiling.
    pub(super) fn pair_agent(&self) -> Result<VerifiedSlip, ScorecardFailure> {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let holder = self.agent.to_hex();
        let link = self
            .vault
            .issue_owner_pairing_link(
                &self.issuer,
                &self.owner_proof,
                scope,
                PAIRING_TTL_SECS,
                PairingPrincipal {
                    holder_ref: Some(holder.clone()),
                    actor_class: Some("agent".to_owned()),
                    ..PairingPrincipal::default()
                },
            )
            .map_err(failed("agent pairing link"))?;
        // A fixture key: the vault is thrown away after the run.
        let signing_key = SigningKey::from_bytes(&[BINDING_SEED; 32]);
        let binding_key = signing_key.verifying_key().to_bytes();
        let transcript = oneiron::authority::pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder,
            link.pin.as_ref(),
        )
        .map_err(failed("agent pairing transcript"))?;
        let slip = self
            .vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder,
                binding_key,
                &signing_key.sign(&transcript).to_bytes(),
            )
            .map_err(failed("agent pairing redeem"))?;
        let request = slip
            .binding_transcript(REQUEST_CHALLENGE)
            .map_err(failed("agent request transcript"))?;
        let signature = signing_key.sign(&request).to_bytes();
        self.vault
            .verify_capability_slip(
                &self.issuer.public_key(),
                &slip,
                REQUEST_CHALLENGE,
                &signature,
            )
            .map_err(failed("agent credential proof"))
    }
}
