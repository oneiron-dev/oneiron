//! A run's proposal submit mints its own attribution
//! (`Memory::repo_proposal_submit_for_run`, `self.code.proposal_submit`):
//! the actor's session, and the `repo.provenance` claim about it, naming
//! the real actor, the model and request the host served, and the exact
//! work and change (code_run/dispatcher/repo_sources.rs).
//!
//! `repo.*` is an engine-owned predicate namespace, so the generic claim
//! candidate door refuses it for every caller. The run path's mint stores
//! its gated claim through the engine's reserved door instead.
//!
//! One agent run is real, as in `symbol_lease_observe.rs`: it proposes a
//! change to math.rs. The test plays the host: it captures the witness of
//! the model request it built for the change, as a host captures the
//! request it serves. No model is called.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_run_proposal_provenance`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    MATH_RS, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try, mint_repo_grant,
    paired_agent_slip,
};
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::memory::repo_doors::RepoProposalSubmitInput;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ClaimApprovalStatus, ClaimSubject, LlmRequest, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};
use rmpv::Value;

/// The run's change: `add_one` adds two.
const MATH_RS_CHANGED: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 2\n}\n";

/// The model the host served the run's request on.
const MODEL: &str = "local/repo-run-provenance@r1";

/// The model request the host served the run: the test builds it, as a
/// host finalizes the request at its send.
fn served_request() -> LlmRequest {
    let model = ModelId::new(MODEL).expect("model id");
    LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// The string at `key` in the map `value`.
fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, field)| field.as_str())
}

/// The value at `key` in the map `value`.
fn nested<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, field)| field)
}

#[test]
fn a_run_proposal_submit_mints_its_repo_provenance_claim() -> TestResult {
    let repo = RepoFixture::new()?;
    let vault = &repo.vault;
    let owner_proof = &repo.owner_proof;
    let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
    let agent = create_enabled_agent(vault, owner_proof, "run-provenance-agent")?;
    let slip = paired_agent_slip(vault, &repo.issuer, owner_proof, agent, 0x63)?;
    let grant = mint_repo_grant(vault, owner_proof, agent, Some(&bounds))?;
    let leased = leased_try(vault, &repo.owner_memory(), repo.owner, agent, "provenance")?;
    let run = agent_run(vault, &slip, leased, repo.repo, grant)?;

    let request = served_request();
    let witness =
        RepoRequestWitness::capture(&request).ok_or("the request has a canonical form")?;
    let prompt_hash = blake3::Hash::from(request.canonical_hash()?)
        .to_hex()
        .to_string();
    let content = MATH_RS_CHANGED.as_bytes();
    assert_ne!(MATH_RS_CHANGED, MATH_RS);
    let content_hash = *blake3::hash(content).as_bytes();
    let submitted = vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_proposal_submit_for_run(
            &run.binding,
            RepoProposalSubmitInput {
                work: run.work,
                path: "math.rs".to_owned(),
                content: content.to_vec(),
                message: "add_one adds two".to_owned(),
                declaration: None,
                repair_of: None,
            },
            None,
            |stamp| {
                run.binding.sources_from_host(
                    vault,
                    stamp,
                    "math.rs".to_owned(),
                    content_hash,
                    &witness,
                    SelfEffect::RepoProposalSubmit,
                )
            },
        )?
        .output;
    assert_eq!(submitted.work, run.work);
    assert_eq!(submitted.path, "math.rs");

    // The claim is the host's attribution of this change: about the
    // actor's session, naming the actor, the served model and request, and
    // the work and path.
    let claim = vault
        .get_claim(&submitted.provenance_claim)?
        .ok_or("the run's provenance claim is stored")?;
    assert_eq!(claim.predicate, "repo.provenance");
    assert_eq!(claim.subject, ClaimSubject::Entity(submitted.session));
    assert_eq!(claim.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(claim.scope_facet, vault.default_facet()?);
    let actor = run.actor.entity_ref().to_hex();
    assert_eq!(text(&claim.value, "actor"), Some(actor.as_str()));
    assert_eq!(text(&claim.value, "model"), Some(MODEL));
    assert_eq!(
        text(&claim.value, "prompt_hash"),
        Some(prompt_hash.as_str())
    );
    let envelope = nested(&claim.value, "derivation_envelope").ok_or("a derivation envelope")?;
    let content_hex = blake3::Hash::from(content_hash).to_hex().to_string();
    assert_eq!(text(envelope, "content_hash"), Some(content_hex.as_str()));
    assert_eq!(
        text(envelope, "version"),
        Some("self.code.proposal_submit.v1")
    );
    let lineage = nested(&claim.value, "diff_lineage_receipt").ok_or("a diff-lineage receipt")?;
    let work = run.work.to_hex();
    assert_eq!(text(lineage, "work"), Some(work.as_str()));
    assert_eq!(text(lineage, "path"), Some("math.rs"));
    let task = run.task.to_hex();
    assert_eq!(text(lineage, "task"), Some(task.as_str()));
    Ok(())
}
