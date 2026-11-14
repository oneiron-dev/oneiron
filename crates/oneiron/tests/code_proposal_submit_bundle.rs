//! L4-25 PR 1 (ARCH-0050 #r7-conflicts): the owner's file-bundle proposal
//! verb `vault.code.proposal_submit_bundle`. The owner stages many files,
//! each with its exact change, as ONE Proposed native bundle proposal with
//! its retained base; the engine binds `owner_request` attribution with the
//! bundle lineage. Nothing is approved, queued or landed. A caller that is
//! not the owner is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_proposal_submit_bundle`.
#![cfg(oneiron_test_support)]

#[path = "code_bundle/fixture.rs"]
mod bundle_fixture;

use bundle_fixture::{A_RS, B_RS, TestResult, bundle_file};
use oneiron::claim::{ClaimBody, ClaimSubject};
use oneiron::code_document::{CodeOpProvenance, CodeProposalView, CodeProposalViewRequest};
use oneiron::codebase::RepoRef;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::memory::code_doors::CodeProposalBundleSubmitRequest;
use oneiron::store::repo_proposal_record::RepoProposalStatus;
use oneiron::{EdgeActorClass, EntityId};
use rmpv::Value;
use serde_json::json;

/// The left bundle's `a.rs`: the base function returns 100 instead of 1.
const LEFT_A_RS: &str = "pub fn a() -> u32 {\n    100\n}\n";
/// The left bundle's `b.rs`: the base function returns 200 instead of 2.
const LEFT_B_RS: &str = "pub fn b() -> u32 {\n    200\n}\n";
/// The left bundle's new `c.rs`, which the base commit does not hold.
const LEFT_C_RS: &str = "pub fn c() -> u32 {\n    3\n}\n";

/// The string at `key` of a MessagePack map.
fn text<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}

/// The map at `key` of a MessagePack map.
fn nested<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The array at `key` of a MessagePack map.
fn listed<'a>(map: &'a Value, key: &str) -> Option<&'a [Value]> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .and_then(|(_, value)| value.as_array())
}

/// The keys of a MessagePack map, sorted.
fn keys(map: &Value) -> Vec<String> {
    let mut keys: Vec<String> = map
        .as_map()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(key, _)| key.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    keys
}

#[test]
fn the_owner_stages_a_file_bundle_proposal() -> TestResult {
    let fixture = bundle_fixture::BundleFixture::new()?;
    let vault = &fixture.vault;
    let memory = fixture.owner_memory();
    assert_ne!(
        (LEFT_A_RS, LEFT_B_RS),
        (A_RS, B_RS),
        "the bundle changes both base files"
    );

    // Another caller cannot borrow the owner's proof.
    let refused = vault
        .memory(EntityId::now(), EdgeActorClass::Human)
        .code_proposal_submit_bundle_as(
            &fixture.owner_proof,
            CodeProposalBundleSubmitRequest {
                repo: fixture.repo,
                files: vec![bundle_file("a.rs", Some(LEFT_A_RS.as_bytes()))],
                message: "not the owner".to_owned(),
                op_provenance: CodeOpProvenance::default(),
                catalog: None,
            },
        )
        .expect_err("a caller that is not the owner is refused");
    assert_eq!(
        refused.code, MEMORY_CODE_FORBIDDEN,
        "a non-owner caller gets MEMORY_CODE_FORBIDDEN: {refused:?}"
    );

    let input = CodeProposalBundleSubmitRequest {
        repo: fixture.repo,
        files: vec![
            bundle_file("a.rs", Some(LEFT_A_RS.as_bytes())),
            bundle_file("b.rs", Some(LEFT_B_RS.as_bytes())),
            bundle_file("c.rs", Some(LEFT_C_RS.as_bytes())),
        ],
        message: "Left bundle".to_owned(),
        op_provenance: CodeOpProvenance::default(),
        catalog: None,
    };
    let submitted = memory.code_proposal_submit_bundle_as(&fixture.owner_proof, input.clone())?;
    assert_eq!(
        (submitted.actor, submitted.repo),
        (fixture.owner, fixture.repo),
        "the bundle proposal is the owner's, on the ingested repo"
    );

    // The proposal as a reviewer reads it: three files, one native
    // bundle, still Proposed.
    let view: CodeProposalView = memory
        .code_proposal_view(&CodeProposalViewRequest {
            proposal_ref: submitted.proposal.to_hex(),
        })?
        .ok_or("the stored bundle proposal reads back")?;
    assert_eq!(
        view.operation_kind, "commit_files",
        "the proposal is a native file bundle: {}",
        view.operation_kind
    );
    assert_eq!(
        view.status,
        RepoProposalStatus::Proposed,
        "nothing is approved, queued or landed"
    );
    assert!(
        view.path.is_none(),
        "a bundle has no single path: {:?}",
        view.path
    );
    let paths: Vec<&str> = view.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        ["a.rs", "b.rs", "c.rs"],
        "the proposal view shows all three bundle files: {paths:?}"
    );

    // The pinned base: the stored pointer's commit, not the live checkout.
    let row = vault
        .repo_proposal(submitted.proposal)?
        .ok_or("the stored bundle proposal row reads back")?;
    assert_eq!(
        RepoRef::parse(&row.repo)?.commit_hash(),
        Some(fixture.commit.as_str()),
        "the bundle proposal is pinned at the base commit"
    );
    assert_eq!(
        submitted.base,
        blake3::Hash::from_bytes(row.pre_action_fork_hash)
            .to_hex()
            .to_string(),
        "the answer names the retained base fork hash"
    );

    // The claim, read back on its own: the closed owner_request form with
    // the bundle lineage.
    let claim: ClaimBody = vault
        .get_claim(&submitted.provenance_claim)?
        .ok_or("the bundle proposal's provenance claim is stored")?;
    assert_eq!(
        claim.predicate, "repo.provenance",
        "the claim is repo provenance"
    );
    assert_eq!(
        claim.subject,
        ClaimSubject::Entity(submitted.session),
        "the claim is on the owner's sitting"
    );
    let value = &claim.value;
    assert_eq!(
        keys(value),
        [
            "actor",
            "derivation_envelope",
            "diff_lineage_receipt",
            "request_hash",
            "session",
            "source_kind",
        ],
        "exactly the owner_request keys, no model field"
    );
    assert_eq!(
        text(value, "source_kind"),
        Some("owner_request"),
        "the claim is the owner_request form"
    );
    let lineage = nested(value, "diff_lineage_receipt").ok_or("a lineage")?;
    assert_eq!(
        keys(lineage),
        ["base_commit", "files", "repo"],
        "the lineage names the bundle's files, not one path"
    );
    assert_eq!(
        text(lineage, "repo"),
        Some(fixture.repo.to_hex().as_str()),
        "the lineage names the ingested repo"
    );
    assert_eq!(
        text(lineage, "base_commit"),
        Some(fixture.commit.as_str()),
        "the lineage names the pinned base commit"
    );
    let files = listed(lineage, "files").ok_or("the bundle lineage lists its files")?;
    let mut seen: Vec<(String, Option<String>)> = files
        .iter()
        .map(|entry| {
            Ok::<_, Box<dyn std::error::Error>>((
                text(entry, "path").ok_or("a bundle file path")?.to_owned(),
                text(entry, "content_hash").map(str::to_owned),
            ))
        })
        .collect::<Result<_, _>>()?;
    seen.sort();
    let hashed = |bytes: &[u8]| blake3::hash(bytes).to_hex().to_string();
    assert_eq!(
        seen,
        [
            ("a.rs".to_owned(), Some(hashed(LEFT_A_RS.as_bytes()))),
            ("b.rs".to_owned(), Some(hashed(LEFT_B_RS.as_bytes()))),
            ("c.rs".to_owned(), Some(hashed(LEFT_C_RS.as_bytes()))),
        ],
        "the lineage binds every staged path in byte order: {seen:?}"
    );

    // The request hash is over the bundle verb, the owner, the sitting,
    // the typed input, the pointer, the base and the staged bytes' hash.
    let envelope = nested(value, "derivation_envelope").ok_or("an envelope")?;
    let bundle_list = serde_json::Value::Array(
        seen.iter()
            .map(|(path, hash)| json!({ "path": path, "content_hash": hash }))
            .collect(),
    );
    let content_hash = blake3::hash(&oneiron::llm::canonical_json_bytes(&bundle_list)?)
        .to_hex()
        .to_string();
    assert_eq!(
        text(envelope, "content_hash"),
        Some(content_hash.as_str()),
        "the envelope binds the bundle list's hash"
    );
    let preimage = json!({
        "version": "vault.code.owner_request.v1",
        "verb": "vault.code.proposal_submit_bundle",
        "actor": fixture.owner.to_hex(),
        "session": submitted.session.to_hex(),
        "input": serde_json::to_value(&input)?,
        "repo_ref": RepoRef::parse(&fixture.repo_ref)?.canonical(),
        "base_commit": fixture.commit,
        "effective_content_hash": content_hash,
    });
    let request_hash = blake3::hash(&oneiron::llm::canonical_json_bytes(&preimage)?)
        .to_hex()
        .to_string();
    assert_eq!(
        text(value, "request_hash"),
        Some(request_hash.as_str()),
        "the request hash binds the bundle verb and its typed input"
    );
    Ok(())
}
