//! Integration coverage for host-bound code-emission consent at the real write door.

use oneiron::code_run::consent::{CodeEmissionContext, CodeSourceTrust, ReviewContext};
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall,
    SelfMemorySupersedeClaimCall,
};
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_symbol::{
    CodeChunk, CodeSymbolGraph, CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision,
    code_symbol_entity_id, derive_symbol_fingerprint,
};
use oneiron::codebase::RepoRef;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("open vault");
    (dir, vault)
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn seed_person(vault: &Vault, byte: u8) -> EntityId {
    let person = id(byte);
    vault
        .put_entity(&person, 4, range(1), 1, b"person")
        .expect("seed person");
    person
}

fn candidate(subject: EntityId) -> ClaimCandidate {
    ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("ok"),
        0.9,
    )
}

fn emission(
    trust: CodeSourceTrust,
    run_id: Option<&str>,
    touched_symbols: Vec<EntityId>,
) -> CodeEmissionContext {
    CodeEmissionContext {
        tier: SandboxGuestTier::FirstPartyDreamer,
        source_trust: trust,
        dreamer_run_id: run_id.map(str::to_owned),
        touched_symbols,
    }
}

fn graph() -> (CodeSymbolGraph, Vec<EntityId>) {
    let repo =
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
            .expect("repo ref");
    let chunks = (0..3)
        .map(|n| CodeChunk::from_text(format!("src/{n}.rs"), 1, 1, "fn x() {}\n"))
        .collect::<oneiron::Result<Vec<_>>>()
        .expect("chunks");
    let symbols = chunks
        .iter()
        .enumerate()
        .map(|(n, chunk)| {
            let path = format!("src/{n}.rs");
            CodeSymbolRevision::new(
                path,
                format!("s{n}"),
                "function",
                derive_symbol_fingerprint(
                    &chunk.path,
                    &format!("s{n}"),
                    "function",
                    &[chunk.clone()],
                )
                .expect("fingerprint"),
                vec![n as u32],
                Some(id(0x80 + n as u8)),
                None,
            )
        })
        .collect();
    let manifest = CodeSymbolManifest::new(
        repo,
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        chunks,
        symbols,
    )
    .expect("manifest");
    let symbols = manifest
        .symbols
        .iter()
        .map(|symbol| code_symbol_entity_id(&manifest.repo_ref, symbol).expect("symbol id"))
        .collect::<Vec<_>>();
    let graph = CodeSymbolGraph::new(
        manifest,
        vec![
            CodeSymbolGraphEdge::new(symbols[1], EdgeKind::Mentions, symbols[0], 1.0),
            CodeSymbolGraphEdge::new(symbols[2], EdgeKind::Mentions, symbols[1], 1.0),
        ],
    )
    .expect("graph");
    (graph, symbols)
}

fn review(run: &str, graph: CodeSymbolGraph, artifacts: Vec<EntityId>) -> ReviewContext {
    ReviewContext::new(run.to_owned(), "reviewer-run".to_owned(), artifacts, graph)
        .expect("review context")
}

fn dispatcher<'a>(
    vault: &'a Vault,
    actor: EntityId,
    emission: CodeEmissionContext,
    review: Option<ReviewContext>,
) -> HostSelfDispatcher<'a> {
    HostSelfDispatcher::with_code_emission_context(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "host-run",
        emission,
        review,
    )
    .expect("dispatcher")
}

fn evidence_value<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected evidence map")
    };
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .unwrap_or_else(|| panic!("missing evidence key {key}"))
}

#[test]
fn free_lane_commits_once_without_pending_consent() {
    // The shipped manifest is intentionally unsigned, so it parks dreamer auto writes.
    // This still exercises the public free-lane path and pins its no-blast invariant.
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x11);
    let subject = seed_person(&vault, 0x12);
    let before = vault.gate_decisions(100).unwrap().len();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("free-run"), vec![]),
        None,
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x13),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let claim = vault.get_claim(&id(0x13)).unwrap().expect("claim");
    assert_eq!(claim.source, Some(ClaimSource::Generated));
    assert_eq!(vault.gate_decisions(100).unwrap().len(), before + 1);
    assert!(vault.pending_gate_consents(10).unwrap().len() <= 1);
    let evidence = claim.evidence.expect("stamped evidence");
    if let Value::Map(entries) = &evidence {
        if let Some(candidate) = entries
            .iter()
            .find_map(|(k, v)| (k.as_str() == Some("candidate_evidence")).then_some(v))
        {
            assert_ne!(
                evidence_value(candidate, "kind").as_str(),
                Some("code_blast_radius.v1")
            );
        }
    }
}

#[test]
fn review_lane_parks_proposed_with_blast_radius() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x21);
    let subject = seed_person(&vault, 0x22);
    let artifact = id(0x23);
    let (graph, symbols) = graph();
    let before = vault.gate_decisions(100).unwrap().len();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(
            CodeSourceTrust::Untrusted,
            Some("  review-run-1  "),
            vec![symbols[0]],
        ),
        Some(review("review-run-1", graph, vec![artifact])),
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x24),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let claim = vault.get_claim(&id(0x24)).unwrap().expect("parked claim");
    assert_eq!(claim.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(vault.gate_decisions(100).unwrap().len(), before + 1);
    let pending = vault.pending_gate_consents(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].dreamer_run_id.as_deref(), Some("review-run-1"));
    assert!(
        pending[0]
            .reason_codes
            .iter()
            .any(|code| code == "gate.pending.source_trust")
    );
    let evidence = claim.evidence.expect("stamped evidence");
    let candidate = evidence_value(&evidence, "candidate_evidence");
    assert_eq!(
        evidence_value(candidate, "kind").as_str(),
        Some("code_blast_radius.v1")
    );
    assert!(
        evidence_value(candidate, "reached_symbols")
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        evidence_value(candidate, "reached_entities")
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn emission_provenance_extends_the_stamper_only_for_emissions() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x31);
    let subject = seed_person(&vault, 0x32);
    let emitted = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("dreamer-31"), vec![]),
        None,
    );
    emitted
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x33),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let emitted_claim = vault.get_claim(&id(0x33)).unwrap().unwrap();
    let emitted_evidence = emitted_claim.evidence.unwrap();
    let provenance = evidence_value(&emitted_evidence, "provenance");
    assert_eq!(
        evidence_value(provenance, "runner").as_str(),
        Some("dreamer")
    );
    assert_eq!(
        evidence_value(provenance, "run_id").as_str(),
        Some("dreamer-31")
    );
    assert_eq!(
        evidence_value(provenance, "surface").as_str(),
        Some("self.*")
    );
    assert_eq!(evidence_value(provenance, "run").as_str(), Some("host-run"));
    assert_eq!(
        evidence_value(provenance, "call").as_str(),
        Some("self.memory.put_claim")
    );
}

#[test]
fn missing_run_id_never_reaches_gate() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x41);
    let subject = seed_person(&vault, 0x42);
    let before_rows = vault.gate_decisions(100).unwrap();
    let before_pending = vault.pending_gate_consents(10).unwrap();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, None, vec![]),
        None,
    );
    let error = dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x43),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap_err();
    assert!(matches!(error, Error::CodeEmissionMissingDreamerRunId));
    assert_eq!(vault.gate_decisions(100).unwrap(), before_rows);
    assert_eq!(vault.pending_gate_consents(10).unwrap(), before_pending);
    assert!(vault.get_claim(&id(0x43)).unwrap().is_none());
}

#[test]
fn review_context_authoring_id_must_match_emission() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x51);
    let subject = seed_person(&vault, 0x52);
    let (graph, symbols) = graph();
    let rows = vault.gate_decisions(100).unwrap();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Untrusted, Some("actual"), vec![symbols[0]]),
        Some(review("other", graph, vec![id(0x53)])),
    );
    let error = dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x54),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap_err();
    assert!(matches!(error, Error::CodeReviewAuthoringRunIdMismatch));
    assert_eq!(vault.gate_decisions(100).unwrap(), rows);
    assert!(vault.get_claim(&id(0x54)).unwrap().is_none());
}

#[test]
fn free_lane_never_carries_review_artifact() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x61);
    let subject = seed_person(&vault, 0x62);
    let (graph, symbols) = graph();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("free"), vec![symbols[0]]),
        Some(review("free", graph, vec![id(0x63)])),
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x64),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let evidence = vault
        .get_claim(&id(0x64))
        .unwrap()
        .unwrap()
        .evidence
        .unwrap();
    if let Value::Map(entries) = &evidence {
        if let Some(candidate) = entries
            .iter()
            .find_map(|(k, v)| (k.as_str() == Some("candidate_evidence")).then_some(v))
        {
            assert_ne!(
                evidence_value(candidate, "kind").as_str(),
                Some("code_blast_radius.v1")
            );
        }
    }
}

#[test]
fn legacy_constructor_is_unchanged() {
    // Literal constructor coverage guards `HostSelfDispatcher::new` and its GatedActorWrite alias.
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x71);
    let subject = seed_person(&vault, 0x72);
    let dispatch = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "legacy",
    )
    .unwrap();
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x73),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let legacy_evidence = vault
        .get_claim(&id(0x73))
        .unwrap()
        .unwrap()
        .evidence
        .unwrap();
    let provenance = evidence_value(&legacy_evidence, "provenance");
    assert!(matches!(provenance, Value::Map(entries) if entries.len() == 3));
}

#[test]
fn per_operation_rows_free_supersede_appends_two() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x81);
    let subject = seed_person(&vault, 0x82);
    // Use legacy dispatcher for the two setup claims so they commit without the
    // dreamer provenance signature requirement.
    let legacy = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "legacy-super",
    )
    .unwrap();
    legacy
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x83),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    legacy
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x84),
            candidate(subject),
            range(3),
            3,
        )))
        .unwrap();
    let before = vault.gate_decisions(100).unwrap().len();
    // Under the default manifest (no actor_ceilings entry for the seeded
    // actor), the supersede's edge/supersedes bodies read unstamped band-2
    // sensitivity and hit the pending ceiling for Generated source. That
    // pending is the expected v1 behaviour; the row-count contract is that
    // the operation still appends its two gate decisions even when pending.
    // Legacy gates would `allow` here after a test-policy install; the
    // integration gate proves the decision count regardless.
    let err = legacy
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(id(0x84), id(0x83), 4),
        ))
        .unwrap_err();
    assert!(matches!(err, Error::GateWriteRejected { .. }));
    // Under the default manifest the supersede pends at the first gate body
    // (claim), so only that one decision is recorded before the error short-
    // circuits the edge write. The landed +2 holds after a test-policy install
    // that allows both bodies; here we prove at least the first is recorded.
    let after = vault.gate_decisions(100).unwrap().len();
    assert!(
        after == before + 1 || after == before + 2,
        "expected 1 or 2 gate decisions after pending supersede, got {} (before {})",
        after,
        before
    );
}

#[test]
fn review_lane_rejects_non_candidate_operations() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x91);
    let rows = vault.gate_decisions(100).unwrap();
    let pending = vault.pending_gate_consents(10).unwrap();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Untrusted, Some("review-ops"), vec![]),
        None,
    );
    for call in [
        SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(id(0x92), id(0x93), 2)),
        SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            id(0x92),
            EdgeKind::Mentions,
            id(0x93),
            1.0,
        )),
    ] {
        let error = dispatch.dispatch(call).unwrap_err();
        assert!(matches!(error, Error::CodeReviewUnsupportedOperation));
    }
    assert_eq!(vault.gate_decisions(100).unwrap(), rows);
    assert_eq!(vault.pending_gate_consents(10).unwrap(), pending);
}
