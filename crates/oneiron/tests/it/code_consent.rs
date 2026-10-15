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
use oneiron::deletion::DeleteReason;
use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, decode_consolidation_evidence, encode_consolidation_evidence,
};
use oneiron::error::{CodeError, GateError};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
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
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            range(1),
            1,
            b"person",
        )
        .expect("seed person");
    person
}

/// A code artifact the review lane can cite: an opaque ASSET body, which is
/// what a stored artifact blob is. The review evidence names entity refs, so a
/// fixture that cites one has to have written it.
fn seed_code_artifact(vault: &Vault, byte: u8) -> EntityId {
    let artifact = id(byte);
    vault
        .put_entity(
            &artifact,
            oneiron::registry::ENTITY_TYPE_ASSET,
            range(1),
            1,
            b"code artifact",
        )
        .expect("seed code artifact");
    artifact
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
                    std::slice::from_ref(chunk),
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
fn review_lane_parks_proposed_with_blast_radius() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x21);
    let subject = seed_person(&vault, 0x22);
    // The review evidence cites this artifact by entity ref, and the write door
    // asks a Dreamer candidate for a ref that RESOLVES — so the fixture writes
    // the artifact it names.
    let artifact = seed_code_artifact(&vault, 0x23);
    let (graph, symbols) = graph();
    let before = vault.gate_decisions(100).unwrap();
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
    // Same two-door shape as the free lane (dispatcher pre-check plus batch
    // preflight); the review lane additionally parks the claim. Pin the door
    // identity of every appended row rather than the bare count.
    let after = vault.gate_decisions(100).unwrap();
    // `gate_decisions` returns newest-first, so the dispatch's rows are the prefix.
    let added = &after[..after.len() - before.len()];
    assert_eq!(added.len(), 2);
    assert_eq!(after[added.len()..], before[..]);
    for decision in added {
        assert_eq!(decision.claim_id, Some(*id(0x24).as_bytes()));
        assert_eq!(decision.content_kind, "claim");
    }
    let pending = vault.pending_gate_consents(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].dreamer_run_id.as_deref(), Some("review-run-1"));
    assert!(
        pending[0]
            .reason_codes
            .iter()
            .any(|code| code == "gate.pending.source_trust")
    );
    // The parked consent is bound to one of the receipts this dispatch
    // appended, so the extra row never detaches the tray from its decision.
    assert!(
        added
            .iter()
            .any(|decision| decision.decision_id == pending[0].decision_id)
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
    assert!(matches!(
        error,
        Error::Code(CodeError::CodeEmissionMissingDreamerRunId)
    ));
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
    assert!(matches!(
        error,
        Error::Code(CodeError::CodeReviewAuthoringRunIdMismatch)
    ));
    assert_eq!(vault.gate_decisions(100).unwrap(), rows);
    assert!(vault.get_claim(&id(0x54)).unwrap().is_none());
}

/// The free lane's candidate evidence is the host's own admission record, and
/// that record is a real entity the door can resolve.
#[test]
fn codeconsent_free_lands_with_emission_record() {
    let (_dir, vault) = vault();
    // A fresh vault already holds the seeded system-agent rows, so this fixture
    // seeds ids outside the production pin list (see `PINNED_ID_BYTES` in
    // `crates/oneiron/src/lib.rs`) rather than aliasing a system identity.
    let actor = seed_person(&vault, 0xE2);
    let subject = seed_person(&vault, 0xE3);
    let before = vault.gate_decisions(100).unwrap();
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("free-record-run"), vec![]),
        None,
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0xE4),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();

    let claim = vault.get_claim(&id(0xE4)).unwrap().expect("claim");
    let evidence = claim.evidence.expect("stamped evidence");
    let stamped = evidence_value(&evidence, "candidate_evidence");
    let envelope = decode_consolidation_evidence(stamped)
        .expect("the free lane's evidence decodes")
        .expect("the free lane carries the consolidation contract");
    assert_eq!(envelope.refs.len(), 1, "one record, cited once");
    assert!(envelope.chain.is_empty());
    assert_eq!(envelope.source_meet, ClaimSource::ToolOutput);

    // The ref RESOLVES, and what it resolves to is the admission itself.
    let record = vault
        .get(&envelope.refs[0])
        .unwrap()
        .expect("the cited emission record resolves");
    let mut cursor = record.as_slice();
    let body = rmpv::decode::read_value(&mut cursor).expect("record body");
    assert_eq!(
        evidence_value(&body, "dreamer_run_id").as_str(),
        Some("free-record-run")
    );
    assert_eq!(evidence_value(&body, "run_ref").as_str(), Some("host-run"));
    assert_eq!(
        evidence_value(&body, "tier").as_str(),
        Some("first_party_dreamer")
    );
    assert_eq!(
        evidence_value(&body, "source_trust").as_str(),
        Some("trusted")
    );

    // Minting the record is a typed entity put, never a claim door: the two
    // receipts are the dispatch's own two claim-door crossings and no more.
    let after = vault.gate_decisions(100).unwrap();
    let added = &after[..after.len() - before.len()];
    assert_eq!(added.len(), 2);
    assert_eq!(after[added.len()..], before[..]);
    for decision in added {
        assert_eq!(decision.claim_id, Some(*id(0xE4).as_bytes()));
        assert_eq!(decision.content_kind, "claim");
    }
}

/// The floor is untouched: a Dreamer candidate whose evidence resolves to
/// nothing is still denied, on the dispatcher pre-check and on the batch door.
#[test]
fn codeconsent_floor_still_denies_candidate() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0xD1);
    let subject = seed_person(&vault, 0xD2);
    let (graph, symbols) = graph();
    let before_pending = vault.pending_gate_consents(10).unwrap();

    // Door 1 — the dispatcher pre-check. The cited artifact is never seeded,
    // so the review lane's own refs resolve to nothing.
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(
            CodeSourceTrust::Untrusted,
            Some("floor-run"),
            vec![symbols[0]],
        ),
        Some(review("floor-run", graph, vec![id(0xD5)])),
    );
    let error = dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0xD4),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap_err();
    assert_precommit_no_evidence(error);
    assert!(vault.get_claim(&id(0xD4)).unwrap().is_none());

    // Door 2 — the public batch candidate door, with a well-formed envelope
    // whose single ref was never written.
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (Value::from("run_id"), Value::from("floor-run")),
        ]))
        .unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let bogus = candidate(subject).with_evidence(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![id(0xD6)],
            chain: Vec::new(),
            source_meet: ClaimSource::ToolOutput,
        },
    ));
    // The candidate id is seeded outside the production pin list (see
    // `PINNED_ID_BYTES` in `crates/oneiron/src/lib.rs`), so "no claim row
    // landed" is read against an id a fresh vault never occupies.
    let error = vault
        .batch()
        .claim_candidate(&id(0xD8), bogus, &envelope, range(2), 2)
        .commit()
        .unwrap_err();
    assert_precommit_no_evidence(error);
    assert!(vault.get_claim(&id(0xD8)).unwrap().is_none());

    assert_eq!(
        vault.pending_gate_consents(10).unwrap(),
        before_pending,
        "a validity denial mints no pending row on either door"
    );
}

fn assert_precommit_no_evidence(error: Error) {
    match error {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "deny");
            assert_eq!(reason_codes, ["gate.deny.dreamer_precommit.no_evidence"]);
        }
        other => panic!("expected the evidence floor's denial, got {other:?}"),
    }
}

// ---- Free-lane admission record: minted once, then VERIFIED before reuse ----

/// The single record ref the free lane cited on `claim`.
fn cited_emission_record(vault: &Vault, claim: EntityId) -> EntityId {
    let evidence = vault
        .get_claim(&claim)
        .expect("read the claim that cites the free-lane emission record")
        .expect("claim")
        .evidence
        .expect("stamped evidence");
    let envelope = decode_consolidation_evidence(evidence_value(&evidence, "candidate_evidence"))
        .expect("the free lane's evidence decodes")
        .expect("the free lane carries the consolidation contract");
    assert_eq!(envelope.refs.len(), 1, "one record, cited once");
    envelope.refs[0]
}

/// The record id an admission derives, read off a throwaway vault: the id is a
/// function of the admission identity (tier, source trust, Dreamer run, host
/// run ref) alone, so an identical admission elsewhere lands on the same id.
fn free_lane_record_id_for(run_id: &str) -> EntityId {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x18);
    let subject = seed_person(&vault, 0x19);
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some(run_id), vec![]),
        None,
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x1A),
            candidate(subject),
            range(2),
            2,
        )))
        .expect("seed the free-lane admission used to derive its record id");
    cited_emission_record(&vault, id(0x1A))
}

/// The owner's own lifecycle: mint the free lane's record, soft-delete it, then
/// repeat the identical admission. ARCH-0038 keeps a parseable 25-byte shell at
/// that id, and the shell is not the record — the dispatch must refuse instead
/// of citing it, and must never remint over the tombstoned id.
#[test]
fn free_lane_reuse_refuses_soft_deleted_record() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x14);
    let subject = seed_person(&vault, 0x15);
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("free-shell-run"), vec![]),
        None,
    );
    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x16),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let record = cited_emission_record(&vault, id(0x16));

    assert!(
        vault
            .delete_entity_with_reason(&record, DeleteReason::UserDelete)
            .unwrap()
            .existed
    );
    assert!(vault.is_deleted_shell(&record).unwrap());
    let shell = vault
        .get_raw(&record)
        .unwrap()
        .expect("a soft delete keeps the shell");

    let before_rows = vault.gate_decisions(100).unwrap();
    let before_pending = vault.pending_gate_consents(10).unwrap();
    let error = dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x17),
            candidate(subject),
            range(3),
            3,
        )))
        .unwrap_err();
    assert!(
        matches!(error, Error::InvariantViolation(_)),
        "a tombstoned admission record is refused, never cited: {error:?}"
    );
    assert!(vault.get_claim(&id(0x17)).unwrap().is_none());
    assert_eq!(vault.gate_decisions(100).unwrap(), before_rows);
    assert_eq!(vault.pending_gate_consents(10).unwrap(), before_pending);
    assert!(
        vault.is_deleted_shell(&record).unwrap(),
        "the refusal resurrects nothing"
    );
    assert_eq!(
        vault.get_raw(&record).unwrap(),
        Some(shell),
        "the tombstoned id is left byte-untouched"
    );
}

/// The id is deterministic, so something else can already be sitting on it.
/// A live entity of the wrong TYPE and a live ASSET with the wrong BODY are
/// both "not this admission's record": refuse, never cite, never overwrite.
#[test]
fn free_lane_reuse_refuses_divergent_occupant() {
    let record = free_lane_record_id_for("free-divergent-run");
    for (entity_type, body) in [
        (
            oneiron::registry::ENTITY_TYPE_PERSON,
            b"a person, not an admission record".as_slice(),
        ),
        (
            ENTITY_TYPE_ASSET,
            b"an asset with the wrong body".as_slice(),
        ),
    ] {
        let (_dir, vault) = vault();
        let actor = seed_person(&vault, 0x1B);
        let subject = seed_person(&vault, 0x1C);
        vault
            .put_entity(&record, entity_type, range(1), 1, body)
            .expect("seed the occupant");
        let before_rows = vault.gate_decisions(100).unwrap();
        let before_pending = vault.pending_gate_consents(10).unwrap();
        let dispatch = dispatcher(
            &vault,
            actor,
            emission(CodeSourceTrust::Trusted, Some("free-divergent-run"), vec![]),
            None,
        );
        let error = dispatch
            .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                id(0x1D),
                candidate(subject),
                range(2),
                2,
            )))
            .unwrap_err();
        assert!(
            matches!(error, Error::InvariantViolation(_)),
            "a divergent occupant of the record id is refused: {error:?}"
        );
        assert!(vault.get_claim(&id(0x1D)).unwrap().is_none());
        assert_eq!(vault.gate_decisions(100).unwrap(), before_rows);
        assert_eq!(vault.pending_gate_consents(10).unwrap(), before_pending);
        assert_eq!(
            vault.get(&record).unwrap().as_deref(),
            Some(body),
            "the occupant is never overwritten or reminted"
        );
    }
}

/// The idempotence the free lane was always meant to have, now earned by the
/// record's own bytes: a second identical admission finds a live ASSET whose
/// body IS this admission's identity, cites the same id, and writes nothing.
#[test]
fn free_lane_reuses_live_exact_body_record() {
    let (_dir, vault) = vault();
    let actor = seed_person(&vault, 0x1E);
    let subject = seed_person(&vault, 0x1F);
    let dispatch = dispatcher(
        &vault,
        actor,
        emission(CodeSourceTrust::Trusted, Some("free-reuse-run"), vec![]),
        None,
    );
    let before_pending = vault.pending_gate_consents(10).unwrap();

    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x20),
            candidate(subject),
            range(2),
            2,
        )))
        .unwrap();
    let record = cited_emission_record(&vault, id(0x20));
    let minted = vault
        .get(&record)
        .unwrap()
        .expect("the minted record is a live entity");
    let first_rows = vault.gate_decisions(100).unwrap();
    let first_pending = vault.pending_gate_consents(10).unwrap();
    let first_assets = vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap();

    dispatch
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id(0x25),
            candidate(subject),
            range(3),
            3,
        )))
        .unwrap();
    assert_eq!(
        cited_emission_record(&vault, id(0x25)),
        record,
        "the same admission cites the same record"
    );
    assert_eq!(
        vault.get(&record).unwrap(),
        Some(minted),
        "the reused record is byte-identical, never rewritten"
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap(),
        first_assets,
        "reuse mints no duplicate entity"
    );

    // Same receipt shape as the first dispatch: the reuse itself adds no gate
    // decision and no pending row of its own.
    let after_rows = vault.gate_decisions(100).unwrap();
    let added = &after_rows[..after_rows.len() - first_rows.len()];
    assert_eq!(added.len(), 2);
    assert_eq!(after_rows[added.len()..], first_rows[..]);
    for decision in added {
        assert_eq!(decision.claim_id, Some(*id(0x25).as_bytes()));
        assert_eq!(decision.content_kind, "claim");
    }
    let after_pending = vault.pending_gate_consents(10).unwrap();
    assert_eq!(
        after_pending.len() + before_pending.len(),
        2 * first_pending.len(),
        "the second dispatch parks exactly what the first did, so the reuse \
         itself parks nothing"
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
        assert!(matches!(
            error,
            Error::Code(CodeError::CodeReviewUnsupportedOperation)
        ));
    }
    assert_eq!(vault.gate_decisions(100).unwrap(), rows);
    assert_eq!(vault.pending_gate_consents(10).unwrap(), pending);
}
