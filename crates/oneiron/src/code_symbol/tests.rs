use super::*;
use crate::code_artifact::{
    CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, encode_code_artifact_body,
};
use crate::edge::EdgeKind;
use crate::error::{Error, ErrorKind};
use crate::registry::ENTITY_TYPE_CODE_SYMBOL;
use crate::temporal::TimeRange;
use crate::types::{HnswConfig, TextAnalyzerConfig, VaultConfig};

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

fn repo_ref() -> RepoRef {
    RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
        .expect("repo ref")
}

fn repo_ref_b() -> RepoRef {
    RepoRef::parse("github:oneiron-dev/oneiron#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .expect("repo ref")
}

fn code_body(repo_ref: &RepoRef) -> CodeArtifactBody {
    CodeArtifactBody::new(
        "Summarize symbol provenance.",
        [0xC5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        repo_ref.canonical(),
    )
}

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("entity id")
}

const GITHUB_TOKEN_SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn assert_secret_scan_rejected(err: Error) {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", "gate.secret_scan.github_token"]
            );
        }
        other => panic!("expected secret-scan GateWriteRejected, got {other:?}"),
    }
}

fn manifest_with_blame(
    claim_id: Option<EntityId>,
    source_session: Option<String>,
) -> Result<CodeSymbolManifest> {
    let chunks = vec![
        CodeChunk::from_text("src/lib.rs", 10, 12, "pub fn answer() -> u8 {\n    42\n}\n")?,
        CodeChunk::from_text("src/lib.rs", 1, 3, "mod answer;\n")?,
    ];
    let fingerprint =
        derive_symbol_fingerprint("src/lib.rs", "answer", "function", &[chunks[0].clone()])?;
    CodeSymbolManifest::new(
        repo_ref(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        chunks,
        vec![CodeSymbolRevision::new(
            "src/lib.rs",
            "answer",
            "function",
            fingerprint,
            vec![0],
            claim_id,
            source_session,
        )],
    )
}

#[test]
fn code_symbol_manifest_codec_is_deterministic_and_sorts_constructor_inputs() -> Result<()> {
    let manifest = manifest_with_blame(Some(entity(0xA1)), Some("session-alpha".to_owned()))?;
    assert_eq!(manifest.chunks[0].start_line, 1);
    assert_eq!(manifest.chunks[1].start_line, 10);
    assert_eq!(
        manifest.symbols[0].chunk_indexes,
        vec![1],
        "constructor must remap symbol indexes after sorting chunks"
    );

    let encoded = encode_code_symbol_manifest(&manifest)?;
    let decoded = decode_code_symbol_manifest(&encoded)?;
    let encoded_again = encode_code_symbol_manifest(&decoded)?;

    assert_eq!(decoded, manifest);
    assert_eq!(encoded_again, encoded);
    Ok(())
}

#[test]
fn code_symbol_manifest_codec_rejects_unsorted_or_duplicate_symbol_revisions() {
    let mut manifest = manifest_with_blame(None, None).expect("manifest");
    let duplicate = manifest.symbols[0].clone();
    manifest.symbols.push(duplicate);

    let err = encode_code_symbol_manifest(&manifest).expect_err("duplicate symbols fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
}

#[test]
fn code_symbol_manifest_rejects_symbol_chunks_from_another_path() -> Result<()> {
    let chunks = vec![CodeChunk::from_text(
        "src/other.rs",
        1,
        1,
        "fn other() {}\n",
    )?];

    let err = CodeSymbolManifest::new(
        repo_ref(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        chunks,
        vec![CodeSymbolRevision::new(
            "src/lib.rs",
            "answer",
            "function",
            [0xAA; CODE_SYMBOL_FINGERPRINT_LEN],
            vec![0],
            None,
            None,
        )],
    )
    .expect_err("symbol cannot point at chunks from another file");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
    Ok(())
}

#[test]
fn text_diff_derives_stable_code_chunks() -> Result<()> {
    let old = "fn a() {\n    one();\n}\nfn b() {\n    two();\n}\n";
    let new = "fn a() {\n    one_more();\n}\nfn b() {\n    two_more();\n}\n";

    let chunks = derive_code_chunks_from_text_diff("src/lib.rs", old, new)?;

    assert_eq!(chunks.len(), 2);
    assert_eq!((chunks[0].start_line, chunks[0].end_line), (1, 3));
    assert_eq!(
        chunks[0].content_hash,
        sha256_bytes("fn a() {\n    one_more();\n}".as_bytes())
    );
    assert_eq!((chunks[1].start_line, chunks[1].end_line), (4, 6));
    assert_eq!(
        chunks[1].content_hash,
        sha256_bytes("fn b() {\n    two_more();\n}".as_bytes())
    );
    Ok(())
}

#[test]
fn text_diff_preserves_equal_length_eof_newline_in_chunk_hash() -> Result<()> {
    let chunks = derive_code_chunks_from_text_diff("README.md", "a\nb\n", "a\nc\n")?;

    assert_eq!(chunks.len(), 1);
    assert_eq!((chunks[0].start_line, chunks[0].end_line), (2, 2));
    assert_eq!(chunks[0].content_hash, sha256_bytes("c\n".as_bytes()));
    Ok(())
}

#[test]
fn rust_ast_chunks_include_doc_context() -> Result<()> {
    let old = "/// Old budget docs\npub fn budget_depletion() -> u8 { 1 }\n";
    let new = "/// Budget depletion is handled here\npub fn budget_depletion() -> u8 { 1 }\n";

    let chunks = derive_code_chunks_from_text_diff("src/llm/budget.rs", old, new)?;

    assert_eq!(chunks.len(), 1);
    assert_eq!((chunks[0].start_line, chunks[0].end_line), (1, 2));
    assert_eq!(
        chunks[0].content_hash,
        sha256_bytes(
            "/// Budget depletion is handled here\npub fn budget_depletion() -> u8 { 1 }"
                .as_bytes()
        )
    );
    Ok(())
}

#[test]
fn rust_ast_incremental_chunks_skip_parent_impl_for_method_body_change() -> Result<()> {
    let repo_ref = repo_ref();
    let path = "src/runner.rs";
    let old = "pub struct Runner;\n\
                   impl Runner {\n\
                       pub fn budget_depletion(&self) -> u8 { 1 }\n\
                       pub fn unrelated(&self) -> u8 { 2 }\n\
                   }\n";
    let new = "pub struct Runner;\n\
                   impl Runner {\n\
                       pub fn budget_depletion(&self) -> u8 { 3 }\n\
                       pub fn unrelated(&self) -> u8 { 2 }\n\
                   }\n";

    let chunks = derive_code_chunks_from_text_diff(path, old, new)?;
    let inputs = derive_code_embedding_inputs_from_text_diff(&repo_ref, path, old, new)?;

    assert_eq!(chunks.len(), 1);
    assert_eq!((chunks[0].start_line, chunks[0].end_line), (3, 3));
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].name, "budget_depletion");
    assert_eq!((inputs[0].start_line, inputs[0].end_line), (3, 3));
    Ok(())
}

#[test]
fn incremental_code_embeddings_reembed_only_changed_ast_chunk_and_search_top5() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let code_artifact_id = entity(0xD5);
    let repo_ref = repo_ref();
    let path = "src/llm/budget.rs";
    let old = "pub fn budget_depletion() -> &'static str { \"old budget path\" }\n\
                   pub fn unrelated() -> &'static str { \"unchanged\" }\n";
    let new = "pub fn budget_depletion() -> &'static str { \"budget depletion handled here\" }\n\
                   pub fn unrelated() -> &'static str { \"unchanged\" }\n";

    let inputs = derive_code_embedding_inputs_from_text_diff(&repo_ref, path, old, new)?;

    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].path, path);
    assert_eq!(inputs[0].name, "budget_depletion");
    assert!(inputs[0].text.contains("budget depletion handled here"));

    let mut embed_call_count = 0;
    let vectors = embed_code_chunks(&inputs, |batch| {
        embed_call_count += batch.len();
        Ok(batch
            .iter()
            .map(|input| {
                if input.text.contains("budget depletion") {
                    vec![1.0, 0.0, 0.0, 0.0]
                } else {
                    vec![0.0, 1.0, 0.0, 0.0]
                }
            })
            .collect())
    })?;
    assert_eq!(embed_call_count, 1);

    let graph = derive_code_symbol_graph_from_sources(
        repo_ref.clone(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        [CodeSymbolSource::new(path, new)],
    )?;
    vault.put_code_artifact(
        &code_artifact_id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_graph(
        &code_artifact_id,
        &graph,
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_embedding_vectors(&vectors)?;

    let top5 = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 5)?;
    assert!(
        top5.iter()
            .take(5)
            .any(|result| result.id == inputs[0].entity_id)
    );
    Ok(())
}

#[test]
fn symbol_fingerprint_canonicalizes_chunk_order() -> Result<()> {
    let first = CodeChunk::from_text("src/lib.rs", 1, 1, "fn first() {}\n")?;
    let second = CodeChunk::from_text("src/lib.rs", 10, 10, "fn second() {}\n")?;

    let ordered = derive_symbol_fingerprint(
        "src/lib.rs",
        "answer",
        "function",
        &[first.clone(), second.clone()],
    )?;
    let reversed = derive_symbol_fingerprint("src/lib.rs", "answer", "function", &[second, first])?;

    assert_eq!(ordered, reversed);
    Ok(())
}

#[test]
fn rust_tree_sitter_symbol_graph_extracts_refs_and_contiguity_edges() -> Result<()> {
    let graph = derive_code_symbol_graph_from_sources(
        repo_ref(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        [CodeSymbolSource::new(
            "src/lib.rs",
            "pub struct Runner;\n\
                 pub fn answer() -> u8 { 42 }\n\
                 pub fn caller() -> u8 { answer() }\n",
        )],
    )?;

    let names = graph
        .manifest
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["Runner", "answer", "caller"]);
    assert!(graph.manifest.symbols.iter().all(|symbol| {
        symbol
            .source_session
            .as_deref()
            .is_some_and(|source| source.starts_with("rust:github:oneiron-dev/oneiron"))
    }));

    let answer = graph
        .manifest
        .symbols
        .iter()
        .find(|symbol| symbol.name == "answer")
        .expect("answer symbol");
    let caller = graph
        .manifest
        .symbols
        .iter()
        .find(|symbol| symbol.name == "caller")
        .expect("caller symbol");
    let answer_id = code_symbol_entity_id(&graph.manifest.repo_ref, answer)?;
    let caller_id = code_symbol_entity_id(&graph.manifest.repo_ref, caller)?;
    assert!(graph.edges.iter().any(|edge| {
        edge.source == caller_id && edge.kind == EdgeKind::Mentions && edge.target == answer_id
    }));
    assert!(graph.edges.iter().any(|edge| {
        edge.source == answer_id && edge.kind == EdgeKind::Attached && edge.target == caller_id
    }));
    assert!(graph.edges.iter().any(|edge| {
        edge.source == caller_id && edge.kind == EdgeKind::Attached && edge.target == answer_id
    }));
    Ok(())
}

#[test]
fn code_symbol_graph_persists_entities_refs_callers_and_ppr_neighbors() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xD1);
    let repo_ref = repo_ref();
    let graph = derive_code_symbol_graph_from_sources(
        repo_ref.clone(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        [CodeSymbolSource::new(
            "src/lib.rs",
            "pub fn answer() -> u8 { 42 }\n\
                 pub fn caller() -> u8 { answer() }\n",
        )],
    )?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_graph(&id, &graph, TimeRange { start: 10, end: 10 }, 11)?;

    let answer = vault.code_symbol_definitions(&id, "answer")?;
    assert_eq!(answer.len(), 1);
    let answer = &answer[0];
    assert_eq!(
        vault.get_entity_type(&answer.entity_id)?,
        Some(ENTITY_TYPE_CODE_SYMBOL)
    );
    assert!(vault.edge_exists(&answer.entity_id, EdgeKind::PartOf, &id)?);

    let references =
        vault.code_symbol_references(&id, &answer.path, &answer.name, &answer.fingerprint)?;
    let callers =
        vault.code_symbol_callers(&id, &answer.path, &answer.name, &answer.fingerprint)?;
    assert_eq!(references, callers);
    assert_eq!(callers.len(), 1);
    let caller = vault.code_symbol_definitions(&id, "caller")?;
    assert_eq!(caller.len(), 1);
    assert_eq!(callers[0], caller[0].entity_id);

    let neighbors = vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?;
    assert!(
        neighbors
            .iter()
            .any(|neighbor| neighbor.id == caller[0].entity_id)
    );
    Ok(())
}

#[test]
fn symbol_blame_returns_provenance_claim_and_source_session_when_available() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB1);
    let claim_id = entity(0xC1);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(Some(claim_id), Some("codex-session-001".to_owned()))?;
    let fingerprint = manifest.symbols[0].fingerprint;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;

    let direct = vault
        .code_symbol_blame(&id, "src/lib.rs", "answer", &fingerprint)?
        .expect("direct blame");
    assert_eq!(direct.provenance_claim_id, Some(claim_id));
    assert_eq!(direct.source_session.as_deref(), Some("codex-session-001"));

    let lookup = vault
        .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)?
        .expect("indexed blame");
    assert_eq!(lookup, direct);
    Ok(())
}

#[test]
fn code_symbol_manifest_rejects_secret_source_session_before_sidecar_mutation() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB8);
    let repo_ref = repo_ref();
    let safe_manifest = manifest_with_blame(None, Some("codex-session-001".to_owned()))?;
    let secret_manifest = manifest_with_blame(None, Some(GITHUB_TOKEN_SECRET_FIXTURE.to_owned()))?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &safe_manifest)?;

    let err = vault
        .put_code_symbol_manifest(&id, &secret_manifest)
        .expect_err("secret source_session must reject before sidecar mutation");

    assert_secret_scan_rejected(err);
    assert_eq!(vault.get_code_symbol_manifest(&id)?, Some(safe_manifest));
    Ok(())
}

#[test]
fn symbol_blame_lookup_skips_orphaned_index_after_code_artifact_delete() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB3);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;

    assert!(vault.delete_entity(&id)?);

    assert!(
        vault
            .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)?
            .is_none()
    );
    Ok(())
}

#[test]
fn symbol_blame_lookup_fails_closed_after_code_artifact_repo_ref_overwrite() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB4);
    let repo_a = repo_ref();
    let repo_b = repo_ref_b();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_a),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;
    vault.put_code_artifact(
        &id,
        &code_body(&repo_b),
        TimeRange { start: 12, end: 12 },
        13,
    )?;

    let err = vault
        .lookup_code_symbol_blame(&repo_a, "src/lib.rs", "answer", &fingerprint)
        .expect_err("stale sidecar must not return blame after repo_ref overwrite");
    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);

    let err = vault
        .code_symbol_blame(&id, "src/lib.rs", "answer", &fingerprint)
        .expect_err("direct stale sidecar read must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
    Ok(())
}

#[test]
fn symbol_blame_lookup_propagates_corrupt_live_entity() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB5);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), b"bad")?;
        Ok(())
    })?;

    let err = vault
        .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)
        .expect_err("corrupt live entity must not be swallowed as no-blame");
    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    Ok(())
}

#[test]
fn symbol_blame_lookup_propagates_corrupt_manifest_sidecar() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB6);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &code_symbol_manifest_key(&id), b"\xc1")?;
        Ok(())
    })?;

    let err = vault
        .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)
        .expect_err("corrupt manifest must not be swallowed as no-blame");
    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
    Ok(())
}

#[test]
fn corrupt_manifest_fallback_deletes_only_well_shaped_index_rows_for_id() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB7);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;
    let well_shaped_key =
        code_symbol_revision_index_key(&repo_ref, "src/lib.rs", "answer", &fingerprint, &id);
    let mut malformed_key = CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX.to_vec();
    malformed_key.extend_from_slice(b"malformed");
    malformed_key.extend_from_slice(id.as_bytes());

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_code_symbol_manifest(&id, &manifest)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &code_symbol_manifest_key(&id), b"\xc1")?;
        vault.store.vault_meta.put(wtxn, &malformed_key, &[])?;
        assert!(delete_code_symbol_manifest_in_txn(&vault.store, wtxn, &id)?);
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &code_symbol_manifest_key(&id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &well_shaped_key)?
            .is_none()
    );
    assert!(vault.store.vault_meta.get(&rtxn, &malformed_key)?.is_some());
    Ok(())
}

#[test]
fn symbol_manifest_repo_ref_must_match_code_artifact() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity(0xB2);
    let repo_ref = repo_ref();
    let other_repo =
        RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let manifest = manifest_with_blame(None, None)?;

    vault.put_code_artifact(
        &id,
        &code_body(&other_repo),
        TimeRange { start: 10, end: 10 },
        11,
    )?;

    let err = vault
        .put_code_symbol_manifest(&id, &manifest)
        .expect_err("manifest cannot be attached to another repo");
    assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);

    let artifact = encode_code_artifact_body(&code_body(&repo_ref))?;
    assert!(decode_code_artifact_body(&artifact).is_ok());
    Ok(())
}
