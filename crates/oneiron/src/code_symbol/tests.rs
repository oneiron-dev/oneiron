use super::*;
use crate::code_artifact::{
    CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, encode_code_artifact_body,
};
use crate::edge::EdgeKind;
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_CODE_SYMBOL;
use crate::temporal::TimeRange;

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

use crate::test_util::{assert_secret_scan_rejected, embedding_test_config, entity};

const GITHUB_TOKEN_SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

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
    let manifest = manifest_with_blame(Some(entity(0x51)), Some("session-alpha".to_owned()))?;
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
fn incremental_code_embeddings_reembed_only_changed_ast_chunk_and_search_top5() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
fn code_symbol_graph_persists_entities_refs_callers_and_ppr_neighbors() -> Result<()> {
    let (_dir, mut vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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

    vault.set_edge_vad(
        &caller[0].entity_id,
        EdgeKind::Mentions,
        &answer.entity_id,
        crate::Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    let neighbors = vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?;
    let baseline = neighbors
        .iter()
        .find(|row| row.id == caller[0].entity_id)
        .expect("caller is reachable")
        .score;
    let bits = |rows: &[ScoredEntity]| {
        rows.iter()
            .map(|row| (row.id, row.score.to_bits()))
            .collect::<Vec<_>>()
    };
    vault.config.ppr_vad_alpha = -0.0;
    assert_eq!(
        bits(&neighbors),
        bits(&vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?)
    );
    vault.config.ppr_vad_alpha = 0.4;
    let weighted = vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?;
    assert!(
        weighted
            .iter()
            .find(|row| row.id == caller[0].entity_id)
            .expect("caller is reachable")
            .score
            > baseline
    );
    assert_eq!(
        bits(&weighted),
        bits(&vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?)
    );
    vault.config.ppr_vad_alpha = 0.0;
    assert_eq!(
        bits(&neighbors),
        bits(&vault.code_symbol_ppr_neighbors(&id, "answer", 2, 8)?)
    );
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 0.41] {
        vault.config.ppr_vad_alpha = alpha;
        for (name, limit) in [("answer", 8), ("answer", 0), ("missing", 8)] {
            assert!(matches!(
                vault.code_symbol_ppr_neighbors(&id, name, 2, limit),
                Err(Error::InvalidConfig(_))
            ));
        }
    }
    Ok(())
}

#[test]
fn symbol_blame_returns_provenance_claim_and_source_session_when_available() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let id = entity(0xB1);
    let claim_id = entity(0xC1);
    let repo_ref = repo_ref();
    let mut manifest = manifest_with_blame(Some(claim_id), Some("codex-session-001".to_owned()))?;
    let op = CodeProducingOperation {
        operation: entity(11),
        actor: entity(12),
        turn: entity(13),
        activity: entity(14),
        intent: entity(15),
    };
    manifest.symbols[0].producing_operations = vec![op.clone()];
    manifest.chunks[1].producing_operations = vec![op.clone()];
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
    assert_eq!(direct.producing_operations, vec![op]);
    assert_eq!(
        vault.get_code_symbol_manifest(&id)?.unwrap().chunks[1].producing_operations,
        direct.producing_operations
    );
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    assert_eq!(vault.get_code_symbol_manifest(&id)?, Some(safe_manifest));
    Ok(())
}

#[test]
fn symbol_blame_lookup_skips_orphaned_index_after_code_artifact_delete() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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

    assert!(
        vault.delete_entity_with_options(
            &id,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?
    );

    assert!(
        vault
            .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)?
            .is_none()
    );
    Ok(())
}

#[test]
fn symbol_blame_lookup_fails_closed_after_code_artifact_repo_ref_overwrite() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
            .put(wtxn, &MANIFEST.key_bytes(&id), b"\xc1")?;
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let id = entity(0xB7);
    let repo_ref = repo_ref();
    let manifest = manifest_with_blame(None, None)?;
    let fingerprint = manifest.symbols[0].fingerprint;
    let well_shaped_key =
        code_symbol_revision_index_key(&repo_ref, "src/lib.rs", "answer", &fingerprint, &id);
    let mut malformed_key = REVISION_INDEX.decl().prefix.to_vec();
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
            .put(wtxn, &MANIFEST.key_bytes(&id), b"\xc1")?;
        vault.store.vault_meta.put(wtxn, &malformed_key, &[])?;
        assert!(delete_code_symbol_manifest_in_txn(&vault.store, wtxn, &id)?);
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &MANIFEST.key_bytes(&id))?
            .is_none()
    );
    assert!(!REVISION_INDEX.contains(&vault.store, &rtxn, &well_shaped_key)?);
    assert!(vault.store.vault_meta.get(&rtxn, &malformed_key)?.is_some());
    Ok(())
}

#[test]
fn symbol_manifest_repo_ref_must_match_code_artifact() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
