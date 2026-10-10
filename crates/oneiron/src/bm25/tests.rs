use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use crate::{Error, Vault};
use core::assert_matches;
use rmpv::Value;

fn test_config() -> VaultConfig {
    VaultConfig {
        failure_signals: Default::default(),
        store_clock: crate::ports::StoreClock::default(),
        ppr_vad_alpha: crate::config::PPR_VAD_ALPHA_DEFAULT,
        ppr_community: crate::config::PprCommunityConfig::default(),
        retrieval_telemetry_capture: false,
        map_size: 16 * 1024 * 1024,
        dimensions: 4,
        fast_dims: None,
        embedding_model: None,
        embedding_transform: None,
        vector_evidence: crate::config::VectorEvidenceFloors::default(),
        tagging: None,
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::config::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        assistant_display_names: Vec::new(),
        skip_text_index_manifest_check: false,
        off_record_enabled: true,
        off_record_overlay_budget_bytes: crate::config::DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES,
        privacy: crate::config::VaultPrivacyConfig::default(),
    }
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn contains_id(results: &[ScoredEntity], id: &EntityId) -> bool {
    results.iter().any(|r| r.id == *id)
}

fn put_text_doc(vault: &Vault, id: &EntityId, text: &str) -> Result<()> {
    put_text_doc_at(vault, id, text, 2)
}

fn put_text_doc_at(vault: &Vault, id: &EntityId, text: &str, learned_at: u64) -> Result<()> {
    vault
        .batch()
        .put(id, 1, test_time_range(1, 1), learned_at, b"text-doc")
        .text(id, &[("body", text)])
        .commit()
}

fn test_entity_id(n: u16) -> EntityId {
    let mut bytes = [0x42; ENTITY_ID_LEN];
    bytes[14..].copy_from_slice(&n.to_be_bytes());
    EntityId::from_bytes_unchecked(bytes)
}

fn lh_prefixed_id(fill: u8) -> Result<EntityId> {
    let mut raw = [fill; ENTITY_ID_LEN];
    raw[0] = b'L';
    raw[1] = b'H';
    raw[ENTITY_ID_LEN - 1] &= 0x7F;
    EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid LH-prefixed test id"))
}

fn seed_raw_claim(vault: &Vault, id: &EntityId, body: ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(&body)?;
    seed_raw_claim_bytes(vault, id, &data)
}

fn seed_raw_claim_bytes(vault: &Vault, id: &EntityId, data: &[u8]) -> Result<()> {
    let header = crate::batch::EntityMetadataHeader {
        entity_type: ENTITY_TYPE_CLAIM,
        occurred_start: 1,
        occurred_end: 1,
        learned_at: 2,
    };
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(header.entity_type);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

fn final_word_token(term: &str) -> Token {
    Token::new(
        term,
        0,
        u32::try_from(term.len()).expect("test token fits in u32"),
        0,
        AnalyzerChannel::Surface,
        TokenKind::Word,
    )
}

fn put_raw_posting_terms_with_ids(vault: &Vault, postings: &[(String, EntityId)]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut fields = BTreeMap::new();
    fields.insert(AnalyzerChannel::Surface.field_id(), 1);
    for (term, id) in postings {
        let mut entry = Vec::new();
        encode_posting_entry(id, &fields, &mut entry)?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, term.as_bytes(), &entry)?;
    }
    wtxn.commit()?;
    Ok(())
}

#[test]
fn scoped_prefix_expansion_resolves_lexical_hint_target() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"actor",
    )?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        crate::claim::ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["scopedprefixalpha"],
        )
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let mut scope_checks = 0usize;
    let mut exact_posting_matches_scope = |id: &EntityId| {
        scope_checks += 1;
        Ok(*id == claim)
    };
    let hits = search_text_scoped_with_recency(
        &vault.store,
        &rtxn,
        &vault.analyzer,
        &Bm25Config::default(),
        "scopedprefix",
        10,
        Bm25SearchOptions {
            recency: None,
            exact_posting_matches_scope: &mut exact_posting_matches_scope,
            private_note_ids: None,
        },
    )?;

    assert_eq!(hits.first().map(|hit| hit.id), Some(claim));
    assert!(scope_checks > 0);
    Ok(())
}

#[test]
fn lh_prefixed_text_only_postings_remain_searchable() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = lh_prefixed_id(0x61)?;

    vault
        .batch()
        .text(&id, &[("body", "lhprefix text only document")])
        .commit()?;

    let hits = vault.search_text("lhprefix", 10)?;
    assert_eq!(hits.first().map(|hit| hit.id), Some(id));
    Ok(())
}

#[test]
fn scoped_prefix_expansion_ignores_dead_lexical_hint_exact_posting() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let live = EntityId::now();
    put_text_doc(&vault, &live, "deadprobealive")?;

    let missing_target = EntityId::now();
    let dead_hint = lh_prefixed_id(0x62)?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        crate::claim::ClaimSubject::Entity(missing_target),
        crate::claim::encode_lexical_query_hint_value(&missing_target, "deadprobe"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.stale = true;
    seed_raw_claim(&vault, &dead_hint, body)?;
    vault
        .batch()
        .text(&dead_hint, &[("query_hint", "deadprobe")])
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let mut exact_posting_matches_scope = |id: &EntityId| Ok(*id == live);
    let hits = search_text_scoped_with_recency(
        &vault.store,
        &rtxn,
        &vault.analyzer,
        &Bm25Config::default(),
        "deadprobe",
        10,
        Bm25SearchOptions {
            recency: None,
            exact_posting_matches_scope: &mut exact_posting_matches_scope,
            private_note_ids: None,
        },
    )?;

    assert_eq!(hits.first().map(|hit| hit.id), Some(live));
    assert!(!hits.iter().any(|hit| hit.id == dead_hint));
    Ok(())
}

#[test]
fn malformed_non_empty_lexical_hint_claim_posting_fails_closed() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let hint = lh_prefixed_id(0x63)?;

    seed_raw_claim_bytes(&vault, &hint, b"not-msgpack")?;
    vault
        .batch()
        .text(&hint, &[("query_hint", "malformedhintprobe")])
        .commit()?;

    let err = vault
        .search_text("malformedhintprobe", 10)
        .expect_err("malformed non-empty lexical hint rows must not be hidden");
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

#[test]
fn non_stale_lexical_hint_claim_posting_does_not_collapse_to_target() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let target = EntityId::now();
    let hint = lh_prefixed_id(0x65)?;

    let target_body = ClaimBody::new(
        "profile.preference",
        crate::claim::ClaimSubject::Entity(EntityId::now()),
        Value::from("sencha"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    seed_raw_claim(&vault, &target, target_body)?;

    let body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        crate::claim::ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "nonstalehintprobe"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    seed_raw_claim(&vault, &hint, body)?;
    vault
        .batch()
        .text(&hint, &[("query_hint", "nonstalehintprobe")])
        .commit()?;

    let hits = vault.search_text("nonstalehintprobe", 10)?;
    assert!(hits.is_empty());
    Ok(())
}

#[test]
fn final_token_prefix_scan_budget_ignores_out_of_scope_completions() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let prefix = "scopeaware";
    let old_prescope_cap = MAX_FINAL_TOKEN_PREFIX_TERMS * 16;
    let in_scope_index = old_prescope_cap + 1;
    assert!(in_scope_index < MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);

    let in_scope_id = test_entity_id(0x9000);
    let mut postings = (0..in_scope_index)
        .map(|idx| {
            (
                format!("{prefix}{idx:04}"),
                test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
            )
        })
        .collect::<Vec<_>>();
    postings.push((format!("{prefix}{in_scope_index:04}"), in_scope_id));
    put_raw_posting_terms_with_ids(&vault, &postings)?;

    let rtxn = vault.store.env.read_txn()?;
    let mut terms = BTreeMap::new();
    let mut scope_checks = 0usize;
    let mut exact_posting_matches_scope = |id: &EntityId| {
        scope_checks += 1;
        Ok(*id == in_scope_id)
    };
    collect_final_token_prefix_terms(
        &vault.store,
        &rtxn,
        prefix.len(),
        &Bm25Config::default(),
        &[final_word_token(prefix)],
        &mut terms,
        &mut exact_posting_matches_scope,
    )?;

    assert_eq!(
        terms.keys().cloned().collect::<Vec<_>>(),
        vec![format!("{prefix}{in_scope_index:04}")]
    );
    assert!(
        scope_checks > old_prescope_cap,
        "out-of-scope completions must not consume the scoped expansion budget"
    );
    assert!(scope_checks <= MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
    Ok(())
}

#[test]
fn final_token_prefix_does_not_expand_before_dropped_punctuation() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let widened = EntityId::now();

    put_text_doc(&vault, &widened, "foobarbaz")?;

    let results = vault.search_text("foo.", 10)?;
    assert!(
        !contains_id(&results, &widened),
        "token before trailing punctuation must not be treated as a final prefix"
    );
    Ok(())
}

/// Katakana query must retrieve a hiragana-only doc via the kana-fold
/// overlay. Runs only with `ONEIRON_TEST_SUDACHI_DICT` pointing at
/// `system.dic`: the portable/cjk_ngram path doesn't apply kana-fold,
/// so this regression guard requires the morphological analyzer.
#[test]
fn katakana_query_matches_hiragana_document() -> Result<()> {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return Ok(());
    };
    let dict_dir = match std::path::Path::new(&dict_path).parent() {
        Some(p) => p.to_path_buf(),
        None => return Ok(()),
    };

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dict_search_paths = vec![dict_dir];
    let vault = Vault::open(temp_dir.path(), config)?;

    let id = EntityId::now();
    put_text_doc(&vault, &id, "とうきょう")?;
    let hits = vault.search_text("トウキョウ", 10)?;
    assert!(
        contains_id(&hits, &id),
        "katakana query must retrieve hiragana doc via kana-fold overlay",
    );
    // Inverse direction (regression guard for index-side overlay).
    let id2 = EntityId::now();
    put_text_doc(&vault, &id2, "トウキョウ")?;
    let hits2 = vault.search_text("とうきょう", 10)?;
    assert!(contains_id(&hits2, &id2));
    Ok(())
}

#[test]
fn reserved_bm25_doc_ids_are_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    let mut short_id_sentinel = [0xFF; 16];
    short_id_sentinel[0] = 1;

    for raw_id in [TOTAL_DOCS_KEY, TOTAL_LENGTH_KEY, short_id_sentinel] {
        let id = EntityId::from_bytes_unchecked(raw_id);
        let err = vault
            .batch()
            .text(&id, &[("body", "reserved")])
            .commit()
            .unwrap_err();
        assert_matches!(err, Error::InvalidKey);
    }

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(read_total_docs(&vault.store, &rtxn)?, 0);
    Ok(())
}

#[test]
fn stem_exact_hit_does_not_suppress_surface_prefix_expansion() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let stem_exact = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
    let surface_prefix = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

    put_text_doc(&vault, &stem_exact, "she runs daily")?;
    put_text_doc(&vault, &surface_prefix, "runningly specific surface")?;

    let hits = vault.search_text("running", 10)?;

    assert!(contains_id(&hits, &stem_exact));
    assert!(contains_id(&hits, &surface_prefix));
    Ok(())
}

#[test]
fn disabled_channel_exact_hit_does_not_suppress_enabled_prefix() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let disabled_exact = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
    let enabled_prefix = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

    put_text_doc(&vault, &disabled_exact, "she runs daily")?;
    put_text_doc(&vault, &enabled_prefix, "runningly specific surface")?;

    let stem_zero =
        crate::config::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);
    let hits = vault.search_text_with_profile("running", 10, &stem_zero)?;

    assert!(contains_id(&hits, &enabled_prefix));
    Ok(())
}

/// Each search-side variant corrupts BM25 state in a different way, then
/// asserts `search_text` propagates `CorruptedIndex` rather than silently
/// returning wrong rankings.
///
/// Variants:
/// - `corrupted_field_stats`: a `text_bm25_field_stats` row with the
///   wrong byte length (4 vs FIELD_STATS_LEN=12) — `read_field_stats`'s
///   length check must fire instead of swallowing as `avgdl = 0`.
/// - `missing_field_lengths`: full `text_doc_field_lengths` row deleted.
/// - `missing_field_stats_for_used_field`: stats row deleted for the
///   Surface fid that the corpus actually references.
/// - `unknown_field_id`: posting entry rewritten to a fid that no
///   field schema covers (9999).
/// - `df_exceeds_total_docs`: posting entry appends a phantom doc id,
///   driving DF above the corpus size.
/// - `partial_field_lengths`: length row present but missing the
///   Surface fid — must not default `len_f = 0` (would give
///   `norm = 1 - b`, a 4× boost under default b=0.75).
/// - `missing_lengths_for_nonorm_only_match`: the row-existence check
///   must fire even when no `CountLengthIncrement` field has non-zero
///   weight in the rank profile (pre-fix this was nested inside that
///   branch and NoNorm-only matches slipped past).
#[test]
#[allow(clippy::type_complexity)]
fn search_fails_closed_on_all_corruption_variants() -> Result<()> {
    type Setup = fn(&Vault, &EntityId) -> Result<()>;
    fn setup_corrupted_field_stats(vault: &Vault, _id: &EntityId) -> Result<()> {
        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        let short = [0_u8; 4];
        vault
            .store
            .text_bm25_field_stats
            .put(&mut wtxn, &surface_fid.to_be_bytes(), &short)?;
        wtxn.commit()?;
        Ok(())
    }
    fn setup_missing_field_lengths(vault: &Vault, id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(&mut wtxn, id.as_bytes())?
        );
        wtxn.commit()?;
        Ok(())
    }
    fn setup_missing_field_stats_for_used_field(vault: &Vault, _id: &EntityId) -> Result<()> {
        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_bm25_field_stats
                .delete(&mut wtxn, &surface_fid.to_be_bytes())?
        );
        wtxn.commit()?;
        Ok(())
    }
    fn setup_unknown_field_id(vault: &Vault, _id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        // DUP_SORT: `get` returns the first duplicate item, which is
        // the doc's single posting entry here. Swap it for a copy
        // whose field id no schema covers.
        let original = vault
            .store
            .text_postings
            .get(&wtxn, b"alpha")?
            .expect("alpha posting written")
            .to_vec();
        let mut patched = original.clone();
        let fid_offset = ENTITY_ID_LEN + 1;
        patched[fid_offset..fid_offset + 2].copy_from_slice(&9999_u16.to_be_bytes());
        assert!(
            vault
                .store
                .text_postings
                .delete_one_duplicate(&mut wtxn, b"alpha", &original)?
        );
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &patched)?;
        wtxn.commit()?;
        Ok(())
    }
    fn setup_df_exceeds_total_docs(vault: &Vault, _id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        // Appending a phantom entity as a second duplicate drives the
        // dup count (df) above total_docs.
        let phantom = EntityId::now();
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(AnalyzerChannel::Surface.field_id(), 1);
        let mut entry = Vec::new();
        encode_posting_entry(&phantom, &fields, &mut entry)?;
        vault.store.text_postings.put(&mut wtxn, b"alpha", &entry)?;
        wtxn.commit()?;
        Ok(())
    }
    fn setup_partial_field_lengths(vault: &Vault, id: &EntityId) -> Result<()> {
        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(&wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        assert!(lens.remove(&surface_fid).is_some());
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(&mut wtxn, id.as_bytes(), &patched)?;
        wtxn.commit()?;
        Ok(())
    }
    fn setup_missing_lengths_for_nonorm_only_match(vault: &Vault, id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(&mut wtxn, id.as_bytes())?
        );
        wtxn.commit()?;
        Ok(())
    }

    // Default config + custom config for the NoNorm-only variant.
    let default_cfg = || Bm25Config::default();
    let nonorm_only_cfg = || {
        let mut config = Bm25Config::default();
        config.fields[AnalyzerChannel::Surface.field_id() as usize].weight = 0.0;
        config.fields[AnalyzerChannel::Stem.field_id() as usize].weight = 0.0;
        config.fields[AnalyzerChannel::CjkNgram.field_id() as usize].weight = 0.0;
        config
    };

    // (case_name, setup_fn, config_builder, doc_text)
    let cases: Vec<(&str, Setup, fn() -> Bm25Config, &str)> = vec![
        (
            "corrupted_field_stats",
            setup_corrupted_field_stats,
            default_cfg,
            "alpha beta",
        ),
        (
            "missing_field_lengths",
            setup_missing_field_lengths,
            default_cfg,
            "alpha beta",
        ),
        (
            "missing_field_stats_for_used_field",
            setup_missing_field_stats_for_used_field,
            default_cfg,
            "alpha beta",
        ),
        (
            "unknown_field_id",
            setup_unknown_field_id,
            default_cfg,
            "alpha beta",
        ),
        (
            "df_exceeds_total_docs",
            setup_df_exceeds_total_docs,
            default_cfg,
            "alpha beta",
        ),
        (
            "partial_field_lengths",
            setup_partial_field_lengths,
            default_cfg,
            "alpha beta",
        ),
        (
            "missing_lengths_for_nonorm_only_match",
            setup_missing_lengths_for_nonorm_only_match,
            nonorm_only_cfg,
            "alpha",
        ),
    ];

    for (case_name, setup, build_cfg, doc_text) in cases {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, doc_text)?;

        setup(&vault, &id)?;

        let cfg = build_cfg();
        let rtxn = vault.store.env.read_txn()?;
        let err = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &cfg,
            "alpha",
            10,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "case {case_name}: expected CorruptedIndex, got {err:?}"
        );
    }
    Ok(())
}

/// Each deindex-side variant corrupts the BM25 state then asserts
/// `deindex_text` propagates `CorruptedIndex` rather than drifting the
/// corpus stats.
///
/// Variants:
/// - `missing_field_lengths`: full lengths row deleted.
/// - `partial_field_lengths`: lengths row present but missing the
///   Surface fid — per-field stats decrement would silently skip while
///   total_docs-- still fires.
/// - `orphan_length_entry`: lengths row carries a fid (9999) that no
///   forward record references — same drift class, inverse direction.
/// - `zero_length_count_field`: zero length on the Surface channel
///   (which never emits zero-length tokens) would underflow
///   `total_length` decrement.
#[test]
fn deindex_fails_closed_on_all_corruption_variants() -> Result<()> {
    type Setup = fn(&Vault, &EntityId, &mut heed::RwTxn<'_>) -> Result<()>;
    fn setup_missing_field_lengths(
        vault: &Vault,
        id: &EntityId,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(wtxn, id.as_bytes())?
        );
        Ok(())
    }
    fn setup_partial_field_lengths(
        vault: &Vault,
        id: &EntityId,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let surface_fid = AnalyzerChannel::Surface.field_id();
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        assert!(lens.remove(&surface_fid).is_some());
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(wtxn, id.as_bytes(), &patched)?;
        Ok(())
    }
    fn setup_orphan_length_entry(
        vault: &Vault,
        id: &EntityId,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        lens.insert(9999, 7);
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(wtxn, id.as_bytes(), &patched)?;
        Ok(())
    }
    fn setup_zero_length_count_field(
        vault: &Vault,
        id: &EntityId,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let surface_fid = AnalyzerChannel::Surface.field_id();
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        lens.insert(surface_fid, 0);
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(wtxn, id.as_bytes(), &patched)?;
        Ok(())
    }

    // (case_name, setup_fn)
    let cases: Vec<(&str, Setup)> = vec![
        ("missing_field_lengths", setup_missing_field_lengths),
        ("partial_field_lengths", setup_partial_field_lengths),
        ("orphan_length_entry", setup_orphan_length_entry),
        ("zero_length_count_field", setup_zero_length_count_field),
    ];

    for (case_name, setup) in cases {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        setup(&vault, &id, &mut wtxn)?;
        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "case {case_name}: expected CorruptedIndex, got {err:?}"
        );
    }
    Ok(())
}

#[test]
fn deindex_self_heals_missing_postings_and_records_diagnostics() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;

    let before_missing_row = vault
        .diagnostics()
        .bm25_snapshot()
        .count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingRow);
    let mut wtxn = vault.store.env.write_txn()?;
    let entry = match find_posting_dup(&vault.store, &wtxn, "alpha", &id)? {
        PostingLookup::Found(entry) => entry,
        _ => panic!("alpha posting dup for doc must exist"),
    };
    assert!(
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, b"alpha", &entry)?
    );
    deindex_text(&vault.store, &mut wtxn, &id)?;
    wtxn.commit()?;
    assert!(vault.search_text("alpha", 10)?.is_empty());
    assert_eq!(
        vault
            .diagnostics()
            .bm25_snapshot()
            .count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingRow),
        before_missing_row + 1
    );

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    let other = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;
    put_text_doc(&vault, &other, "alpha")?;

    let before_missing_entity = vault
        .diagnostics()
        .bm25_snapshot()
        .count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingEntity);
    let mut wtxn = vault.store.env.write_txn()?;
    let entry = match find_posting_dup(&vault.store, &wtxn, "alpha", &id)? {
        PostingLookup::Found(entry) => entry,
        _ => panic!("alpha posting dup for doc must exist"),
    };
    assert!(
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, b"alpha", &entry)?
    );
    deindex_text(&vault.store, &mut wtxn, &id)?;
    wtxn.commit()?;
    let results = vault.search_text("alpha", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, other);
    assert_eq!(
        vault
            .diagnostics()
            .bm25_snapshot()
            .count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingEntity),
        before_missing_entity + 1
    );

    Ok(())
}

#[test]
fn deindex_missing_posting_after_partial_repair_fails_closed() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    let other = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;
    put_text_doc(&vault, &other, "alpha")?;

    let mut wtxn = vault.store.env.write_txn()?;
    let entry = match find_posting_dup(&vault.store, &wtxn, "alpha", &id)? {
        PostingLookup::Found(entry) => entry,
        _ => panic!("alpha posting dup for doc must exist"),
    };
    assert!(
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, b"alpha", &entry)?
    );

    let raw_lengths = vault
        .store
        .text_doc_field_lengths
        .get(&wtxn, id.as_bytes())?
        .expect("length row written on index")
        .to_vec();
    let lengths = decode_field_lengths(&raw_lengths)?;
    for (&fid, &len) in &lengths {
        let (doc_count, total_length) = read_field_stats(&vault.store, &wtxn, fid)?;
        let doc_count = doc_count
            .checked_sub(1)
            .expect("test setup starts with two indexed docs");
        let total_length = total_length
            .checked_sub(u64::from(len))
            .expect("test setup starts with this doc counted");
        if doc_count == 0 && total_length == 0 {
            vault
                .store
                .text_bm25_field_stats
                .delete(&mut wtxn, &fid.to_be_bytes())?;
        } else {
            write_field_stats(&vault.store, &mut wtxn, fid, doc_count, total_length)?;
        }
    }
    let total_docs = read_total_docs(&vault.store, &wtxn)?;
    write_total_docs(&vault.store, &mut wtxn, total_docs - 1)?;
    wtxn.commit()?;

    let mut wtxn = vault.store.env.write_txn()?;
    let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    drop(wtxn);

    let results = vault.search_text("alpha", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, other);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(read_total_docs(&vault.store, &rtxn)?, 1);
    let raw_other_lengths = vault
        .store
        .text_doc_field_lengths
        .get(&rtxn, other.as_bytes())?
        .expect("other length row remains indexed")
        .to_vec();
    let other_lengths = decode_field_lengths(&raw_other_lengths)?;
    for (&fid, &len) in &other_lengths {
        assert_eq!(
            read_field_stats(&vault.store, &rtxn, fid)?,
            (1, u64::from(len))
        );
    }

    Ok(())
}

#[test]
fn posting_decode_rejects_zero_tf() {
    let mut posting = Vec::new();
    let id = EntityId::now();
    posting.extend_from_slice(id.as_bytes());
    posting.push(1);
    posting.extend_from_slice(&AnalyzerChannel::Surface.field_id().to_be_bytes());
    posting.extend_from_slice(&0_u32.to_le_bytes());
    let err = decode_posting_entry(&Bm25Diagnostics::default(), &posting).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
}

/// A v1-style concatenated multi-entry blob must NOT decode as a
/// single duplicate item — exactly one entry per dup is the ONE-299
/// invariant, so trailing bytes are corruption.
#[test]
fn posting_decode_rejects_concatenated_entries() -> Result<()> {
    let mut fields = BTreeMap::new();
    fields.insert(AnalyzerChannel::Surface.field_id(), 1_u32);
    let mut blob = Vec::new();
    encode_posting_entry(&EntityId::now(), &fields, &mut blob)?;
    encode_posting_entry(&EntityId::now(), &fields, &mut blob)?;
    let err = decode_posting_entry(&Bm25Diagnostics::default(), &blob).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

#[test]
fn decode_rejects_empty_rows() {
    assert!(matches!(
        decode_posting_entry(&Bm25Diagnostics::default(), &[]),
        Err(Error::CorruptedIndex(_)),
    ));
    assert!(matches!(decode_forward(&[]), Err(Error::CorruptedIndex(_)),));
    assert!(matches!(
        decode_field_lengths(&[]),
        Err(Error::CorruptedIndex(_)),
    ));
}

/// ABI v4 forward record layout, literal bytes: `term_len_u16_le |
/// term_bytes | field_id_u16_be` — and nothing else. An
/// implementation still writing the dead v1 `tf` u32 FAILS here.
#[test]
fn forward_record_layout_drops_tf() -> Result<()> {
    let mut m: BTreeMap<String, BTreeMap<u16, u32>> = BTreeMap::new();
    m.entry("ab".into()).or_default().insert(3, 7);
    let bytes = encode_forward(&m)?;
    assert_eq!(bytes, vec![2, 0, b'a', b'b', 0, 3]);

    let back = decode_forward(&bytes)?;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].term, "ab");
    assert_eq!(back[0].field_id, 3);
    Ok(())
}

/// A v1-shaped forward row (with the trailing `tf` u32 per record)
/// must fail decoding, not silently misparse.
#[test]
fn forward_decode_rejects_v1_records_with_tf() {
    let v1_record = [2, 0, b'a', b'b', 0, 3, 7, 0, 0, 0];
    let err = decode_forward(&v1_record).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
}

#[test]
fn field_lengths_roundtrip() -> Result<()> {
    let mut m = HashMap::new();
    m.insert(0, 5);
    m.insert(2, 1);
    m.insert(3, 8);
    let bytes = encode_field_lengths(&m);
    let back = decode_field_lengths(&bytes)?;
    assert_eq!(back, m);
    Ok(())
}

fn collect_posting_dups(vault: &Vault, term: &[u8]) -> Result<Vec<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(dups) = vault.store.text_postings.get_duplicates(&rtxn, term)? else {
        return Ok(Vec::new());
    };
    let mut items = Vec::new();
    for item in dups {
        let (_, dup) = item?;
        items.push(dup.to_vec());
    }
    Ok(items)
}

/// ONE-299 AC1: `text_postings` holds one DUP_SORT duplicate item per
/// (term, entity), bytewise-sorted so items order by entity-id
/// prefix, and each item decodes standalone. A v1-style
/// implementation that concatenates all entries under one value
/// would yield a single dup here and FAIL the count assertion.
#[test]
fn postings_store_one_sorted_dup_item_per_entity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    for id in &ids {
        put_text_doc(&vault, id, "shared")?;
    }
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let items = collect_posting_dups(&vault, b"shared")?;
    assert_eq!(items.len(), 3, "one dup item per (term, entity)");
    for (item, id) in items.iter().zip(&ids) {
        assert_eq!(
            &item[..ENTITY_ID_LEN],
            id.as_bytes(),
            "dup items must sort by entity-id prefix",
        );
        let entry = decode_posting_entry(&vault.store.diagnostics.bm25, item)?;
        assert_eq!(entry.id, *id);
    }
    Ok(())
}

/// ONE-299 AC1 literal bytes: one dup item is exactly
/// `entity_id(16) | field_count(u8) | field_id_u16_be | tf_u32_le`.
/// "apple" stems to "appl", so the `apple` posting carries only the
/// Surface channel (field id 0) with tf 2.
#[test]
fn posting_dup_item_literal_layout() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "apple apple")?;

    let items = collect_posting_dups(&vault, b"apple")?;
    assert_eq!(items.len(), 1);
    let mut expected = id.as_bytes().to_vec();
    expected.push(1); // field_count
    expected.extend_from_slice(&AnalyzerChannel::Surface.field_id().to_be_bytes());
    expected.extend_from_slice(&2_u32.to_le_bytes()); // tf, little-endian
    assert_eq!(items[0], expected);
    Ok(())
}

/// ONE-299 AC2: deindex deletes exactly ONE duplicate item — sibling
/// entities' items survive byte-identical — and deleting the last
/// duplicate removes the term key itself.
#[test]
fn deindex_deletes_exactly_one_dup_item() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    for id in &ids {
        put_text_doc(&vault, id, "shared")?;
    }
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let before = collect_posting_dups(&vault, b"shared")?;
    assert_eq!(before.len(), 3);

    assert!(vault.delete_entity_with_options(
        &ids[1],
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    let after = collect_posting_dups(&vault, b"shared")?;
    assert_eq!(after.len(), 2);
    assert_eq!(
        after[0], before[0],
        "untouched dup must stay byte-identical"
    );
    assert_eq!(
        after[1], before[2],
        "untouched dup must stay byte-identical"
    );

    assert!(vault.delete_entity_with_options(
        &ids[0],
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert!(vault.delete_entity_with_options(
        &ids[2],
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.text_postings.get(&rtxn, b"shared")?.is_none(),
        "term key must disappear with its last duplicate",
    );
    Ok(())
}

/// Two duplicate items sharing one entity prefix violate the
/// one-dup-per-(term, entity) invariant (df would drift). Both the
/// search path and the deindex prefix scan must fail closed.
#[test]
fn duplicate_entity_dup_items_fail_closed() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut fields = BTreeMap::new();
        fields.insert(AnalyzerChannel::Surface.field_id(), 9_u32);
        let mut second = Vec::new();
        encode_posting_entry(&id, &fields, &mut second)?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &second)?;
        wtxn.commit()?;
    }

    let rtxn = vault.store.env.read_txn()?;
    let err = search_text(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &Bm25Config::default(),
        "alpha",
        10,
    )
    .unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    drop(rtxn);

    let mut wtxn = vault.store.env.write_txn()?;
    let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

/// `len` characters of the base64 alphabet's letters and digits, from a fixed
/// seed: one Unicode word, like a pasted key or image blob.
fn synthetic_base64_word(seed: &str, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = vec![0_u8; len];
    blake3::Hasher::new()
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]))
        .collect()
}

/// A pasted 1,583-character base64 word is one term over LMDB's 511-byte key
/// limit. It indexes under a stable digest key, an exact query finds it, a
/// same-head twin stays apart, and reindex and delete both remove it.
#[test]
fn a_1583_character_base64_term_round_trips_through_the_index() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let long = synthetic_base64_word("bm25-long-term", 1_583);
    let mut tokens = Vec::new();
    vault
        .analyzer
        .analyze(&long, &AnalyzerContext::for_index(), &mut tokens);
    assert!(
        tokens.iter().any(|token| token.term.len() > 511),
        "the fixture must reach the index as one over-limit term"
    );
    // Same first 1,000 characters, different tail: a distinct term.
    let twin = format!("{}{}", &long[..1_000], synthetic_base64_word("twin", 583));

    let id = EntityId::now();
    let twin_id = EntityId::now();
    put_text_doc(&vault, &id, &format!("pasted blob {long} end"))?;
    put_text_doc(&vault, &twin_id, &twin)?;
    let hits = vault.search_text(&long, 10)?;
    assert!(contains_id(&hits, &id));
    assert!(!contains_id(&hits, &twin_id));
    assert!(contains_id(&vault.search_text(&twin, 10)?, &twin_id));

    vault
        .batch()
        .text(&id, &[("body", "replaced body")])
        .commit()?;
    assert!(!contains_id(&vault.search_text(&long, 10)?, &id));
    assert!(contains_id(&vault.search_text("replaced", 10)?, &id));

    assert!(vault.delete_entity_with_options(
        &twin_id,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert!(vault.search_text(&twin, 10)?.is_empty());
    Ok(())
}
