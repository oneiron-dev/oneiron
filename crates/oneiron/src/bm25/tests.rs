use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::types::{
    ClaimCandidate, EdgeActorClass, HnswConfig, TimeRange, VaultConfig, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use crate::{Error, Vault};
use core::assert_matches;
use rmpv::Value;

fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 16 * 1024 * 1024,
        dimensions: 4,
        embedding_model: None,
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::types::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        skip_text_index_manifest_check: false,
    }
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn contains_id(results: &[ScoredEntity], id: &EntityId) -> bool {
    results.iter().any(|r| r.id == *id)
}

fn reset_bm25_diagnostics() {
    for counter in &BM25_DIAGNOSTIC_COUNTERS {
        counter.store(0, AtomicOrdering::Relaxed);
    }
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

fn put_raw_posting_terms(vault: &Vault, terms: &[String]) -> Result<()> {
    let postings = terms
        .iter()
        .enumerate()
        .map(|(idx, term)| {
            (
                term.clone(),
                test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
            )
        })
        .collect::<Vec<_>>();
    put_raw_posting_terms_with_ids(vault, &postings)
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

fn cap_prefix_term(index: usize) -> String {
    format!("capbound{index:04}")
}

fn repeated(term: &str, count: usize) -> String {
    std::iter::repeat_n(term, count)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn default_config_matches_plan_defaults() {
    let c = Bm25Config::default();
    assert_eq!(c.k1, 1.2);
    assert_eq!(c.formula, Bm25Formula::Okapi);
    let surface = c.field(AnalyzerChannel::Surface);
    assert_eq!(surface.weight, 1.00);
    assert_eq!(surface.b, 0.75);
    assert_eq!(
        surface.length_policy,
        FieldLengthPolicy::CountLengthIncrement
    );
    let ngram = c.field(AnalyzerChannel::CjkNgram);
    assert_eq!(ngram.weight, 0.45);
    assert_eq!(ngram.b, 0.30);
    let overlay = c.field(AnalyzerChannel::NormalizedOverlay);
    assert_eq!(overlay.length_policy, FieldLengthPolicy::NoNorm);
    // Reserved channels disabled.
    assert_eq!(c.field(AnalyzerChannel::Shingle).weight, 0.0);
    assert_eq!(c.field(AnalyzerChannel::Synonym).weight, 0.0);
    assert_eq!(c.field(AnalyzerChannel::Phonetic).weight, 0.0);
}

#[test]
fn index_and_search_basic() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let id3 = EntityId::now();

    put_text_doc(&vault, &id1, "rust language and systems")?;
    put_text_doc(&vault, &id2, "bm25 ranking in search")?;
    put_text_doc(&vault, &id3, "graph traversal only")?;

    let results = vault.search_text("rust", 10)?;
    assert!(contains_id(&results, &id1));
    assert!(!contains_id(&results, &id2));
    assert!(!contains_id(&results, &id3));
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
    );
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
    assert_matches!(err, Error::CorruptedIndex("lexical query hint claim"));
    Ok(())
}

#[test]
fn header_only_lexical_hint_claim_posting_is_dead_not_corrupt() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let hint = lh_prefixed_id(0x64)?;

    seed_raw_claim_bytes(&vault, &hint, &[])?;
    vault
        .batch()
        .text(&hint, &[("query_hint", "headeronlyhintprobe")])
        .commit()?;

    let hits = vault.search_text("headeronlyhintprobe", 10)?;
    assert!(hits.is_empty());
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
    );
    seed_raw_claim(&vault, &target, target_body)?;

    let body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        crate::claim::ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "nonstalehintprobe"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
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
fn search_ranking_100_docs() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let mut batch = vault.batch();
    let best_idx = 42;
    let mut best_id = None;

    for idx in 0..100 {
        let id = EntityId::now();
        if idx == best_idx {
            best_id = Some(id);
        }
        let tf = if idx == best_idx { 20 } else { 1 };
        let text = repeated("apple", tf);
        batch = batch
            .put(
                &id,
                1,
                test_time_range(idx as u64, idx as u64),
                idx as u64,
                b"doc",
            )
            .text(&id, &[("body", &text)]);
    }
    batch.commit()?;

    let best_id = best_id.ok_or(Error::InvalidKey)?;
    let results = vault.search_text("apple", 10)?;
    assert!(!results.is_empty());
    assert_eq!(results[0].id, best_id);
    Ok(())
}

#[test]
fn deindex_removes_from_search() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    put_text_doc(&vault, &id, "deindex me please")?;
    let before = vault.search_text("deindex", 10)?;
    assert!(contains_id(&before, &id));

    assert!(vault.delete_entity(&id)?);
    let after = vault.search_text("deindex", 10)?;
    assert!(!contains_id(&after, &id));
    Ok(())
}

#[test]
fn multi_term_query() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id_both = EntityId::now();
    let id_alpha = EntityId::now();
    let id_beta = EntityId::now();

    put_text_doc(&vault, &id_both, "alpha beta")?;
    put_text_doc(&vault, &id_alpha, "alpha")?;
    put_text_doc(&vault, &id_beta, "beta")?;

    let results = vault.search_text("alpha beta", 10)?;
    assert_eq!(results[0].id, id_both);
    Ok(())
}

#[test]
fn final_token_prefix_matches_only_last_query_token() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let retrieval = EntityId::now();
    let alpha_only = EntityId::now();
    let unrelated = EntityId::now();

    put_text_doc(&vault, &retrieval, "omega retrieval")?;
    put_text_doc(&vault, &alpha_only, "alpha zulu")?;
    put_text_doc(&vault, &unrelated, "garden zulu")?;

    let results = vault.search_text("alp retr", 10)?;
    assert!(contains_id(&results, &retrieval));
    assert!(
        !contains_id(&results, &alpha_only),
        "non-final query token must not be prefix-expanded",
    );
    assert!(!contains_id(&results, &unrelated));

    Ok(())
}

#[test]
fn final_token_prefix_expands_matching_terms_below_cap() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    put_raw_posting_terms(
        &vault,
        &[
            "normprefixalpha".to_owned(),
            "normprefixbeta".to_owned(),
            "otherprefix".to_owned(),
        ],
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let mut terms = BTreeMap::new();
    let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
    collect_final_token_prefix_terms(
        &vault.store,
        &rtxn,
        "normprefix".len(),
        &Bm25Config::default(),
        &[final_word_token("normprefix")],
        &mut terms,
        &mut exact_posting_matches_scope,
    )?;

    let collected = terms.keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        collected,
        vec!["normprefixalpha".to_owned(), "normprefixbeta".to_owned()]
    );
    assert!(
        terms
            .values()
            .all(|weight| *weight == FINAL_TOKEN_PREFIX_WEIGHT)
    );
    Ok(())
}

#[test]
fn final_token_prefix_ignores_derived_stem_prefixes() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    put_raw_posting_terms(
        &vault,
        &[
            "runner".to_owned(),
            "runningly".to_owned(),
            "runt".to_owned(),
        ],
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let mut terms = BTreeMap::new();
    let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
    collect_final_token_prefix_terms(
        &vault.store,
        &rtxn,
        "running".len(),
        &Bm25Config::default(),
        &[
            final_word_token("running"),
            Token::new(
                "run",
                0,
                "running".len() as u32,
                0,
                AnalyzerChannel::Stem,
                TokenKind::Word,
            ),
        ],
        &mut terms,
        &mut exact_posting_matches_scope,
    )?;

    assert_eq!(
        terms.keys().cloned().collect::<Vec<_>>(),
        vec!["runningly".to_owned()]
    );
    Ok(())
}

#[test]
fn final_token_prefix_expansion_is_capped_in_deterministic_order() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let indexed_terms = (0..MAX_FINAL_TOKEN_PREFIX_TERMS + 2)
        .map(cap_prefix_term)
        .collect::<Vec<_>>();
    put_raw_posting_terms(&vault, &indexed_terms)?;

    let rtxn = vault.store.env.read_txn()?;
    let mut terms = BTreeMap::new();
    let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
    collect_final_token_prefix_terms(
        &vault.store,
        &rtxn,
        "capbound".len(),
        &Bm25Config::default(),
        &[final_word_token("capbound")],
        &mut terms,
        &mut exact_posting_matches_scope,
    )?;

    let collected = terms.keys().cloned().collect::<Vec<_>>();
    let expected = (0..MAX_FINAL_TOKEN_PREFIX_TERMS)
        .map(cap_prefix_term)
        .collect::<Vec<_>>();
    assert_eq!(collected, expected);
    assert!(!terms.contains_key(&cap_prefix_term(MAX_FINAL_TOKEN_PREFIX_TERMS)));
    Ok(())
}

#[test]
fn final_token_prefix_expansion_applies_cap_after_scope_filtering() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let prefix = "scopecap";
    let in_scope_index = MAX_FINAL_TOKEN_PREFIX_TERMS + 1;
    let in_scope_id = test_entity_id(0x8000);
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

    let in_scope_term = format!("{prefix}{in_scope_index:04}");
    assert_eq!(
        terms.keys().cloned().collect::<Vec<_>>(),
        vec![in_scope_term]
    );
    assert!(
        scope_checks > MAX_FINAL_TOKEN_PREFIX_TERMS,
        "scope filtering must happen before the 64-term expansion cap"
    );
    assert!(scope_checks <= MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
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
fn final_token_prefix_scope_filtering_keeps_global_scan_bounded() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let prefix = "scopebound";
    let postings = (0..MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS + 2)
        .map(|idx| {
            (
                format!("{prefix}{idx:04}"),
                test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
            )
        })
        .collect::<Vec<_>>();
    put_raw_posting_terms_with_ids(&vault, &postings)?;

    let rtxn = vault.store.env.read_txn()?;
    let mut terms = BTreeMap::new();
    let mut scope_checks = 0usize;
    let mut exact_posting_matches_scope = |_id: &EntityId| {
        scope_checks += 1;
        Ok(false)
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

    assert!(terms.is_empty());
    assert_eq!(scope_checks, MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
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

#[test]
fn bm25_recency_blend_is_configurable_and_deterministic() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let old = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
    let fresh = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

    put_text_doc_at(&vault, &old, "needle", 0)?;
    put_text_doc_at(&vault, &fresh, "needle", 86_400)?;

    let rtxn = vault.store.env.read_txn()?;
    let config = Bm25Config::default();
    let baseline = search_text_with_recency(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &config,
        "needle",
        10,
        None,
    )?;
    assert_eq!(baseline[0].id, old, "baseline tie breaks by entity id");

    let recency = Some(Bm25RecencyConfig {
        half_life_days: 0.01,
        boost: 4.0,
        now_secs: 86_400,
    });
    let boosted = search_text_with_recency(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &config,
        "needle",
        10,
        recency,
    )?;
    let repeated = search_text_with_recency(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &config,
        "needle",
        10,
        recency,
    )?;
    assert_eq!(boosted[0].id, fresh);
    assert_eq!(boosted.len(), repeated.len());
    for (left, right) in boosted.iter().zip(repeated.iter()) {
        assert_eq!(left.id, right.id);
        assert_eq!(left.score, right.score);
    }
    Ok(())
}

#[test]
fn empty_query_returns_empty() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "hello world")?;

    let results = vault.search_text("", 10)?;
    assert!(results.is_empty());
    Ok(())
}

#[test]
fn zero_limit_returns_empty() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "hello world")?;

    let results = vault.search_text("hello", 0)?;
    assert!(results.is_empty());
    Ok(())
}

#[test]
fn empty_vault_query_returns_empty() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let results = vault.search_text("hello", 10)?;
    assert!(results.is_empty());
    Ok(())
}

#[test]
fn empty_document() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 2, b"empty")
        .text(&id, &[("title", ""), ("body", "")])
        .commit()?;

    let results = vault.search_text("anything", 10)?;
    assert!(!contains_id(&results, &id));
    Ok(())
}

#[test]
fn reindex_overwrites_cleanly() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    put_text_doc(&vault, &id, "foo bar")?;
    vault.batch().text(&id, &[("body", "baz qux")]).commit()?;

    let foo_results = vault.search_text("foo", 10)?;
    let baz_results = vault.search_text("baz", 10)?;

    assert!(!contains_id(&foo_results, &id));
    assert!(contains_id(&baz_results, &id));
    Ok(())
}

#[test]
fn fullwidth_ascii_document_matches_ascii_query() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "ＡＢＣ fullwidth mixed with regular ABC")?;

    let lower = vault.search_text("abc", 10)?;
    assert!(contains_id(&lower, &id));
    let upper = vault.search_text("ABC", 10)?;
    assert!(contains_id(&upper, &id));
    let fullwidth = vault.search_text("ＡＢＣ", 10)?;
    assert!(contains_id(&fullwidth, &id));
    Ok(())
}

#[test]
fn stem_channel_enables_cross_inflection_recall() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id_runs = EntityId::now();
    let id_ran = EntityId::now();
    put_text_doc(&vault, &id_runs, "she runs every morning before work")?;
    // `runs`, `running`, `runnings` all Snowball-stem to `run`, so a
    // `running` query must reach a doc that only carries a sibling
    // inflection. Regression guard for symmetric stem emission.
    put_text_doc(&vault, &id_ran, "he runnings the marathon next spring")?;

    let hits = vault.search_text("running", 10)?;
    assert!(contains_id(&hits, &id_runs));
    assert!(contains_id(&hits, &id_ran));
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

/// End-to-end check on the analyzer contract: kana-fold emissions on
/// `NormalizedOverlay` must persist a zero field length (Surface
/// still records its own length), and deindex must tolerate that
/// zero given the matching forward-index entry.
#[test]
fn normalized_overlay_persists_zero_field_length() -> Result<()> {
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
    put_text_doc(&vault, &id, "トウキョウ")?;

    let overlay_fid = AnalyzerChannel::NormalizedOverlay.field_id();
    {
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(&rtxn, id.as_bytes())?
            .expect("lengths row written");
        let lens = decode_field_lengths(raw)?;
        assert_eq!(
            lens.get(&overlay_fid).copied(),
            Some(0),
            "NormalizedOverlay field length must be 0 under zero-length-token contract",
        );
        let (doc_count, total_length) = read_field_stats(&vault.store, &rtxn, overlay_fid)?;
        assert_eq!(doc_count, 1);
        assert_eq!(total_length, 0);
    }

    assert!(vault.delete_entity(&id)?);
    Ok(())
}

#[test]
fn cjk_query_matches_bigram_channel() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    put_text_doc(&vault, &id, "東京塔")?;
    // "東京" matches the `東京` bigram on the CjkNgram channel.
    let results = vault.search_text("東京", 10)?;
    assert!(contains_id(&results, &id));
    Ok(())
}

#[test]
fn single_character_cjk_document_is_searchable() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();

    put_text_doc(&vault, &id, "東")?;
    let results = vault.search_text("東", 10)?;
    assert!(contains_id(&results, &id));
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
fn bm25_plus_formula_does_not_require_reindex() -> Result<()> {
    // Changing the rank profile is scoring-only — same index, same
    // postings, different score. Plan §4.2.
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "hello world")?;

    let okapi = vault.search_text("hello", 10)?;
    assert!(contains_id(&okapi, &id));

    let rtxn = vault.store.env.read_txn()?;
    let plus_cfg = Bm25Config {
        formula: Bm25Formula::Plus { delta: 1.0 },
        ..Bm25Config::default()
    };
    let plus = search_text(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &plus_cfg,
        "hello",
        10,
    )?;
    assert!(contains_id(&plus, &id));
    // BM25+ adds a positive delta·idf term per query term, so the
    // scored value must be strictly greater than Okapi's.
    let okapi_score = okapi.iter().find(|r| r.id == id).unwrap().score;
    let plus_score = plus.iter().find(|r| r.id == id).unwrap().score;
    assert!(plus_score > okapi_score);

    // Release the read txn — LMDB allows one read txn per thread and
    // the public path below opens its own.
    drop(rtxn);

    // Public path: the same formula switch through the
    // `Bm25RankProfile` knob must produce the identical BM25+ score
    // against the same index — no reindex happened in between.
    let plus_profile =
        crate::types::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });
    let public_plus = vault.search_text_with_profile("hello", 10, &plus_profile)?;
    let public_plus_score = public_plus.iter().find(|r| r.id == id).unwrap().score;
    assert_eq!(public_plus_score, plus_score);
    assert!(public_plus_score > okapi_score);
    Ok(())
}

#[test]
fn okapi_surface_score_matches_formula_fixture() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    let other_alpha = EntityId::now();
    let other_beta = EntityId::now();
    put_text_doc(&vault, &id, "alpha alpha alpha")?;
    put_text_doc(&vault, &other_alpha, "alpha")?;
    put_text_doc(&vault, &other_beta, "beta")?;

    let mut config = Bm25Config {
        fields: [FieldConfig::disabled(); BM25_FIELD_COUNT],
        ..Bm25Config::default()
    };
    config.fields[AnalyzerChannel::Surface.field_id() as usize] = FieldConfig {
        weight: 1.0,
        b: 0.75,
        length_policy: FieldLengthPolicy::CountLengthIncrement,
    };

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?,
        (3, 5),
        "fixture must be three Surface documents with five total tokens"
    );
    let results = search_text(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &config,
        "alpha",
        10,
    )?;
    let score = results
        .iter()
        .find(|result| result.id == id)
        .expect("document must score")
        .score as f64;

    let n = 3.0_f64;
    let df = 2.0_f64;
    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
    let avgdl = 5.0_f64 / 3.0_f64;
    let norm = 1.0 - 0.75 + 0.75 * (3.0 / avgdl);
    let x_t_d = 3.0_f64 / norm;
    let expected = idf * ((config.k1 + 1.0) * x_t_d / (config.k1 + x_t_d));
    assert!(
        (score - expected).abs() < 1e-6,
        "score {score} did not match expected {expected}"
    );
    Ok(())
}

/// The public default profile must lower to the literal ARCH-0031
/// channel table (weights / `b` / length policy), the pinned global
/// `k1 = 1.2`, and the Okapi default formula. Reserved channels stay
/// disabled. The profile deliberately exposes no `k1` knob.
#[test]
fn rank_profile_default_lowers_to_contract_literals() -> Result<()> {
    let c = crate::types::Bm25RankProfile::default().to_bm25_config()?;
    assert_eq!(c.k1, 1.2);
    assert_eq!(c.formula, Bm25Formula::Okapi);

    let surface = c.field(AnalyzerChannel::Surface);
    assert_eq!(surface.weight, 1.00);
    assert_eq!(surface.b, 0.75);
    assert_eq!(
        surface.length_policy,
        FieldLengthPolicy::CountLengthIncrement
    );
    let stem = c.field(AnalyzerChannel::Stem);
    assert_eq!(stem.weight, 0.35);
    assert_eq!(stem.b, 0.65);
    assert_eq!(stem.length_policy, FieldLengthPolicy::CountLengthIncrement);
    let overlay = c.field(AnalyzerChannel::NormalizedOverlay);
    assert_eq!(overlay.weight, 0.55);
    assert_eq!(overlay.b, 0.00);
    assert_eq!(overlay.length_policy, FieldLengthPolicy::NoNorm);
    let ngram = c.field(AnalyzerChannel::CjkNgram);
    assert_eq!(ngram.weight, 0.45);
    assert_eq!(ngram.b, 0.30);
    assert_eq!(ngram.length_policy, FieldLengthPolicy::CountLengthIncrement);

    for reserved in [
        AnalyzerChannel::Shingle,
        AnalyzerChannel::Synonym,
        AnalyzerChannel::Phonetic,
    ] {
        assert_eq!(c.field(reserved).weight, 0.0);
    }
    Ok(())
}

/// AC3: a `weight == 0.0` channel override excludes that channel from
/// scoring through both public paths (`search_text_with_profile` and
/// the pipeline's `rank_profile`). The query `running` reaches the
/// doc only via the Stem channel (`runs` and `running` both stem to
/// `run`), so zeroing Stem must drop the doc entirely.
#[test]
fn zero_weight_channel_excluded_through_public_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "she runs every morning before work")?;

    // Default profile: stem channel carries the match.
    let default_profile = crate::types::Bm25RankProfile::default();
    let stem_only_query = "running.";
    let hits = vault.search_text_with_profile(stem_only_query, 10, &default_profile)?;
    assert!(contains_id(&hits, &id));

    // Stem weight zeroed: the only matching channel is excluded. The
    // punctuation keeps this assertion isolated from final-token prefix
    // widening, which may legitimately match `runs` through Surface.
    let stem_zero =
        crate::types::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);
    let hits = vault.search_text_with_profile(stem_only_query, 10, &stem_zero)?;
    assert!(
        !contains_id(&hits, &id),
        "zero-weight Stem channel must be excluded from scoring",
    );

    // Same exclusion through the pipeline path.
    let hits = vault
        .query()
        .search_text(stem_only_query, 10)
        .rank_profile(stem_zero)
        .run()?;
    assert!(!contains_id(&hits, &id));
    let hits = vault.query().search_text(stem_only_query, 10).run()?;
    assert!(contains_id(&hits, &id), "default pipeline still matches");

    // All four v1 channels zeroed: even a direct surface match is
    // excluded and the result set is empty.
    let all_zero = crate::types::Bm25RankProfile::default()
        .with_channel_weight(AnalyzerChannel::Surface, 0.0)
        .with_channel_weight(AnalyzerChannel::Stem, 0.0)
        .with_channel_weight(AnalyzerChannel::NormalizedOverlay, 0.0)
        .with_channel_weight(AnalyzerChannel::CjkNgram, 0.0);
    let hits = vault.search_text_with_profile("runs", 10, &all_zero)?;
    assert!(hits.is_empty());
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
        crate::types::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);
    let hits = vault.search_text_with_profile("running", 10, &stem_zero)?;

    assert!(contains_id(&hits, &enabled_prefix));
    Ok(())
}

/// AC6: invalid rank-profile inputs are rejected fail-closed with the
/// typed `Error::InvalidRankProfile` through both public paths —
/// never clamped, skipped, or silently defaulted. Boundary-legal
/// values stay accepted.
#[test]
fn rank_profile_validation_fails_closed() -> Result<()> {
    use crate::types::Bm25RankProfile;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "hello world")?;

    let cases: Vec<(&str, Bm25RankProfile, &'static str)> = vec![
        (
            "weight_nan",
            Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Surface, f64::NAN),
            "channel.weight",
        ),
        (
            "weight_negative",
            Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Surface, -0.1),
            "channel.weight",
        ),
        (
            "weight_infinite",
            Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Surface, f64::INFINITY),
            "channel.weight",
        ),
        (
            "b_nan",
            Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, f64::NAN),
            "channel.b",
        ),
        (
            "b_negative",
            Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, -0.01),
            "channel.b",
        ),
        (
            "b_above_one",
            Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, 1.01),
            "channel.b",
        ),
        (
            "delta_nan",
            Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: f64::NAN }),
            "formula.delta",
        ),
        (
            "delta_zero",
            Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 0.0 }),
            "formula.delta",
        ),
        (
            "delta_negative",
            Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: -1.0 }),
            "formula.delta",
        ),
        (
            "delta_infinite",
            Bm25RankProfile::default().with_formula(Bm25Formula::Plus {
                delta: f64::INFINITY,
            }),
            "formula.delta",
        ),
        (
            "weight_on_reserved_channel",
            Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Shingle, 0.5),
            "weight.reserved_channel",
        ),
        (
            "b_on_reserved_channel",
            Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Phonetic, 0.5),
            "b.reserved_channel",
        ),
    ];

    for (case_name, profile, expected_parameter) in cases {
        let err = vault
            .search_text_with_profile("hello", 10, &profile)
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::InvalidRankProfile { parameter, .. } if parameter == expected_parameter
            ),
            "case {case_name}: expected InvalidRankProfile({expected_parameter}), got {err:?}",
        );

        // The pipeline fails closed too — even with no text search
        // attached, an invalid profile is a caller bug.
        let err = vault.query().rank_profile(profile).run().unwrap_err();
        assert!(
            matches!(err, Error::InvalidRankProfile { .. }),
            "case {case_name} (pipeline): expected InvalidRankProfile, got {err:?}",
        );
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidRankProfile);
    }

    // Boundary-legal values stay accepted: weight 0.0, b 0.0 / 1.0,
    // small positive delta; the last override per channel wins.
    let legal = crate::types::Bm25RankProfile::default()
        .with_formula(Bm25Formula::Plus { delta: 1e-6 })
        .with_channel_weight(AnalyzerChannel::Surface, 0.0)
        .with_channel_weight(AnalyzerChannel::Surface, 2.5)
        .with_channel_b(AnalyzerChannel::Stem, 0.0)
        .with_channel_b(AnalyzerChannel::CjkNgram, 1.0);
    let config = legal.to_bm25_config()?;
    assert_eq!(config.field(AnalyzerChannel::Surface).weight, 2.5);
    assert_eq!(config.field(AnalyzerChannel::Stem).b, 0.0);
    assert_eq!(config.field(AnalyzerChannel::CjkNgram).b, 1.0);
    assert_eq!(config.formula, Bm25Formula::Plus { delta: 1e-6 });
    assert!(vault.search_text_with_profile("hello", 10, &legal).is_ok());
    Ok(())
}

#[test]
fn field_stats_track_per_field_lengths() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha beta gamma")?;

    let rtxn = vault.store.env.read_txn()?;
    let (doc_count, total_length) =
        read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?;
    assert_eq!(doc_count, 1);
    assert_eq!(total_length, 3);
    Ok(())
}

#[test]
fn deindex_decrements_per_field_stats() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha beta")?;
    assert!(vault.delete_entity(&id)?);

    let rtxn = vault.store.env.read_txn()?;
    let (doc_count, total_length) =
        read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?;
    assert_eq!(doc_count, 0);
    assert_eq!(total_length, 0);
    Ok(())
}

#[test]
fn cjk_ngram_field_length_reflects_bigram_count() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let short_id = EntityId::now();
    let long_id = EntityId::now();
    put_text_doc(&vault, &short_id, "東京")?;
    put_text_doc(&vault, &long_id, "東京大学研究所")?;

    let rtxn = vault.store.env.read_txn()?;
    let ngram_fid = AnalyzerChannel::CjkNgram.field_id();

    let read_len = |id: &EntityId| -> Result<u32> {
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(&rtxn, id.as_bytes())?
            .expect("doc must have field lengths");
        let map = decode_field_lengths(raw)?;
        Ok(map.get(&ngram_fid).copied().unwrap_or(0))
    };

    let short_len = read_len(&short_id)?;
    let long_len = read_len(&long_id)?;
    // "東京" → 1 bigram; "東京大学研究所" → 6 bigrams.
    assert_eq!(short_len, 1);
    assert_eq!(long_len, 6);

    let (doc_count, total_length) = read_field_stats(&vault.store, &rtxn, ngram_fid)?;
    assert_eq!(doc_count, 2);
    assert_eq!(total_length, u64::from(short_len) + u64::from(long_len));
    Ok(())
}

#[test]
fn long_cjk_document_loses_to_short_one_on_shared_bigram() -> Result<()> {
    // Isolate CjkNgram by zeroing every other field so the assertion
    // doesn't ride on Surface/Stem length norm.
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let short_id = EntityId::now();
    let long_id = EntityId::now();
    put_text_doc(&vault, &short_id, "東京")?;
    put_text_doc(&vault, &long_id, "東京研究所大学図書館")?;

    let mut fields = [FieldConfig::disabled(); BM25_FIELD_COUNT];
    fields[AnalyzerChannel::CjkNgram.field_id() as usize] = FieldConfig {
        weight: 1.0,
        b: 0.30,
        length_policy: FieldLengthPolicy::CountLengthIncrement,
    };
    let cjk_only = Bm25Config {
        k1: 1.2,
        formula: Bm25Formula::Okapi,
        fields,
    };

    let rtxn = vault.store.env.read_txn()?;
    let results = search_text(
        &vault.store,
        &rtxn,
        &MultilingualAnalyzer::portable(),
        &cjk_only,
        "東京",
        10,
    )?;
    let short_score = results
        .iter()
        .find(|r| r.id == short_id)
        .expect("short doc in results")
        .score;
    let long_score = results
        .iter()
        .find(|r| r.id == long_id)
        .expect("long doc in results")
        .score;
    assert!(
        short_score > long_score,
        "expected short doc to outrank long doc on CjkNgram channel once length norm fires: short={short_score} long={long_score}",
    );
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
fn bm25_diagnostics_snapshot_has_stable_privacy_preserving_labels() {
    let snapshot = bm25_diagnostics_snapshot();
    let labels = snapshot
        .counters
        .iter()
        .map(|counter| counter.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        [
            "malformed_posting_alignment",
            "missing_scored_document_metadata",
            "deindex_self_healed_missing_posting_row",
            "deindex_self_healed_missing_posting_entity",
        ]
    );
    for counter in snapshot.counters {
        assert_eq!(snapshot.count(counter.kind), counter.count);
    }
}

#[test]
fn bm25_diagnostics_increment_for_targeted_search_corruption() -> Result<()> {
    reset_bm25_diagnostics();
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;

    let before_missing_metadata =
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::MissingScoredDocumentMetadata);
    let mut wtxn = vault.store.env.write_txn()?;
    assert!(
        vault
            .store
            .text_doc_field_lengths
            .delete(&mut wtxn, id.as_bytes())?
    );
    wtxn.commit()?;
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
    assert_eq!(
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::MissingScoredDocumentMetadata),
        before_missing_metadata + 1
    );

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;

    let before_malformed =
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::MalformedPostingAlignment);
    let mut wtxn = vault.store.env.write_txn()?;
    let original = vault
        .store
        .text_postings
        .get(&wtxn, b"alpha")?
        .expect("alpha posting written")
        .to_vec();
    assert!(
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, b"alpha", &original)?
    );
    vault.store.text_postings.put(&mut wtxn, b"alpha", b"bad")?;
    wtxn.commit()?;
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
    assert_eq!(
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::MalformedPostingAlignment),
        before_malformed + 1
    );

    Ok(())
}

#[test]
fn deindex_self_heals_missing_postings_and_records_diagnostics() -> Result<()> {
    reset_bm25_diagnostics();
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;

    let before_missing_row =
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingRow);
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
        bm25_diagnostics_snapshot().count(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingRow),
        before_missing_row + 1
    );

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = EntityId::now();
    let other = EntityId::now();
    put_text_doc(&vault, &id, "alpha")?;
    put_text_doc(&vault, &other, "alpha")?;

    let before_missing_entity = bm25_diagnostics_snapshot()
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
        bm25_diagnostics_snapshot()
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
    let err = decode_posting_entry(&posting).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
}

#[test]
fn posting_decode_rejects_truncated_entry() {
    let id = EntityId::now();
    let mut posting = id.as_bytes().to_vec();
    posting.push(1); // claim one field but supply no bytes
    let err = decode_posting_entry(&posting).unwrap_err();
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
    let err = decode_posting_entry(&blob).unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

#[test]
fn decode_rejects_empty_rows() {
    assert!(decode_posting_entry(&[]).is_err());
    assert!(decode_forward(&[]).is_err());
    assert!(decode_field_lengths(&[]).is_err());
}

#[test]
fn forward_roundtrips_utf8_terms() -> Result<()> {
    let mut m: BTreeMap<String, BTreeMap<u16, u32>> = BTreeMap::new();
    m.entry("東京".into()).or_default().insert(0, 1);
    m.entry("hello".into()).or_default().insert(0, 2);
    m.get_mut("hello").unwrap().insert(1, 1);
    let bytes = encode_forward(&m)?;
    let back = decode_forward(&bytes)?;
    assert_eq!(back.len(), 3);
    assert_eq!(back[0].term, "hello");
    assert_eq!(back[2].term, "東京");
    Ok(())
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
        let entry = decode_posting_entry(item)?;
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

    assert!(vault.delete_entity(&ids[1])?);
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

    assert!(vault.delete_entity(&ids[0])?);
    assert!(vault.delete_entity(&ids[2])?);
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
