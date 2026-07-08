use super::*;

#[test]
fn discover_with_no_paths_returns_portable() {
    let ja = JapaneseAnalyzer::discover(&[]).unwrap();
    assert_eq!(ja.mode(), AnalyzerMode::Portable);
}

#[test]
fn discover_with_empty_dir_returns_portable() {
    let dir = tempfile::tempdir().unwrap();
    let ja = JapaneseAnalyzer::discover(&[dir.path().to_path_buf()]).unwrap();
    assert_eq!(ja.mode(), AnalyzerMode::Portable);
}

#[test]
fn portable_path_delegates_to_cjk_ngram() {
    let ja = JapaneseAnalyzer::portable();
    let mut out = Vec::new();
    ja.analyze("東京大学", 0, 0, false, &mut out);

    let surface: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::Surface)
        .map(|t| t.term.as_ref())
        .collect();
    assert_eq!(surface, vec!["東", "京", "大", "学"]);

    let ngram: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
        .map(|t| t.term.as_ref())
        .collect();
    assert_eq!(ngram, vec!["東京", "京大", "大学"]);
}

#[test]
fn empty_input_returns_position_base() {
    let ja = JapaneseAnalyzer::portable();
    let mut out = Vec::new();
    let next = ja.analyze("", 0, 5, false, &mut out);
    assert_eq!(next, 5);
    assert!(out.is_empty());
}

#[test]
fn kana_fold_if_changed_identifies_only_katakana_bearing_input() {
    assert!(kana_fold_if_changed("ひらがな").is_none());
    assert!(kana_fold_if_changed("ascii").is_none());
    assert_eq!(
        kana_fold_if_changed("カタカナ"),
        Some("かたかな".to_string())
    );
}

/// Morphological-mode integration: only runs when a real Sudachi dict is
/// available via `ONEIRON_TEST_SUDACHI_DICT` (absolute path to `system.dic`).
/// Not part of default `cargo test` because `system.dic` is ~12 MB and not
/// bundled with the repo.
#[test]
fn morphological_path_with_env_dict() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    assert_eq!(ja.mode(), AnalyzerMode::Morphological);

    let mut out = Vec::new();
    ja.analyze("東京大学で研究する", 0, 0, false, &mut out);
    assert!(!out.is_empty());
    let surface: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::Surface)
        .map(|t| t.term.as_ref())
        .collect();
    // Mode A should segment at least to 東京 / 大学 / で / 研究 / する boundaries.
    assert!(surface.contains(&"東京"));
    assert!(surface.contains(&"大学"));
}

/// Query-side kana-fold overlay must fire so katakana queries retrieve
/// hiragana documents (fold is a symmetric normalization, not a lemma
/// expansion). Uses the real Sudachi dict via `ONEIRON_TEST_SUDACHI_DICT`.
#[test]
fn kana_fold_overlay_fires_on_query() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    ja.analyze("トウキョウ", 0, 0, /* query_mode */ true, &mut out);
    let overlay_terms: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::NormalizedOverlay)
        .map(|t| t.term.as_ref())
        .collect();
    assert!(
        !overlay_terms.is_empty(),
        "katakana query must emit at least one kana-folded overlay",
    );
    for term in &overlay_terms {
        assert!(
            !term.chars().any(|c| ('\u{30A0}'..='\u{30FF}').contains(&c)),
            "overlay {term:?} still contains katakana — fold did not run",
        );
    }
}

/// Morph path must emit CjkNgram bigrams alongside surface morphemes so
/// a query `"東京"` recalls docs indexed via Sudachi-segmented input —
/// parity with the ZH / KO morph paths.
#[test]
fn jp_morph_emits_cjk_bigrams() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    ja.analyze("東京大学", 0, 0, false, &mut out);
    let ngrams: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
        .map(|t| t.term.as_ref())
        .collect();
    assert!(
        ngrams.contains(&"東京"),
        "missing 東京 bigram in {ngrams:?}"
    );
    assert!(
        ngrams.contains(&"京大"),
        "missing 京大 bigram in {ngrams:?}"
    );
    assert!(
        ngrams.contains(&"大学"),
        "missing 大学 bigram in {ngrams:?}"
    );
}

/// After F3's U+30FC remap, `スーパー` is a single Katakana run — the
/// JP morph path should still form a bigram across the prolonged sound
/// mark (e.g. `スー`) via the shared `cjk_ngram::emit_bigram_overlay`.
#[test]
fn jp_morph_emits_bigram_across_prolonged_mark() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    ja.analyze("スーパーマン", 0, 0, false, &mut out);
    let ngrams: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
        .map(|t| t.term.as_ref())
        .collect();
    assert!(
        ngrams.iter().any(|t| t.contains('ー')),
        "expected at least one bigram spanning ー in {ngrams:?}",
    );
}

/// `NormalizedOverlay` uses `NoNorm` — its tokens must not count
/// toward `avgdl`. Both overlay emitters (kana-fold and Mode C
/// compound) therefore carry `length_increment = 0`, which is the
/// analyzer contract that
/// `AnalyzerChannel::permits_zero_doc_field_length()` relies on.
#[test]
fn normalized_overlay_tokens_have_zero_length_increment() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    // `トウキョウ` covers the kana-fold overlay; `大阪大学` covers the
    // Mode C compound overlay.
    ja.analyze("トウキョウ", 0, 0, false, &mut out);
    ja.analyze("大阪大学", 5, 0, false, &mut out);
    let mut saw_overlay = false;
    for t in &out {
        if t.channel == AnalyzerChannel::NormalizedOverlay {
            saw_overlay = true;
            assert_eq!(
                t.length_increment, 0,
                "NormalizedOverlay token {:?} must not contribute to avgdl",
                t.term,
            );
        }
    }
    assert!(
        saw_overlay,
        "no NormalizedOverlay tokens emitted — test did not exercise the contract"
    );
}

/// Mode C overlay must fire in query mode so `"大阪大学"` as a query
/// can reach indexed Mode C compounds that don't split under Mode A.
#[test]
fn jp_mode_c_overlay_emitted_in_query_mode() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    ja.analyze("大阪大学", 0, 0, /* query_mode */ true, &mut out);
    let overlay_terms: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::NormalizedOverlay)
        .map(|t| t.term.as_ref())
        .collect();
    assert!(
        overlay_terms.contains(&"大阪大学"),
        "Mode C compound missing from query-side overlay: {overlay_terms:?}",
    );
}

/// `analyze_morphological` must return a position past every emitted
/// token, including bigram-overlay positions. For `"東京大学"`, Mode A
/// produces 2 morphemes (`a_count = 2`) but the bigram overlay assigns
/// positions 0..=2; returning `position_base + a_count` would let the
/// next run start on already-used position 2.
#[test]
fn jp_morph_returns_position_past_bigram_overlay() {
    let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
        return;
    };
    let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path)).expect("dict should load");
    let mut out = Vec::new();
    let next = ja.analyze("東京大学", 0, 0, false, &mut out);
    let max_emitted = out.iter().map(|t| t.position).max().unwrap_or(0);
    assert!(
        next > max_emitted,
        "analyze_morphological returned {next} but emitted token at position {max_emitted}",
    );
}
