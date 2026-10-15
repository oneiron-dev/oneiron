use super::*;

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
