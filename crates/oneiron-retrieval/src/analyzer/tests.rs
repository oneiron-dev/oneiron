use super::*;

fn surface_terms(tokens: &[Token]) -> Vec<&str> {
    tokens
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::Surface)
        .map(|t| t.term.as_ref())
        .collect()
}

// `portable_analyzer_reports_portable_for_all_cjk` deleted as a
// tautology — asserting a portable analyzer reports portable mode for
// every lang adds no coverage beyond `MultilingualAnalyzer::portable()`.

/// ARCH-0031 dispatch row "Emoji / unknown → Grapheme per token"
/// through the full pipeline: a pure-emoji input forms a Common run
/// and emits one Surface token per grapheme cluster.
#[test]
fn emoji_common_run_emits_grapheme_per_token() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    let next = a.analyze("🦀🔥", &AnalyzerContext::for_index(), &mut out);
    assert_eq!(surface_terms(&out), vec!["🦀", "🔥"]);
    assert_eq!(next, 2);
    for tok in &out {
        assert_eq!(tok.kind, TokenKind::Emoji);
        assert_eq!(tok.length_increment, 1, "AC1: length_increment 1");
        assert_eq!(tok.channel, AnalyzerChannel::Surface);
    }
    // Offsets index the original UTF-8: 🦀 = 4 bytes, 🔥 = 4 bytes.
    assert_eq!((out[0].byte_start, out[0].byte_end), (0, 4));
    assert_eq!((out[1].byte_start, out[1].byte_end), (4, 8));
}

/// Multi-codepoint clusters through the full pipeline (NFKC included):
/// ZWJ sequences and skin-tone modifiers are exactly ONE token each.
/// A codepoint-per-token implementation fails this on count.
#[test]
fn multi_codepoint_clusters_are_single_tokens_end_to_end() {
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}"; // 👨‍👩‍👧‍👦
    let thumbs = "\u{1F44D}\u{1F3FD}"; // 👍🏽
    for (case_name, input) in [("zwj_family", family), ("skin_tone", thumbs)] {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze(input, &AnalyzerContext::for_index(), &mut out);
        assert_eq!(
            out.len(),
            1,
            "case {case_name}: cluster must be exactly one token, got {:?}",
            surface_terms(&out),
        );
        assert_eq!(out[0].term.as_ref(), input, "case {case_name}");
        assert_eq!(
            (out[0].byte_start, out[0].byte_end),
            (0, input.len() as u32),
            "case {case_name}: offsets must span the whole cluster"
        );
    }
}

/// Emoji absorbed into a Latin run (Script=Common) still emit, and the
/// same term is produced on the query side so postings round-trip.
#[test]
fn emoji_in_latin_text_emits_on_both_index_and_query_sides() {
    let a = MultilingualAnalyzer::portable();
    let mut indexed = Vec::new();
    a.analyze("hello 🦀🔥", &AnalyzerContext::for_index(), &mut indexed);
    assert_eq!(surface_terms(&indexed), vec!["hello", "🦀", "🔥"]);

    let mut queried = Vec::new();
    a.analyze("🦀", &AnalyzerContext::for_query(), &mut queried);
    assert_eq!(surface_terms(&queried), vec!["🦀"]);
}

/// End-to-end through the full router: a regional-indicator flag and a
/// keycap reach the emoji lane (Common runs → ICU) and each emits exactly
/// one Surface token; two adjacent flags split per UAX #29. Guards the
/// "silent under-indexing" risk of the old Extended_Pictographic-only
/// gate against the real routing path, not just the lane in isolation.
#[test]
fn flags_and_keycaps_round_trip_through_router() {
    let a = MultilingualAnalyzer::portable();

    let flag = "\u{1F1FA}\u{1F1E6}"; // 🇺🇦
    let mut out = Vec::new();
    a.analyze(flag, &AnalyzerContext::for_index(), &mut out);
    assert_eq!(
        surface_terms(&out),
        vec![flag],
        "🇺🇦 must index as one token"
    );

    let keycap = "\u{0031}\u{FE0F}\u{20E3}"; // 1️⃣
    let mut out = Vec::new();
    a.analyze(keycap, &AnalyzerContext::for_index(), &mut out);
    assert_eq!(
        surface_terms(&out),
        vec![keycap],
        "1️⃣ must index as one token"
    );

    let japan = "\u{1F1EF}\u{1F1F5}"; // 🇯🇵
    let two = format!("{flag}{japan}");
    let mut out = Vec::new();
    a.analyze(&two, &AnalyzerContext::for_index(), &mut out);
    assert_eq!(surface_terms(&out), vec![flag, japan], "🇺🇦🇯🇵 → two flags");
}

#[test]
fn fullwidth_ascii_folds_to_ascii_with_original_offsets() {
    let a = MultilingualAnalyzer::portable();
    let text = "ＡＢＣ";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    let surface = surface_terms(&out);
    assert_eq!(surface, vec!["abc"]);
    let tok = &out[0];
    // Offsets must reference the ORIGINAL UTF-8 (9 bytes), not the
    // normalized form (3 bytes).
    assert_eq!(tok.byte_start, 0);
    assert_eq!(tok.byte_end, text.len() as u32);
    let slice = &text[tok.byte_start as usize..tok.byte_end as usize];
    assert_eq!(slice, "ＡＢＣ");
}

/// Regression guard for cross-run hint bleed: a hiragana run must not
/// hand `LanguageHint::Ja` to the Latin analyzer in the *other* run, or
/// the English Snowball stemmer would silently disable (so `running`
/// would emit no `run` stem). Variants flip the run order.
///
/// Variants:
/// - `latin_before_hiragana`: `"running とうきょう"`.
/// - `latin_after_hiragana`:  `"とうきょう running"`.
#[test]
fn latin_run_with_hiragana_still_stems_english() {
    let cases: Vec<(&str, &str)> = vec![
        ("latin_before_hiragana", "running とうきょう"),
        ("latin_after_hiragana", "とうきょう running"),
    ];

    for (case_name, input) in cases {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze(input, &AnalyzerContext::for_index(), &mut out);
        let stems: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Stem)
            .map(|t| t.term.as_ref())
            .collect();
        assert!(
            stems.contains(&"run"),
            "case {case_name}: expected English stem `run` from `running`, got stems: {stems:?}",
        );
    }
}

/// Explicit `LanguageHint::Ja` must route Han runs to the JP analyzer
/// even when only the ZH dict is loaded. Prior DualHanFallback preferred
/// the loaded dict, so an explicit JP caller lost to a ZH-indexed corpus.
#[test]
fn explicit_ja_hint_does_not_route_to_loaded_zh_dict() {
    let dir = tempfile::tempdir().unwrap();
    let dict_path = dir.path().join("tiny.dict.utf8");
    std::fs::write(&dict_path, "北京 100 ns\n大学 80 n\n").unwrap();
    let chinese = chinese::ChineseAnalyzer::with_dict(&dict_path).expect("inline dict should load");
    assert_eq!(chinese.mode(), AnalyzerMode::Morphological);

    let analyzer = MultilingualAnalyzer {
        splitter: script::ScriptRunSplitter::new(),
        japanese: japanese::JapaneseAnalyzer::portable(),
        chinese,
        korean: korean::KoreanAnalyzer::portable(),
        normalization: NormalizationPolicy::default(),
    };
    let ctx = AnalyzerContext::for_index().with_language(LanguageHint::Ja);
    let mut out = Vec::new();
    analyzer.analyze("北京大学", &ctx, &mut out);

    // Jieba with the inline dict would emit multi-char Surface tokens
    // `北京` + `大学`. Ja hint routes to the JP portable path, which
    // delegates to cjk_ngram and emits per-char Surface.
    assert_eq!(surface_terms(&out), vec!["北", "京", "大", "学"]);
}
