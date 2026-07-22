use super::*;

fn surface_terms(tokens: &[Token]) -> Vec<&str> {
    tokens
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::Surface)
        .map(|t| t.term.as_ref())
        .collect()
}

#[test]
fn whichlang_eligible_only_for_latin_cyrillic_greek_and_han() {
    fn expected(class: ScriptClass) -> bool {
        match class {
            ScriptClass::Latin | ScriptClass::Cyrillic | ScriptClass::Greek | ScriptClass::Han => {
                true
            }
            ScriptClass::Hebrew
            | ScriptClass::Arabic
            | ScriptClass::Hiragana
            | ScriptClass::Katakana
            | ScriptClass::Hangul
            | ScriptClass::Thai
            | ScriptClass::Lao
            | ScriptClass::Khmer
            | ScriptClass::Myanmar
            | ScriptClass::Devanagari
            | ScriptClass::Tamil
            | ScriptClass::Common
            | ScriptClass::Other => false,
        }
    }

    let classes = [
        ScriptClass::Latin,
        ScriptClass::Cyrillic,
        ScriptClass::Greek,
        ScriptClass::Hebrew,
        ScriptClass::Arabic,
        ScriptClass::Han,
        ScriptClass::Hiragana,
        ScriptClass::Katakana,
        ScriptClass::Hangul,
        ScriptClass::Thai,
        ScriptClass::Lao,
        ScriptClass::Khmer,
        ScriptClass::Myanmar,
        ScriptClass::Devanagari,
        ScriptClass::Tamil,
        ScriptClass::Common,
        ScriptClass::Other,
    ];

    for class in classes {
        assert_eq!(
            whichlang_eligible(class),
            expected(class),
            "unexpected whichlang eligibility for {}",
            class.as_str(),
        );
    }
}

// `portable_analyzer_reports_portable_for_all_cjk` deleted as a
// tautology — asserting a portable analyzer reports portable mode for
// every lang adds no coverage beyond `MultilingualAnalyzer::portable()`.

#[test]
fn manifest_channels_match_v1() {
    let a = MultilingualAnalyzer::portable();
    let m = a.manifest();
    let actual: Vec<&str> = m.channels.iter().map(String::as_str).collect();
    assert_eq!(
        actual,
        ["surface", "stem", "normalized_overlay", "cjk_ngram"]
    );
    assert_eq!(AnalyzerChannel::ALL_V1.len(), 4);
}

#[test]
fn manifest_hash_stable() {
    let a = MultilingualAnalyzer::portable();
    let h1 = a.manifest().canonical_hash().unwrap();
    let h2 = a.manifest().canonical_hash().unwrap();
    assert_eq!(h1, h2);
}

/// ONE-1118 AC4: the emoji-lane tokenization change must flow through
/// ANALYZER_VERSION into the manifest hash. Pins the literal "v3" and
/// proves the version field alone flips the canonical hash — which is
/// what makes a populated v2-era index fail closed at the handshake.
#[test]
fn analyzer_version_v3_flips_manifest_hash_vs_v2() {
    assert_eq!(ANALYZER_VERSION, "v3");
    let a = MultilingualAnalyzer::portable();
    let mut m = a.manifest();
    assert_eq!(m.analyzer_version, "v3");
    let h_v3 = m.canonical_hash().unwrap();
    m.analyzer_version = "v2".into();
    let h_v2 = m.canonical_hash().unwrap();
    assert_ne!(
        h_v3, h_v2,
        "analyzer_version must participate in the manifest hash"
    );
}

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

/// Emoji adjacent to CJK splits into its own Common run; the emoji
/// token appears and no CjkNgram bigram absorbs it.
#[test]
fn emoji_after_cjk_run_stays_out_of_bigrams() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("東京🦀", &AnalyzerContext::for_index(), &mut out);
    assert_eq!(surface_terms(&out), vec!["東", "京", "🦀"]);
    for tok in out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
    {
        assert!(
            !tok.term.contains('🦀'),
            "cjk_ngram token {:?} must not absorb emoji",
            tok.term,
        );
    }
}

/// AC2: numerics in Common runs are unchanged and punctuation stays
/// dropped when the emoji lane is active.
#[test]
fn numerics_unchanged_and_punctuation_dropped_alongside_emoji() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("123 🦀 ...!!!", &AnalyzerContext::for_index(), &mut out);
    assert_eq!(surface_terms(&out), vec!["123", "🦀"]);
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
fn empty_input_returns_zero() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    let next = a.analyze("", &AnalyzerContext::for_index(), &mut out);
    assert_eq!(next, 0);
    assert!(out.is_empty());
}

#[test]
fn latin_routes_to_latin_analyzer_with_detected_hint() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze(
        "The quick brown fox jumps over the lazy dog",
        &AnalyzerContext::for_index(),
        &mut out,
    );
    // English stemmer should produce at least one stem overlay.
    assert!(
        out.iter().any(|t| t.channel == AnalyzerChannel::Stem),
        "expected stem overlays for English text"
    );
}

#[test]
fn hiragana_routes_to_japanese_portable() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("とうきょう", &AnalyzerContext::for_index(), &mut out);
    // Portable JP falls through to cjk_ngram → per-char unigrams on Surface.
    let terms = surface_terms(&out);
    assert_eq!(terms, vec!["と", "う", "き", "ょ", "う"]);
}

#[test]
fn hangul_routes_to_korean_portable() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("안녕하세요", &AnalyzerContext::for_index(), &mut out);
    let terms = surface_terms(&out);
    assert_eq!(terms, vec!["안", "녕", "하", "세", "요"]);
}

/// Han-only runs in Portable mode yield both unigram Surface tokens and
/// a bigram CjkNgram overlay. Variants exercise the same path with
/// different inputs to confirm the overlay shape across multiple
/// realistic strings.
///
/// Variants:
/// - `four_char_japanese_word` (was `han_portable_produces_unigrams_and_bigram_overlay`):
///   `"東京大学"` → surface `[東,京,大,学]`, bigrams `[東京,京大,大学]`.
/// - `three_char_chinese_phrase` (was `portable_han_only_run_yields_cjk_ngram_shaped_output`):
///   `"我喜欢"` → surface `[我,喜,欢]`, bigrams `[我喜,喜欢]`.
#[test]
fn portable_han_yields_unigrams_and_bigram_overlay() {
    let cases: Vec<(&str, &str, Vec<&str>, Vec<&str>)> = vec![
        (
            "four_char_japanese_word",
            "東京大学",
            vec!["東", "京", "大", "学"],
            vec!["東京", "京大", "大学"],
        ),
        (
            "three_char_chinese_phrase",
            "我喜欢",
            vec!["我", "喜", "欢"],
            vec!["我喜", "喜欢"],
        ),
    ];

    for (case_name, input, expected_surface, expected_bigrams) in cases {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze(input, &AnalyzerContext::for_index(), &mut out);
        let surface = surface_terms(&out);
        assert_eq!(
            surface, expected_surface,
            "case {case_name}: unexpected Surface tokens"
        );
        let bigrams: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(
            bigrams, expected_bigrams,
            "case {case_name}: unexpected CjkNgram bigrams"
        );
    }
}

#[test]
fn mixed_script_no_cross_boundary_bigram() {
    let a = MultilingualAnalyzer::portable();
    let text = "とう東京";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    // Any cjk_ngram token must not span the hiragana→han boundary.
    // `とう` ends at byte 6; `東京` starts at byte 6. Reject any token
    // whose [start, end) crosses the boundary of 6.
    for tok in out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
    {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(
            e <= 6 || s >= 6,
            "bigram {:?} [{}..{}] crosses script boundary at byte 6",
            tok.term,
            s,
            e,
        );
    }
}

#[test]
fn cjk_digit_mix_no_cross_boundary_bigram() {
    let a = MultilingualAnalyzer::portable();
    // `東京` ends at byte 6; `123` starts at byte 6. No cjk_ngram token
    // may span byte 6, and no cjk_ngram token may contain ASCII digits.
    let text = "東京123";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    for tok in out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
    {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(
            e <= 6 || s >= 6,
            "bigram {:?} [{}..{}] crosses script boundary at byte 6",
            tok.term,
            s,
            e,
        );
        assert!(
            !tok.term.chars().any(|c| c.is_ascii_digit()),
            "cjk_ngram token {:?} must not contain ASCII digits",
            tok.term,
        );
    }
}

#[test]
fn cjk_with_leading_common_no_cross_boundary_bigram() {
    let a = MultilingualAnalyzer::portable();
    // `2024` 0..4, `東京` 4..10. No cjk_ngram token may contain an
    // ASCII digit, and no cjk_ngram token may span byte 4.
    let text = "2024東京";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    for tok in out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
    {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(
            s >= 4,
            "cjk_ngram {:?} [{}..{}] must start at/after the CJK boundary (byte 4)",
            tok.term,
            s,
            e,
        );
        assert!(
            !tok.term.chars().any(|c| c.is_ascii_digit()),
            "cjk_ngram token {:?} must not contain ASCII digits",
            tok.term,
        );
    }
}

#[test]
fn cjk_punct_mix_no_cross_boundary_bigram() {
    let a = MultilingualAnalyzer::portable();
    // `北京` 0..6, `、` 6..9, `大学` 9..15. No cjk_ngram may contain the
    // fullwidth comma or span across it.
    let text = "北京、大学";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    for tok in out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
    {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(
            (e <= 6) || (s >= 9),
            "bigram {:?} [{}..{}] crosses CJK/punct boundary",
            tok.term,
            s,
            e,
        );
        assert!(
            !tok.term.contains('、'),
            "cjk_ngram token {:?} must not contain fullwidth comma",
            tok.term,
        );
    }
}

#[test]
fn thai_routes_to_icu_segmenter() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("ไปโรงเรียน", &AnalyzerContext::for_index(), &mut out);
    // ICU4X returns at least one word-like segment for Thai.
    assert!(!surface_terms(&out).is_empty());
}

#[test]
fn offsets_slice_original_utf8() {
    let a = MultilingualAnalyzer::portable();
    let text = "hello 東京 안녕 สวัสดี";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    for tok in &out {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(s <= e && e <= text.len());
        // Slicing must not panic — this enforces valid UTF-8 boundaries.
        let _ = &text[s..e];
    }
}

#[test]
fn positions_monotonic_across_runs() {
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    a.analyze("hello 東京", &AnalyzerContext::for_index(), &mut out);
    let mut last = 0u32;
    for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::Surface) {
        assert!(tok.position >= last);
        last = tok.position;
    }
}

#[test]
fn discover_with_no_paths_returns_all_portable() {
    let a = MultilingualAnalyzer::discover(&[]).unwrap();
    let m = a.manifest();
    assert_eq!(m.langs["ja"].mode, AnalyzerMode::Portable);
    assert_eq!(m.langs["zh"].mode, AnalyzerMode::Portable);
    assert_eq!(m.langs["ko"].mode, AnalyzerMode::Portable);
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

#[test]
fn halfwidth_katakana_indexes_like_fullwidth() {
    let a = MultilingualAnalyzer::portable();
    let mut half = Vec::new();
    let mut full = Vec::new();
    a.analyze("ｶﾀｶﾅ", &AnalyzerContext::for_index(), &mut half);
    a.analyze("カタカナ", &AnalyzerContext::for_index(), &mut full);
    // After NFKC, halfwidth katakana indexes the same surface terms
    // as the fullwidth form. Byte offsets differ since the sources
    // have different lengths — equality of terms is what matters.
    assert_eq!(surface_terms(&half), surface_terms(&full));
}

#[test]
fn original_offsets_survive_mixed_normalization() {
    // Mixed-script sample with a fullwidth-ASCII prefix; every emitted
    // token must still slice valid UTF-8 out of the ORIGINAL input.
    let a = MultilingualAnalyzer::portable();
    let text = "ＡＢＣ 東京";
    let mut out = Vec::new();
    a.analyze(text, &AnalyzerContext::for_index(), &mut out);
    assert!(!out.is_empty());
    for tok in &out {
        let s = tok.byte_start as usize;
        let e = tok.byte_end as usize;
        assert!(s <= e && e <= text.len(), "offsets out of range: {s}..{e}");
        let _ = &text[s..e];
    }
    assert!(surface_terms(&out).contains(&"abc"));
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

#[test]
fn explicit_hint_overrides_per_run_inference_for_latin() {
    // Short accent-less Spanish falls back to English under the
    // length-gated ASCII short-circuit; the explicit hint is the
    // caller's escape hatch for symmetric Spanish stem recall.
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    let ctx = AnalyzerContext::for_index().with_language(LanguageHint::Es);
    a.analyze("hablando", &ctx, &mut out);
    let stems: Vec<&str> = out
        .iter()
        .filter(|t| t.channel == AnalyzerChannel::Stem)
        .map(|t| t.term.as_ref())
        .collect();
    assert!(
        stems.iter().any(|s| *s != "hablando"),
        "expected Spanish stem distinct from surface, got stems: {stems:?}",
    );
}

#[test]
fn explicit_japanese_hint_on_han_only_run_prefers_japanese_path() {
    // No dicts loaded in Portable mode — both paths fall through to
    // cjk_ngram, so the observable output is identical. But dispatch
    // must not panic when the hint is Ja on Han text.
    let a = MultilingualAnalyzer::portable();
    let mut out = Vec::new();
    let ctx = AnalyzerContext::for_index().with_language(LanguageHint::Ja);
    a.analyze("東京", &ctx, &mut out);
    assert_eq!(surface_terms(&out), vec!["東", "京"]);
}

// `portable_han_only_run_yields_cjk_ngram_shaped_output` folded into
// `portable_han_yields_unigrams_and_bigram_overlay` above.

#[test]
fn zh_han_run_with_loaded_chinese_dict_uses_chinese_morphological_path() {
    assert_eq!(
        detect::detect_with_whichlang("我喜欢学习中文"),
        Some(LanguageHint::Zh)
    );

    let dir = tempfile::tempdir().unwrap();
    let dict_path = dir.path().join("tiny.dict.utf8");
    std::fs::write(&dict_path, "我喜欢 100 n\n学习 80 v\n中文 80 n\n").unwrap();
    let chinese = chinese::ChineseAnalyzer::with_dict(&dict_path).expect("inline dict should load");
    assert_eq!(chinese.mode(), AnalyzerMode::Morphological);

    let analyzer = MultilingualAnalyzer {
        splitter: script::ScriptRunSplitter::new(),
        japanese: japanese::JapaneseAnalyzer::portable(),
        chinese,
        korean: korean::KoreanAnalyzer::portable(),
        normalization: NormalizationPolicy::default(),
    };

    let mut out = Vec::new();
    analyzer.analyze("我喜欢学习中文", &AnalyzerContext::for_index(), &mut out);
    let surfaces = surface_terms(&out);
    assert!(
        surfaces.iter().any(|term| term.chars().count() > 1),
        "expected Chinese morphological path to emit multi-character surface, got {surfaces:?}",
    );
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

/// Symmetric: explicit `LanguageHint::Zh` must route even if only JP is
/// loaded. We can't build a morphological JP without env dict, so we
/// assert the mirror-image invariant via a portable-ZH analyzer — the
/// output is cjk_ngram-shaped either way, but the dispatch target
/// differs, and `dispatch_han`'s match arm ordering is what we exercise.
#[test]
fn explicit_zh_hint_routes_to_chinese_on_portable_analyzer() {
    let a = MultilingualAnalyzer::portable();
    let ctx = AnalyzerContext::for_index().with_language(LanguageHint::Zh);
    let mut out = Vec::new();
    a.analyze("東京", &ctx, &mut out);
    assert_eq!(surface_terms(&out), vec!["東", "京"]);
}
