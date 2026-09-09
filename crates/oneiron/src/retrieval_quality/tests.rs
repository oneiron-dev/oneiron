use serde::de::DeserializeOwned;
use serde_json::json;

use super::*;

// Independent contract lists: new telemetry components must not expand the tier.
const CHANNELS: [RetrievalSignal; 5] = [
    RetrievalSignal::Vector,
    RetrievalSignal::Text,
    RetrievalSignal::Phonetic,
    RetrievalSignal::Temporal,
    RetrievalSignal::Ppr,
];
const OTHER_SIGNALS: [RetrievalSignal; 7] = [
    RetrievalSignal::Recency,
    RetrievalSignal::Salience,
    RetrievalSignal::Confidence,
    RetrievalSignal::Gravity,
    RetrievalSignal::Rerank,
    RetrievalSignal::Hyde,
    RetrievalSignal::HydeRetry,
];
const MARKERS: [RetrievalDegradation; 4] = [
    RetrievalDegradation::PprCacheMiss,
    RetrievalDegradation::EmbeddingTimeout,
    RetrievalDegradation::Bm25Stale,
    RetrievalDegradation::TemporalSignalSkipped,
];

fn diagnostics(
    attempted: &[RetrievalSignal],
    succeeded: &[RetrievalSignal],
    ppr_cache: Option<PprCacheOutcome>,
    degradation: &[RetrievalDegradation],
) -> RetrievalDiagnostics {
    RetrievalDiagnostics {
        attempted: attempted.to_vec(),
        succeeded: succeeded.to_vec(),
        ppr_cache,
        degradation: degradation.to_vec(),
    }
}

fn selected<T: Copy>(values: &[T], mask: u8) -> Vec<T> {
    values
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .map(|(_, &value)| value)
        .collect()
}

fn assert_report(
    report: &RetrievalQualityReport,
    quality: RetrievalQuality,
    degradation: &[RetrievalDegradation],
) {
    let confidence_adjustment = match quality {
        RetrievalQuality::Full => ConfidenceAdjustment::FULL,
        RetrievalQuality::Degraded => ConfidenceAdjustment::DEGRADED,
        RetrievalQuality::Passthrough => ConfidenceAdjustment::PASSTHROUGH,
    };
    assert_eq!(report.quality, quality);
    assert_eq!(report.degradation, degradation);
    assert_eq!(report.confidence_adjustment, confidence_adjustment);
}

fn assert_truth_table_row(
    attempted: u8,
    succeeded: u8,
    cache: Option<PprCacheOutcome>,
    markers: u8,
) {
    let input = diagnostics(
        &selected(&CHANNELS, attempted),
        &selected(&CHANNELS, succeeded),
        cache,
        &selected(&MARKERS, markers),
    );
    let mut expected_markers = selected(&MARKERS, markers);
    if attempted & 16 != 0 && cache == Some(PprCacheOutcome::Miss) && markers & 1 == 0 {
        expected_markers.push(RetrievalDegradation::PprCacheMiss);
    }
    if attempted & 8 != 0 && succeeded & 8 == 0 && markers & 8 == 0 {
        expected_markers.push(RetrievalDegradation::TemporalSignalSkipped);
    }
    let completed = (attempted & succeeded).count_ones();
    let (quality, confidence_adjustment) = match completed {
        5 if cache == Some(PprCacheOutcome::Hit) && markers == 0 => {
            (RetrievalQuality::Full, ConfidenceAdjustment::FULL)
        }
        2..=5 => (RetrievalQuality::Degraded, ConfidenceAdjustment::DEGRADED),
        _ => (
            RetrievalQuality::Passthrough,
            ConfidenceAdjustment::PASSTHROUGH,
        ),
    };
    assert_eq!(
        classify_retrieval_quality(&input),
        RetrievalQualityReport {
            quality,
            degradation: expected_markers,
            confidence_adjustment,
        },
        "diagnostics: {input:?}",
    );
}

#[test]
fn classification_truth_table_covers_all_original_channel_and_marker_subsets() {
    for attempted in 0_u8..32 {
        for succeeded in 0_u8..32 {
            for cache in [
                None,
                Some(PprCacheOutcome::Hit),
                Some(PprCacheOutcome::Miss),
                Some(PprCacheOutcome::Disabled),
            ] {
                for markers in 0_u8..16 {
                    assert_truth_table_row(attempted, succeeded, cache, markers);
                }
            }
        }
    }
}

#[test]
fn duplicates_and_other_telemetry_components_cannot_replace_original_channels() {
    let mut attempted = vec![RetrievalSignal::Vector; 8];
    attempted.extend(OTHER_SIGNALS);
    let input = diagnostics(&attempted, &attempted, Some(PprCacheOutcome::Hit), &[]);
    assert_report(
        &classify_retrieval_quality(&input),
        RetrievalQuality::Passthrough,
        &[],
    );
    let input = diagnostics(&OTHER_SIGNALS, &OTHER_SIGNALS, None, &[]);
    assert_report(
        &classify_retrieval_quality(&input),
        RetrievalQuality::Passthrough,
        &[],
    );
    // Duplicates cannot turn four original channels into five.
    attempted.extend_from_slice(&CHANNELS[..4]);
    let input = diagnostics(&attempted, &attempted, Some(PprCacheOutcome::Hit), &[]);
    assert_report(
        &classify_retrieval_quality(&input),
        RetrievalQuality::Degraded,
        &[],
    );
    // An uncompleted blend component also cannot degrade healthy originals.
    attempted.extend(CHANNELS);
    let input = diagnostics(&attempted, &CHANNELS, Some(PprCacheOutcome::Hit), &[]);
    assert_report(
        &classify_retrieval_quality(&input),
        RetrievalQuality::Full,
        &[],
    );
}

#[test]
fn marker_deduplication_keeps_first_observation_and_appends_derived_causes() {
    let input = diagnostics(
        &CHANNELS,
        &CHANNELS[..3],
        Some(PprCacheOutcome::Miss),
        &[
            RetrievalDegradation::Bm25Stale,
            RetrievalDegradation::EmbeddingTimeout,
            RetrievalDegradation::Bm25Stale,
            RetrievalDegradation::EmbeddingTimeout,
        ],
    );
    let before = input.clone();
    let report = classify_retrieval_quality(&input);
    assert_report(
        &report,
        RetrievalQuality::Degraded,
        &[
            RetrievalDegradation::Bm25Stale,
            RetrievalDegradation::EmbeddingTimeout,
            RetrievalDegradation::PprCacheMiss,
            RetrievalDegradation::TemporalSignalSkipped,
        ],
    );
    assert_eq!(input, before);
    for rotation in 0..MARKERS.len() {
        let mut ordered = MARKERS;
        ordered.rotate_left(rotation);
        let repeated: Vec<_> = ordered.into_iter().chain(ordered).chain(ordered).collect();
        assert_eq!(deduplicate_degradation(&repeated), ordered);
        let input = diagnostics(&CHANNELS, &[], Some(PprCacheOutcome::Miss), &repeated);
        assert_report(
            &classify_retrieval_quality(&input),
            RetrievalQuality::Passthrough,
            &ordered,
        );
    }
}

fn assert_wire_values<T>(cases: &[(T, &str)])
where
    T: Copy + fmt::Debug + PartialEq + Serialize + DeserializeOwned,
{
    for &(value, wire) in cases {
        let json = serde_json::to_string(&value).expect("serialize enum JSON");
        assert_eq!(json, format!("\"{wire}\""));
        assert_eq!(
            serde_json::from_str::<T>(&json).expect("decode enum"),
            value
        );
        let packed = rmp_serde::to_vec(&value).expect("serialize enum MessagePack");
        assert_eq!(
            rmp_serde::from_slice::<String>(&packed).expect("string wire enum"),
            wire,
        );
        assert_eq!(
            rmp_serde::from_slice::<T>(&packed).expect("decode enum"),
            value
        );
    }
}

#[test]
fn enum_wire_values_and_defaults_are_pinned() {
    assert_wire_values(&[
        (RetrievalQuality::Full, "full"),
        (RetrievalQuality::Degraded, "degraded"),
        (RetrievalQuality::Passthrough, "passthrough"),
    ]);
    assert_wire_values(&[
        (RetrievalDegradation::PprCacheMiss, "ppr_cache_miss"),
        (RetrievalDegradation::EmbeddingTimeout, "embedding_timeout"),
        (RetrievalDegradation::Bm25Stale, "bm25_stale"),
        (
            RetrievalDegradation::TemporalSignalSkipped,
            "temporal_signal_skipped",
        ),
    ]);
    assert_wire_values(&[
        (PprCacheOutcome::Hit, "hit"),
        (PprCacheOutcome::Miss, "miss"),
        (PprCacheOutcome::Disabled, "disabled"),
    ]);
    assert_eq!(RetrievalQuality::default(), RetrievalQuality::Passthrough);
    assert_eq!(
        ConfidenceAdjustment::default(),
        ConfidenceAdjustment::PASSTHROUGH,
    );
    assert!(serde_json::from_str::<RetrievalQuality>("\"Full\"").is_err());
    assert!(serde_json::from_str::<RetrievalDegradation>("\"bm25Stale\"").is_err());
    assert!(serde_json::from_str::<PprCacheOutcome>("\"unknown\"").is_err());
}

#[test]
fn confidence_serializes_as_pinned_numbers_not_scaled_integers_or_strings() {
    for (adjustment, wire, number) in [
        (ConfidenceAdjustment::FULL, "0.0", 0.0_f64),
        (ConfidenceAdjustment::DEGRADED, "-0.15", -0.15),
        (ConfidenceAdjustment::PASSTHROUGH, "-0.35", -0.35),
    ] {
        assert_eq!(
            serde_json::to_string(&adjustment).expect("JSON number"),
            wire,
        );
        assert_eq!(
            serde_json::to_value(adjustment).expect("JSON value"),
            json!(number),
        );
        assert_eq!(
            serde_json::from_str::<ConfidenceAdjustment>(wire).expect("pinned decimal"),
            adjustment,
        );
        let packed = rmp_serde::to_vec(&adjustment).expect("MessagePack number");
        assert_eq!(
            rmp_serde::from_slice::<f64>(&packed).expect("numeric wire"),
            number,
        );
        assert_eq!(
            rmp_serde::from_slice::<ConfidenceAdjustment>(&packed).expect("pinned number"),
            adjustment,
        );
        assert_eq!(adjustment.as_f32(), number as f32);
    }
}

fn packed_f32(value: f32) -> Vec<u8> {
    let mut bytes = vec![0xca];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

fn packed_f64(value: f64) -> Vec<u8> {
    let mut bytes = vec![0xcb];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn confidence_accepts_native_float_widths_and_normalizes_integer_and_negative_zero() {
    for (adjustment, value) in [
        (ConfidenceAdjustment::FULL, 0.0_f64),
        (ConfidenceAdjustment::DEGRADED, -0.15),
        (ConfidenceAdjustment::PASSTHROUGH, -0.35),
        (ConfidenceAdjustment::FULL, -0.0),
    ] {
        for bytes in [packed_f64(value), packed_f32(value as f32)] {
            assert_eq!(
                rmp_serde::from_slice::<ConfidenceAdjustment>(&bytes).expect("native float"),
                adjustment,
            );
        }
    }
    for (wire, expected) in [
        ("0", ConfidenceAdjustment::FULL),
        ("-0", ConfidenceAdjustment::FULL),
        ("-0.0", ConfidenceAdjustment::FULL),
        ("0e0", ConfidenceAdjustment::FULL),
        ("-15e-2", ConfidenceAdjustment::DEGRADED),
        ("-35e-2", ConfidenceAdjustment::PASSTHROUGH),
    ] {
        let value: ConfidenceAdjustment = serde_json::from_str(wire).expect("pinned value");
        assert_eq!(value, expected);
    }
    // Positive fixint, signed int8 zero, and unsigned int8 zero.
    for bytes in [vec![0x00], vec![0xd0, 0x00], vec![0xcc, 0x00]] {
        let value: ConfidenceAdjustment = rmp_serde::from_slice(&bytes).expect("integer zero");
        assert_eq!(value, ConfidenceAdjustment::FULL);
        assert_eq!(value.as_f32().to_bits(), 0.0_f32.to_bits());
    }
}

#[test]
fn confidence_rejects_non_pinned_json_numbers_and_wrong_types() {
    for wire in [
        "-1500",
        "-3500",
        "1",
        "-1",
        "0.15",
        "-0.1501",
        "-0.14999",
        "-0.34999",
        "-0.35001",
        "-0.15000000000000002",
        "-0.35000000000000003",
        "1e999",
        "NaN",
        "Infinity",
        "null",
        "true",
        "[]",
        "{}",
        "\"-0.15\"",
    ] {
        assert!(
            serde_json::from_str::<ConfidenceAdjustment>(wire).is_err(),
            "accepted {wire}",
        );
    }
}

#[test]
fn confidence_rejects_non_finite_and_neighboring_messagepack_floats_without_rounding() {
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        1.0,
        -1500.0,
        -3500.0,
        0.0_f64.next_up(),
        0.0_f64.next_down(),
        (-0.15_f64).next_up(),
        (-0.15_f64).next_down(),
        (-0.35_f64).next_up(),
        (-0.35_f64).next_down(),
        f64::from(-0.15_f32),
        f64::from(-0.35_f32),
    ] {
        assert!(rmp_serde::from_slice::<ConfidenceAdjustment>(&packed_f64(value)).is_err());
    }
    for value in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::MAX,
        1.0,
        -1500.0,
        -3500.0,
        0.0_f32.next_up(),
        0.0_f32.next_down(),
        (-0.15_f32).next_up(),
        (-0.15_f32).next_down(),
        (-0.35_f32).next_up(),
        (-0.35_f32).next_down(),
    ] {
        assert!(rmp_serde::from_slice::<ConfidenceAdjustment>(&packed_f32(value)).is_err());
    }
    for value in [
        json!(-1500),
        json!(-3500),
        json!(1),
        json!(null),
        json!(true),
        json!("-0.15"),
        json!([0]),
        json!({}),
    ] {
        let bytes = rmp_serde::to_vec(&value).expect("invalid adjustment fixture");
        assert!(rmp_serde::from_slice::<ConfidenceAdjustment>(&bytes).is_err());
    }
}

#[test]
fn report_json_casing_omission_and_named_messagepack_round_trip_are_pinned() {
    for (cache, expected) in [
        (
            PprCacheOutcome::Hit,
            json!({"quality": "full", "confidenceAdjustment": 0.0}),
        ),
        (
            PprCacheOutcome::Miss,
            json!({
                "quality": "degraded",
                "degradation": ["ppr_cache_miss"],
                "confidenceAdjustment": -0.15,
            }),
        ),
    ] {
        let input = diagnostics(&CHANNELS, &CHANNELS, Some(cache), &[]);
        let report = classify_retrieval_quality(&input);
        let value = serde_json::to_value(&report).expect("report JSON");
        let bytes = rmp_serde::to_vec_named(&report).expect("named report");
        let named = rmp_serde::from_slice::<serde_json::Value>(&bytes).expect("named map");
        for observed in [&value, &named] {
            let fields = observed.as_object().expect("report map");
            assert_eq!(fields.get("quality"), expected.get("quality"));
            assert_eq!(
                fields.get("confidenceAdjustment"),
                expected.get("confidenceAdjustment"),
            );
            if let Some(markers) = expected.get("degradation") {
                assert_eq!(fields.get("degradation"), Some(markers));
            } else {
                assert!(!fields.contains_key("degradation"));
            }
        }
        let decoded =
            serde_json::from_value::<RetrievalQualityReport>(expected.clone()).expect("report");
        let json_round_trip =
            serde_json::from_value::<RetrievalQualityReport>(value).expect("JSON round trip");
        let packed_round_trip =
            rmp_serde::from_slice::<RetrievalQualityReport>(&bytes).expect("report");
        for observed in [decoded, json_round_trip, packed_round_trip] {
            assert_eq!(observed.quality, report.quality);
            assert_eq!(observed.degradation, report.degradation);
            assert_eq!(observed.confidence_adjustment, report.confidence_adjustment);
        }
    }
    let input = diagnostics(&CHANNELS[..1], &CHANNELS[..1], None, &[]);
    let minimal = classify_retrieval_quality(&input);
    let value = serde_json::to_value(minimal).expect("minimal report");
    let fields = value.as_object().expect("minimal report map");
    assert_eq!(fields.get("quality"), Some(&json!("passthrough")));
    assert_eq!(fields.get("confidenceAdjustment"), Some(&json!(-0.35)));
    assert!(!fields.contains_key("degradation"));
}

#[test]
fn report_named_messagepack_defaults_omitted_degradation_but_requires_tier_and_adjustment() {
    let without_markers = json!({"quality": "degraded", "confidenceAdjustment": -0.15});
    let bytes = rmp_serde::to_vec_named(&without_markers).expect("omitted optional field");
    let report: RetrievalQualityReport = rmp_serde::from_slice(&bytes).expect("default markers");
    assert_report(&report, RetrievalQuality::Degraded, &[]);
    for value in [
        json!({"quality": "full"}),
        json!({"confidenceAdjustment": 0.0}),
        json!({"quality": "full", "confidence_adjustment": 0.0}),
        json!({"quality": "full", "confidenceAdjustment": -0.1501}),
        json!({"quality": "full", "confidenceAdjustment": 0.0, "degradation": null}),
    ] {
        let bytes = rmp_serde::to_vec_named(&value).expect("invalid report fixture");
        assert!(rmp_serde::from_slice::<RetrievalQualityReport>(&bytes).is_err());
        assert!(serde_json::from_value::<RetrievalQualityReport>(value).is_err());
    }
}

#[test]
fn confidence_helper_adds_then_clamps_and_fails_closed_for_non_finite_input() {
    for (adjustment, confidence, expected) in [
        (ConfidenceAdjustment::FULL, 0.8, 0.8),
        (ConfidenceAdjustment::DEGRADED, 0.8, 0.65),
        (ConfidenceAdjustment::PASSTHROUGH, 0.8, 0.45),
        (ConfidenceAdjustment::DEGRADED, 0.15, 0.0),
        (ConfidenceAdjustment::PASSTHROUGH, 0.35, 0.0),
        (ConfidenceAdjustment::PASSTHROUGH, 1.2, 0.85),
    ] {
        assert!((adjustment.apply_to(confidence) - expected).abs() <= f32::EPSILON);
    }
    for adjustment in [
        ConfidenceAdjustment::FULL,
        ConfidenceAdjustment::DEGRADED,
        ConfidenceAdjustment::PASSTHROUGH,
    ] {
        for value in [
            0.0,
            -1.0,
            f32::MIN,
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ] {
            assert_eq!(adjustment.apply_to(value), 0.0);
        }
        for value in [2.0, f32::MAX] {
            assert_eq!(adjustment.apply_to(value), 1.0);
        }
    }
}
