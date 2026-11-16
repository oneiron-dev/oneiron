//! UC-03 PR 0r (M-4 = a): `RecordedSeconds` is the bare `u64` on the wire, so a stored seconds field that
//! switches to it (the Gate ledger's `created_at`, Setting's `SettingChange.at`, Schedule's `Trigger::At`)
//! keeps its bytes, and a row a vault already holds decodes unchanged. `from_millis` is the one
//! milliseconds-to-seconds step. Red on main: main has no `RecordedSeconds`, so this file does not build.

use oneiron_contracts::RecordedSeconds;
use serde::{Deserialize, Serialize};

/// Values on both sides of each MessagePack integer width, and a 2026 stamp in seconds and in milliseconds.
const SAMPLES: [u64; 10] = [
    0,
    1,
    127,
    128,
    255,
    65_535,
    65_536,
    1_763_190_000,
    1_763_190_000_000,
    u64::MAX,
];

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct BareRow {
    created_at: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TypedRow {
    created_at: RecordedSeconds,
}

#[test]
fn msgpack_bytes_are_the_bare_u64() {
    for secs in SAMPLES {
        let typed = RecordedSeconds::from_secs(secs);
        let bare = rmp_serde::to_vec(&secs).unwrap();
        assert_eq!(rmp_serde::to_vec(&typed).unwrap(), bare, "{secs}");
        assert_eq!(
            rmp_serde::from_slice::<RecordedSeconds>(&bare).unwrap(),
            typed,
            "{secs}"
        );
    }
}

#[test]
fn msgpack_row_bytes_are_unchanged_in_both_struct_forms() {
    for secs in SAMPLES {
        let bare = BareRow { created_at: secs };
        let typed = TypedRow {
            created_at: RecordedSeconds::from_secs(secs),
        };
        // The array form (`to_vec`) and the map form (`to_vec_named`) both appear on stored rows.
        let bare_array = rmp_serde::to_vec(&bare).unwrap();
        let bare_map = rmp_serde::to_vec_named(&bare).unwrap();
        assert_eq!(rmp_serde::to_vec(&typed).unwrap(), bare_array, "{secs}");
        assert_eq!(rmp_serde::to_vec_named(&typed).unwrap(), bare_map, "{secs}");
        // A row written with the bare field reads into the typed field, and back.
        assert_eq!(
            rmp_serde::from_slice::<TypedRow>(&bare_array).unwrap(),
            typed,
            "{secs}"
        );
        assert_eq!(
            rmp_serde::from_slice::<TypedRow>(&bare_map).unwrap(),
            typed,
            "{secs}"
        );
        let typed_map = rmp_serde::to_vec_named(&typed).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<BareRow>(&typed_map).unwrap(),
            bare,
            "{secs}"
        );
    }
}

#[test]
fn json_bytes_are_the_bare_u64() {
    for secs in SAMPLES {
        let typed = RecordedSeconds::from_secs(secs);
        let bare = serde_json::to_string(&secs).unwrap();
        assert_eq!(serde_json::to_string(&typed).unwrap(), bare, "{secs}");
        assert_eq!(
            serde_json::from_str::<RecordedSeconds>(&bare).unwrap(),
            typed,
            "{secs}"
        );
        let row = serde_json::to_string(&BareRow { created_at: secs }).unwrap();
        assert_eq!(
            serde_json::to_string(&TypedRow { created_at: typed }).unwrap(),
            row,
            "{secs}"
        );
        assert_eq!(
            serde_json::from_str::<TypedRow>(&row).unwrap().created_at,
            typed,
            "{secs}"
        );
    }
}

#[test]
fn json_rejects_what_the_bare_u64_rejects() {
    for text in ["-1", "1.5", "\"1500\"", "null", "18446744073709551616"] {
        assert!(serde_json::from_str::<u64>(text).is_err(), "{text}");
        assert!(
            serde_json::from_str::<RecordedSeconds>(text).is_err(),
            "{text}"
        );
    }
}

#[test]
fn from_millis_rounds_down_to_whole_seconds() {
    assert_eq!(RecordedSeconds::from_millis(1_500_000).secs(), 1_500);
    assert_eq!(
        RecordedSeconds::from_millis(1_500_000),
        RecordedSeconds::from_secs(1_500)
    );
    assert_eq!(RecordedSeconds::from_millis(1_999).secs(), 1);
    assert_eq!(RecordedSeconds::from_millis(999).secs(), 0);
    assert_eq!(RecordedSeconds::from_millis(0).secs(), 0);
    assert_eq!(
        RecordedSeconds::from_millis(1_763_190_000_123).secs(),
        1_763_190_000
    );
    assert_eq!(
        RecordedSeconds::from_millis(u64::MAX).secs(),
        u64::MAX / 1_000
    );
}

#[test]
fn secs_returns_what_from_secs_took_and_orders_by_time() {
    for secs in SAMPLES {
        assert_eq!(RecordedSeconds::from_secs(secs).secs(), secs);
    }
    assert!(RecordedSeconds::from_secs(1) < RecordedSeconds::from_secs(2));
    assert_eq!(RecordedSeconds::default().secs(), 0);
}
