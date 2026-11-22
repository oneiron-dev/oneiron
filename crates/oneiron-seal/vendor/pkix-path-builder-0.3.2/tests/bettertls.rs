//! BetterTLS pathbuilding fixture characterization tests.
//!
//! Source: the 47 `bettertls::pathbuilding::*` testcases that pkix-path-builder
//! currently fails on against the x509-limbo Tier-2 corpus (PKIX-g9vc.4,
//! see `pkix-difftest/baseline-limbo-analysis.md`). 25 representative
//! fixtures are committed under `tests/fixtures/bettertls/`, distributed
//! across the five failure-mode buckets (see that directory's `README.md`
//! for provenance and the bucket breakdown).
//!
//! # What this test does
//!
//! Walks each fixture, runs [`pkix_path_builder::build_path`] then
//! [`pkix_path::validate_path`], records the observed pass/fail status,
//! and asserts the result matches `baseline-pkix-path.json` at the fixture
//! root.
//!
//! # Why characterization, not pass/fail
//!
//! Per PKIX-lwr9.1 acceptance criteria, the harness is a *baseline* for
//! the heuristic work in PKIX-lwr9.2/.3/.4. All 25 cases currently report
//! a `build_failed` or `validation_failed` status; the corpus expects
//! 23 of 25 to validate successfully (the other 2 — tc41 and a corpus
//! intersection — are expected FAILURE). As the heuristic-fix beads land,
//! they will update `baseline-pkix-path.json` to reflect the new
//! observed status, and the test continues to pass on the snapshot.
//!
//! This mirrors the snapshot pattern used by `pkix-difftest/baseline-*.json`.
//!
//! # Discovering / refreshing the baseline
//!
//! Set the `BETTERTLS_BASELINE_DISCOVER` environment variable to print the
//! observed status for every fixture in `baseline-pkix-path.json` format
//! to stdout, without asserting:
//!
//! ```text
//! BETTERTLS_BASELINE_DISCOVER=1 cargo test -p pkix-path-builder --test bettertls -- --nocapture
//! ```
//!
//! Pipe that output into `tests/fixtures/bettertls/baseline-pkix-path.json`
//! when intentionally rebaselining (e.g., after a heuristic fix lands).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_path, CertPool};
use x509_cert::Certificate;

/// Per-fixture metadata produced by `tests/fixtures/bettertls/extract.py`.
///
/// Field names match the JSON keys verbatim. This is the corpus snapshot
/// from x509-limbo (what limbo.json said about the testcase) — it does
/// not record pkix-path-builder behaviour.
#[derive(Debug)]
struct Testcase {
    id: String,
    bucket: String,
    validation_time: String,
    expected_result: String, // "SUCCESS" or "FAILURE" per limbo
}

/// The observed pkix-path-builder + pkix-path behaviour for a fixture.
///
/// `Built { valid }` means `build_path` returned `Ok(chain)`; `valid`
/// records whether `validate_path` then accepted the chain.
/// `BuildFailed { error }` means `build_path` returned `Err`; the
/// `error` field is the [`pkix_path_builder::Error`] `Debug` representation.
#[derive(Debug, PartialEq, Eq)]
enum Observed {
    Built { valid: Option<String> },
    BuildFailed { error: String },
}

impl Observed {
    /// JSON-shape rendering used by both the baseline file and the
    /// discover-mode stdout dump.
    fn to_json(&self) -> String {
        match self {
            Observed::Built { valid: None } => String::from(r#"{"phase":"built_and_valid"}"#),
            Observed::Built {
                valid: Some(reason),
            } => format!(r#"{{"phase":"validation_failed","reason":{:?}}}"#, reason),
            Observed::BuildFailed { error } => {
                format!(r#"{{"phase":"build_failed","error":{:?}}}"#, error)
            }
        }
    }
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bettertls")
}

/// RFC 3339 → Unix seconds.
///
/// Bettertls fixtures use the form `YYYY-MM-DDTHH:MM:SS[.fff]<TZ>` with
/// `<TZ>` either `Z` or `±HH:MM`. Fractional seconds and TZ offsets are
/// honoured; fractional precision is truncated to whole seconds (matches
/// `ValidationPolicy::new`'s u64 input).
///
/// This is a deliberate copy of the inline parser in
/// `pkix-difftest/src/corpus/limbo.rs`, kept here to avoid a dev-dep on
/// `pkix-difftest` (it pulls in oracle backends we do not need for unit
/// testing path-builder behaviour). Howard Hinnant's "days from civil"
/// algorithm is the standard textbook approach.
fn rfc3339_to_unix(s: &str) -> u64 {
    // YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)
    let bytes = s.as_bytes();
    assert!(bytes.len() >= 19, "RFC3339 string too short: {s}");
    let year: i64 = s[0..4].parse().expect("year");
    let month: u32 = s[5..7].parse().expect("month");
    let day: u32 = s[8..10].parse().expect("day");
    let hour: u64 = s[11..13].parse().expect("hour");
    let minute: u64 = s[14..16].parse().expect("minute");
    let second: u64 = s[17..19].parse().expect("second");

    // Skip optional fractional seconds.
    let mut i = 19;
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }

    // Timezone offset.
    let tz_offset_secs: i64 = if i < bytes.len() && (bytes[i] == b'Z' || bytes[i] == b'z') {
        0
    } else if i + 6 <= bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        let sign = if bytes[i] == b'+' { 1 } else { -1 };
        let oh: i64 = s[i + 1..i + 3].parse().expect("offset hours");
        let om: i64 = s[i + 4..i + 6].parse().expect("offset minutes");
        sign * (oh * 3600 + om * 60)
    } else {
        panic!("invalid TZ in RFC3339: {s}");
    };

    // Howard Hinnant's days_from_civil (Gregorian → epoch days).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe: i64 = y - era * 400; // [0, 399]
    let m = month as i64;
    let d = day as i64;
    let doy: i64 = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe: i64 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch: i64 = era * 146_097 + doe - 719_468;

    let total =
        days_since_epoch * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64)
            - tz_offset_secs;
    assert!(total >= 0, "RFC3339 predates Unix epoch: {s}");
    total as u64
}

fn load_testcase(case_dir: &Path) -> Testcase {
    let json = std::fs::read_to_string(case_dir.join("testcase.json"))
        .unwrap_or_else(|e| panic!("read testcase.json in {}: {e}", case_dir.display()));
    // Trivial single-line field extraction. testcase.json is generated by
    // extract.py with stable formatting (sorted keys, two-space indent),
    // and the fields we read are flat strings. A real JSON parser would be
    // overkill for a test fixture.
    let get = |key: &str| -> String {
        let needle = format!("\"{key}\":");
        let i = json
            .find(&needle)
            .unwrap_or_else(|| panic!("testcase.json in {} missing {key}", case_dir.display()));
        let after = &json[i + needle.len()..];
        let after = after.trim_start();
        assert!(
            after.starts_with('"'),
            "testcase.json field {key} not a string"
        );
        let rest = &after[1..];
        let end = rest.find('"').expect("string terminator");
        rest[..end].to_string()
    };
    Testcase {
        id: get("id"),
        bucket: get("bucket"),
        validation_time: get("validation_time"),
        expected_result: get("expected_result"),
    }
}

fn load_pem_chain(path: &Path) -> Vec<Certificate> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Certificate::load_pem_chain(&bytes)
        .unwrap_or_else(|e| panic!("parse PEM at {}: {e}", path.display()))
}

fn run_fixture(case_dir: &Path) -> (Testcase, Observed) {
    let tc = load_testcase(case_dir);
    let now = rfc3339_to_unix(&tc.validation_time);

    let mut peer = load_pem_chain(&case_dir.join("peer.pem"));
    assert_eq!(
        peer.len(),
        1,
        "{}: peer.pem must hold exactly one cert",
        tc.id
    );
    let peer = peer.remove(0);

    let intermediates = load_pem_chain(&case_dir.join("intermediates.pem"));
    let anchors_certs = load_pem_chain(&case_dir.join("anchors.pem"));
    assert!(
        !anchors_certs.is_empty(),
        "{}: anchors.pem must contain at least one cert",
        tc.id
    );

    let anchors: Vec<TrustAnchor> = anchors_certs.iter().map(TrustAnchor::from).collect();
    let pool: CertPool = intermediates.into_iter().collect();

    let observed = match build_path(&peer, &pool, &anchors) {
        Ok(chain) => {
            let policy = ValidationPolicy::new(now);
            let verifier = DefaultVerifier;
            match pkix_path::validate_path(&chain, &anchors, &policy, &verifier) {
                Ok(_) => Observed::Built { valid: None },
                Err(e) => Observed::Built {
                    valid: Some(format!("{e:?}")),
                },
            }
        }
        Err(e) => Observed::BuildFailed {
            error: format!("{e:?}"),
        },
    };

    (tc, observed)
}

fn load_baseline(root: &Path) -> BTreeMap<String, String> {
    let path = root.join("baseline-pkix-path.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut out = BTreeMap::new();
    // Generated by this same test in discover mode: one entry per line of
    // the form `  "tcN": <observed-json>,` inside a single top-level object.
    // We parse line-by-line because pulling in serde_json as a dev-dep just
    // for fixture metadata is excessive (per workspace pattern; e.g.,
    // pkix-difftest reads its own snapshot files with hand-rolled scans).
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('"') {
            continue;
        }
        let rest = &line[1..];
        let key_end = rest.find('"').expect("baseline: key terminator");
        let key = rest[..key_end].to_string();
        let after_key = rest[key_end + 1..].trim_start();
        let after_colon = after_key
            .strip_prefix(':')
            .expect("baseline: missing colon")
            .trim_start();
        // Value spans from the opening '{' to the matching '}'. Reject any
        // line where braces don't balance — JSON-on-one-line is our format
        // contract, enforced when discover-mode regenerates the file.
        let mut depth = 0i32;
        let mut end = None;
        for (i, c) in after_colon.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("baseline: unbalanced braces on entry");
        let value = after_colon[..end].to_string();
        out.insert(key, value);
    }
    out
}

#[test]
fn bettertls_pathbuilding_characterization() {
    let root = fixtures_root();
    let discover = std::env::var_os("BETTERTLS_BASELINE_DISCOVER").is_some();

    // Walk fixture subdirectories deterministically.
    let mut case_dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", root.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() && path.join("testcase.json").exists() {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    case_dirs.sort_by_key(|p| {
        // Sort by numeric tc suffix so output is tc1, tc2, ... tc68 not
        // tc1, tc16, tc2 (lexicographic).
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let n: u32 = name
            .strip_prefix("tc")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        n
    });

    assert!(
        case_dirs.len() >= 25,
        "expected at least 25 bettertls fixtures, found {}",
        case_dirs.len()
    );

    let mut results: Vec<(Testcase, Observed)> = Vec::with_capacity(case_dirs.len());
    for case_dir in &case_dirs {
        results.push(run_fixture(case_dir));
    }

    if discover {
        println!("{{");
        let last = results.len().saturating_sub(1);
        for (i, (tc, obs)) in results.iter().enumerate() {
            let short = tc.id.rsplit("::").next().unwrap_or(&tc.id);
            let comma = if i == last { "" } else { "," };
            println!("  \"{short}\": {}{comma}", obs.to_json());
        }
        println!("}}");
        // Discover mode short-circuits assertion. The caller redirects
        // stdout into baseline-pkix-path.json when intentionally
        // rebaselining; the test always passes in this mode.
        return;
    }

    let baseline = load_baseline(&root);
    let mut mismatches: Vec<String> = Vec::new();

    for (tc, obs) in &results {
        let short = tc.id.rsplit("::").next().unwrap_or(&tc.id);
        let observed_json = obs.to_json();
        match baseline.get(short) {
            Some(expected) if expected == &observed_json => {
                // Cross-check that the corpus's expected_result and the
                // bucket label are still consistent with what we observe.
                // This is a sanity check on fixture provenance, not a
                // pkix-path-builder assertion.
                assert!(
                    !tc.bucket.is_empty(),
                    "{}: testcase.json missing bucket label",
                    tc.id
                );
                assert!(
                    tc.expected_result == "SUCCESS" || tc.expected_result == "FAILURE",
                    "{}: unexpected expected_result {:?}",
                    tc.id,
                    tc.expected_result
                );
            }
            Some(expected) => {
                mismatches.push(format!(
                    "  {short}: baseline={expected} observed={observed_json}"
                ));
            }
            None => {
                mismatches.push(format!(
                    "  {short}: missing from baseline-pkix-path.json (observed: {observed_json})"
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "pkix-path-builder behaviour differs from baseline for {} fixture(s):\n{}\n\n\
         If this change is intentional (e.g., a PKIX-lwr9.2/.3/.4 heuristic landed), \
         regenerate the baseline:\n  \
         BETTERTLS_BASELINE_DISCOVER=1 cargo test -p pkix-path-builder \
         --test bettertls -- --nocapture > tests/fixtures/bettertls/baseline-pkix-path.json",
        mismatches.len(),
        mismatches.join("\n")
    );
}
