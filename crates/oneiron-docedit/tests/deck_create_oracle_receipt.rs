//! L4-20 (ARCH-0077 slides lane): the `deck-create-v1` Office receipts committed under
//! `scripts/office/results/deck-create-v1/` stay bound to the candidates the emitter writes today, hash every
//! output, keep one PowerPoint fit row per fit-unverified unit, and name the font account by its role only (Engine
//! RULING L4-20-OFFICE-ACCOUNT, 14 Nov 11:22: no macOS account name in a committed receipt).
//! `cargo test --locked -p oneiron-docedit --all-features --test deck_create_oracle_receipt`.

use oneiron_docedit::emit::oracle_cases::{self, UnitKind};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The repository root above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The JSON file at `path`, or a failure naming it.
fn read_json(path: &Path) -> Value {
    let bytes =
        std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Canon `slides:oracle`: the oracle runs once per case set to create golden outputs, so the stored receipt still names the candidate the emitter writes.
#[test]
fn every_case_candidate_matches_its_stored_receipt() {
    let root = repo();
    let loaded = oracle_cases::load(&root).expect("load deck-create-v1");
    let results = root.join(oracle_cases::STORED_RESULTS);
    let run = read_json(&results.join("run.json"));
    let source = run
        .get("source")
        .and_then(Value::as_str)
        .expect("run.json source");
    let config = read_json(&root.join("scripts/office/environment.json"));
    let expected = config
        .get("environment")
        .expect("environment.json environment");
    let approved = config
        .get("approved_font_inventories")
        .expect("environment.json approvals");
    let manifest_sha = oracle_cases::sha256_hex(&loaded.manifest_bytes);
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        let built = oracle_cases::case_candidate(&root, &loaded, case)
            .unwrap_or_else(|reason| panic!("{id}: refused: {reason}"));
        let receipt = read_json(&results.join(id).join("receipt.json"));
        assert_eq!(
            receipt.get("status").and_then(Value::as_str),
            Some("clean"),
            "{id}: status"
        );
        let input = receipt
            .get("input")
            .unwrap_or_else(|| panic!("{id}: receipt has no input"));
        let sha = oracle_cases::sha256_hex(&built.candidate.bytes);
        assert_eq!(
            input.get("sha256").and_then(Value::as_str),
            Some(sha.as_str()),
            "{id}: the emitter no longer writes the receipted candidate; rerun the deck-create-v1 Office pass (docs/ops/deck-gate.md)"
        );
        let bytes = u64::try_from(built.candidate.bytes.len()).expect("candidate size");
        assert_eq!(
            input.get("bytes").and_then(Value::as_u64),
            Some(bytes),
            "{id}: input bytes"
        );
        let binding = receipt
            .get("binding")
            .unwrap_or_else(|| panic!("{id}: receipt has no binding"));
        assert_eq!(
            binding.get("case_set").and_then(Value::as_str),
            Some("deck-create-v1"),
            "{id}: binding case set"
        );
        assert_eq!(
            binding.get("case").and_then(Value::as_str),
            Some(id),
            "{id}: binding case"
        );
        assert_eq!(
            binding.get("case_manifest_sha256").and_then(Value::as_str),
            Some(manifest_sha.as_str()),
            "{id}: binding manifest"
        );
        assert_eq!(
            binding.get("source").and_then(Value::as_str),
            Some(source),
            "{id}: binding source"
        );
        let environment = receipt
            .get("environment")
            .unwrap_or_else(|| panic!("{id}: receipt has no environment"));
        for (key, want) in expected.as_object().expect("environment.json environment") {
            assert_eq!(
                environment.get(key.as_str()),
                Some(want),
                "{id}: environment {key}"
            );
        }
        let account = environment.get("font_account").and_then(Value::as_str);
        assert!(
            matches!(account, Some("owner-console" | "isolated-console")),
            "{id}: the receipt names the font account by its role only, not {account:?}"
        );
        let role = environment
            .get("font_role")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{id}: environment has no font role"));
        let inventory = environment
            .get("font_inventory_sha256")
            .unwrap_or_else(|| panic!("{id}: environment has no font inventory"));
        assert_eq!(Some(inventory), approved.get(role), "{id}: font inventory");
    }
}

/// Canon 0077 PowerPoint oracle table: "Hash every input and output."
#[test]
fn every_receipt_hashes_every_output() {
    let root = repo();
    let loaded = oracle_cases::load(&root).expect("load deck-create-v1");
    let results = root.join(oracle_cases::STORED_RESULTS);
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        let dir = results.join(id);
        let receipt = read_json(&dir.join("receipt.json"));
        let pages = receipt
            .get("pages")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("{id}: receipt has no pages"));
        let outputs = receipt
            .get("outputs")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{id}: receipt has no outputs"));
        let mut want = vec!["render.pdf".to_owned(), "reference.pptx".to_owned()];
        for page in 1..=pages {
            want.push(format!("page-{page:04}.png"));
        }
        want.sort();
        let mut held: Vec<String> = outputs.keys().cloned().collect();
        held.sort();
        assert_eq!(held, want, "{id}: outputs");
        for name in &want {
            let entry = outputs
                .get(name.as_str())
                .unwrap_or_else(|| panic!("{id}: receipt has no output {name}"));
            let path = dir.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let sha = oracle_cases::sha256_hex(&bytes);
            assert_eq!(
                entry.get("sha256").and_then(Value::as_str),
                Some(sha.as_str()),
                "{id}: {name} hash"
            );
            let size = u64::try_from(bytes.len()).expect("output size");
            assert_eq!(
                entry.get("bytes").and_then(Value::as_u64),
                Some(size),
                "{id}: {name} size"
            );
        }
    }
}

/// ARCH-0077 creation status: text, tables and charts return FitUnverified, so every such unit keeps the row PowerPoint measured for it.
#[test]
fn every_fit_unverified_unit_has_a_measured_row() {
    let root = repo();
    let loaded = oracle_cases::load(&root).expect("load deck-create-v1");
    let results = root.join(oracle_cases::STORED_RESULTS);
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        let built = oracle_cases::case_candidate(&root, &loaded, case)
            .unwrap_or_else(|reason| panic!("{id}: refused: {reason}"));
        let receipt = read_json(&results.join(id).join("receipt.json"));
        let fit = receipt
            .get("fit")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{id}: receipt has no fit"));
        assert_eq!(fit.len(), built.units.len(), "{id}: fit rows");
        for (row, unit) in fit.iter().zip(&built.units) {
            let block = unit.block.as_str();
            assert_eq!(
                row.get("slide").and_then(Value::as_u64),
                Some(u64::from(unit.slide)),
                "{id}: {block} slide"
            );
            assert_eq!(
                row.get("shape_index").and_then(Value::as_u64),
                Some(u64::from(unit.shape_index)),
                "{id}: {block} shape index"
            );
            assert_eq!(
                row.get("shape_id").and_then(Value::as_u64),
                Some(u64::from(unit.shape_id)),
                "{id}: {block} shape id"
            );
            assert_eq!(
                row.get("name").and_then(Value::as_str),
                Some(unit.name.as_str()),
                "{id}: {block} name"
            );
            assert_eq!(
                row.get("block").and_then(Value::as_str),
                Some(block),
                "{id}: {block} block"
            );
            let kind = match &unit.kind {
                UnitKind::Text => "text",
                UnitKind::Table => "table",
                UnitKind::Chart => "chart",
            };
            assert_eq!(
                row.get("kind").and_then(Value::as_str),
                Some(kind),
                "{id}: {block} kind"
            );
            let planned = row
                .get("planned_emu")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{id}: {block} has no planned frame"));
            assert_eq!(
                planned.len(),
                unit.planned_emu.len(),
                "{id}: {block} planned frame"
            );
            for (held, want) in planned.iter().zip(unit.planned_emu) {
                assert_eq!(held.as_i64(), Some(want), "{id}: {block} planned frame");
            }
            let verdict = row
                .get("verdict")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{id}: {block} has no verdict"));
            assert!(
                matches!(verdict, "fits" | "overflows" | "inconclusive"),
                "{id}: {block} verdict {verdict}"
            );
            if matches!(unit.kind, UnitKind::Chart) {
                assert_eq!(verdict, "inconclusive", "{id}: {block} chart");
            }
            if verdict == "fits" {
                let inner = row
                    .get("inner_emu")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("{id}: {block} fits without an inner size"));
                let bound = row
                    .get("bound_emu")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("{id}: {block} fits without a bound size"));
                assert_eq!(inner.len(), 2, "{id}: {block} inner size");
                assert_eq!(bound.len(), 2, "{id}: {block} bound size");
                for (axis, (held, room)) in bound.iter().zip(inner.iter()).enumerate() {
                    let held = held
                        .as_i64()
                        .unwrap_or_else(|| panic!("{id}: {block} bound is not measured"));
                    let room = room
                        .as_i64()
                        .unwrap_or_else(|| panic!("{id}: {block} inner is not measured"));
                    assert!(
                        held <= room + 635,
                        "{id}: {block} axis {axis}: bound {held} past inner {room}"
                    );
                }
            }
        }
        let script = receipt
            .get("fit_script_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{id}: receipt has no fit script hash"));
        assert_eq!(script.len(), 64, "{id}: fit script hash");
        assert!(
            script.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{id}: fit script hash is hex"
        );
    }
}

/// Canon `slides:oracle`: CI uses the stored outputs, so the stored run still names this case set, its manifest, its source and its cases.
#[test]
fn the_stored_run_names_this_case_set() {
    let root = repo();
    let loaded = oracle_cases::load(&root).expect("load deck-create-v1");
    let run = read_json(&root.join(oracle_cases::STORED_RESULTS).join("run.json"));
    assert_eq!(
        run.get("schema").and_then(Value::as_str),
        Some("oneiron.deck-create-office/1"),
        "run.json schema"
    );
    assert_eq!(
        run.get("case_set").and_then(Value::as_str),
        Some("deck-create-v1"),
        "run.json case set"
    );
    let sha = oracle_cases::sha256_hex(&loaded.manifest_bytes);
    assert_eq!(
        run.get("case_manifest_sha256").and_then(Value::as_str),
        Some(sha.as_str()),
        "run.json manifest"
    );
    let source = run
        .get("source")
        .and_then(Value::as_str)
        .expect("run.json source");
    assert_eq!(source.len(), 40, "run.json source");
    assert!(
        source
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "run.json source is lower-case hex"
    );
    assert!(
        run.get("stopped").is_some_and(Value::is_null),
        "run.json stopped"
    );
    let candidates = run
        .get("candidates")
        .and_then(Value::as_object)
        .expect("run.json candidates");
    let mut held: Vec<&str> = candidates.keys().map(String::as_str).collect();
    held.sort_unstable();
    let mut want: Vec<&str> = loaded
        .set
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect();
    want.sort_unstable();
    assert_eq!(held, want, "run.json candidates");
}
