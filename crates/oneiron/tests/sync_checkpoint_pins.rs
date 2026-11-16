//! The checkpoint dispatch's answers (UC-10 PR 6): `root_entry`, `key_refusal`,
//! `withheld_part_key`, `withheld_client_key` and `withheld_key` for a fixed
//! cross product of window root map, key and value, one line each, printed as
//! one sha256 per root (`PIN-ROOT`) and one over all (`PINS`). Run at the
//! commit before the dispatch moves onto one row table and at the commit
//! after: both runs print the same `PINS` line.
//!
//! From the move's commit B (D5) on, a turn program row filed under a key other
//! than its own places under no one, so the lines of the two turn program maps
//! change there on purpose; `PINS-WITHOUT-TURN-PROGRAMS` hashes every other
//! line, which no commit of the move may change.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::test_doors::sync_checkpoint_pins::{fixture_placements, pins, window_roots};
use sha2::{Digest, Sha256};

/// The prefix of the names of the two turn program window maps.
const TURN_PROGRAM_ROOT_PREFIX: &str = "turn_program_";

/// The sha256 of `lines` joined by newlines, as lowercase hex.
fn digest_of(lines: &[&str]) -> String {
    format!("{:x}", Sha256::digest(lines.join("\n").as_bytes()))
}

#[test]
fn sync_checkpoint_pins() {
    let lines = pins().expect("the pin table builds");
    let all: Vec<&str> = lines.iter().map(String::as_str).collect();
    // One hash per root keeps the log small (the table is tens of thousands
    // of lines) and still names the root whose lines differ.
    let mut roots: Vec<&str> = Vec::new();
    for line in &all {
        let root = line.split(' ').next().unwrap_or_default();
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    for root in roots {
        let prefix = format!("{root} ");
        let of_root: Vec<&str> = all
            .iter()
            .copied()
            .filter(|line| line.starts_with(prefix.as_str()))
            .collect();
        println!(
            "PIN-ROOT {root} sha256={} lines={}",
            digest_of(&of_root),
            of_root.len()
        );
    }
    println!("PINS sha256={} lines={}", digest_of(&all), all.len());
    let without_turn_programs: Vec<&str> = all
        .iter()
        .copied()
        .filter(|line| !line.starts_with(TURN_PROGRAM_ROOT_PREFIX))
        .collect();
    println!(
        "PINS-WITHOUT-TURN-PROGRAMS sha256={} lines={}",
        digest_of(&without_turn_programs),
        without_turn_programs.len()
    );
    let fixtures = fixture_placements().expect("the fixtures place");
    for line in &fixtures {
        println!("FIXTURE {line}");
    }
    let undecodable = fixtures
        .iter()
        .filter(|line| line.contains("reason: Undecodable"))
        .count();
    println!(
        "FIXTURES total={} undecodable={undecodable}",
        fixtures.len()
    );
    for root in window_roots() {
        let prefix = format!("{root} ");
        assert!(
            lines.iter().any(|line| line.starts_with(prefix.as_str())),
            "no line for the window root {root}"
        );
    }
}
