//! The golden day (`oneiron_testkit::golden_day`): one scripted day on a
//! fresh vault, and the normalised dump of what it leaves in the receipt
//! streams and the authority audit.
//!
//! The dump is a regression signal, not a merge block (the lead, 12 Nov
//! 06:55). A PR that changes behaviour on purpose regenerates the golden
//! file: run this file with `ONEIRON_TESTKIT_GOLDEN=write`, read the diff,
//! and commit it with the PR, saying why it changed.
//!
//! Each day prints every model request on a `## SEEN` line. When a day does
//! not normalise or leaves its script, it also prints its raw trace on one
//! `## GOLDEN-DAY RAW` line and each unclassified key on a
//! `## GOLDEN-DAY UNKNOWN` line; a golden mismatch prints the new golden form
//! between `## GOLDEN-DAY BEGIN` and `## GOLDEN-DAY END`.

use std::fs;
use std::path::PathBuf;

use oneiron_testkit::dreamer::print_seen;
use oneiron_testkit::golden_day::{self, GOLDEN_FILE, GoldenDayRun, MEASURED, Normaliser, render};
use serde_json::{Value, json};

/// The env var that makes the golden test write the golden file.
const WRITE_GOLDEN: &str = "ONEIRON_TESTKIT_GOLDEN";

/// How many differing lines a golden mismatch prints before the new form.
const DIFF_LINES: usize = 60;

/// Runs the day once on a fresh vault: the run and its golden form.
fn run_day(label: &str) -> (GoldenDayRun, Value) {
    let backend = golden_day::backend();
    let run = golden_day::run(&backend).unwrap_or_else(|error| panic!("{error}"));
    print_seen(&backend.seen());
    let normalised = run.normalise();
    let script = backend.check();
    if normalised.is_err() || script.is_err() {
        println!("## GOLDEN-DAY RAW {label} {}", run.raw());
    }
    if let Err(error) = &normalised {
        for line in error.to_string().lines() {
            println!("## GOLDEN-DAY UNKNOWN {label} {line}");
        }
    }
    // An unscripted model call fails here first, with its prompt and digest.
    backend.finish();
    let normalised = normalised.unwrap_or_else(|error| panic!("{error}"));
    (run, normalised)
}

/// The lines of `new` that differ from `old`, side by side, at most
/// [`DIFF_LINES`] of them.
fn differing_lines(old: &str, new: &str) -> Vec<String> {
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    (0..old.len().max(new.len()))
        .filter(|&index| old.get(index) != new.get(index))
        .take(DIFF_LINES)
        .map(|index| {
            format!(
                "line {}: - {} | + {}",
                index + 1,
                old.get(index).copied().unwrap_or("<none>"),
                new.get(index).copied().unwrap_or("<none>")
            )
        })
        .collect()
}

/// Whether `answer` names `claim` anywhere in it.
fn names(answer: &Value, claim: &str) -> bool {
    answer.to_string().contains(claim)
}

#[test]
fn two_fresh_golden_days_leave_the_same_normalised_trace() {
    let (_, first) = run_day("first");
    let (_, second) = run_day("second");
    let (first, second) = (render(&first), render(&second));
    let differing = differing_lines(&first, &second);
    for line in &differing {
        println!("## GOLDEN-DAY DIFF {line}");
    }
    assert!(
        differing.is_empty(),
        "two fresh runs of the same day normalised differently in {} line(s); the first is above",
        differing.len()
    );
}

#[test]
fn the_golden_day_lands_its_claims_ends_the_agents_reads_at_the_revoke_and_matches_its_golden_file()
{
    let (run, normalised) = run_day("golden");
    let text = render(&normalised);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_FILE);
    if std::env::var(WRITE_GOLDEN).as_deref() == Ok("write") {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).expect("create the golden dir");
        }
        fs::write(&path, &text).expect("write the golden file");
        println!("## GOLDEN-DAY WROTE {}", path.display());
    }
    let golden = fs::read_to_string(&path).unwrap_or_default();
    let matches = golden == text;
    if !matches {
        for line in differing_lines(&golden, &text) {
            println!("## GOLDEN-DAY DIFF {line}");
        }
        println!("## GOLDEN-DAY BEGIN");
        print!("{text}");
        println!("## GOLDEN-DAY END");
    }

    // What the day must do, whatever the golden file says.
    let pass = run
        .answer("dreamer-turn-wake")
        .unwrap_or_else(|| panic!("{:?}", run.refusal("dreamer-turn-wake")));
    assert_eq!(pass["stop"], "QueueEmpty", "{pass:#}");
    let landed = run
        .bindings()
        .iter()
        .find(|(_, name)| name == "claim:remembered")
        .map(|(raw, _)| raw.clone())
        .unwrap_or_else(|| {
            panic!(
                "vault.remember named no claim: {:?}",
                run.answer("remember")
            )
        });
    assert!(
        pass["attempts"].as_array().is_some_and(|attempts| attempts
            .iter()
            .any(|attempt| attempt["landed"]
                .as_array()
                .is_some_and(|landed| !landed.is_empty()))),
        "the turn wake's scripted extraction landed no claim: {pass:#}"
    );
    let before = run
        .answer("agent-claims")
        .unwrap_or_else(|| panic!("{:?}", run.refusal("agent-claims")));
    assert!(
        names(before, &landed),
        "the granted agent does not list the remembered claim: {before:#}"
    );
    let revoked = run
        .answer("grant-revoke")
        .unwrap_or_else(|| panic!("{:?}", run.refusal("grant-revoke")));
    assert_eq!(revoked["changed"], true, "{revoked:#}");
    let again = run
        .answer("grant-revoke-again")
        .unwrap_or_else(|| panic!("{:?}", run.refusal("grant-revoke-again")));
    assert_eq!(
        again["changed"], false,
        "a repeat revoke changed something: {again:#}"
    );
    if let Some(after) = run.answer("agent-after-revoke-claims") {
        assert!(
            !names(after, &landed),
            "the agent still lists the remembered claim after the revoke: {after:#}"
        );
    }
    for stream in ["gate_ledger", "family"] {
        assert!(
            !run.stream_rows(stream).is_empty(),
            "the {stream} stream is empty"
        );
    }

    assert!(
        matches,
        "the golden day's trace differs from {}: the new form is printed above. If the PR \
         changes this behaviour on purpose, rerun with {WRITE_GOLDEN}=write and commit the file.",
        path.display()
    );
}

#[test]
fn a_trace_key_the_manifest_does_not_classify_fails_the_normalisation_with_its_path() {
    let trace = json!({"steps": [{"step": "witness", "golden_day_unclassified": 1}]});

    let error = Normaliser::new()
        .normalise(&trace)
        .expect_err("an unclassified key must fail the normalisation");

    assert_eq!(error.unknown.len(), 1, "{error}");
    assert_eq!(error.unknown[0].key, "golden_day_unclassified");
    assert_eq!(
        error.unknown[0].paths,
        ["$.steps[0].golden_day_unclassified"]
    );
    assert!(
        error.to_string().contains("golden_day_unclassified"),
        "{error}"
    );
}

#[test]
fn run_minted_refs_are_named_in_first_seen_order_bound_refs_by_name_and_real_time_masked() {
    let owner = "0123456789abcdef0123456789abcdef";
    let trace = json!({"steps": [
        {"receipt_ref": "r-1", "claim_ref": "c-1", "actor_ref": owner,
         "refused": format!("the owner {owner} refused claim c-1")},
        {"receipt_ref": "r-2", "claim_ref": "c-1", "wall_ms": 17},
    ]});
    let mut normaliser = Normaliser::new();
    normaliser.bind(owner, "owner");

    let normalised = normaliser
        .normalise(&trace)
        .unwrap_or_else(|error| panic!("{error}"));

    let steps = &normalised["steps"];
    assert_eq!(steps[0]["receipt_ref"], "receipt#1");
    assert_eq!(steps[1]["receipt_ref"], "receipt#2");
    assert_eq!(steps[0]["claim_ref"], "claim#1");
    assert_eq!(steps[1]["claim_ref"], "claim#1", "equal refs share a name");
    assert_eq!(steps[0]["actor_ref"], "owner");
    // A bound ref of 16 bytes or more is named inside other strings too; a
    // short run-minted one is named only where the manifest classifies it.
    assert_eq!(steps[0]["refused"], "the owner owner refused claim c-1");
    assert_eq!(steps[1]["wall_ms"], MEASURED);
}
