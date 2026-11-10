//! The test lint finds sleeps, wall-clock reads, network, fixed ports and
//! real models in test code, and nothing in comments, non-test code or lines
//! allowed with a reason. Sample sources that would trip the workspace lint
//! themselves are assembled with `concat!`.

use oneiron_testkit::lint::{Baseline, LintReport, Rule, scan_source, whole_file_is_test};

fn rules(path: &str, source: &str) -> Vec<(usize, Rule)> {
    scan_source(path, source)
        .into_iter()
        .map(|finding| (finding.line, finding.rule))
        .collect()
}

const TEST_FILE: &str = "crates/oneiron/tests/sample.rs";

#[test]
fn sleeps_and_wall_clock_reads_in_test_code_are_found() {
    let source = "fn a() {\n    std::thread::sleep(d);\n    tokio::time::sleep(d).await;\n    let t = std::time::SystemTime::now();\n    let i = Instant::now();\n}\n";
    assert_eq!(
        rules(TEST_FILE, source),
        [
            (2, Rule::Sleep),
            (3, Rule::Sleep),
            (4, Rule::WallClock),
            (5, Rule::WallClock)
        ]
    );
}

#[test]
fn comments_strings_methods_and_definitions_are_not_sleeps() {
    let source = "// thread::sleep(d) in a comment\n/* Instant::now() */\nlet s = \"thread::sleep(d)\";\nclock.sleep(d);\nfn sleep(d: u64) {}\n";
    assert!(rules(TEST_FILE, source).is_empty());
}

#[test]
fn urls_to_real_hosts_and_fixed_ports_are_found_but_loopback_and_reserved_names_are_not() {
    let source = concat!(
        "let a = \"",
        "https://",
        "github.com/x\";\n",
        "let b = \"http://127.0.0.1:0/\";\n",
        "let c = \"https://",
        "sub.example.com/a\";\n",
        "let d = \"http://",
        "api.test/x\";\n",
        "let e = \"127.0.0.1",
        ":8080\";\n",
        "let f = format!(\"http://{addr}/v1\");\n",
    );
    assert_eq!(
        rules(TEST_FILE, source),
        [(1, Rule::Network), (5, Rule::FixedPort)]
    );
}

#[test]
fn real_model_keys_hosts_and_files_are_found() {
    let source = concat!(
        "env::var(\"",
        "OPENAI",
        "_API_KEY\");\n",
        "let u = \"https://",
        "api.openai.com",
        "/v1\";\n",
        "let m = \"model",
        ".gg",
        "uf\";\n",
    );
    assert_eq!(
        rules(TEST_FILE, source),
        [
            (1, Rule::RealModel),
            (2, Rule::RealModel),
            (3, Rule::RealModel)
        ]
    );
}

#[test]
fn only_test_code_is_read_in_a_source_file() {
    let source = "fn shipped() { std::thread::sleep(d); }\n#[cfg(test)]\nmod tests {\n    fn t() { std::thread::sleep(d); }\n}\n#[cfg(not(test))]\nfn other() { std::thread::sleep(d); }\n#[cfg(feature = \"test-hooks\")]\nfn hook() { std::thread::sleep(d); }\n";
    assert_eq!(
        rules("crates/oneiron/src/lib.rs", source),
        [(4, Rule::Sleep)]
    );
    assert!(whole_file_is_test("crates/oneiron/src/gate/tests.rs"));
    assert!(whole_file_is_test(
        "crates/oneiron/src/gate/policy_tests.rs"
    ));
    assert!(whole_file_is_test("crates/oneiron-server/tests/it/main.rs"));
    assert!(!whole_file_is_test("crates/oneiron/src/gate/mod.rs"));
}

#[test]
fn a_file_gated_as_test_and_a_bodiless_test_item_are_read_too() {
    let gated = "#![cfg(test)]\nfn t() { std::thread::sleep(d); }\n";
    assert_eq!(
        rules("crates/oneiron-seal/src/native/verify/review.rs", gated),
        [(2, Rule::Sleep)]
    );
    let item = concat!(
        "#[cfg(test)]\nconst URL: &str = \"https://",
        "github.com/\";\nconst SHIPPED: &str = \"https://",
        "github.com/\";\n"
    );
    assert_eq!(
        rules("crates/oneiron/src/lib.rs", item),
        [(2, Rule::Network)]
    );
}

#[test]
fn an_allow_with_a_reason_covers_its_line_or_the_next_and_one_without_covers_nothing() {
    let source = concat!(
        "let a = Instant::now(); // testkit-lint: allow(wall-clock) a nightly budget test's bound\n",
        "// testkit-lint: allow(sleep) the sandbox's own timer under test\n",
        "std::thread::sleep(d);\n",
        "let b = Instant::now(); // testkit-lint: allow(wall-clock)\n",
    );
    assert_eq!(rules(TEST_FILE, source), [(4, Rule::WallClock)]);
}

#[test]
fn a_rule_fails_only_when_its_total_rises_above_the_baseline() {
    let before = scan_source(TEST_FILE, "fn a() { std::thread::sleep(d); }\n");
    let baseline =
        Baseline::parse(&Baseline::of(&before).render()).expect("the rendered baseline parses");
    assert_eq!(baseline.total(Rule::Sleep), 1);

    // The same sleep, moved to another file: no total rises.
    let moved = scan_source(
        "crates/oneiron/tests/moved.rs",
        "fn a() { std::thread::sleep(d); }\n",
    );
    assert!(LintReport::compare(&moved, &baseline).passed());

    // A new sleep: the total rises and the report names the file.
    let grown = scan_source(
        TEST_FILE,
        "fn a() { std::thread::sleep(d); }\nfn b() { std::thread::sleep(d); }\n",
    );
    let report = LintReport::compare(&grown, &baseline);
    assert!(!report.passed());
    assert!(report.to_string().contains("sample.rs:2: sleep"));

    // One fewer: it passes and says the baseline can fall.
    let report = LintReport::compare(&[], &baseline);
    assert!(report.passed());
    assert_eq!(report.fallen, [(Rule::Sleep, 1, 0)]);
}
