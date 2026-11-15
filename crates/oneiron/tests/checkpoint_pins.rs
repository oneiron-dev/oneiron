//! The nine checkpoint getters' pins (UC-10 PR 3): one fixed seed, one
//! printed table. Run at the commit before the getters move onto the shared
//! descriptor and at the commit after; both runs print the same table.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::checkpoint_pins as doors;
use oneiron::{Vault, VaultConfig};
use sha2::{Digest, Sha256};

/// The nine getters, in pin order.
const GETTERS: [&str; 9] = [
    "bm25",
    "batch",
    "provenance_body",
    "codebase",
    "outbound_ledger",
    "blocked_reports",
    "embed",
    "workflow_tool",
    "source_audience",
];

#[test]
fn checkpoint_pins_table_of_the_nine_getters() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let source = Vault::open(directory.path().join("source"), VaultConfig::device())
        .expect("open the source vault");
    doors::seed(&source).expect("seed every getter's rows");
    let target = Vault::open(directory.path().join("target"), VaultConfig::device())
        .expect("open the target vault");
    let lines = doors::pins(&source, &target).expect("pin the nine getters");
    for line in &lines {
        println!("PIN {line}");
    }
    let joined = lines.join("\n");
    let digest = format!("{:x}", Sha256::digest(joined.as_bytes()));
    println!("PINS sha256={digest} lines={n}", n = lines.len());
    for getter in GETTERS {
        let owner_prefix = format!("OWNER {getter} ");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(owner_prefix.as_str())),
            "no owner line for {getter}"
        );
        let raw_prefix = format!("RAW {getter} ");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(raw_prefix.as_str())),
            "no raw row for {getter} in the target"
        );
    }
}
