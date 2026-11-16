//! The names of four crate-private name tables, one line per row, taken from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these enums
//! became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron/src/agent_dispatch/resident/message_class.rs` (`MessageClass`, `SenderKind`)
//! - `crates/oneiron/src/dreamer_consolidation/nightly_links/pairs.rs` (`NightlyLinkVerdict`)
//! - `crates/oneiron/src/secret_custody/reveal/file/repo.rs` (`RepoFileRevealScope`)
//!
//! No test can name these enums or their tables, so `test_doors::enum_name_rows` reads each row
//! where its enum lives: the variant, the name its table writes, what serde writes for the
//! variant and what serde reads from the name. Green on the hand tables and on the adoption (the
//! derive), so no stored or sent name changed (M-1 keep).

#![cfg(oneiron_test_support)]

use oneiron::test_doors::enum_name_rows::{NameRow, PrivateNames};
use serde_json::Value;

/// `rows` are `expected` (variant, name) in order, and serde writes and reads each name.
fn assert_rows(rows: &[NameRow], expected: &[(&str, &str)]) {
    let got: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.variant.as_str(), row.name))
        .collect();
    assert_eq!(got, expected);
    for row in rows {
        assert_eq!(row.written, Value::String(row.name.to_owned()), "{row:?}");
        assert_eq!(row.read, row.variant, "{row:?}");
    }
}

#[test]
fn every_message_class_keeps_its_name() {
    assert_rows(
        &PrivateNames::message_class(),
        &[
            ("Interrupt", "interrupt"),
            ("Steer", "steer"),
            ("FollowUp", "follow_up"),
            ("Digest", "digest"),
        ],
    );
}

#[test]
fn every_sender_kind_keeps_its_name() {
    assert_rows(
        &PrivateNames::sender_kind(),
        &[
            ("VaultPerson", "vault_person"),
            ("Person", "person"),
            ("Agent", "agent"),
            ("Unknown", "unknown"),
        ],
    );
}

#[test]
fn every_nightly_link_verdict_keeps_its_option() {
    assert_rows(
        &PrivateNames::nightly_link_verdict(),
        &[
            ("SameAs", "same_as"),
            ("NoLink", "no_link"),
            ("Unresolved", "unresolved"),
        ],
    );
}

#[test]
fn every_repo_file_reveal_scope_keeps_its_name() {
    assert_rows(
        &PrivateNames::repo_file_reveal_scope(),
        &[
            ("File", "file"),
            ("FileTask", "file_task"),
            ("Repo", "repo"),
            ("RepoTask", "repo_task"),
        ],
    );
}
