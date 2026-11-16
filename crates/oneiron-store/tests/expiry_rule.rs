//! UC-12 PR 3: the one expiry instant, `oneiron_store::expiry`. A row or lease that lives until
//! `expires_at` is dead from that second on, an entry due at `due_at` is due from that second
//! on, and each deadline helper keeps its overflow rule.
//!
//! `cargo test --locked -p oneiron-store --test expiry_rule` (default features: a store-alone
//! `--all-features` build fails on main, FIX STORE-ALONE-NEEDS-BASE-SYNC).

use oneiron_store::expiry::{expires_at_checked, expires_at_saturating, is_due, is_expired};

const AT: u64 = 1_800_000_000;

#[test]
fn a_row_is_dead_from_its_expires_at_second_on() {
    assert!(!is_expired(AT - 1, AT), "live one second before");
    assert!(is_expired(AT, AT), "dead at its expires_at second");
    assert!(is_expired(AT + 1, AT), "dead after it");
    assert!(is_expired(0, 0), "a row that expires at 0 is dead at 0");
    assert!(!is_expired(u64::MAX - 1, u64::MAX));
    assert!(is_expired(u64::MAX, u64::MAX));
}

#[test]
fn an_entry_is_due_from_its_due_second_on() {
    assert!(!is_due(AT - 1, AT), "not due one second before");
    assert!(is_due(AT, AT), "due at its second");
    assert!(is_due(AT + 1, AT), "due after it");
}

#[test]
fn a_due_entry_and_an_expired_row_share_the_instant() {
    for now in [AT - 1, AT, AT + 1] {
        assert_eq!(is_due(now, AT), is_expired(now, AT), "at {now}");
    }
}

#[test]
fn each_deadline_helper_keeps_its_overflow_rule() {
    assert_eq!(expires_at_checked(AT, 600), Some(AT + 600));
    assert_eq!(expires_at_saturating(AT, 600), AT + 600);
    assert_eq!(expires_at_checked(u64::MAX - 600, 600), Some(u64::MAX));
    assert_eq!(
        expires_at_checked(u64::MAX - 599, 600),
        None,
        "checked refuses"
    );
    assert_eq!(
        expires_at_saturating(u64::MAX - 599, 600),
        u64::MAX,
        "saturating holds at u64::MAX"
    );
    assert!(
        !is_expired(u64::MAX - 1, expires_at_saturating(u64::MAX - 599, 600)),
        "a held deadline is still a deadline"
    );
}
