//! `ScopeKind` is a Register (`#[derive(Register)]`, ratchet metric 8): the names it stores and
//! sends are the spellings of the hand table it replaced, and each name reads back to its row.

use oneiron_contracts::register::Register;
use oneiron_setting_contract::{LEARNED_SCOPES, ScopeKind};

/// The hand-written `ScopeKind::as_str` table on main 62d2d72f, row for row.
const HAND_TABLE: [(ScopeKind, &str); 10] = [
    (ScopeKind::Vault, "vault"),
    (ScopeKind::World, "world"),
    (ScopeKind::Project, "project"),
    (ScopeKind::SubProject, "sub_project"),
    (ScopeKind::Thread, "thread"),
    (ScopeKind::Goal, "goal"),
    (ScopeKind::TaskType, "task_type"),
    (ScopeKind::Agent, "agent"),
    (ScopeKind::Person, "person"),
    (ScopeKind::Repo, "repo"),
];

#[test]
fn every_scope_kind_keeps_its_hand_table_name() {
    assert_eq!(ScopeKind::NAME, "setting.scope_kind");
    assert_eq!(ScopeKind::ROWS.len(), HAND_TABLE.len());
    for (row, (kind, name)) in ScopeKind::ROWS.iter().zip(HAND_TABLE) {
        assert_eq!(*row, kind);
        assert_eq!(kind.as_str(), name);
        assert_eq!(kind.name(), name);
        assert_eq!(ScopeKind::named(name), Some(kind));
    }
    assert_eq!(ScopeKind::named("sub-project"), None);
}

#[test]
fn every_kind_is_on_the_read_chain_and_learned_scopes_are_kinds() {
    for kind in ScopeKind::ROWS {
        assert!(ScopeKind::NARROWEST_FIRST.contains(kind));
    }
    assert_eq!(
        LEARNED_SCOPES,
        [
            ScopeKind::Goal,
            ScopeKind::Project,
            ScopeKind::TaskType,
            ScopeKind::Vault
        ]
    );
}
