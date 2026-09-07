//! Source-scan guard and fixtures for the never-automatic-hard-delete rule.

pub(super) fn destructive_door(code: &str) -> Option<&str> {
    // Exempt only the complete identifier of the presence-only marker read.
    // Keep rejecting other hard-delete references, including suffixed doors
    // and calls separated from their opening parenthesis by whitespace.
    code.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .find(|identifier| {
            identifier.contains("local_hard_delete")
                && *identifier != "local_hard_delete_marker_exists_in_txn"
        })
        .or_else(|| {
            [
                "DeleteReason::UserDelete",
                "DeleteReason::UserHardDelete",
                "DeleteReason::GdprDelete",
                "DeleteReason::PolicyDelete",
                "hard_erase",
                "HardEraseSweep",
                "delete_entity(",
                "erase_entity",
                "apply_replayed_tombstone",
                "soft_erase_active_store_in_txn",
                "sweep_queue",
            ]
            .into_iter()
            .find(|forbidden| code.contains(*forbidden))
        })
}

#[test]
fn marker_presence_read_is_not_a_destructive_door() {
    assert_eq!(
        destructive_door("self.local_hard_delete_marker_exists_in_txn(wtxn, entity)?"),
        None
    );
}

#[test]
fn destructive_calls_and_references_stay_forbidden_beside_a_marker_read() {
    let marker_read = "self.local_hard_delete_marker_exists_in_txn(wtxn, entity)?;";
    for code in [
        "self.local_hard_delete(entity)?;",
        "self.local_hard_delete (entity)?;",
        "self.local_hard_delete\n(entity)?;",
        "Vault::local_hard_delete(self, entity)?;",
        "let delete = Vault::local_hard_delete;",
        "self.local_hard_delete_in_txn(wtxn, entity)?;",
        "self.local_hard_delete_marker_exists_in_txn_unchecked(wtxn, entity)?;",
        "self.delete_entity(entity)?;",
        "self.erase_entity(entity)?;",
        "self.hard_erase(entity)?;",
        "HardEraseSweep::default();",
        "self.apply_replayed_tombstone(entity, value)?;",
        "self.soft_erase_active_store_in_txn(wtxn, entity)?;",
        "self.sweep_queue();",
        "DeleteReason::UserDelete",
        "DeleteReason::UserHardDelete",
        "DeleteReason::GdprDelete",
        "DeleteReason::PolicyDelete",
    ] {
        assert!(destructive_door(code).is_some(), "missed `{code}`");
        let with_marker_read = format!("{marker_read} {code}");
        assert!(
            destructive_door(&with_marker_read).is_some(),
            "marker read hid `{code}`"
        );
    }
}
