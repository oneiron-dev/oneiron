use super::*;

/// An unrooted vault's owner deleting their own PERSON is proved with that PERSON taken as live: `OwnerRow::DeletingItself` asks the owner census with the owner's shelled PERSON taken as live and passes, while `OwnerRow::Live` reads the shell as it stands and is refused with `OWNER_BINDING_REQUIRED`; red at `610f54397651` because the unrooted embedded-owner branch ignored its `row` and always read the PERSON as it stands, so a shell refused `DeletingItself` too.
#[test]
fn an_unrooted_owner_deleting_their_own_person_is_proved_with_it_taken_as_live() {
    let (_dir, vault) = open_vault();
    let owner = put_owner(&vault);
    vault
        .delete_entity_with_reason(&owner, crate::DeleteReason::UserDelete)
        .expect("soft-delete the owner's PERSON to a shell");
    let txn = vault.store.env.read_txn().expect("read txn");
    verify_owner_binding_in_txn(&vault, &txn, owner, OwnerRow::DeletingItself)
        .expect("deleting its own PERSON proves with it taken as live");
    let err = verify_owner_binding_in_txn(&vault, &txn, owner, OwnerRow::Live)
        .expect_err("a live read of a shelled owner is refused");
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
}
