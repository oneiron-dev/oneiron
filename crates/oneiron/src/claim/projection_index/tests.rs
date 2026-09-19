use super::*;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimSubject, TimeRange};
use rmpv::Value;

#[test]
fn predicate_projection_tracks_overwrites_rollback_and_deletion() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let id = entity(0x75);
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(entity(0x76)),
        Value::from("Ada"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let at = TimeRange { start: 1, end: 1 };
    vault.put_claim(&id, &body, at, 1)?;
    let lookup = |predicate: &str| -> Result<Vec<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        claim_ids_for_predicate_in_txn(&vault.store, &txn, predicate)
    };
    assert_eq!(lookup("profile.name")?, vec![id]);
    body.predicate = "profile.alias".into();
    {
        let mut txn = vault.store.env.write_txn()?;
        maintain_claim_projection_index(&vault.store, &mut txn, id, &body)?;
        // Drop aborts both reverse and forward edits.
    }
    assert_eq!(lookup("profile.name")?, vec![id]);
    assert!(lookup("profile.alias")?.is_empty());
    vault.put_claim(&id, &body, at, 1)?;
    assert!(lookup("profile.name")?.is_empty());
    assert_eq!(lookup("profile.alias")?, vec![id]);
    vault.batch().delete(&id).commit()?;
    assert!(lookup("profile.alias")?.is_empty());
    Ok(())
}
