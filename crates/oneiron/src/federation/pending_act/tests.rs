const WEEK: u64 = 7 * 24 * 60 * 60;
use super::*;
use crate::TimeRange;
use crate::federation::InitialSharedMember;
use crate::store::GateDecisionId;

fn fixture(
    preset: SharedVaultPreset,
) -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    AuthenticatedOwner,
    AuthenticatedOwner,
) {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let mut holders = Vec::new();
    for _ in 0..3 {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
        holders.push(
            vault
                .authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
                .unwrap(),
        );
    }
    let admin = holders.pop().unwrap();
    let other = holders.pop().unwrap();
    let owner = holders.pop().unwrap();
    vault
        .initialize_shared_vault(
            &owner,
            42,
            Some(preset),
            &[
                InitialSharedMember {
                    member_ref: other.actor(),
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: admin.actor(),
                    role: Some(Role::Admin),
                },
            ],
            10,
        )
        .unwrap();
    (dir, vault, owner, other, admin)
}

#[test]
fn preset_seeds_only_four_rows_and_personal_has_none() -> Result<()> {
    for preset in [
        SharedVaultPreset::Family,
        SharedVaultPreset::Team,
        SharedVaultPreset::Org,
        SharedVaultPreset::Community,
    ] {
        let (_dir, vault, owner, _other, _admin) = fixture(preset);
        for name in [
            "delete_vault",
            "erase",
            "transfer_ownership",
            "remove_owner",
        ] {
            assert_eq!(
                vault.shared_act_policy(name)?,
                Some(SharedActPolicy {
                    wait_secs: WEEK,
                    objector_roles: vec![Role::Owner]
                })
            );
            assert!(
                !vault
                    .start_authority_act(&owner, 42, name, vec![], 100)?
                    .completed
            );
        }
        assert_eq!(vault.shared_act_policy("export")?, None);
        assert!(
            vault
                .start_authority_act(&owner, 42, "export", vec![], 100)?
                .completed
        );
    }
    let (_dir, vault, owner, _other, _admin) = fixture(SharedVaultPreset::Personal);
    assert_eq!(vault.shared_act_policy("delete_vault")?, None);
    assert!(
        vault
            .start_authority_act(&owner, 42, "delete_vault", vec![], 100)?
            .completed
    );
    Ok(())
}

#[test]
fn window_notifies_named_holders_refuses_admin_and_holds_until_withdrawn() -> Result<()> {
    let (dir, vault, owner, other, admin) = fixture(SharedVaultPreset::Team);
    let act = vault.start_authority_act(&owner, 42, "delete_vault", b"opaque".to_vec(), 100)?;
    assert_eq!(act.deadline, 100 + WEEK);
    assert_eq!(act.payload, b"opaque");
    assert_eq!(vault.pending_act_started_events(&owner, 42, 101)?.len(), 1);
    assert_eq!(vault.pending_act_started_events(&other, 42, 101)?.len(), 1);
    assert!(
        vault
            .pending_act_started_events(&admin, 42, 101)?
            .is_empty()
    );
    assert!(
        vault
            .change_authority_objection(&admin, &act.id, true, 101)
            .is_err()
    );
    assert!(
        vault
            .change_authority_objection(&other, &act.id, true, 100 + WEEK)
            .is_err()
    );
    assert!(
        !vault
            .advance_authority_act(&act.id, 100 + WEEK - 1)?
            .completed
    );
    let held = vault.change_authority_objection(&other, &act.id, true, 101)?;
    assert!(!held.completed);
    assert!(!vault.advance_authority_act(&act.id, 100 + WEEK)?.completed);
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::test_util::embedding_test_config())?;
    assert!(
        !reopened
            .advance_authority_act(&act.id, 100 + WEEK + 1)?
            .completed
    );
    assert!(
        reopened
            .change_authority_objection(&other, &act.id, false, 100 + WEEK + 2)?
            .completed
    );
    assert!(reopened.pending_authority_act(&act.id)?.unwrap().completed);
    Ok(())
}

#[test]
fn no_objection_completes_and_row_changes_behavior_without_code_change() -> Result<()> {
    let (_dir, vault, owner, other, admin) = fixture(SharedVaultPreset::Org);
    let self_erasure =
        vault.start_authority_act_with_setting(&owner, 42, "erase", vec![], None, 99)?;
    assert!(self_erasure.completed);
    assert_eq!(vault.shared_act_policy("erase")?.unwrap().wait_secs, WEEK);
    let old = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
    assert!(
        !vault
            .advance_authority_act(&old.id, 100 + WEEK - 1)?
            .completed
    );
    assert!(vault.advance_authority_act(&old.id, 100 + WEEK)?.completed);
    assert!(
        vault
            .set_shared_act_policy(&owner, &[], 42, "erase", None, 101)
            .is_err()
    );
    vault.set_shared_act_policy(
        &owner,
        &[&other],
        42,
        "erase",
        Some(SharedActPolicy {
            wait_secs: 5,
            objector_roles: vec![Role::Admin],
        }),
        101,
    )?;
    let updated = vault.start_authority_act(&owner, 42, "erase", vec![], 102)?;
    assert_eq!(updated.deadline, 107);
    assert!(
        vault
            .pending_act_started_events(&admin, 42, 102)?
            .iter()
            .any(|event| event.act_id == updated.id)
    );
    assert!(
        vault
            .change_authority_objection(&other, &updated.id, true, 103)
            .is_err()
    );
    assert!(
        !vault
            .change_authority_objection(&admin, &updated.id, true, 103)?
            .completed
    );
    assert!(!vault.advance_authority_act(&updated.id, 107)?.completed);
    assert!(
        vault
            .change_authority_objection(&admin, &updated.id, false, 108)?
            .completed
    );
    vault.set_shared_act_policy(&owner, &[&other], 42, "erase", None, 109)?;
    assert!(
        vault
            .start_authority_act(&owner, 42, "erase", vec![], 110)?
            .completed
    );
    assert!(
        vault
            .set_shared_act_policy(&admin, &[&owner, &other], 42, "erase", None, 111)
            .is_err()
    );
    Ok(())
}
