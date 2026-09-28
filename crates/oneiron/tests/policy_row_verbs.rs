//! Public-door policy-row proof independent of unrelated lib-test compilation.
use oneiron::policy_model::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn owner_edits_are_immediate_receipted_and_reversible() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let add = PolicyRowChange::Add {
        row_ref: "mine".into(),
        text: "Let me know".into(),
        action: PolicyRowAction::Warn,
        scope: PolicyRowScope::Vault,
    };
    let r1 = vault.change_policy_row(&auth, add, 10)?;
    for (at, action) in [
        (11, PolicyRowAction::Block),
        (12, PolicyRowAction::Warn),
        (13, PolicyRowAction::Block),
    ] {
        vault.change_policy_row(
            &auth,
            PolicyRowChange::Edit {
                row_ref: "mine".into(),
                text: "Let me know".into(),
                action,
                scope: PolicyRowScope::Vault,
            },
            at,
        )?;
    }
    assert_eq!(vault.policy_row_change_log()?.len(), 4);
    assert_eq!(vault.policy_changed_events()?.len(), 4);
    assert_eq!(
        vault.policy_row_change_log()?[1]
            .previous_receipt_id
            .as_deref(),
        Some(r1.receipt_id.as_str())
    );
    vault.change_policy_row(
        &auth,
        PolicyRowChange::Remove {
            row_ref: "mine".into(),
            scope: PolicyRowScope::Vault,
        },
        14,
    )?;
    assert_eq!(vault.policy_row_change_log()?.len(), 5);
    Ok(())
}

#[test]
fn non_owner_cannot_land_a_row_by_presenting_an_authenticated_person() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let actor = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    assert!(
        vault
            .change_policy_row(
                &actor,
                PolicyRowChange::Add {
                    row_ref: "mine".into(),
                    text: "No".into(),
                    action: PolicyRowAction::Block,
                    scope: PolicyRowScope::Vault
                },
                10
            )
            .is_err()
    );
    assert!(vault.policy_row_change_log()?.is_empty());
    Ok(())
}
