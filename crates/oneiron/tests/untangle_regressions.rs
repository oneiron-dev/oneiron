//! Untangle regressions (lead 19:05 9 Nov, TESTS-MUST-RUN): the ruled
//! behaviour tests of X01 (#6878), X02 (#6879), CONSENT-RAMP (#6872) and the
//! repeat revoke (#6874), run from an integration target because the lib test
//! target does not compile. Crate-private items are reached through the
//! hidden doors in `oneiron::test_support::untangle_regressions`; every
//! assertion is here.

use oneiron::consent_graduation::{DemotionReason, RampScope};
use oneiron::test_support::untangle_regressions as doors;
use oneiron::{Result, Vault};

/// The authenticated owner every consent and graduation door needs: the
/// vault's embedded owner.
fn owner(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            actor,
            "principal:owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticate owner")
}

// ─── the repeat revoke (#6874) ──────────────────────────────────────────

/// The eligible graduation scope: a propose-lane surface whose grant bound
/// the plain mint accepts.
fn eligible_scope() -> RampScope {
    RampScope::new("send_email", "client_followup", "agent-a").expect("scope")
}

/// #6874 (lead 10:31 REVOKE-IDEMPOTENT, review round 1 P1): a re-mint of the
/// same bound has the same grant ref, so a repeat revoke answers from the
/// grant's current issuance only. Create G, revoke it (R1), re-mint the same
/// bound and demote it to propose: the owner's revoke then succeeds with
/// `already_revoked`, writes nothing, returns no receipt and names the
/// demotion's receipt as `revoked_by`, never R1. The owner door used to
/// write a second Revoked receipt.
#[test]
fn revoke_consent_grant_repeat_current_issuance() -> Result<()> {
    let (_dir, vault) = doors::open_test_vault_with(doors::embedding_test_config());
    let owner = owner(&vault);
    let scope = eligible_scope();
    let grant_ref = scope.grant_ref()?;
    vault.create_standing_grant(&owner, scope.to_grant_bound()?)?;
    let first = doors::owner_revoke(&vault, &owner, &grant_ref).expect("the first revoke");
    assert!(!first.already_revoked, "{first:?}");
    let r1 = first.receipt.expect("the first revoke's receipt R1");
    // The same bound again: the same grant ref, a new issuance.
    vault.create_standing_grant(&owner, scope.to_grant_bound()?)?;
    vault.demote_scope_to_propose(&owner, &scope, DemotionReason::AgentJudgment)?;
    let demotions = doors::ramp_demotion_receipt_ids(&vault)?;
    let [demotion] = demotions.as_slice() else {
        panic!("one demotion receipt, found {demotions:?}");
    };
    let ledger = doors::gate_decision_ids_for_grant(&vault, &grant_ref)?;
    let receipts = doors::gate_receipt_ids(&vault)?;

    let answer = doors::owner_revoke(&vault, &owner, &grant_ref).expect("a repeat revoke succeeds");
    assert_eq!(
        doors::gate_decision_ids_for_grant(&vault, &grant_ref)?,
        ledger,
        "a repeat revoke writes no new receipt"
    );
    assert_eq!(
        doors::gate_receipt_ids(&vault)?,
        receipts,
        "a repeat revoke writes nothing"
    );
    assert!(answer.already_revoked, "{answer:?}");
    assert_eq!(
        answer.receipt, None,
        "the current issuance has no consent revoke receipt; R1 ({r1}) was the older issuance's"
    );
    assert_eq!(
        answer.revoked_by.as_deref(),
        Some(demotion.as_str()),
        "the demotion revoked the current issuance, not R1 ({r1})"
    );
    Ok(())
}

/// #6874 (lead 10:31; Engine 12:32/12:33 REVOKE-NO-RECEIPT-SUCCEEDS): a grant
/// revoked by a path that writes no consent receipt (here a graduation
/// demotion) and then revoked by the owner: success, `already_revoked`, no
/// receipt, and nothing written. The owner door used to write a fresh
/// Revoked receipt there.
#[test]
fn revoke_consent_grant_repeat_receiptless() -> Result<()> {
    let (_dir, vault) = doors::open_test_vault_with(doors::embedding_test_config());
    let owner = owner(&vault);
    let scope = eligible_scope();
    let grant_ref = scope.grant_ref()?;
    vault.create_standing_grant(&owner, scope.to_grant_bound()?)?;
    vault.demote_scope_to_propose(&owner, &scope, DemotionReason::AgentJudgment)?;
    let demotions = doors::ramp_demotion_receipt_ids(&vault)?;
    let [demotion] = demotions.as_slice() else {
        panic!("one demotion receipt, found {demotions:?}");
    };
    let ledger = doors::gate_decision_ids_for_grant(&vault, &grant_ref)?;
    let receipts = doors::gate_receipt_ids(&vault)?;

    let answer = doors::owner_revoke(&vault, &owner, &grant_ref)
        .expect("the owner's revoke of a grant revoked without a consent receipt succeeds");
    assert_eq!(
        doors::gate_decision_ids_for_grant(&vault, &grant_ref)?,
        ledger,
        "a repeat revoke writes no new receipt"
    );
    assert_eq!(
        doors::gate_receipt_ids(&vault)?,
        receipts,
        "a repeat revoke writes nothing"
    );
    assert!(answer.already_revoked, "{answer:?}");
    assert_eq!(answer.receipt, None, "no consent receipt revoked it");
    assert_eq!(answer.revoked_by.as_deref(), Some(demotion.as_str()));
    Ok(())
}

/// #6874: a revoke of a grant that does not exist stays NotFound, as before.
/// The control: it passes on the base by design.
#[test]
fn revoke_consent_grant_repeat_missing_grant() -> Result<()> {
    let (_dir, vault) = doors::open_test_vault_with(doors::embedding_test_config());
    let owner = owner(&vault);
    let grant_ref = eligible_scope().grant_ref()?;
    assert_eq!(
        doors::owner_revoke(&vault, &owner, &grant_ref),
        Err("ConsentGrantNotFound".to_owned())
    );
    Ok(())
}
