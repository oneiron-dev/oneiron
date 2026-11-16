//! Untangle regressions (lead 19:05 9 Nov, TESTS-MUST-RUN): the ruled
//! behaviour tests of X01 (#6878), CONSENT-RAMP (#6872) and the repeat revoke
//! (#6874), run from an integration target because the lib test target does
//! not compile. X02 (#6879) left with the native strength archive (untangle
//! 6.9c): a Dreamer archive is a derive batch, judged by the derive verdict.
//! Crate-private items are reached through the hidden doors in
//! `oneiron::test_doors::untangle_regressions`, built only under
//! `--cfg oneiron_test_support`; every assertion is here. Without that cfg
//! this target is empty, so a plain `cargo test` still builds.
#![cfg(oneiron_test_support)]

use oneiron::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, DemotionReason, RampScope};
use oneiron::identity_topology::ProposalOutcome;
use oneiron::test_doors::untangle_regressions as doors;
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

// ─── X01 (#6878) ────────────────────────────────────────────────────────

/// X01 (untangle slice 6.1): the Dreamer's side doors (gap scan, owner
/// intent, retrieval shadow) returned a TURN's own words before asking the
/// Dreamer's gate, so a TURN the owner's policy keeps from the Dreamer
/// reached its text. They read it as the Dreamer now, and the writer's
/// re-check asks the gate for such a TURN too.
#[test]
fn a_turn_the_dreamer_may_not_read_gives_its_side_doors_no_words() -> Result<()> {
    let (_dir, vault) = doors::open_dreamer_vault();
    let at = vault.now_recorded_at();
    let session = doors::seed_session(&vault, 28, at);
    let said = "My door code is 4410.";
    doors::withhold_dreamer_read(&vault)?;
    let turn = doors::seed_turn(&vault, &session, "user", said, at);
    assert_eq!(doors::side_door_turn_text(&vault, &turn)?.text(), None);
    assert!(doors::turn_text_for_shadow(&vault, &turn).is_err());

    doors::install_shipped_policy(&vault)?;
    let record = doors::side_door_turn_text(&vault, &turn)?;
    assert_eq!(record.text(), Some(said));
    doors::withhold_dreamer_read(&vault)?;
    assert!(
        record.recheck_as_dreamer(&vault, &turn).is_err(),
        "the writer refuses words the Dreamer may no longer read"
    );
    Ok(())
}

// ─── CONSENT-RAMP (#6872) ───────────────────────────────────────────────

/// CONSENT-RAMP: a scope whose graduation bound names the catastrophe floor
/// is never offered, since the mint must refuse it (no tap can graduate it).
#[test]
fn catastrophe_class_scopes_are_never_offered_graduation() {
    let (_dir, vault) = doors::open_test_vault_with(doors::embedding_test_config());
    let owner = owner(&vault);
    // A scope whose graduation bound names the catastrophe floor. Shape-valid,
    // graduatable by op-kind rule (not identity-topology), measurable like any scope.
    let scope = RampScope::new("mass_secret_export", "vault", "agent-a").expect("scope");
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&owner, &scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }
    // The offer is a promise the tap can keep: a floor class must never surface.
    assert!(
        vault.graduation_offers().expect("offers").is_empty(),
        "a catastrophe-floor class must never surface a graduation offer: no tap can mint it"
    );
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
