//! Untangle regressions (lead 19:05 9 Nov, TESTS-MUST-RUN): the ruled
//! behaviour tests of X01 (#6878), X02 (#6879), CONSENT-RAMP (#6872) and the
//! repeat revoke (#6874), run from an integration target because the lib test
//! target does not compile. Crate-private items are reached through the
//! hidden doors in `oneiron::test_doors::untangle_regressions`, built only
//! under `--cfg oneiron_test_support`; every assertion is here. Without that
//! cfg this target is empty, so a plain `cargo test` still builds.
#![cfg(oneiron_test_support)]

use oneiron::Vault;
use oneiron::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope};
use oneiron::identity_topology::ProposalOutcome;
use oneiron::test_doors::untangle_regressions as doors;

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
