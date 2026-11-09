//! Untangle regressions (lead 19:05 9 Nov, TESTS-MUST-RUN): the ruled
//! behaviour tests of X01 (#6878), X02 (#6879), CONSENT-RAMP (#6872) and the
//! repeat revoke (#6874), run from an integration target because the lib test
//! target does not compile. Crate-private items are reached through the
//! hidden doors in `oneiron::test_support::untangle_regressions`; every
//! assertion is here.

use std::sync::Arc;

use oneiron::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use oneiron::test_support::untangle_regressions as doors;
use oneiron::test_support::untangle_regressions::DreamerLandingRow;
use oneiron::{EntityId, Result, Vault, VaultConfig};

// ─── X02 (#6879) ────────────────────────────────────────────────────────

/// X02 (untangle slice 6.2): the strength archive takes back what the Dreamer
/// landed, so it is judged in its own write by the rows that let it land: the
/// Dreamer's Auto actor ceiling and its `Generated` permit. With either row
/// removed nothing is archived and no receipt is written; with the shipped
/// rows the claim is archived and its receipt names the rows and the policy
/// frontier it was judged under. Before, the archive judged nothing and
/// minted its own approved receipt.
#[test]
fn the_strength_archive_is_judged_by_the_dreamers_landing_rows() -> Result<()> {
    for removed in [
        None,
        Some(DreamerLandingRow::ActorCeiling),
        Some(DreamerLandingRow::GeneratedPermit),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        doors::authorize_test_inference(&vault)?;
        let node_id = doors::load_or_mint_client_id(&vault)?;
        let conversation = doors::seed_session(&vault, 0x6e, 1);
        let turn = doors::seed_turn(&vault, &conversation, "user", "call me Owen", 10);
        let subject = EntityId::now();
        doors::seed_person(&vault, &subject, 1)?;
        doors::enqueue_micro(&vault, "run-strength", 20)?;
        let report = doors::micro_wake_pass_with_extraction(&vault, &subject, &turn, node_id, 21)?;
        assert_eq!(report.completed, 1, "{report:?}");
        let claims: Vec<EntityId> = vault
            .claims_for_subject(&subject)?
            .into_iter()
            .filter(|id| {
                vault
                    .get_claim(id)
                    .ok()
                    .flatten()
                    .is_some_and(|body| body.predicate == "profile.name")
            })
            .collect();
        let [claim] = claims.as_slice() else {
            panic!("one landed claim, found {}", claims.len());
        };
        let claim = *claim;
        let attempt = doors::micro_attempt(&vault)?.expect("the micro attempt");

        // Every landed claim is quiet and weak under this strength policy.
        vault.set_consolidation_strength_policy(&ConsolidationStrengthPolicy {
            archive_below: 1.0,
            quiet_ms: 1,
        })?;
        if let Some(row) = removed {
            doors::seeded_without_dreamer_landing_row(&vault, row)?;
            let reach = vault.dreamer_weave_reach()?;
            assert!(
                reach.reads && !reach.lands_auto,
                "{row:?}: only the landing is narrowed"
            );
        }
        let now_ms = (vault.now_recorded_at() + 30 * 86_400).saturating_mul(1_000);
        let archived = doors::archive_quiet_claims(&vault, attempt, now_ms)?;
        let receipts: Vec<_> = doors::gate_decisions_for_claim(&vault, &claim)?
            .into_iter()
            .filter(|record| record.content_kind == "dreamer_strength_archive")
            .collect();
        match removed {
            Some(row) => {
                assert_eq!(archived, 0, "{row:?}: nothing is archived");
                assert!(receipts.is_empty(), "{row:?}: no receipt is written");
                assert!(
                    vault.consolidation_strength_snapshots(&claim)?.is_empty(),
                    "{row:?}"
                );
            }
            None => {
                assert_eq!(archived, 1, "the shipped rows let the archive land");
                let [receipt] = receipts.as_slice() else {
                    panic!("one archive receipt, found {}", receipts.len());
                };
                assert_ne!(receipt.read_frontier_hash, [0; 32]);
                assert_eq!(
                    receipt.grant_ref.as_deref(),
                    Some(doors::dreamer_landing_rows_ref())
                );
            }
        }
    }
    Ok(())
}
