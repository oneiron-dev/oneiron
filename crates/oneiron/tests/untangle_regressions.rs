//! Untangle regressions (lead 19:05 9 Nov, TESTS-MUST-RUN): the ruled
//! behaviour tests of X01 (#6878), X02 (#6879), CONSENT-RAMP (#6872) and the
//! repeat revoke (#6874), run from an integration target because the lib test
//! target does not compile. Crate-private items are reached through the
//! hidden doors in `oneiron::test_doors::untangle_regressions`, built only
//! under `--cfg oneiron_test_support`; every assertion is here. Without that
//! cfg this target is empty, so a plain `cargo test` still builds.
#![cfg(oneiron_test_support)]

use oneiron::Result;
use oneiron::test_doors::untangle_regressions as doors;

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
