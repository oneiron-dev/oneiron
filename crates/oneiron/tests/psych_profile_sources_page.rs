//! The psych profile sources page answers a base agent only under a standing
//! Steward grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test psych_profile_sources_page`.
#![cfg(oneiron_test_support)]

use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::snapshot_read::{PsychProfileSourcesPageRequest, psych_profile_sources_page};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, grant_mark, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// Returns a fixture or assertion error without hiding its source.
type PsychSourcesPageTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Opens the Dreamer fixture vault, reopened owned, with the engine machines
/// provisioned and the embedded owner ensured. No Steward grant row stands.
fn open_psych_sources_vault(dir: &tempfile::TempDir) -> PsychSourcesPageTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// A base agent whose MACHINE is provisioned and that has no standing Steward
/// row is refused: its manifest rows never stand in for the grant on this
/// page. Once its grant stands, the same call is answered.
#[test]
fn a_base_agent_without_a_standing_steward_row_is_refused_until_its_grant_stands()
-> PsychSourcesPageTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_psych_sources_vault(&dir)?;
    let person = EntityId::now();
    seed_named_person(&vault, &person, "owen", vault.now_recorded_at())?;
    let request = PsychProfileSourcesPageRequest {
        person,
        facet: None,
        world: None,
    };
    let actor = dreamer(&vault)?;
    assert!(
        grant_mark(&vault, actor)?.is_none(),
        "no Steward row stands for the Dreamer yet"
    );
    let Err(refused) =
        psych_profile_sources_page(&vault.memory(actor, EdgeActorClass::System), &request)
    else {
        panic!("a base agent with no standing Steward row is refused");
    };
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains("live Steward reader"),
        "the page's own refusal: {}",
        refused.message
    );
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    psych_profile_sources_page(&vault.memory(actor, EdgeActorClass::System), &request)?;
    Ok(())
}
