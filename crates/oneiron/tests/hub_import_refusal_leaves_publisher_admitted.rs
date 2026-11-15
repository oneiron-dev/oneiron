//! HUB-IMPORT-REFUSAL-LEAVES-PUBLISHER-ADMITTED: a refused hub skill import
//! withdraws the publisher it just admitted.
//!
//! `Vault::import_skill_from_hub_ref` admits the named publisher in a writer
//! of its own before the fetch, the fit and the import's commit writer. A
//! refusal after that used to leave the publisher's offer-only Grant
//! (`skill.offer` on `hub:<id>`) standing, with no receipt tying it to the
//! refused import. The import now withdraws a publisher it just admitted
//! when it refuses, and keeps one that already stood.
//!
//! Fixture: a vault with its owner, and a local folder hub (an existing
//! absolute directory, pinned-commit policy). A tag pin on that hub refuses
//! in the fetch, after the admission, without touching the network or git.
//! The grant ref is computed from the publisher identity and hub id, as the
//! admission door does, without admitting.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hub_import_refusal_leaves_publisher_admitted`.

use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::skill_hub::{HubPin, HubSyncPolicy, SkillHubKind, SkillHubRecord, SkillHubTrustTier};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn at(now: u64) -> TimeRange {
    TimeRange { start: now, end: now }
}

/// The ref of the one Grant that admits `identity` to offer from `hub`, as
/// `Vault::admit_skill_publisher` mints it.
fn publisher_grant_ref(identity: &str, hub: EntityId) -> TestResult<String> {
    Ok(GrantBound::action(
        ActorBound::new(identity)?.with_actor_class("foreign-publisher")?,
        ActionClass::new("skill.offer")?,
        ActionEnvelope::new([format!("hub:{}", hub.to_hex())])?,
    )?
    .digest()
    .to_hex())
}

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    hub: EntityId,
    _vault_dir: tempfile::TempDir,
    _hub_dir: tempfile::TempDir,
}

fn fixture() -> TestResult<Fixture> {
    let vault_dir = tempfile::tempdir()?;
    let hub_dir = tempfile::tempdir()?;
    let vault = Vault::open(vault_dir.path(), VaultConfig::default())?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:fixture-owner",
        true,
        GateDecisionId::now(),
    )?;
    let hub = EntityId::now();
    let record = SkillHubRecord::new(
        SkillHubKind::LocalDir,
        hub_dir.path().to_str().expect("hub path is UTF-8"),
        SkillHubTrustTier::Community,
        HubSyncPolicy::PinnedCommit,
    )?;
    vault.configure_skill_hub(&owner, &hub, &record, at(10), 10)?;
    Ok(Fixture {
        vault,
        owner,
        hub,
        _vault_dir: vault_dir,
        _hub_dir: hub_dir,
    })
}

#[test]
fn refused_import_withdraws_publisher_it_just_admitted() -> TestResult {
    let fixture = fixture()?;
    let identity = "publisher:refused-import";
    let grant_ref = publisher_grant_ref(identity, fixture.hub)?;
    assert!(
        fixture.vault.consent_grant(&grant_ref)?.is_none(),
        "no grant before the refused import"
    );
    let refused = fixture.vault.import_skill_from_hub_ref(
        &fixture.owner,
        fixture.hub,
        "skills/example",
        HubPin::Tag("v1".to_owned()),
        identity,
    );
    assert!(
        refused.is_err(),
        "a tag pin on a local folder hub refuses"
    );
    let grant = fixture.vault.consent_grant(&grant_ref)?;
    assert!(
        grant.as_ref().is_none_or(|row| !row.is_active()),
        "a refused import leaves no standing publisher grant, got {grant:?}"
    );
    Ok(())
}

#[test]
fn refused_import_keeps_publisher_that_already_stood() -> TestResult {
    let fixture = fixture()?;
    let identity = "publisher:already-stood";
    fixture
        .vault
        .admit_skill_publisher(&fixture.owner, identity, fixture.hub)?;
    let grant_ref = publisher_grant_ref(identity, fixture.hub)?;
    assert!(
        fixture
            .vault
            .consent_grant(&grant_ref)?
            .is_some_and(|row| row.is_active()),
        "the publisher stands before the refused import"
    );
    let refused = fixture.vault.import_skill_from_hub_ref(
        &fixture.owner,
        fixture.hub,
        "skills/example",
        HubPin::Tag("v1".to_owned()),
        identity,
    );
    assert!(
        refused.is_err(),
        "a tag pin on a local folder hub refuses"
    );
    assert!(
        fixture
            .vault
            .consent_grant(&grant_ref)?
            .is_some_and(|row| row.is_active()),
        "a refused import keeps a publisher that already stood"
    );
    Ok(())
}
