//! Census case and regression for the worlds an agent may read.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::pipeline::{
    ActiveWorldSelection, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, WorldAuthoritySet, world_access_claim_body,
};
use crate::ports::ManualClock;
use crate::recovery::checkpoint::RestoreReason;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use crate::test_util::entity;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance, write_envelope_evidence};
use crate::{EntityId, Result, TimeRange, Vault, VaultConfig};

const ROW: &str = "world selection authority";

/// The instant the regression's clock stands at.
const NOW: u64 = 1_000;

const AT: TimeRange = TimeRange { start: 1, end: 1 };

fn config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// A vault holding an agent and two worlds, on `config`.
fn open_vault(config: VaultConfig) -> Result<(tempfile::TempDir, Vault, EntityId, [EntityId; 2])> {
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let agent = entity(0xB1);
    vault.put_entity(&agent, ENTITY_TYPE_PERSON, AT, 1, b"agent")?;
    let worlds = [entity(0xB2), entity(0xB3)];
    for world in worlds {
        vault.put_entity(&world, ENTITY_TYPE_WORLD, AT, 1, b"world")?;
    }
    Ok((dir, vault, agent, worlds))
}

/// The owner's grant `id` of `worlds` to `agent`, in force from `from`
/// until `to`.
fn grant(
    vault: &Vault,
    id: EntityId,
    agent: EntityId,
    worlds: &[EntityId],
    (from, to): (Option<u64>, Option<u64>),
) -> Result<()> {
    let body = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        agent,
        &WorldAuthoritySet::new(false, worlds.iter().copied())?,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        from,
        to,
    )?;
    vault.put_claim(&id, &body, AT, 1)
}

/// The default `id` of `worlds` that `agent` wrote itself, learned at
/// `learned_at`.
fn own_default(
    vault: &Vault,
    id: EntityId,
    agent: EntityId,
    worlds: &[EntityId],
    learned_at: u64,
) -> Result<()> {
    let mut body = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
        agent,
        &WorldAuthoritySet::new(false, worlds.iter().copied())?,
        ClaimSource::Inferred,
        ClaimApprovalStatus::Auto,
        None,
        None,
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(agent, EdgeActorClass::Agent),
        ClaimSource::Inferred,
        WriteProvenance::new(rmpv::Value::from("world-default-test"))?,
        ClaimApprovalStatus::Auto,
    );
    body.evidence = Some(write_envelope_evidence(&envelope, None));
    let at = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    vault.put_claim(&id, &body, at, learned_at)
}

const ALWAYS: (Option<u64>, Option<u64>) = (None, None);

/// An agent reads the newest in-force default it wrote itself, inside every
/// owner grant about it. A narrower default learned again since the backup,
/// its body unchanged, is one a restore would take back to the wider one,
/// widening the read; the wider one learned again narrows nothing. (This case
/// once narrowed with a grant's `claim_of` edge put back since the backup. The
/// fold now reads the grant rows (engine-prs-06), so an edge narrows nothing,
/// and a grant written since the backup is a world-access row, which the
/// authority-row guard refuses before this decision is asked.)
pub(super) fn world_selection_authority() -> Result<Case> {
    let (dir, vault, agent, [w1, w2]) = open_vault(config())?;
    let (wide, narrower, wider) = (entity(0xB4), entity(0xB7), entity(0xB8));
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    own_default(&vault, narrower, agent, &[w1], 10)?;
    own_default(&vault, wider, agent, &[w1, w2], 20)?;
    Case::after_backup(
        ROW,
        (dir, vault),
        move |vault| own_default(vault, wider, agent, &[w1, w2], 30),
        move |vault| own_default(vault, narrower, agent, &[w1], 40),
    )
}

/// A backup of a vault, an unguarded restore of it made after a write since
/// the backup, and what a guarded restore of it answered.
struct Restored {
    unguarded: Vault,
    guarded: Result<()>,
    _backups: tempfile::TempDir,
}

/// Backs `vault` up, makes `since` on it, and restores the backup beside it.
fn restore_after(vault: &Vault, since: impl FnOnce(&Vault) -> Result<()>) -> Result<Restored> {
    let backups = crate::test_support::restore_tempdir();
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    since(vault)?;
    let (unguarded, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("unguarded"),
        vault.config.clone(),
        RestoreReason::Restore,
        NOW,
    )?;
    let guarded = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("guarded"),
        vault.config.clone(),
        vault,
        NOW,
    )
    .map(drop);
    Ok(Restored {
        unguarded,
        guarded,
        _backups: backups,
    })
}

/// Whether the world fold of `vault` admits `agent`'s explicit selection of
/// `world` at `NOW`.
fn admits(vault: &Vault, agent: EntityId, world: EntityId) -> Result<bool> {
    let selection = ActiveWorldSelection {
        agent_ref: agent,
        selected: Some(WorldAuthoritySet::new(false, [world])?),
    };
    let txn = vault.store.env.read_txn()?;
    Ok(crate::pipeline::resolve_world_authority(&vault.store, &txn, &selection, NOW).is_ok())
}

/// Whether a turn of `agent` that names no world reads `world` at `NOW`.
fn admits_by_default(vault: &Vault, agent: EntityId, world: EntityId) -> Result<bool> {
    let selection = ActiveWorldSelection {
        agent_ref: agent,
        selected: None,
    };
    let txn = vault.store.env.read_txn()?;
    let resolved = crate::pipeline::resolve_world_authority(&vault.store, &txn, &selection, NOW)?;
    Ok(resolved.default_subset.worlds().contains(&world))
}

/// Panics unless `guarded` refused, naming `what`.
fn assert_refused(guarded: Result<()>, sequence: &str, what: &str) {
    match guarded {
        Ok(()) => panic!("{sequence}: a restore that widens an agent's worlds went ahead"),
        Err(error) => assert!(
            error.to_string().contains(what),
            "{sequence}: refused for another reason: {error}"
        ),
    }
}

/// A restore never widens the worlds an agent may read, at any instant its
/// grants and defaults decide. A narrower grant written since the backup is
/// one an unguarded restore takes off. It is a world-access row, so the
/// authority-row guard refuses the restore, whether the grant is in force
/// now, only after now, or outlasting a narrower mask. A narrower default
/// learned again since the backup leaves every row as it was; only the world
/// decision sees that it is the one in force, and its guard refuses the
/// restore. (The grant cases once put a grant's `claim_of` edge back since
/// the backup, which no row comparison saw. The fold now reads the grant rows
/// (engine-prs-06), so an edge narrows nothing.)
#[test]
fn a_restore_does_not_widen_the_worlds_an_agent_may_read() -> Result<()> {
    let clock = ManualClock::new(NOW);
    let mut config = config();
    config.store_clock = clock.bundle();
    let (wide, narrow, mask) = (entity(0xB4), entity(0xB5), entity(0xB6));
    let grant_rows = "world access";

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    let restored = restore_after(&vault, |vault| grant(vault, narrow, agent, &[w1], ALWAYS))?;
    assert!(
        !admits(&vault, agent, w2)?,
        "the narrower grant keeps the live vault off the second world"
    );
    assert!(
        admits(&restored.unguarded, agent, w2)?,
        "an unguarded restore takes the narrower grant off"
    );
    assert_refused(
        restored.guarded,
        "a narrower grant since the backup",
        grant_rows,
    );

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    let restored = restore_after(&vault, |vault| {
        grant(vault, narrow, agent, &[w1], (Some(NOW + 100), None))
    })?;
    assert_refused(
        restored.guarded,
        "a narrower grant in force after now",
        grant_rows,
    );

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    grant(&vault, mask, agent, &[w1], (None, Some(NOW + 200)))?;
    let restored = restore_after(&vault, |vault| grant(vault, narrow, agent, &[w1], ALWAYS))?;
    assert_refused(
        restored.guarded,
        "a narrower grant outlasting a mask",
        grant_rows,
    );

    let (_dir, vault, agent, [w1, w2]) = open_vault(config)?;
    let (narrower, wider) = (entity(0xB7), entity(0xB8));
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    own_default(&vault, narrower, agent, &[w1], 10)?;
    own_default(&vault, wider, agent, &[w1, w2], 20)?;
    let restored = restore_after(&vault, |vault| {
        own_default(vault, narrower, agent, &[w1], 30)
    })?;
    assert!(
        !admits_by_default(&vault, agent, w2)?,
        "the narrower default keeps the live vault's turns off the second world"
    );
    assert!(
        admits_by_default(&restored.unguarded, agent, w2)?,
        "an unguarded restore takes the wider default back"
    );
    assert_refused(restored.guarded, "a narrower default learned again", ROW);
    Ok(())
}
