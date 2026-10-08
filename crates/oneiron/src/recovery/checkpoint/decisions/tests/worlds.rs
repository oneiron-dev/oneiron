//! Census case and regression for the worlds an agent may read.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::{EdgeActorClass, EdgeKind};
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

/// An agent reads only the worlds every owner grant its `claim_of` edges
/// reach allows. A narrower grant whose edge was put back since the backup,
/// its body unchanged, is one a restore would take off, widening the read
/// (Astra R4-2); one that repeats a grant the backup already folds narrows
/// nothing.
pub(super) fn world_selection_authority() -> Result<Case> {
    let (dir, vault, agent, [w1, w2]) = open_vault(config())?;
    let (wide, narrow, repeat) = (entity(0xB4), entity(0xB5), entity(0xB6));
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    grant(&vault, narrow, agent, &[w1], ALWAYS)?;
    grant(&vault, repeat, agent, &[w1, w2], ALWAYS)?;
    for detached in [narrow, repeat] {
        vault.delete_edge(&detached, EdgeKind::ClaimOf, &agent)?;
    }
    Case::after_backup(
        ROW,
        (dir, vault),
        move |vault| vault.put_edge(&repeat, EdgeKind::ClaimOf, &agent, 1.0),
        move |vault| vault.put_edge(&narrow, EdgeKind::ClaimOf, &agent, 1.0),
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
    let backups = tempfile::tempdir()?;
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

/// Panics unless `guarded` refused, naming the world row.
fn assert_refused(guarded: Result<()>, sequence: &str) {
    match guarded {
        Ok(()) => panic!("{sequence}: a restore that widens an agent's worlds went ahead"),
        Err(error) => assert!(
            error.to_string().contains(ROW),
            "{sequence}: refused for another reason: {error}"
        ),
    }
}

/// A restore never widens the worlds an agent may read, at any instant its
/// grants and defaults decide. A narrower grant whose edge was put back
/// since the backup is one an unguarded restore takes off (Astra R4-2), and
/// the guard refuses it; so it does when that grant comes into force only
/// after now, when it outlasts another grant as narrow that goes out of
/// force after now, and when a narrower default learned again since the
/// backup is the one in force.
#[test]
fn a_restore_does_not_widen_the_worlds_an_agent_may_read() -> Result<()> {
    let clock = ManualClock::new(NOW);
    let mut config = config();
    config.store_clock = clock.bundle();
    let (wide, narrow, mask) = (entity(0xB4), entity(0xB5), entity(0xB6));

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    grant(&vault, narrow, agent, &[w1], ALWAYS)?;
    vault.delete_edge(&narrow, EdgeKind::ClaimOf, &agent)?;
    let restored = restore_after(&vault, |vault| {
        vault.put_edge(&narrow, EdgeKind::ClaimOf, &agent, 1.0)
    })?;
    assert!(
        !admits(&vault, agent, w2)?,
        "the reattached grant keeps the live vault off the second world"
    );
    assert!(
        admits(&restored.unguarded, agent, w2)?,
        "an unguarded restore lifts the reattached grant"
    );
    assert_refused(restored.guarded, "a reattached narrower grant");

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    grant(&vault, narrow, agent, &[w1], (Some(NOW + 100), None))?;
    vault.delete_edge(&narrow, EdgeKind::ClaimOf, &agent)?;
    let restored = restore_after(&vault, |vault| {
        vault.put_edge(&narrow, EdgeKind::ClaimOf, &agent, 1.0)
    })?;
    assert_refused(restored.guarded, "a narrower grant in force after now");

    let (_dir, vault, agent, [w1, w2]) = open_vault(config.clone())?;
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    grant(&vault, mask, agent, &[w1], (None, Some(NOW + 200)))?;
    grant(&vault, narrow, agent, &[w1], ALWAYS)?;
    vault.delete_edge(&narrow, EdgeKind::ClaimOf, &agent)?;
    let restored = restore_after(&vault, |vault| {
        vault.put_edge(&narrow, EdgeKind::ClaimOf, &agent, 1.0)
    })?;
    assert_refused(restored.guarded, "a narrower grant outlasting a mask");

    let (_dir, vault, agent, [w1, w2]) = open_vault(config)?;
    let (narrower, wider) = (entity(0xB7), entity(0xB8));
    grant(&vault, wide, agent, &[w1, w2], ALWAYS)?;
    own_default(&vault, narrower, agent, &[w1], 10)?;
    own_default(&vault, wider, agent, &[w1, w2], 20)?;
    let restored = restore_after(&vault, |vault| {
        own_default(vault, narrower, agent, &[w1], 30)
    })?;
    assert_refused(restored.guarded, "a narrower default learned again");
    Ok(())
}
