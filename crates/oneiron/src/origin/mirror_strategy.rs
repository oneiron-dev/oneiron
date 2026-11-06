//! Core half of `origin::mirror_strategy`: its store-layer items live in `oneiron_store::origin::mirror_strategy` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::mirror_strategy::*;

use super::mirror::{OriginMirrorTarget, TARGETS};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// What a setup of `repo` at `url`, `user` and `secret_ref` writes beside
/// the row it replaces. A named strategy wins. With none, the same URL keeps
/// its strategy, as it keeps its push history; a new mirror or a new URL
/// starts at the default. The revision moves only when the strategy does.
/// The generation is a fresh id for a new mirror and whenever the URL,
/// user, custody record or served name moves, so a mirror cleared and set
/// again never takes a generation an earlier request could name.
pub(super) fn configured_strategy(
    previous: Option<&OriginMirrorTarget>,
    repo: &str,
    destination: (&str, &str, &str),
    asked: Option<OriginMirrorSyncStrategy>,
) -> ConfiguredStrategy {
    let (url, user, secret_ref) = destination;
    let Some(previous) = previous else {
        return ConfiguredStrategy {
            strategy: asked.unwrap_or_default(),
            revision: 1,
            generation: Some(EntityId::now()),
        };
    };
    let strategy = match asked {
        Some(strategy) => strategy,
        None if previous.url == url => previous.sync_strategy,
        None => ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY,
    };
    let revision = if strategy == previous.sync_strategy {
        previous.strategy_revision
    } else {
        previous.strategy_revision.saturating_add(1)
    };
    let moved = previous.repo != repo
        || previous.url != url
        || previous.user != user
        || previous.secret_ref != secret_ref;
    let generation = if moved {
        Some(EntityId::now())
    } else {
        previous.target_generation
    };
    ConfiguredStrategy {
        strategy,
        revision,
        generation,
    }
}

impl Vault {
    /// Sets the sync strategy of a served repository's mirror, as the owner
    /// asked. It changes the strategy and its revision only: never the URL,
    /// the custody record, the cadence or what was pushed.
    pub fn set_served_origin_mirror_strategy(
        &self,
        repo_name: &str,
        strategy: OriginMirrorSyncStrategy,
    ) -> Result<OriginMirrorTarget> {
        let mut txn = self.store.env.write_txn()?;
        let row = self.set_served_origin_mirror_strategy_in_txn(&mut txn, repo_name, strategy)?;
        txn.commit()?;
        self.wake_origin_mirrors();
        Ok(row)
    }

    /// [`Self::set_served_origin_mirror_strategy`] as the caller's owner
    /// proof, revalidated in the transaction that changes it (FIX 8214).
    pub fn set_served_origin_mirror_strategy_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
        strategy: OriginMirrorSyncStrategy,
    ) -> Result<OriginMirrorTarget> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let row = self.set_served_origin_mirror_strategy_in_txn(&mut txn, repo_name, strategy)?;
        txn.commit()?;
        self.wake_origin_mirrors();
        Ok(row)
    }

    /// The strategy setter, in the transaction its owner proof is checked in.
    /// `EntityNotFound` when the repository has no mirror.
    pub(crate) fn set_served_origin_mirror_strategy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_name: &str,
        strategy: OriginMirrorSyncStrategy,
    ) -> Result<OriginMirrorTarget> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let mut row = TARGETS
            .get(&self.store, txn, &repo_id)?
            .ok_or(Error::EntityNotFound)?;
        if row.sync_strategy != strategy {
            row.sync_strategy = strategy;
            row.strategy_revision = row.strategy_revision.saturating_add(1);
            TARGETS.put(&self.store, txn, &repo_id, &row)?;
            self.pause_mirror_work_on_change_in_txn(txn, repo_id, false);
        }
        Ok(row)
    }
}
