//! Each origin mirror's sync strategy (FIX 6866; owner ruling 10-21 06:3x).
//!
//! A mirror carries one strategy, never a public or private flag:
//! - [`OriginMirrorSyncStrategy::AskMe`]: nothing goes out until the owner or
//!   a Grant holder approves an exact ref and commit, pushed once
//!   (`origin::publish`). The scheduler never pushes such a mirror, and a
//!   push-now refuses with [`PublishRequestRequired`].
//! - [`OriginMirrorSyncStrategy::Schedule`]: the scheduled push of every
//!   published ref at the mirror's cadence, and push-now, exactly as before.
//!
//! A mirror with no strategy set is [`ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY`]:
//! a row stored without one decodes as it. Exact publish requests do not
//! read the strategy, so changing it leaves every pending or approved
//! request as it stands.
//!
//! Only the live owner changes a strategy: through mirror setup, or through
//! [`Vault::set_served_origin_mirror_strategy_in_txn`], which changes the
//! strategy and its revision and nothing else. A change of the mirror's URL,
//! user, custody record or served name moves its target generation instead,
//! which every exact request is bound to.

use serde::{Deserialize, Serialize};

use super::mirror::{OriginMirrorTarget, TARGETS};
use crate::Vault;
use crate::error::{Error, Result};

/// How one mirror sends what this vault publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorSyncStrategy {
    /// Nothing goes out until an exact publish request is approved; each
    /// request pushes one commit to one branch, once.
    AskMe,
    /// Every published ref (imported refs aside) is pushed at the mirror's
    /// cadence, forced, with deletions, as the scheduled mirror always did.
    Schedule,
}

/// The strategy of a mirror that names none (CALLS "FIX 6866 sync
/// strategy"): ask first.
pub const ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY: OriginMirrorSyncStrategy =
    OriginMirrorSyncStrategy::AskMe;

impl Default for OriginMirrorSyncStrategy {
    fn default() -> Self {
        ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY
    }
}

impl OriginMirrorSyncStrategy {
    /// Whether the scheduler pushes the mirror when its cadence comes due.
    #[must_use]
    pub const fn runs_on_interval(self) -> bool {
        matches!(self, Self::Schedule)
    }

    /// Whether a push-now sends the whole published set.
    #[must_use]
    pub const fn pushes_whole_refs(self) -> bool {
        matches!(self, Self::Schedule)
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AskMe => "ask_me",
            Self::Schedule => "schedule",
        }
    }
}

/// The stable code a push-now on an ask-me mirror refuses with.
pub const ORIGIN_MIRROR_PUBLISH_REQUEST_REQUIRED: &str = "publish_request_required";

/// A whole-ref push asked of a mirror whose strategy asks first. It names
/// its bound: an exact publish request, or the owner's switch to schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequestRequired {
    /// The served repository.
    pub repo: String,
    /// The mirror's strategy.
    pub strategy: OriginMirrorSyncStrategy,
}

impl From<PublishRequestRequired> for Error {
    fn from(refusal: PublishRequestRequired) -> Self {
        Error::Refused(format!(
            "{ORIGIN_MIRROR_PUBLISH_REQUEST_REQUIRED}: the mirror of {} is {}, so nothing goes \
             out whole; ask for an exact ref and commit with vault.code.origin.publish.request, \
             or have the owner set its strategy to schedule",
            refusal.repo,
            refusal.strategy.as_str()
        ))
    }
}

/// The strategy, its revision and the target generation a setup writes.
pub(super) struct ConfiguredStrategy {
    pub(super) strategy: OriginMirrorSyncStrategy,
    pub(super) revision: u64,
    pub(super) generation: u64,
}

/// What a setup of `repo` at `url`, `user` and `secret_ref` writes beside
/// the row it replaces. A named strategy wins. With none, the same URL keeps
/// its strategy, as it keeps its push history; a new mirror or a new URL
/// starts at the default. The revision moves only when the strategy does.
/// The generation moves when the URL, user, custody record or served name
/// does, never below the vault clock, so a mirror cleared and set again
/// starts past every generation an earlier request could name.
pub(super) fn configured_strategy(
    previous: Option<&OriginMirrorTarget>,
    repo: &str,
    destination: (&str, &str, &str),
    asked: Option<OriginMirrorSyncStrategy>,
    now: u64,
) -> ConfiguredStrategy {
    let (url, user, secret_ref) = destination;
    let Some(previous) = previous else {
        return ConfiguredStrategy {
            strategy: asked.unwrap_or_default(),
            revision: 1,
            generation: now.max(1),
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
        previous.target_generation.saturating_add(1).max(now)
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
        }
        Ok(row)
    }
}
