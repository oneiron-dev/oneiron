//! The atomic multi-database write-batch builder and its two terminals.

mod apply;
mod claims;
mod commit;
mod edges;
mod ops;
mod preflight;
mod puts;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::off_record::PromoteReplayGrant;

use super::BaseWriteOrigin;
use super::vad_postcommit;

pub(crate) use self::ops::BatchOp;
use self::puts::CommitCheck;

/// Builder for atomic multi-database write batches.
///
/// One builder, two terminals. [`commit()`](Self::commit) opens, owns and
/// commits its own write transaction ([`Vault::batch`]);
/// [`apply()`](Self::apply) stages the same ops into a caller's transaction
/// without committing ([`Vault::batch_in`], typically inside
/// [`Vault::with_write_txn`]).
#[must_use = "BatchBuilder performs no writes until `.commit()` or `.apply()` is called"]
pub struct BatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
    /// Checks only the committing terminal runs, before it opens its
    /// transaction and ahead of `validation_error`, in call order. The
    /// caller-transaction terminal leaves them to the in-transaction gates
    /// every put already passes (see [`CommitCheck`]).
    commit_checks: Vec<CommitCheck>,
    /// Why this batch may touch the ids it touches (ARCH-0052 D2).
    origin: BaseWriteOrigin<'a>,
    /// The FACET every NOTE and ASSET this batch births is stamped with.
    /// `None` stamps the vault default.
    birth_mask: Option<EntityId>,
    #[cfg(feature = "sync")]
    import_tier: crate::sync::client::ImportTier,
    /// Op indexes of the replicated puts a federated import tier queued; their
    /// bodies pass federation admission inside the transaction.
    #[cfg(feature = "sync")]
    federated_puts: Vec<usize>,
}

impl<'a> BatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self::with_origin(vault, Vec::new(), BaseWriteOrigin::Ordinary)
    }

    /// The off-record promotion entry (ARCH-0052 D4, ONE-1730).
    ///
    /// Takes an already-built replay program rather than growing verb methods:
    /// the ops come from the typed journal verbatim (only their edge arm is
    /// re-shaped to carry the journaled `created_at`), so re-deriving them
    /// through builder verbs would be a chance to drift from what the room
    /// actually staged.
    ///
    /// This is the ONLY constructor that carries a non-`Ordinary` origin, and
    /// it demands the capability itself: a [`PromoteReplayGrant`] can only be
    /// minted inside `off_record::promote`, out of the closure that promote
    /// transaction is replaying. Crate code without a grant cannot reach this
    /// constructor at all, and a grant cannot answer for any other session's
    /// overlay ids.
    pub(crate) fn promotion_replay(
        vault: &'a Vault,
        ops: Vec<BatchOp>,
        grant: &'a PromoteReplayGrant,
    ) -> Self {
        Self::with_origin(vault, ops, BaseWriteOrigin::PromoteReplay(grant))
    }

    fn with_origin(vault: &'a Vault, ops: Vec<BatchOp>, origin: BaseWriteOrigin<'a>) -> Self {
        Self {
            vault,
            ops,
            validation_error: None,
            commit_checks: Vec::new(),
            origin,
            birth_mask: None,
            #[cfg(feature = "sync")]
            import_tier: crate::sync::client::ImportTier::OwnDevice,
            #[cfg(feature = "sync")]
            federated_puts: Vec::new(),
        }
    }

    /// Sets the active mask every NOTE and ASSET this batch births is
    /// stamped with. It must be a stored FACET row.
    pub(crate) fn mask(mut self, mask: Option<EntityId>) -> Self {
        self.birth_mask = mask;
        self
    }

    /// Sets the import tier the replicated puts queued after it arrive under.
    /// A federated tier sends each one through federation admission inside
    /// the transaction.
    #[cfg(feature = "sync")]
    pub(crate) fn with_import_tier(mut self, tier: crate::sync::client::ImportTier) -> Self {
        self.import_tier = tier;
        self
    }
}
