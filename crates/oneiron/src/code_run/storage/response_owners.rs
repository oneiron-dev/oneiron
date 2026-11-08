//! Whose reply content a code run's replay row holds (FIX 5718, KEY STORE =
//! A): one row per replay record, a run's or a write receipt's, naming the
//! run whose content it is and the actor its host stamped on the run's
//! writes, taken from the host before the run's first write. An erase of
//! that actor finds every record it owns by these rows, a write receipt
//! included, which names no parent of its own; the row then says Erased
//! for good, so each later write of the record and each read of its
//! results meets the erase.
//!
//! A soft delete of the actor leaves the row Deleted (FIX 6591): its
//! replies read as erased for good, as an erase's do, and the row keeps the
//! actor and the reply bodies the delete released, so that actor's later
//! erase still selects the record and retires those bodies. Neither is a
//! live hold or an authority; that erase leaves the row Erased.

use serde::{Deserialize, Serialize};

use super::super::replay::{CodeRunReplayGeneration, CodeRunReplayRecord};
use super::routing::ExecutorStorage;
use crate::provenance::body::{BodyRef, OwnedBody};
use crate::side_table::{self, Named, SideKey, SideTable, SideTableDbs};
use crate::{EntityId, Result};

/// The rows. Key: id16(the record's run id: a run's own, or a write
/// receipt's).
const OWNERS: SideTable<EntityId, ResponseOwner, Named> =
    SideTable::new(&side_table::CODE_RUN_RESPONSE_OWNER);

/// Whose reply content one replay record holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResponseOwner {
    /// The run whose content it is: the record's own run, or the run a
    /// write receipt's call was made in.
    pub(crate) run: EntityId,
    pub(crate) content: ResponseContent,
}

/// What a record still holds for its run's actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseContent {
    /// Its replies, for `actor`'s run.
    Kept { actor: EntityId },
    /// A soft delete of `actor` took its replies (FIX 6591): every reply it
    /// held reads as erased and no later write or retry brings one back. The
    /// actor stays only so its later erase selects the record, and
    /// `released` names each reply body that delete released, for that erase
    /// to retire.
    Deleted {
        actor: EntityId,
        released: Vec<ReleasedReplyBody>,
    },
    /// Its actor was erased: what the run did stays, every reply it held
    /// reads as erased, and no later write brings one back.
    Erased,
}

/// One reply body occurrence a soft delete released (FIX 6591): the run
/// that held it, the occurrence and the bytes it held, read before the
/// release. It keeps no reply bytes and no preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReleasedReplyBody {
    pub(crate) owner: EntityId,
    pub(crate) occurrence: EntityId,
    pub(crate) body: BodyRef,
}

impl ReleasedReplyBody {
    /// What the descriptor `held` holds, read before its release; `None`
    /// when it holds no bytes.
    pub(crate) fn of(held: &OwnedBody) -> Option<Self> {
        held.state.held().map(|body| Self {
            owner: held.owner,
            occurrence: held.occurrence,
            body: body.clone(),
        })
    }
}

impl ResponseOwner {
    /// The actor whose run the record holds live; `None` once a delete or
    /// an erase took its replies.
    pub(crate) const fn actor(&self) -> Option<EntityId> {
        match self.content {
            ResponseContent::Kept { actor } => Some(actor),
            ResponseContent::Deleted { .. } | ResponseContent::Erased => None,
        }
    }

    /// The actor whose erase selects the record (FIX 6591): the one it
    /// holds live, or the one a soft delete took its replies from. It is no
    /// live hold.
    pub(crate) const fn retirement_actor(&self) -> Option<EntityId> {
        match self.content {
            ResponseContent::Kept { actor } | ResponseContent::Deleted { actor, .. } => Some(actor),
            ResponseContent::Erased => None,
        }
    }

    /// Whether a delete or an erase took the record's replies.
    pub(crate) const fn erased(&self) -> bool {
        !matches!(self.content, ResponseContent::Kept { .. })
    }

    /// The reply bodies a soft delete released (FIX 6591); `None` unless
    /// the row is Deleted.
    pub(crate) fn into_released(self) -> Option<Vec<ReleasedReplyBody>> {
        match self.content {
            ResponseContent::Deleted { released, .. } => Some(released),
            ResponseContent::Kept { .. } | ResponseContent::Erased => None,
        }
    }
}

/// Stamps `record`'s owner, `actor`'s run `run`, in `wtxn`, unless the
/// record has one: the first stamp stands, and a deleted or erased one
/// stays so.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn stamp_response_owner_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: EntityId,
    run: EntityId,
    actor: EntityId,
) -> Result<()> {
    if OWNERS.contains(dbs, wtxn, &record)? {
        return Ok(());
    }
    let owner = ResponseOwner {
        run,
        content: ResponseContent::Kept { actor },
    };
    OWNERS.put(dbs, wtxn, &record, &owner)
}

/// `record`'s owner as `txn` sees it; `None` for a record with none, and for
/// a row that does not decode.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn response_owner_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<ResponseOwner>> {
    OWNERS.get_lenient(dbs, txn, record)
}

/// Every record `actor`'s rows name as its own, with its owner: each it
/// holds live and each a soft delete of it left Deleted (FIX 6591). A row
/// that does not decode names no actor.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owner_rows_of_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(EntityId, ResponseOwner)>> {
    let mut owned = Vec::new();
    for row in OWNERS.iter_raw_from(dbs, txn, &[])? {
        let (key, bytes) = row?;
        let Some(record) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(owner) = OWNERS.decode_value(&bytes)
            && owner.retirement_actor() == Some(*actor)
        {
            owned.push((record, owner));
        }
    }
    Ok(owned)
}

/// Marks `record`'s replies deleted in `wtxn`, as a soft delete of `actor`
/// takes them (FIX 6591): its owner row says Deleted, keeping the run it
/// names (`run` when it had no row) and the actor it names (`actor` when it
/// names none), and adds each of `released` it does not keep yet. An erased
/// row stays erased, and a deleted one keeps every body it named: a
/// repeated delete never overwrites them.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn mark_response_deleted_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: EntityId,
    run: EntityId,
    actor: EntityId,
    released: Vec<ReleasedReplyBody>,
) -> Result<()> {
    let prior = response_owner_in_txn(dbs, wtxn, &record)?;
    let run = prior.as_ref().map_or(run, |owner| owner.run);
    let (actor, mut kept) = match prior.map(|owner| owner.content) {
        Some(ResponseContent::Erased) => return Ok(()),
        Some(ResponseContent::Deleted {
            actor,
            released: kept,
        }) => (actor, kept),
        Some(ResponseContent::Kept { actor }) => (actor, Vec::new()),
        None => (actor, Vec::new()),
    };
    for body in released {
        if !kept.contains(&body) {
            kept.push(body);
        }
    }
    let deleted = ResponseOwner {
        run,
        content: ResponseContent::Deleted {
            actor,
            released: kept,
        },
    };
    OWNERS.put(dbs, wtxn, &record, &deleted)
}

/// Marks `record`'s replies erased in `wtxn`: its owner row says Erased,
/// keeping the run it names, or `run` when it had no row. A soft delete's
/// actor and released bodies go with it (FIX 6591).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn mark_response_erased_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: EntityId,
    run: EntityId,
) -> Result<()> {
    let run = response_owner_in_txn(dbs, wtxn, &record)?.map_or(run, |owner| owner.run);
    let erased = ResponseOwner {
        run,
        content: ResponseContent::Erased,
    };
    OWNERS.put(dbs, wtxn, &record, &erased)
}

/// Stamps run `child`'s owner as the owner of `source`, the run it was
/// forked from, in `wtxn`: the same actor's, deleted for that actor when a
/// soft delete took the source's replies (none of the bodies it released
/// are the child's), or erased when the source's replies are. A source with
/// no owner row stamps none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn inherit_response_owner_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    child: EntityId,
    source: &EntityId,
) -> Result<()> {
    match response_owner_in_txn(dbs, wtxn, source)?.map(|owner| owner.content) {
        Some(ResponseContent::Kept { actor }) => {
            stamp_response_owner_in_txn(dbs, wtxn, child, child, actor)
        }
        Some(ResponseContent::Deleted { actor, .. }) => {
            mark_response_deleted_in_txn(dbs, wtxn, child, child, actor, Vec::new())
        }
        Some(ResponseContent::Erased) => mark_response_erased_in_txn(dbs, wtxn, child, child),
        None => Ok(()),
    }
}

impl ExecutorStorage<'_> {
    /// Whether an erase of run `owner`'s actor took its replies (FIX 5718),
    /// as the run's storage reads it. A session's run reads its owner row
    /// through its room's composed view: an on-record stretch stamps one in
    /// base (FIX 7429), an off-record one in the overlay (FIX 6586). The
    /// vault's erase does not reach an overlay row in its own transaction,
    /// so a session's run also reads as erased once the actor its row names
    /// is gone in the vault (FIX 7366).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn code_run_response_erased(&self, owner: EntityId) -> Result<bool> {
        match self {
            Self::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn()?;
                Ok(response_owner_in_txn(*vault, &rtxn, &owner)?
                    .as_ref()
                    .is_some_and(ResponseOwner::erased))
            }
            Self::Session(binding) => binding.answered(|| {
                binding.session.routed_side_read(|rtxn, dbs| {
                    let Some(owner) = response_owner_in_txn(&dbs, rtxn, &owner)? else {
                        return Ok(false);
                    };
                    let base = super::wait_delivery::canonical_store(&dbs);
                    Ok(owner.erased()
                        || owner.actor().is_some_and(|actor| {
                            super::replay_capsule::actor_gone_in_store(base, rtxn, &actor)
                        }))
                })
            }),
        }
    }

    /// [`Self::put_code_run_replay_record_if_generation_with_heal`], with
    /// the record's owner, `actor`'s run `run`, stamped in the same writer
    /// unless it has one (FIX 5718), before the erase fence reads that owner:
    /// a first save after the actor is gone cannot publish fresh replies.
    /// This is how a run's start and a write's reservation name whose replies
    /// the record will hold. A session's run
    /// stamps it along its route: in base on an on-record stretch (FIX
    /// 7429), in the room's overlay off record (FIX 6586).
    ///
    /// # Errors
    ///
    /// As the put's.
    pub(crate) fn put_owned_code_run_replay_record(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        run: EntityId,
        actor: EntityId,
    ) -> Result<CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_prepared(
                record,
                expected,
                None,
                |wtxn| stamp_response_owner_in_txn(*vault, wtxn, record.run_id, run, actor),
                |_| Ok(()),
            ),
            Self::Session(binding) => {
                binding.put_owned_replay_record_if_generation(record, expected, run, actor)
            }
        }
    }
}
