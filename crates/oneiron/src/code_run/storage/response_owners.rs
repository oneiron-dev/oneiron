//! Whose reply content a code run's replay row holds (FIX 5718, KEY STORE =
//! A): one row per replay record, a run's or a write receipt's, naming the
//! run whose content it is and the actor its host stamped on the run's
//! writes, taken from the host before the run's first write. An erase of
//! that actor finds every record it owns by these rows, a write receipt
//! included, which names no parent of its own; the row then says Erased
//! for good, so each later write of the record and each read of its
//! results meets the erase.

use serde::{Deserialize, Serialize};

use super::super::replay::{CodeRunReplayGeneration, CodeRunReplayRecord};
use super::routing::ExecutorStorage;
use crate::side_table::{self, Named, SideKey, SideTable, SideTableDbs};
use crate::{EntityId, Result};

/// The rows. Key: id16(the record's run id: a run's own, or a write
/// receipt's).
const OWNERS: SideTable<EntityId, ResponseOwner, Named> =
    SideTable::new(&side_table::CODE_RUN_RESPONSE_OWNER);

/// Whose reply content one replay record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResponseOwner {
    /// The run whose content it is: the record's own run, or the run a
    /// write receipt's call was made in.
    pub(crate) run: EntityId,
    pub(crate) content: ResponseContent,
}

/// What a record still holds for its run's actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseContent {
    /// Its replies, for `actor`'s run.
    Kept { actor: EntityId },
    /// Its actor was erased: what the run did stays, every reply it held
    /// reads as erased, and no later write brings one back.
    Erased,
}

impl ResponseOwner {
    /// The actor whose run the record holds; `None` once it is erased.
    pub(crate) const fn actor(self) -> Option<EntityId> {
        match self.content {
            ResponseContent::Kept { actor } => Some(actor),
            ResponseContent::Erased => None,
        }
    }

    /// Whether an erase took the record's replies.
    pub(crate) const fn erased(self) -> bool {
        matches!(self.content, ResponseContent::Erased)
    }
}

/// Stamps `record`'s owner, `actor`'s run `run`, in `wtxn`, unless the
/// record has one: the first stamp stands, and an erased one stays erased.
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

/// Every record `actor`'s rows name as its own, with its owner. A row that
/// does not decode names no actor.
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
            && owner.actor() == Some(*actor)
        {
            owned.push((record, owner));
        }
    }
    Ok(owned)
}

/// Marks `record`'s replies erased in `wtxn`: its owner row says Erased,
/// keeping the run it names, or `run` when it had no row.
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
/// forked from, in `wtxn`: the same actor's, or erased when the source's
/// replies are. A source with no owner row stamps none.
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
        Some(ResponseContent::Erased) => mark_response_erased_in_txn(dbs, wtxn, child, child),
        None => Ok(()),
    }
}

impl ExecutorStorage<'_> {
    /// Whether an erase of run `owner`'s actor took its replies (FIX 5718),
    /// as the run's storage reads it. A session's run keeps its rows on its
    /// own route, which stamps no owner: never erased here.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn code_run_response_erased(&self, owner: EntityId) -> Result<bool> {
        match self {
            Self::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn()?;
                Ok(
                    response_owner_in_txn(*vault, &rtxn, &owner)?
                        .is_some_and(ResponseOwner::erased),
                )
            }
            Self::Session(_) => Ok(false),
        }
    }

    /// [`Self::put_code_run_replay_record_if_generation_with_heal`], with
    /// the record's owner, `actor`'s run `run`, stamped in the same writer
    /// unless it has one (FIX 5718): how a run's start and a write's
    /// reservation name whose replies the record will hold. A session's run
    /// stamps it only on an on-record stretch, where its rows land in base
    /// (FIX 7429); an off-record row stamps none.
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
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_with_heal_and(
                record,
                expected,
                None,
                |wtxn| stamp_response_owner_in_txn(*vault, wtxn, record.run_id, run, actor),
            ),
            Self::Session(binding) => {
                binding.put_owned_replay_record_if_generation(record, expected, run, actor)
            }
        }
    }
}
