//! The worlds of the rows one code run is served (FIX 6130): its ledger in
//! `CODE_RUN_READ_WORLD`, on the run's own storage (the vault for a canonical
//! run, the room's captured route for one bound to an off-record session),
//! never capped. A header row keeps the capture epochs still open and why the
//! ledger misses rows the run was served; one row per world a served row sat
//! in keeps the bridge positions it was served at. A blocked report freezes a
//! complete ledger's worlds in its filing commit
//! ([`read_world_snapshot_in_txn`]); a ledger that is not complete freezes
//! none, and its code fix reads the worlds it inferred before.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::records::REPLAY_RECORDS;
use super::routing::ExecutorStorage;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Result, Vault};

/// The byte a header row's key ends with, after the run.
const HEADER_TAG: u8 = 0;

/// The byte a world row's key carries between the run and the world.
const SEEN_TAG: u8 = 1;

/// Header rows. Key: [`HeaderKey`].
const HEADERS: SideTable<HeaderKey, ReadWorldHeader, Named> =
    SideTable::new(&side_table::CODE_RUN_READ_WORLD);

/// World rows, in the same table. Key: [`SeenKey`].
const SEEN: SideTable<SeenKey, ReadWorldSeen, Named> =
    SideTable::new(&side_table::CODE_RUN_READ_WORLD);

/// One run's header row: the run, then [`HEADER_TAG`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeaderKey(EntityId);

impl SideKey for HeaderKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.as_bytes());
        out.push(HEADER_TAG);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes.split_at_checked(16)? {
            (run, [HEADER_TAG]) => Some(Self(EntityId::from_bytes(run.try_into().ok()?).ok()?)),
            _ => None,
        }
    }
}

/// One world a run was served a row of: the run, [`SEEN_TAG`], the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeenKey {
    run: EntityId,
    world: EntityId,
}

impl SideKey for SeenKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.run.as_bytes());
        out.push(SEEN_TAG);
        out.extend_from_slice(self.world.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (run, rest) = bytes.split_at_checked(16)?;
        let (&tag, world) = rest.split_first()?;
        if tag != SEEN_TAG {
            return None;
        }
        Some(Self {
            run: EntityId::from_bytes(run.try_into().ok()?).ok()?,
            world: EntityId::from_bytes(world.try_into().ok()?).ok()?,
        })
    }
}

/// The key bytes every world row of `run` starts with.
fn seen_prefix(run: EntityId) -> Vec<u8> {
    let mut prefix = run.as_bytes().to_vec();
    prefix.push(SEEN_TAG);
    prefix
}

/// Why a run's ledger misses rows it was served (FIX 6130). Any one of them
/// keeps the ledger from reading complete, for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadWorldUnknown {
    /// The run had a record before its ledger began: a continuation's copied
    /// prefix, or a run from before the ledger.
    NotFromStart,
    /// A call was answered from a read no capture covers.
    Uncaptured,
    /// A verb hook showed the guest a view of its own in place of a call's
    /// answer.
    HookView,
    /// A callable skill ran inside a call, from the stored skill it loaded.
    CallableSkill,
    /// The run read a result another run kept.
    RetainedResult,
    /// A wait's reply reached the run.
    WaitReply,
    /// A served row's world could not be proved in the read that served it.
    Unproved,
    /// A ledger write failed.
    WriteFailed,
}

/// What a run's ledger knows of itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ReadWorldHeader {
    /// The capture epochs entered and not closed: one whose host stopped
    /// mid-entry, or met a ledger write it could not make, stays open.
    open: BTreeSet<EntityId>,
    /// Why the ledger misses rows the run was served.
    unknown: BTreeSet<ReadWorldUnknown>,
}

impl ReadWorldHeader {
    /// The header a ledger begins with: one begun once the run already has a
    /// record misses whatever that record carries.
    fn begun(recorded: bool) -> Self {
        let mut header = Self::default();
        if recorded {
            header.unknown.insert(ReadWorldUnknown::NotFromStart);
        }
        header
    }
}

/// One world a run was served a row of.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ReadWorldSeen {
    /// The bridge positions a row of the world was served at.
    at: BTreeSet<u64>,
}

/// The capture epoch a run's host holds while every answer the run was
/// served in it is in the run's ledger: what a blocked report the run files
/// freezes the ledger under (FIX 6130).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadWorldSeal {
    pub(crate) epoch: EntityId,
}

/// A complete ledger's worlds, as a blocked report's filing commit read them
/// (FIX 6130): each world a row the run was served up to the report sat in,
/// base reality by its own id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadWorldSnapshot {
    pub(crate) worlds: Vec<EntityId>,
}

/// The worlds of `run`'s ledger as `txn` reads it, when the ledger is
/// complete there: it began with the run, misses nothing, and the one epoch
/// it holds open is the one `seal` names, its host's own. `None` otherwise,
/// and on a read that fails: the report files as it did before.
pub(crate) fn read_world_snapshot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    seal: ReadWorldSeal,
) -> Option<ReadWorldSnapshot> {
    let header = HEADERS.get(&vault.store, txn, &HeaderKey(run)).ok()??;
    if !header.unknown.is_empty() || header.open.iter().any(|epoch| *epoch != seal.epoch) {
        return None;
    }
    let worlds = SEEN
        .scan_keys(&vault.store, txn, &seen_prefix(run))
        .ok()?
        .into_iter()
        .map(|key| key.world)
        .collect();
    Some(ReadWorldSnapshot { worlds })
}

impl ExecutorStorage<'_> {
    /// Opens capture epoch `epoch` of `run`'s ledger, beginning the ledger
    /// when the run has none.
    pub(crate) fn open_read_world_epoch(&self, run: EntityId, epoch: EntityId) -> Result<()> {
        self.update_read_world_header(run, |header| {
            header.open.insert(epoch);
        })
    }

    /// Closes `epoch` of `run`'s ledger: every answer the run was served in
    /// it is in the ledger.
    pub(crate) fn close_read_world_epoch(&self, run: EntityId, epoch: EntityId) -> Result<()> {
        self.update_read_world_header(run, |header| {
            header.open.remove(&epoch);
        })
    }

    /// Marks `run`'s ledger as missing rows it was served, for `cause`.
    pub(crate) fn mark_read_world_unknown(
        &self,
        run: EntityId,
        cause: ReadWorldUnknown,
    ) -> Result<()> {
        self.update_read_world_header(run, |header| {
            header.unknown.insert(cause);
        })
    }

    /// Notes each of `worlds` in `run`'s ledger as served at bridge position
    /// `at`.
    pub(crate) fn note_read_worlds(
        &self,
        run: EntityId,
        at: u64,
        worlds: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let key_of = |world: &EntityId| SeenKey { run, world: *world };
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                for world in worlds {
                    let key = key_of(world);
                    let mut seen = SEEN.get(&vault.store, &*txn, &key)?.unwrap_or_default();
                    seen.at.insert(at);
                    SEEN.put(&vault.store, txn, &key, &seen)?;
                }
                Ok(())
            }),
            Self::Session(binding) => binding.answered(|| {
                let session = &binding.session;
                for world in worlds {
                    let key = key_of(world);
                    let mut seen = session.side_table_get(&SEEN, &key)?.unwrap_or_default();
                    seen.at.insert(at);
                    session.side_table_put_routed(&binding.route, &SEEN, &key, &seen)?;
                }
                Ok(())
            }),
        }
    }

    /// Rewrites `run`'s header with `update`, on the run's own route. A run
    /// with no header begins one, missing the record it already has.
    fn update_read_world_header(
        &self,
        run: EntityId,
        update: impl FnOnce(&mut ReadWorldHeader),
    ) -> Result<()> {
        let key = HeaderKey(run);
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                let store = &vault.store;
                let mut header = match HEADERS.get(store, &*txn, &key)? {
                    Some(header) => header,
                    None => ReadWorldHeader::begun(REPLAY_RECORDS.contains(store, &*txn, &run)?),
                };
                update(&mut header);
                HEADERS.put(store, txn, &key, &header)
            }),
            Self::Session(binding) => binding.answered(|| {
                let session = &binding.session;
                let mut header = match session.side_table_get(&HEADERS, &key)? {
                    Some(header) => header,
                    None => {
                        let recorded = session.side_table_get(&REPLAY_RECORDS, &run)?;
                        ReadWorldHeader::begun(recorded.is_some())
                    }
                };
                update(&mut header);
                session.side_table_put_routed(&binding.route, &HEADERS, &key, &header)
            }),
        }
    }
}
