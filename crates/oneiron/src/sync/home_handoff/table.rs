//! The tables a home move carries. A domain implements [`HomeTable`] for each
//! node-local table that must follow the home, and passes the carrier one
//! [`HomeTableRegistration`] per table. The carrier walks those registrations
//! and never reads or writes a table's rows itself: each table exports its
//! own typed rows and adopts them through its own typed writes.
//!
//! On the wire a section names its table by the declaration's name and
//! carries the rows as the table's named MessagePack DTO, whatever codec the
//! table stores them in.
//!
//! FIX 8875: a table exports its rows split in two ([`Partitioned`]): the
//! content-free facts every copy keeps, and each actor's content apart, which
//! the carrier seals under that actor's erasable key (`super::actor_content`).
//! On adoption a table gets the facts and the content of each actor whose key
//! opened here and who is not erased here; a row whose actor's content did
//! not open lands as its facts alone, never as a Conflict.

use heed::{RoTxn, RwTxn};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::{HomeFence, HomeMove, refused};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Named, SideCodec, SideDb, SideTableDecl};

/// A restore image's rows of one database, sorted by key.
pub(crate) type ImageRows = [(Vec<u8>, Vec<u8>)];

/// What one table's adopt did with the rows it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TableAdopt {
    /// The rows are this node's now: equal rows were a no-op, a proven
    /// successor merged as the domain merges it.
    Applied,
    /// Rows here diverge from the carried ones and neither follows the
    /// other. The carrier drops its writer, so no section lands.
    Conflict,
}

/// One actor's content among a table's rows (FIX 8875): sealed apart under
/// that actor's erasable key, never beside the facts, so the actor's erase
/// leaves it unreadable wherever a copy went.
pub(crate) trait ActorContent: Serialize + DeserializeOwned {
    /// The actor whose key seals it: a PERSON, MACHINE or AGENT_DEF, whose
    /// erase retires that key.
    fn actor(&self) -> EntityId;
}

/// A table's rows as a move carries them (FIX 8875): the content-free facts,
/// and each actor's content apart.
pub(crate) struct Partitioned<F, A> {
    pub(crate) facts: F,
    pub(crate) actors: Vec<A>,
}

/// One node-local table that follows the vault's home.
pub(crate) trait HomeTable: Send + Sync + 'static {
    /// The facts a move carries: a typed DTO the domain owns, never raw
    /// rows, that names no actor and holds no actor's words.
    type Rows: Serialize + DeserializeOwned;
    /// One actor's content among the rows (FIX 8875).
    type Actor: ActorContent;
    /// The table's declaration; its name is the section's id on the wire.
    const TABLE: &'static SideTableDecl;
    /// The version of [`Self::Rows`]. A target adopts only the version it
    /// registers.
    const SCHEMA_VERSION: u16;

    /// Whether every write this table admitted before the move has settled,
    /// so its rows can freeze.
    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, movement: &HomeMove) -> Result<bool>;

    /// The rows the move carries, read in the source's final writer: the
    /// facts, and each actor's content apart.
    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        fence: &HomeFence,
    ) -> Result<Partitioned<Self::Rows, Self::Actor>>;

    /// Lands `rows` in the target's one adopting transaction: the facts, and
    /// the content of each actor whose key opened here and who is not erased
    /// here. A row whose actor's content is not among them lands as its facts
    /// alone, never as a Conflict. An error or a [`TableAdopt::Conflict`]
    /// drops that transaction, earlier sections too.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        fence: &HomeFence,
        rows: Partitioned<Self::Rows, Self::Actor>,
    ) -> Result<TableAdopt>;

    /// The full stored keys of every row this table manages now, deletion
    /// witnesses and new descendants included, for restore to keep live.
    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>>;

    /// The full stored keys this table manages among `image`, a restore
    /// image's rows of [`Self::TABLE`]'s database (FIX 5661 C2b): with
    /// [`Self::live_keys`] they restore live, so this node's current row, or
    /// its absence, wins over the image's. A table may read this node's rows
    /// in `txn` to judge one, and may name keys only this node holds. By
    /// default every key of the table's family.
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(image
            .iter()
            .filter(|(key, _)| key.starts_with(Self::TABLE.prefix))
            .map(|(key, _)| key.clone())
            .collect())
    }
}

/// One table's export as the carrier seals it (FIX 8875): the encoded facts,
/// and each actor's encoded content beside the actor whose key seals it.
pub(super) struct ExportedRows {
    pub(super) facts: Vec<u8>,
    pub(super) actors: Vec<(EntityId, Zeroizing<Vec<u8>>)>,
}

type QuiescentFn = fn(&Vault, &RoTxn<'_>, &HomeMove) -> Result<bool>;
type ExportFn = fn(&Vault, &RoTxn<'_>, &HomeFence) -> Result<ExportedRows>;
type CheckFn = fn(&[u8]) -> Result<()>;
type AdoptFn =
    fn(&Vault, &mut RwTxn<'_>, &HomeFence, &[u8], Vec<Zeroizing<Vec<u8>>>) -> Result<TableAdopt>;
type LiveKeysFn = fn(&Vault, &RoTxn<'_>) -> Result<Vec<Vec<u8>>>;
type ManagesFn = fn(&Vault, &RoTxn<'_>, &ImageRows) -> Result<Vec<Vec<u8>>>;

/// One registered [`HomeTable`], its row type erased: what the carrier walks.
#[derive(Clone, Copy)]
pub(crate) struct HomeTableRegistration {
    table: &'static SideTableDecl,
    schema_version: u16,
    quiescent: QuiescentFn,
    export: ExportFn,
    check: CheckFn,
    adopt: AdoptFn,
    live_keys: LiveKeysFn,
    manages: ManagesFn,
}

impl HomeTableRegistration {
    /// The registration of `T`.
    pub(crate) const fn of<T: HomeTable>() -> Self {
        Self {
            table: T::TABLE,
            schema_version: T::SCHEMA_VERSION,
            quiescent: T::quiescent,
            export: export_rows::<T>,
            check: check_rows::<T>,
            adopt: adopt_rows::<T>,
            live_keys: T::live_keys,
            manages: T::manages,
        }
    }

    /// The table's id on the wire: its declaration's name.
    pub(crate) fn table_id(&self) -> &'static str {
        self.table.name
    }

    pub(crate) fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// The full stored keys of every row the table manages now.
    pub(crate) fn live_keys(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        (self.live_keys)(vault, txn)
    }

    /// The database the table's rows are in.
    pub(crate) fn database(&self) -> SideDb {
        self.table.db
    }

    /// The full stored keys the table manages among a restore image's rows
    /// of its database ([`HomeTable::manages`]).
    pub(crate) fn manages(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        image: &ImageRows,
    ) -> Result<Vec<Vec<u8>>> {
        (self.manages)(vault, txn, image)
    }

    pub(super) fn quiescent(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        movement: &HomeMove,
    ) -> Result<bool> {
        (self.quiescent)(vault, txn, movement)
    }

    pub(super) fn export(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        fence: &HomeFence,
    ) -> Result<ExportedRows> {
        (self.export)(vault, txn, fence)
    }

    /// Whether `rows` decode as this table's rows, before any writer.
    pub(super) fn check(&self, rows: &[u8]) -> Result<()> {
        (self.check)(rows)
    }

    /// Lands the encoded facts `rows` with `actors`, the content of each
    /// actor part whose key opened here.
    pub(super) fn adopt(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        fence: &HomeFence,
        rows: &[u8],
        actors: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<TableAdopt> {
        (self.adopt)(vault, txn, fence, rows, actors)
    }
}

/// Refuses a registry that names one table twice: each table is one section.
pub(super) fn check_registry(tables: &[HomeTableRegistration]) -> Result<()> {
    for (index, table) in tables.iter().enumerate() {
        if tables[..index]
            .iter()
            .any(|earlier| earlier.table_id() == table.table_id())
        {
            return Err(refused("the registry names one table twice"));
        }
    }
    Ok(())
}

fn export_rows<T: HomeTable>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    fence: &HomeFence,
) -> Result<ExportedRows> {
    let Partitioned { facts, actors } = T::export(vault, txn, fence)?;
    let facts = <Named as SideCodec<T::Rows>>::encode(&facts)
        .map_err(|_| refused("a table's rows do not encode"))?;
    let actors = actors
        .iter()
        .map(|content| {
            <Named as SideCodec<T::Actor>>::encode(content)
                .map(|bytes| (content.actor(), Zeroizing::new(bytes)))
                .map_err(|_| refused("an actor's content does not encode"))
        })
        .collect::<Result<_>>()?;
    Ok(ExportedRows { facts, actors })
}

fn decode_rows<T: HomeTable>(rows: &[u8]) -> Result<T::Rows> {
    <Named as SideCodec<T::Rows>>::decode(rows)
        .map_err(|_| refused("a section's rows do not decode"))
}

fn check_rows<T: HomeTable>(rows: &[u8]) -> Result<()> {
    decode_rows::<T>(rows).map(drop)
}

/// FIX 10764: an actor erased here gives none of its content, whatever its
/// key still opens, so a carried row never lands the erased actor again.
fn adopt_rows<T: HomeTable>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    fence: &HomeFence,
    rows: &[u8],
    actors: Vec<Zeroizing<Vec<u8>>>,
) -> Result<TableAdopt> {
    let facts = decode_rows::<T>(rows)?;
    let mut opened = Vec::with_capacity(actors.len());
    for plain in actors {
        let content = <Named as SideCodec<T::Actor>>::decode(&plain)
            .map_err(|_| refused("an actor's content does not decode"))?;
        if crate::ports::removed_in_txn(&vault.store, txn, &content.actor())? {
            continue;
        }
        opened.push(content);
    }
    T::adopt(
        vault,
        txn,
        fence,
        Partitioned {
            facts,
            actors: opened,
        },
    )
}
