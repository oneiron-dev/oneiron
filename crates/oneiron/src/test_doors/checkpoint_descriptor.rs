//! The checkpoint adapter descriptor (UC-10 PR 2) over real side tables,
//! beside the getters it replaces, for `tests/checkpoint_descriptor.rs`.
//! Compiled only under `--cfg oneiron_test_support`; never API.
//!
//! Its adapters restate two getters as descriptor rows: the text index's
//! source text (each row whole, under its document) and the row births (each
//! birth split by its process actor, each born-from row held while its
//! trigger is). Each comparison runs the descriptor and the getter over the
//! same rows.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideCodec, SideKey, SideTable};
use crate::store::Store;
use crate::store::birth_record::{BIRTH_BY_TRIGGER, ROW_BIRTH, RowBirth};
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, CapturedByAdapter, Check, Join, PlacedTable,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowDb, RowLocator,
    RowPart, TypedRow,
};
use crate::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};

/// The text index's source text, as `store/text_index` declares it.
const TEXT_SOURCE: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// The field a birth's process actor fills, as the birth getter names it.
const PROCESS: &str = "made_by.process.actor";

#[allow(
    clippy::unnecessary_wraps,
    reason = "a placement callback: PlacedTable's fn pointer returns Result"
)]
fn place_text(out: &mut Captured, row: TypedRow<EntityId, Vec<(String, String)>>) -> Result<()> {
    out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    Ok(())
}

fn place_birth(out: &mut Captured, row: TypedRow<EntityId, RowBirth>) -> Result<()> {
    let born = row.key;
    rows::split_actors(out, OwnerRef::entity(&born), ROW_BIRTH, row, |birth| {
        let actor = std::mem::replace(&mut birth.made_by.process.actor, born);
        vec![(PROCESS.to_owned(), actor)]
    })
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "a placement callback: PlacedTable's fn pointer returns Result"
)]
fn place_born_from(out: &mut Captured, row: TypedRow<(EntityId, EntityId), ()>) -> Result<()> {
    let (trigger, born) = row.key;
    let owner = OwnerRef::entity(&born);
    out.depends(owner, &row.at, OwnerRef::entity(&trigger));
    out.exact(owner, row.at, row.bytes);
    Ok(())
}

fn join_birth(
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if !at.in_table(ROW_BIRTH.decl()) {
        return Err(rows::bad_part());
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let birth = rows::join_actors(ROW_BIRTH, value, parts, |birth, field, actor| {
        if field != PROCESS {
            return Err(rows::bad_part());
        }
        birth.made_by.process.actor = actor;
        Ok(())
    })?;
    ROW_BIRTH.encode_value(&birth).map(Some)
}

fn capture_text_source(store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    out.merge(crate::bm25::checkpoint::ADAPTER.capture(store, txn)?);
    Ok(())
}

fn text_row_owner(at: &RowLocator) -> Option<OwnerRef> {
    let key = at.key.strip_prefix(TEXT_SOURCE.decl().prefix)?;
    EntityId::decode_key(key).map(|id| OwnerRef::entity(&id))
}

fn refuse_every_part(_: &RowLocator, _: &[u8]) -> Result<()> {
    Err(rows::bad_part())
}

static TEXT_SOURCE_BY_TABLE: Adapter = Adapter {
    tables: &[&PlacedTable {
        table: TEXT_SOURCE,
        place: place_text,
    }],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
};

static TEXT_SOURCE_OWN_CAPTURE: Adapter = Adapter {
    tables: &[&CapturedByAdapter(TEXT_SOURCE)],
    capture: Capture::Own(capture_text_source),
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
};

/// A table its adapter's own capture places, listed in a by-table capture.
static TEXT_SOURCE_MISLISTED: Adapter = Adapter {
    tables: &[&CapturedByAdapter(TEXT_SOURCE)],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
};

static TEXT_SOURCE_GATED: Adapter = Adapter {
    tables: &[&PlacedTable {
        table: TEXT_SOURCE,
        place: place_text,
    }],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: Some(text_row_owner),
    join: Join::NoSplit,
};

static TEXT_SOURCE_OWN_CHECK: Adapter = Adapter {
    tables: &[&PlacedTable {
        table: TEXT_SOURCE,
        place: place_text,
    }],
    capture: Capture::ByTable,
    check: Check::Own(refuse_every_part),
    row_owner: None,
    join: Join::NoSplit,
};

static BIRTHS: Adapter = Adapter {
    tables: &[
        &PlacedTable {
            table: ROW_BIRTH,
            place: place_birth,
        },
        &PlacedTable {
            table: BIRTH_BY_TRIGGER,
            place: place_born_from,
        },
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::Row(join_birth),
};

/// The rows [`seed_rows`] wrote.
#[derive(Clone, Debug)]
pub struct SeededRows {
    pub documents: Vec<EntityId>,
    pub born: Vec<EntityId>,
}

/// Writes `count` text-source rows and `count` row births. Each birth names
/// its own process actor and has one born-from row naming its own trigger.
///
/// # Errors
///
/// The vault's.
pub fn seed_rows(vault: &Vault, count: usize) -> Result<SeededRows> {
    let mut txn = vault.store.env.write_txn()?;
    let mut seeded = SeededRows {
        documents: Vec::new(),
        born: Vec::new(),
    };
    for index in 0..count {
        let document = EntityId::now();
        let fields = vec![("title".to_owned(), format!("descriptor document {index}"))];
        TEXT_SOURCE.put(vault, &mut txn, &document, &fields)?;
        seeded.documents.push(document);
        let born = EntityId::now();
        let birth = RowBirth::stated(MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: EntityId::now(),
                class: MadeByClass::Stated,
                identity: "checkpoint-descriptor".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: 1,
            trigger: None,
        });
        ROW_BIRTH.put(vault, &mut txn, &born, &birth)?;
        BIRTH_BY_TRIGGER.put(vault, &mut txn, &(EntityId::now(), born), &())?;
        seeded.born.push(born);
    }
    txn.commit()?;
    Ok(seeded)
}

/// One adapter's capture through the descriptor, beside its getter's.
#[derive(Clone, Debug)]
pub struct CaptureComparison {
    pub adapter: &'static str,
    pub owners: usize,
    pub parts: usize,
    pub actor_parts: usize,
    pub dependencies: usize,
    pub unclassified: usize,
    /// The descriptor placed every row as the getter does.
    pub same_capture: bool,
    /// Each owner's framed compartment bytes are the getter's.
    pub same_frames: bool,
}

fn compare_capture(
    adapter: &'static str,
    descriptor: &Adapter,
    ours: &Captured,
    theirs: &Captured,
    frame: impl Fn(&OwnerRows) -> Result<Vec<u8>>,
) -> Result<CaptureComparison> {
    let mine: Vec<&OwnerRows> = ours.owners().collect();
    let getter: Vec<&OwnerRows> = theirs.owners().collect();
    let same_capture = mine == getter
        && ours.structure == theirs.structure
        && ours.dispatched == theirs.dispatched
        && ours.unclassified == theirs.unclassified;
    let mut same_frames = mine.len() == getter.len();
    for (rows, getter_rows) in mine.iter().copied().zip(getter.iter().copied()) {
        same_frames &= descriptor.bytes_for_owner(rows)? == frame(getter_rows)?;
    }
    Ok(CaptureComparison {
        adapter,
        owners: mine.len(),
        parts: mine.iter().map(|rows| rows.rows.len()).sum(),
        actor_parts: mine.iter().map(|rows| rows.actor_parts.len()).sum(),
        dependencies: mine.iter().map(|rows| rows.dependencies.len()).sum(),
        unclassified: ours.unclassified.len(),
        same_capture,
        same_frames,
    })
}

/// The text-source adapter (by table, and through its own capture) and the
/// births adapter, each captured and framed through the descriptor and
/// through its getter.
///
/// # Errors
///
/// The vault's.
pub fn compare_captures(vault: &Vault) -> Result<Vec<CaptureComparison>> {
    let store = &vault.store;
    let txn = store.env.read_txn()?;
    let text = crate::bm25::checkpoint::ADAPTER.capture(store, &txn)?;
    let births = crate::provenance::birth::checkpoint::capture(store, &txn)?;
    Ok(vec![
        compare_capture(
            "text source by table",
            &TEXT_SOURCE_BY_TABLE,
            &TEXT_SOURCE_BY_TABLE.capture(store, &txn)?,
            &text,
            |rows| crate::bm25::checkpoint::ADAPTER.bytes_for_owner(rows),
        )?,
        compare_capture(
            "text source by its own capture",
            &TEXT_SOURCE_OWN_CAPTURE,
            &TEXT_SOURCE_OWN_CAPTURE.capture(store, &txn)?,
            &text,
            |rows| crate::bm25::checkpoint::ADAPTER.bytes_for_owner(rows),
        )?,
        compare_capture(
            "row births",
            &BIRTHS,
            &BIRTHS.capture(store, &txn)?,
            &births,
            crate::provenance::birth::checkpoint::bytes_for_owner,
        )?,
    ])
}

/// Whether a by-table capture that lists a table its adapter's own capture
/// places refuses.
///
/// # Errors
///
/// The vault's.
pub fn mislisted_capture_refuses(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(TEXT_SOURCE_MISLISTED.capture(&vault.store, &txn).is_err())
}

/// One adapter's restore through the descriptor into one vault, beside its
/// getter's into another.
#[derive(Clone, Debug)]
pub struct RestoreComparison {
    pub adapter: &'static str,
    pub written: usize,
    pub dropped: usize,
    /// The descriptor wrote and dropped, owner by owner, what the getter did.
    pub same_restore: bool,
    /// Every source row the restore did not drop is in both targets with
    /// its source bytes.
    pub kept_rows_back: bool,
}

/// A vault's raw rows of some side tables: each full key (prefix and key)
/// and its value.
type VaultRows = BTreeMap<Vec<u8>, Vec<u8>>;

fn raw_rows<K: SideKey, V, C: SideCodec<V>>(
    vault: &Vault,
    table: SideTable<K, V, C>,
    into: &mut VaultRows,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    for row in table.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, value) = row?;
        let mut full = table.decl().prefix.to_vec();
        full.extend_from_slice(&key);
        into.insert(full, value);
    }
    Ok(())
}

fn text_rows(vault: &Vault) -> Result<VaultRows> {
    let mut rows = BTreeMap::new();
    raw_rows(vault, TEXT_SOURCE, &mut rows)?;
    Ok(rows)
}

fn birth_rows(vault: &Vault) -> Result<VaultRows> {
    let mut rows = BTreeMap::new();
    raw_rows(vault, ROW_BIRTH, &mut rows)?;
    raw_rows(vault, BIRTH_BY_TRIGGER, &mut rows)?;
    Ok(rows)
}

/// Each owner `descriptor` captures in `source`, framed and opened: with its
/// actor parts when `actors_open`, with none when no actor opened.
fn opened_owners(
    descriptor: &Adapter,
    source: &Vault,
    actors_open: bool,
) -> Result<Vec<OpenedOwnerRows>> {
    let txn = source.store.env.read_txn()?;
    let captured = descriptor.capture(&source.store, &txn)?;
    let mut opened = Vec::new();
    for rows in captured.owners() {
        let actors = if actors_open {
            rows.actor_parts.clone()
        } else {
            Vec::new()
        };
        opened.push(OpenedOwnerRows::open(
            &descriptor.bytes_for_owner(rows)?,
            actors,
            BTreeSet::new(),
        )?);
    }
    Ok(opened)
}

fn compare_restore(
    adapter: &'static str,
    descriptor: &Adapter,
    (source, descriptor_target, getter_target): (&Vault, &Vault, &Vault),
    actors_open: bool,
    getter_restore: impl Fn(&Store, &mut RwTxn<'_>, OpenedOwnerRows) -> Result<Restored>,
    rows_of: fn(&Vault) -> Result<VaultRows>,
) -> Result<RestoreComparison> {
    let mut written = 0;
    let mut dropped = BTreeSet::new();
    let mut same_restore = true;
    let mut mine = descriptor_target.store.env.write_txn()?;
    let mut theirs = getter_target.store.env.write_txn()?;
    for opened in opened_owners(descriptor, source, actors_open)? {
        let ours =
            descriptor.restore_in_txn(&descriptor_target.store, &mut mine, opened.clone())?;
        let getter = getter_restore(&getter_target.store, &mut theirs, opened)?;
        same_restore &= ours.written == getter.written && ours.dropped == getter.dropped;
        written += ours.written;
        dropped.extend(ours.dropped.into_iter().map(|at| at.key));
    }
    mine.commit()?;
    theirs.commit()?;
    let source_rows = rows_of(source)?;
    let ours = rows_of(descriptor_target)?;
    let getter = rows_of(getter_target)?;
    let kept_rows_back = source_rows
        .iter()
        .filter(|(key, _)| !dropped.contains(*key))
        .all(|(key, value)| ours.get(key) == Some(value) && getter.get(key) == Some(value));
    Ok(RestoreComparison {
        adapter,
        written,
        dropped: dropped.len(),
        same_restore,
        kept_rows_back,
    })
}

/// The text-source and births adapters' rows in `source`, framed, opened and
/// restored through the descriptor into `descriptor_target` and through each
/// getter into `getter_target`.
///
/// # Errors
///
/// The vaults'.
pub fn compare_restores(
    source: &Vault,
    descriptor_target: &Vault,
    getter_target: &Vault,
    actors_open: bool,
) -> Result<Vec<RestoreComparison>> {
    let vaults = (source, descriptor_target, getter_target);
    Ok(vec![
        compare_restore(
            "text source by table",
            &TEXT_SOURCE_BY_TABLE,
            vaults,
            actors_open,
            |store, txn, opened| {
                crate::bm25::checkpoint::ADAPTER.restore_in_txn(store, txn, opened)
            },
            text_rows,
        )?,
        compare_restore(
            "row births",
            &BIRTHS,
            vaults,
            actors_open,
            |store, txn, opened| {
                crate::provenance::birth::checkpoint::restore_in_txn(store, txn, opened)
            },
            birth_rows,
        )?,
    ])
}

/// Whether one opened part restores: through the descriptor, and through
/// the getter that takes the same step (`None` where none does).
#[derive(Clone, Debug)]
pub struct RestoreVerdict {
    pub case: &'static str,
    pub descriptor_admits: bool,
    pub getter_admits: Option<bool>,
}

fn opened_part(owner: &EntityId, part: RowPart) -> OpenedOwnerRows {
    let owner = OwnerRef::entity(owner);
    OpenedOwnerRows {
        subtype: owner.subtype,
        owner32: owner.owner32,
        occurrence_hint: None,
        rows: vec![part],
        dependencies: Vec::new(),
        actor_parts: Vec::new(),
        unavailable: BTreeSet::new(),
    }
}

/// Whether `descriptor` restores `opened` into `vault`; the write is never
/// committed.
fn descriptor_admits(vault: &Vault, descriptor: &Adapter, opened: OpenedOwnerRows) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    Ok(descriptor
        .restore_in_txn(&vault.store, &mut txn, opened)
        .is_ok())
}

/// Whether the text getter restores `opened` into `vault`; the write is
/// never committed.
fn text_getter_admits(vault: &Vault, opened: OpenedOwnerRows) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    Ok(crate::bm25::checkpoint::ADAPTER
        .restore_in_txn(&vault.store, &mut txn, opened)
        .is_ok())
}

/// Text-source parts opened from `owner`'s compartment, each restored
/// through a descriptor and through the text getter.
///
/// # Errors
///
/// The vault's.
pub fn restore_verdicts(
    vault: &Vault,
    owner: EntityId,
    other: EntityId,
) -> Result<Vec<RestoreVerdict>> {
    let text_at =
        |id: &EntityId| RowLocator::row(RowDb::of(TEXT_SOURCE.decl()), TEXT_SOURCE.key_bytes(id));
    let fields = TEXT_SOURCE.encode_value(&vec![("title".to_owned(), "verdict".to_owned())])?;
    let exact = |at: RowLocator, value: &[u8]| RowPart::Exact {
        at,
        value: value.to_vec(),
    };
    let born_from_at = RowLocator::row(
        RowDb::of(BIRTH_BY_TRIGGER.decl()),
        BIRTH_BY_TRIGGER.key_bytes(&(owner, other)),
    );
    let cases: [(&'static str, &Adapter, RowPart, bool); 7] = [
        (
            "its own text row",
            &TEXT_SOURCE_BY_TABLE,
            exact(text_at(&owner), &fields),
            true,
        ),
        (
            "an undecodable text value",
            &TEXT_SOURCE_BY_TABLE,
            exact(text_at(&owner), b"\xff not a named value"),
            true,
        ),
        (
            "a row of a table the adapter does not hold",
            &TEXT_SOURCE_BY_TABLE,
            exact(born_from_at, &[]),
            true,
        ),
        (
            "a no-one-form part where no actor splits out",
            &TEXT_SOURCE_BY_TABLE,
            RowPart::NoActor {
                at: text_at(&owner),
                value: fields.clone(),
            },
            true,
        ),
        (
            "another owner's text row behind the owner gate",
            &TEXT_SOURCE_GATED,
            exact(text_at(&other), &fields),
            true,
        ),
        (
            "its own text row behind the owner gate",
            &TEXT_SOURCE_GATED,
            exact(text_at(&owner), &fields),
            true,
        ),
        (
            "its own text row under an own check that refuses every part",
            &TEXT_SOURCE_OWN_CHECK,
            exact(text_at(&owner), &fields),
            false,
        ),
    ];
    let mut verdicts = Vec::new();
    for (case, descriptor, part, getter_step) in cases {
        let opened = opened_part(&owner, part);
        let getter_admits = if getter_step {
            Some(text_getter_admits(vault, opened.clone())?)
        } else {
            None
        };
        verdicts.push(RestoreVerdict {
            case,
            descriptor_admits: descriptor_admits(vault, descriptor, opened)?,
            getter_admits,
        });
    }
    Ok(verdicts)
}

/// Which tables' rows the text-source and births adapters own.
#[derive(Clone, Copy, Debug)]
pub struct Ownership {
    pub births_own_a_birth: bool,
    pub births_own_a_born_from_row: bool,
    pub births_own_a_text_row: bool,
    pub text_owns_a_text_row: bool,
    pub text_owns_a_birth: bool,
}

/// The rows `owner`'s birth, born-from row and text row sit at, each asked
/// of both adapters' `owns`.
#[must_use]
pub fn ownership(owner: EntityId, trigger: EntityId) -> Ownership {
    let birth = RowLocator::row(RowDb::of(ROW_BIRTH.decl()), ROW_BIRTH.key_bytes(&owner));
    let born_from = RowLocator::row(
        RowDb::of(BIRTH_BY_TRIGGER.decl()),
        BIRTH_BY_TRIGGER.key_bytes(&(trigger, owner)),
    );
    let text = RowLocator::row(RowDb::of(TEXT_SOURCE.decl()), TEXT_SOURCE.key_bytes(&owner));
    Ownership {
        births_own_a_birth: BIRTHS.owns(&birth),
        births_own_a_born_from_row: BIRTHS.owns(&born_from),
        births_own_a_text_row: BIRTHS.owns(&text),
        text_owns_a_text_row: TEXT_SOURCE_BY_TABLE.owns(&text),
        text_owns_a_birth: TEXT_SOURCE_BY_TABLE.owns(&birth),
    }
}
