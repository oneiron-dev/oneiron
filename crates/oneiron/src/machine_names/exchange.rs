//! The machine-name cells the owner's machines exchange through their residence home (FIX
//! [DEVICE-DISPLAY-NAME]; Engine RULING MACHINE-NAMES-CARRIER = B, Mon 16 Nov 03:13).
//!
//! Two cells name a machine: the owner's name for it, which any machine of his sets or clears,
//! and the name and model it reports for itself, which only that machine writes. Each cell is
//! dated by its writer: `written_at` from the writer's recording clock, and the writer's MACHINE
//! row. Of two cells for one machine and kind, the later `(written_at, writer)` wins on every
//! node, so nodes that hold the same cells show the same names. A clear is a dated cell without
//! a name: it wins over the name it clears, and a later name wins over it.
//!
//! A node dates the cell it writes past the one it holds (the recording clock, or one past the
//! held cell's time when the clock is not past it), so the owner's latest act on a machine wins
//! over every cell that machine had seen.
//!
//! On each steady pass a machine sends its home the cells it wrote and takes every cell the home
//! holds (`residence.machine_names.exchange`): at most two cells for each machine the fold names,
//! so no cursor is kept, and a pass the home refuses (an older home answers an unknown method)
//! leaves the cells to the next one. The home keeps an owner cell only from the machine that wrote
//! it, and a reported cell only from the machine it names. Every node judges a cell it takes as
//! its own writer does: a machine its fold names, one line without NUL, at most
//! [`MACHINE_NAME_MAX_BYTES`] bytes.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{MACHINE_NAME_MAX_BYTES, MachineOwnerName, OWNER_NAME, declared};
use crate::Vault;
use crate::authority::AuthorityView;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::GateDecisionId;

/// The name and model each machine reports for itself, as that machine dated it. Key: the
/// MACHINE row.
pub(super) const REPORTED_NAME: SideTable<EntityId, MachineReportedName, Named> =
    SideTable::new(&side_table::MACHINE_REPORTED_NAME);

/// One reported cell: the name and model a machine reports for itself, as its host declares
/// them, and the time that machine wrote them. This install's own row follows its host's
/// declaration; every other row came from the home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MachineReportedName {
    pub(crate) name: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) written_at: u64,
}

/// Whether a masked copy of a reported row still reads as one, for the historical lift sweep's
/// acceptance check.
pub(crate) fn accepts_masked_report(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<MachineReportedName, Named>(bytes)
}

/// One machine-name cell as `residence.machine_names.exchange` carries it, both ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineNameCell {
    /// The owner's name for `machine`, or its clear (`name` null), as `writer` set it at
    /// `written_at`. `receipt` (32 hex) names the act's Gate record on the writer.
    Owner {
        machine: EntityId,
        name: Option<String>,
        written_at: u64,
        writer: EntityId,
        receipt: String,
    },
    /// The name and model `machine` reports for itself, as it wrote them at `written_at`.
    Reported {
        machine: EntityId,
        name: Option<String>,
        model: Option<String>,
        written_at: u64,
    },
}

/// Whose cells a node takes in one merge.
#[derive(Debug, Clone, Copy)]
enum CellSource {
    /// The home's answer, on a machine: any writer's cells, except a report of this install's
    /// own machine, which its host declares.
    Home { this: EntityId },
    /// One proved machine's cells, at the home: the owner cells it wrote and its own report.
    Machine { peer: EntityId },
}

impl Vault {
    /// The cells this install wrote, for its home: each owner name or clear set here, and its
    /// own report, first brought up to its host's declaration. `None` while this install serves
    /// no machine of the fold.
    ///
    /// # Errors
    /// The store's and the fold's.
    pub(crate) fn machine_name_cells_written_here(&self) -> Result<Option<Vec<MachineNameCell>>> {
        let Some(this) = self.serving_machine_in_txn(&self.store.env.read_txn()?)? else {
            return Ok(None);
        };
        self.refresh_own_report(this);
        let txn = self.store.env.read_txn()?;
        let mut cells = Vec::new();
        if let Some(row) = REPORTED_NAME.get(&self.store, &txn, &this)? {
            cells.push(reported_cell(this, row));
        }
        for (machine, row) in OWNER_NAME.scan(&self.store, &txn)? {
            if row.writer.is_none_or(|writer| writer == this) {
                cells.push(owner_cell(machine, row, this));
            }
        }
        Ok(Some(cells))
    }

    /// Takes the cells of the home's answer: each one later than the cell held here for its
    /// machine and kind replaces it. A cell for a machine this fold does not name, a report of
    /// this install's own machine, and a cell its writer could not have written are left out.
    /// Returns how many cells changed here.
    ///
    /// # Errors
    /// The store's and the fold's.
    pub(crate) fn take_machine_name_cells(&self, cells: Vec<MachineNameCell>) -> Result<usize> {
        let Some(this) = self.serving_machine_in_txn(&self.store.env.read_txn()?)? else {
            return Ok(0);
        };
        self.with_write_txn_grouped(|txn| {
            merge_cells_in_txn(self, txn, CellSource::Home { this }, cells)
        })
    }

    /// The home's half of `residence.machine_names.exchange`, for `peer`, a machine of the
    /// owner's its socket proved: keeps each cell `peer` wrote that is later than the one held
    /// here, then answers every cell held here for a machine the fold names, this home's own
    /// report first brought up to its host's declaration.
    ///
    /// # Errors
    /// The store's and the fold's.
    pub(crate) fn exchange_machine_name_cells_at_home(
        &self,
        peer: EntityId,
        cells: Vec<MachineNameCell>,
    ) -> Result<Vec<MachineNameCell>> {
        let this = self.serving_machine_in_txn(&self.store.env.read_txn()?)?;
        if let Some(this) = this {
            self.refresh_own_report(this);
        }
        self.with_write_txn_grouped(|txn| {
            merge_cells_in_txn(self, txn, CellSource::Machine { peer }, cells)
        })?;
        let txn = self.store.env.read_txn()?;
        held_cells_in_txn(self, &txn, this)
    }

    /// Brings this install's own reported cell up to its host's declaration, dated past the cell
    /// it replaces. The row is compared with the declaration on every pass, so it is written as
    /// given, through the store without a custody door: a declaration the side-row wall would
    /// mask is refused, and the old cell stays, rather than a fresh handle changing the row on
    /// every pass (`SidePayload::Authored`).
    fn refresh_own_report(&self, this: EntityId) {
        let name = declared(self.config.machine_reported_name.as_deref());
        let model = declared(self.config.machine_reported_model.as_deref());
        let refreshed = self.with_write_txn_grouped(|txn| {
            let held = REPORTED_NAME.get(&self.store, txn, &this)?;
            if held
                .as_ref()
                .is_some_and(|held| held.name == name && held.model == model)
            {
                return Ok(());
            }
            let row = MachineReportedName {
                name: name.clone(),
                model: model.clone(),
                written_at: written_at_past_in_txn(self, txn, held.map(|held| held.written_at))?,
            };
            REPORTED_NAME.put(&self.store, txn, &this, &row)
        });
        if let Err(error) = refreshed {
            tracing::debug!(%error, "this install's reported machine name was not kept");
        }
    }
}

/// The time a node dates a cell it writes: its recording clock, observed in `txn`, or one past
/// `held`, the time of the cell it replaces, when the clock is not past it.
pub(super) fn written_at_past_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    held: Option<u64>,
) -> Result<u64> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    Ok(held.map_or(now, |held| now.max(held.saturating_add(1))))
}

/// Merges `cells` from `source` in `txn`; returns how many cells changed.
fn merge_cells_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: CellSource,
    cells: Vec<MachineNameCell>,
) -> Result<usize> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut changed = 0;
    for cell in cells {
        if merge_cell_in_txn(vault, txn, &fold, source, cell)? {
            changed += 1;
        }
    }
    Ok(changed)
}

/// Merges one cell; `true` when it replaced the cell held here.
fn merge_cell_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    fold: &AuthorityView,
    source: CellSource,
    cell: MachineNameCell,
) -> Result<bool> {
    match cell {
        MachineNameCell::Owner {
            machine,
            name,
            written_at,
            writer,
            receipt,
        } => {
            if matches!(source, CellSource::Machine { peer } if peer != writer)
                || fold.machine(machine).is_none()
            {
                return Ok(false);
            }
            let Some(name) = judged_owner_name(name) else {
                return Ok(false);
            };
            let Some(receipt) = oneiron_hex::decode_any_case::<16>(&receipt) else {
                return Ok(false);
            };
            let held = OWNER_NAME.get(&vault.store, txn, &machine)?;
            if held
                .as_ref()
                .is_some_and(|held| (held.written_at, held.writer) >= (written_at, Some(writer)))
            {
                return Ok(false);
            }
            let row = MachineOwnerName {
                name: name.unwrap_or_default(),
                receipt,
                written_at,
                writer: Some(writer),
            };
            super::put_owner_name_in_txn(vault, txn, machine, held.as_ref(), &row)?;
            Ok(true)
        }
        MachineNameCell::Reported {
            machine,
            name,
            model,
            written_at,
        } => {
            let refused = match source {
                CellSource::Home { this } => machine == this,
                CellSource::Machine { peer } => machine != peer,
            };
            if refused || fold.machine(machine).is_none() {
                return Ok(false);
            }
            if !judged_report(name.as_deref()) || !judged_report(model.as_deref()) {
                return Ok(false);
            }
            let held = REPORTED_NAME.get(&vault.store, txn, &machine)?;
            if held
                .as_ref()
                .is_some_and(|held| held.written_at >= written_at)
            {
                return Ok(false);
            }
            REPORTED_NAME.put(
                vault,
                txn,
                &machine,
                &MachineReportedName {
                    name,
                    model,
                    written_at,
                },
            )?;
            Ok(true)
        }
    }
}

/// An owner name as its writer's door would have kept it: `Some(None)` for a clear,
/// `Some(Some(name))` for a trimmed name of one line without NUL and at most
/// [`MACHINE_NAME_MAX_BYTES`] bytes, `None` for any other text.
fn judged_owner_name(name: Option<String>) -> Option<Option<String>> {
    let Some(name) = name else {
        return Some(None);
    };
    let kept = name.trim() == name
        && !name.is_empty()
        && name.len() <= MACHINE_NAME_MAX_BYTES
        && !name.contains(['\n', '\r', '\0']);
    kept.then_some(Some(name))
}

/// Whether a reported name or model reads as its writer's host declaration left it.
fn judged_report(text: Option<&str>) -> bool {
    text.is_none_or(|text| declared(Some(text)).as_deref() == Some(text))
}

/// Every cell held here for a machine the fold names, for the home's answer. `this` is the
/// home's own machine, the writer of an owner row written before rows were dated.
fn held_cells_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    this: Option<EntityId>,
) -> Result<Vec<MachineNameCell>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut cells = Vec::new();
    for (machine, row) in REPORTED_NAME.scan(&vault.store, txn)? {
        if fold.machine(machine).is_some() {
            cells.push(reported_cell(machine, row));
        }
    }
    for (machine, row) in OWNER_NAME.scan(&vault.store, txn)? {
        let Some(writer) = row.writer.or(this) else {
            continue;
        };
        if fold.machine(machine).is_some() {
            cells.push(owner_cell(machine, row, writer));
        }
    }
    Ok(cells)
}

/// The cell of one reported row.
fn reported_cell(machine: EntityId, row: MachineReportedName) -> MachineNameCell {
    MachineNameCell::Reported {
        machine,
        name: row.name,
        model: row.model,
        written_at: row.written_at,
    }
}

/// The cell of one owner row; `writer` stands in for a row written before rows were dated.
fn owner_cell(machine: EntityId, row: MachineOwnerName, writer: EntityId) -> MachineNameCell {
    MachineNameCell::Owner {
        machine,
        name: (!row.name.is_empty()).then_some(row.name),
        written_at: row.written_at,
        writer: row.writer.unwrap_or(writer),
        receipt: GateDecisionId::from_bytes(row.receipt).to_hex(),
    }
}
