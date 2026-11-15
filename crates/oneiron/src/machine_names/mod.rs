//! The names the owner's machine list shows (FIX [DEVICE-DISPLAY-NAME]; Engine TASK
//! SECRETS-VIEW-ROWS, Mon 16 Nov 00:55: a display-only owner row keyed by machine id, outside
//! the signed machine profile, never read by authority, policy or routing; by default the name
//! the device reports, else its class; the owner renames).
//!
//! A machine is named by the first of: the owner's own name for it (this module's side table,
//! set through [`Vault::set_machine_owner_name`]), the name the machine reports for itself, the
//! model it reports, and its class (`Phone`, `Computer`). This install reports its own name and
//! model as its host declares them (`VaultConfig::machine_reported_name`,
//! `VaultConfig::machine_reported_model`). Another machine's report, and a name the owner gave
//! on another machine, reach this install through its residence home on each steady pass
//! ([`exchange`]): every node holds the latest dated cell of each, and a clear is a dated cell
//! without a name.
//!
//! Display only. Nothing here enters the signed machine profile, and no authority, policy or
//! routing code reads it: a name changes no machine's revision, role or reach.

pub(crate) mod exchange;
pub(crate) mod tables;

pub use exchange::MachineNameCell;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{FoldedMachine, MachineDeviceClass, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

/// The owner's own name for each of his machines. Key: the MACHINE row.
const OWNER_NAME: SideTable<EntityId, MachineOwnerName, Named> =
    SideTable::new(&side_table::MACHINE_OWNER_NAME);

/// The longest name, in bytes, a machine is shown by: the owner's, and a
/// host's report, which is cut to it.
pub const MACHINE_NAME_MAX_BYTES: usize = 128;

/// Gate reason code: the owner named one of his machines.
const OWNER_NAME_REASON_SET: &str = "gate.machine.owner_name.set";
/// Gate reason code: the owner cleared his name for one of his machines.
const OWNER_NAME_REASON_CLEARED: &str = "gate.machine.owner_name.cleared";
/// The Gate content kind of a machine-name ruling.
const OWNER_NAME_CONTENT_KIND: &str = "machine_owner_name";

/// One owner name: the text the side-row wall stored, empty for a clear (a
/// dated cell without a name), the Gate receipt of the act that wrote it on
/// its writer, and the cell's date: the writer's recording time and the
/// writer's MACHINE row. The Gate row behind the receipt, on the writer,
/// carries who set it. A row written before rows were dated reads as dated
/// 0 by no writer, and so loses to every dated cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MachineOwnerName {
    pub(crate) name: String,
    pub(crate) receipt: [u8; 16],
    #[serde(default)]
    pub(crate) written_at: u64,
    #[serde(default)]
    pub(crate) writer: Option<EntityId>,
}

/// Whether a masked copy of an owner-name row still reads as one, for the
/// historical lift sweep's acceptance check.
pub(crate) fn accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<MachineOwnerName, Named>(bytes)
}

/// Where the name a machine is shown by comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MachineNameSource {
    /// The owner's own name for it.
    Owner,
    /// The name the machine reports for itself.
    Reported,
    /// The model the machine reports for itself.
    Model,
    /// Its class: `Phone` or `Computer`.
    Class,
}

/// One machine of the owner's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineListing {
    /// The MACHINE row.
    pub machine: EntityId,
    /// Its class, as its profile names it.
    pub class: MachineDeviceClass,
    /// The roster chain's role, as `GET /v1/owner/machines/answer` reads it;
    /// `None` with no roster chain.
    pub role: Option<MachineRole>,
    /// Whether any chain of it stands live here.
    pub live: bool,
    /// The name it is shown by.
    pub name: String,
    /// Where [`Self::name`] comes from.
    pub name_source: MachineNameSource,
    /// The owner's own name for it, as the side-row wall stored it.
    pub owner_name: Option<String>,
    /// The name it reports for itself.
    pub reported_name: Option<String>,
    /// The model it reports for itself.
    pub reported_model: Option<String>,
    /// Whether it is this install's own machine.
    pub this_install: bool,
    /// Its answer revision, which an answer or a removal presents back as
    /// `seen`. A name never moves it.
    pub revision: [u8; 32],
}

/// What a machine-name act left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineOwnerNameSet {
    /// The machine as the list shows it now.
    pub machine: MachineListing,
    /// The act's Gate receipt, `gate:<id>`.
    pub receipt: String,
}

impl Vault {
    /// Every machine the authority fold names, this install's first, each
    /// with the name it is shown by, read in one snapshot under the owner's
    /// proof. A removed machine stays in the list, its role `Removed`.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's; the store's and the fold's.
    pub fn machine_list(&self, owner: &AuthenticatedOwner) -> Result<Vec<MachineListing>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let this = self.serving_machine_in_txn(&txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let mut machines = Vec::with_capacity(fold.machines.len());
        for (machine, folded) in &fold.machines {
            if let Some(listing) =
                self.machine_listing_in_txn(&txn, *machine, folded, this == Some(*machine))?
            {
                machines.push(listing);
            }
        }
        machines.sort_by_key(|listing| !listing.this_install);
        Ok(machines)
    }

    /// Sets the owner's own name for one of his machines, or clears it when
    /// `name` is `None` or blank, so the machine is shown by its report or
    /// class again. Either way a Gate record keeps the act, the row's receipt
    /// is its link to it, and the row is dated past the cell it replaces, so
    /// the act wins on every machine of the owner's the home reaches
    /// ([`exchange`]). The name is admitted by the
    /// side-row wall, as any authored text is, and validated like a label:
    /// trimmed, one line, no NUL, at most [`MACHINE_NAME_MAX_BYTES`] bytes.
    /// Display only: the machine's profile, revision, role and reach do not
    /// move.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. [`Error::EntityNotFound`] for a machine the authority
    /// fold does not name. [`GateError::InvalidConsentBound`] for a name past
    /// the byte cap, or one holding a line break or NUL.
    pub fn set_machine_owner_name(
        &self,
        owner: &AuthenticatedOwner,
        machine: EntityId,
        name: Option<&str>,
    ) -> Result<MachineOwnerNameSet> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let serving = self.serving_machine_in_txn(txn)?;
            let this_install = serving == Some(machine);
            let folded = self
                .authority_view_readonly_in_txn(txn)?
                .machine(machine)
                .cloned()
                .ok_or(Error::EntityNotFound)?;
            let trimmed = name.map(str::trim).filter(|text| !text.is_empty());
            if let Some(text) = trimmed {
                if text.len() > MACHINE_NAME_MAX_BYTES {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "a machine name is at most 128 bytes",
                    )));
                }
                if text.contains(['\n', '\r', '\0']) {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "a machine name is one line without NUL",
                    )));
                }
            }
            let decision =
                append_owner_name_ruling_in_txn(self, txn, actor, machine, trimmed.is_some())?;
            let held = OWNER_NAME.get(&self.store, txn, &machine)?;
            let written_at = exchange::written_at_past_in_txn(
                self,
                txn,
                held.as_ref().map(|held| held.written_at),
            )?;
            let row = MachineOwnerName {
                name: trimmed.unwrap_or_default().to_owned(),
                receipt: decision.as_bytes(),
                written_at,
                writer: serving,
            };
            put_owner_name_in_txn(self, txn, machine, held.as_ref(), &row)?;
            let listing = self
                .machine_listing_in_txn(txn, machine, &folded, this_install)?
                .ok_or(Error::EntityNotFound)?;
            Ok(MachineOwnerNameSet {
                machine: listing,
                receipt: format!("gate:{}", decision.to_hex()),
            })
        })
    }

    /// One machine as the list shows it, read in `txn`: `None` for a folded
    /// machine with no chain, which names no class.
    fn machine_listing_in_txn(
        &self,
        txn: &RoTxn<'_>,
        machine: EntityId,
        folded: &FoldedMachine,
        this_install: bool,
    ) -> Result<Option<MachineListing>> {
        let Some(chain) = folded
            .roster
            .as_ref()
            .or_else(|| folded.chains().next().map(|(_, chain)| chain))
        else {
            return Ok(None);
        };
        let class = chain.profile.device_class;
        let owner_name = OWNER_NAME
            .get(&self.store, txn, &machine)?
            .map(|row| row.name)
            .filter(|name| !name.is_empty());
        let (reported_name, reported_model) = if this_install {
            (
                declared(self.config.machine_reported_name.as_deref()),
                declared(self.config.machine_reported_model.as_deref()),
            )
        } else {
            exchange::REPORTED_NAME
                .get(&self.store, txn, &machine)?
                .map_or((None, None), |row| (row.name, row.model))
        };
        let (name, name_source) = shown_name(
            owner_name.as_deref(),
            reported_name.as_deref(),
            reported_model.as_deref(),
            class,
        );
        Ok(Some(MachineListing {
            machine,
            class,
            role: folded.roster.as_ref().map(|roster| roster.profile.role),
            live: folded.chains().any(|(_, chain)| chain.is_live()),
            name,
            name_source,
            owner_name,
            reported_name,
            reported_model,
            this_install,
            revision: folded.answer_revision(),
        }))
    }
}

/// The name a machine is shown by, and where it comes from: the owner's,
/// else the reported name, else the reported model, else the class word.
fn shown_name(
    owner: Option<&str>,
    reported: Option<&str>,
    model: Option<&str>,
    class: MachineDeviceClass,
) -> (String, MachineNameSource) {
    if let Some(name) = owner {
        (name.to_owned(), MachineNameSource::Owner)
    } else if let Some(name) = reported {
        (name.to_owned(), MachineNameSource::Reported)
    } else if let Some(model) = model {
        (model.to_owned(), MachineNameSource::Model)
    } else {
        let word = match class {
            MachineDeviceClass::Phone => "Phone",
            MachineDeviceClass::Computer => "Computer",
        };
        (word.to_owned(), MachineNameSource::Class)
    }
}

/// A host's report as the list shows it: its first line, trimmed, without
/// NUL or other control characters, cut to [`MACHINE_NAME_MAX_BYTES`] at a
/// character boundary; `None` when nothing is left.
fn declared(report: Option<&str>) -> Option<String> {
    let line: String = report?
        .lines()
        .next()?
        .chars()
        .filter(|ch| !ch.is_control())
        .collect();
    let line = line.trim();
    let mut end = line.len().min(MACHINE_NAME_MAX_BYTES);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    let cut = line[..end].trim_end();
    (!cut.is_empty()).then(|| cut.to_owned())
}

/// Writes `row` as the owner's name for `machine`, through the side-row
/// wall. A clear (an empty name) over a held name first drops the custody
/// the wall lifted out of it, as an authored row's erase does; the dated
/// empty row stays, so the clear wins over the name it clears on every node.
fn put_owner_name_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    machine: EntityId,
    held: Option<&MachineOwnerName>,
    row: &MachineOwnerName,
) -> Result<()> {
    if row.name.is_empty() && held.is_some_and(|held| !held.name.is_empty()) {
        let place = format!("side:{}", OWNER_NAME.decl().name);
        let origin =
            crate::batch::secret_scan::side_row_origin(&place, &OWNER_NAME.key_bytes(&machine))?;
        crate::secret_custody::revoke_side_row_custody_in_txn(vault, txn, &origin, None)?;
    }
    OWNER_NAME.put(vault, txn, &machine, row)
}

/// Appends the owner's machine-name set or clear to the Gate receipt
/// family, in `txn`. The details name the machine and the act only, never
/// the name.
fn append_owner_name_ruling_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    machine: EntityId,
    set: bool,
) -> Result<GateDecisionId> {
    let (reason, action) = if set {
        (OWNER_NAME_REASON_SET, "action:set")
    } else {
        (OWNER_NAME_REASON_CLEARED, "action:cleared")
    };
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![reason.into()],
        receipt_reasons: Vec::new(),
        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
            OWNER_NAME_CONTENT_KIND,
            vec![format!("machine:{}", machine.to_hex()), action.to_owned()],
        ),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: OWNER_NAME_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: machine.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}
