//! Display-edit proposals (FIX [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]: "an agent
//! may file it as an ask the owner answers"; Engine RULING DISPLAY-EDIT-PROPOSAL-SCOPE = A, Mon 16
//! Nov 04:46). An agent proposes a secret's label or purpose, or a machine's name, and the owner
//! accepts or declines it.
//!
//! The agent never writes the edited row. A proposal raises one inbox Ask per live owner. The
//! owner's accept runs the owner's own door ([`Vault::set_secret_handle_label`],
//! [`Vault::set_secret_handle_purpose`], [`Vault::set_machine_owner_name`]) inside the accept's
//! writer, so the Gate record names the accepting owner and refuses what the door refuses, and
//! the proposal closes in that same writer. A decline changes nothing else. An answered or
//! replaced proposal is deleted, and its Asks are settled.
//!
//! What an agent may propose: a secret by any handle the reveal door resolves for it, with the
//! reveal door's refusals (a secret a run found only by that run, FIX 8028); a machine by its id,
//! any machine of this vault. One open proposal per agent, edit and subject: a newer one replaces
//! it. An agent keeps at most the owner's cap of open ones (32 by default). A proposed value and its
//! why are one line each and are scanned as a reveal's why is, so a credential in them refuses.
//! A proposal never expires.

pub(crate) mod tables;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Every open proposal. Key: the proposal.
const PROPOSALS: SideTable<EntityId, ProposalRow, Named> =
    SideTable::new(&side_table::DISPLAY_EDIT_PROPOSAL);

/// Producer name of a display-edit proposal's inbox Ask.
pub const NOTIFICATION_PRODUCER_DISPLAY_EDIT: &str = "display_edit.proposal";

/// What a proposal's notice says. The proposal and its subject ride in the
/// notice's result and subjects.
const DISPLAY_EDIT_NOTICE_DETAIL: &str =
    "an agent proposes a name or a purpose; accept or decline it at the display-edit door";

/// The open proposals one agent keeps by default (Engine RULING
/// DISPLAY-EDIT-PROPOSAL-SCOPE = A): the default of the owner's Setting key
/// `display_edits.max_open_per_agent`, which waits on the Setting primitive.
pub const DISPLAY_EDITS_MAX_OPEN_PER_AGENT_DEFAULT: usize = 32;

/// The longest proposed purpose and the longest why, in bytes: a reveal's
/// why's cap.
pub const DISPLAY_EDIT_TEXT_MAX_BYTES: usize = 512;

/// The edit a proposal asks the owner to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisplayEditTarget {
    /// A secret's display label, set at [`Vault::set_secret_handle_label`].
    SecretLabel,
    /// What a secret is for, set at [`Vault::set_secret_handle_purpose`].
    SecretPurpose,
    /// The owner's name for one of his machines, set at
    /// [`Vault::set_machine_owner_name`].
    MachineName,
}

/// One open proposal, as the owner's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayEditProposal {
    /// The proposal.
    pub id: EntityId,
    /// The edit it asks for.
    pub target: DisplayEditTarget,
    /// What it edits: a secret's bare handle, or a machine's 32 hex.
    pub subject: String,
    /// The proposed text; `None` asks the owner to clear it.
    pub value: Option<String>,
    /// The agent's one-line why.
    pub why: String,
    /// The proposing agent.
    pub proposer: EntityId,
    /// When it was filed (recording seconds).
    pub proposed_at: u64,
}

/// An accepted proposal and the Gate receipt of the owner's act it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayEditAccepted {
    /// The proposal, closed now.
    pub proposal: DisplayEditProposal,
    /// The owner's act's Gate receipt, `gate:<32 hex>`.
    pub receipt: String,
}

/// The agent a proposal is filed for, as its host bound it: never a field
/// the agent sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisplayEditProposer {
    /// The proposing agent.
    pub(crate) agent: EntityId,
    /// The leased try the agent's run holds: the run a run-bound secret's
    /// record names (FIX 8028); `None` for an agent no run binds.
    pub(crate) attempt: Option<crate::AttemptId>,
}

/// One stored proposal: the edit, its subject (the bare handle or the
/// machine's hex, and the record it names), the proposed text, the agent's
/// why, who filed it and when, and the inbox Asks it raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProposalRow {
    target: DisplayEditTarget,
    subject: String,
    subject_ref: EntityId,
    value: Option<String>,
    why: String,
    proposer: EntityId,
    proposed_at: u64,
    notices: Vec<EntityId>,
}

impl ProposalRow {
    fn proposal(&self, id: EntityId) -> DisplayEditProposal {
        DisplayEditProposal {
            id,
            target: self.target,
            subject: self.subject.clone(),
            value: self.value.clone(),
            why: self.why.clone(),
            proposer: self.proposer,
            proposed_at: self.proposed_at,
        }
    }
}

/// The open proposals one agent may keep (Engine RULING
/// DISPLAY-EDIT-PROPOSAL-SCOPE = A): the owner's Setting key
/// `display_edits.max_open_per_agent` once the Setting primitive lands, read
/// here; until then its default.
pub(crate) fn max_open_per_agent_in_txn(_vault: &Vault, _txn: &RoTxn<'_>) -> usize {
    DISPLAY_EDITS_MAX_OPEN_PER_AGENT_DEFAULT
}

impl Vault {
    /// Files an agent's proposal of a display edit for the owner to answer,
    /// in one write transaction: checks the text, resolves the subject as
    /// the module doc says, replaces the agent's open proposal of the same
    /// edit on the same subject, holds the agent to its open cap, and raises
    /// one inbox Ask per live owner. Nothing it names changes.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`] for an empty, overlong or
    /// multi-line why, a value past its door's cap or holding a line break
    /// or NUL, and an agent at its open cap; the scan's refusal for a
    /// credential in either. What handle resolution returns for a secret no
    /// live custody record names, and the reveal door's refusal of another
    /// run's secret. [`Error::EntityNotFound`] for a machine id that is not
    /// 32 hex or names no machine of this vault.
    pub(crate) fn propose_display_edit(
        &self,
        proposer: &DisplayEditProposer,
        target: DisplayEditTarget,
        subject: &str,
        value: Option<&str>,
        why: &str,
    ) -> Result<DisplayEditProposal> {
        let why = proposal_why(why)?;
        let value = proposed_value(target, value)?;
        let id = self.store.clock.entity_id()?;
        self.with_write_txn_grouped(|txn| {
            let (subject, subject_ref) = match target {
                DisplayEditTarget::SecretLabel | DisplayEditTarget::SecretPurpose => self
                    .display_edit_secret_subject_in_txn(txn, subject, proposer.attempt.as_ref())?,
                DisplayEditTarget::MachineName => {
                    let machine =
                        EntityId::from_hex(subject.trim()).map_err(|_| Error::EntityNotFound)?;
                    if self
                        .authority_view_readonly_in_txn(txn)?
                        .machine(machine)
                        .is_none()
                    {
                        return Err(Error::EntityNotFound);
                    }
                    (machine.to_hex(), machine)
                }
            };
            let mut open = 0usize;
            for (held_id, mut held) in PROPOSALS.scan(&self.store, txn)? {
                if held.proposer != proposer.agent {
                    continue;
                }
                if held.target == target && held.subject_ref == subject_ref {
                    settle_notices_in_txn(self, txn, &mut held)?;
                    PROPOSALS.delete(&self.store, txn, &held_id)?;
                } else {
                    open += 1;
                }
            }
            if open >= max_open_per_agent_in_txn(self, txn) {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "the agent holds as many open display-edit proposals as the owner allows; the owner answers them first",
                )));
            }
            let mut row = ProposalRow {
                target,
                subject,
                subject_ref,
                value,
                why,
                proposer: proposer.agent,
                proposed_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                notices: Vec::new(),
            };
            notify_owners_in_txn(self, txn, &id, &mut row)?;
            PROPOSALS.put(&self.store, txn, &id, &row)?;
            Ok(row.proposal(id))
        })
    }

    /// Every open display-edit proposal, newest first, under the owner's
    /// proof.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's; storage errors.
    pub fn display_edit_proposals(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<DisplayEditProposal>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let mut proposals: Vec<DisplayEditProposal> = PROPOSALS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(id, row)| row.proposal(id))
            .collect();
        proposals.sort_by(|a, b| {
            b.proposed_at
                .cmp(&a.proposed_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(proposals)
    }

    /// The owner accepts a proposal: in one writer, his door makes the edit
    /// as his own act, and the proposal closes and its Asks are settled.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's. [`Error::EntityNotFound`] for a proposal that is not open.
    /// Whatever the owner's door refuses (a secret or machine gone since, a
    /// value the door does not take); the proposal then stays open.
    pub fn accept_display_edit(
        &self,
        owner: &AuthenticatedOwner,
        proposal: EntityId,
    ) -> Result<DisplayEditAccepted> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut row = PROPOSALS
                .get(&self.store, txn, &proposal)?
                .ok_or(Error::EntityNotFound)?;
            let value = row.value.as_deref();
            let receipt = match row.target {
                DisplayEditTarget::SecretLabel => {
                    self.set_secret_handle_label_in_txn(txn, owner, &row.subject, value)?
                        .receipt
                }
                DisplayEditTarget::SecretPurpose => {
                    self.set_secret_handle_purpose_in_txn(txn, owner, &row.subject, value)?
                        .receipt
                }
                DisplayEditTarget::MachineName => {
                    self.set_machine_owner_name_in_txn(txn, owner, row.subject_ref, value)?
                        .receipt
                }
            };
            settle_notices_in_txn(self, txn, &mut row)?;
            PROPOSALS.delete(&self.store, txn, &proposal)?;
            Ok(DisplayEditAccepted {
                proposal: row.proposal(proposal),
                receipt,
            })
        })
    }

    /// The owner declines a proposal: it closes and its Asks are settled;
    /// nothing it names changes.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's. [`Error::EntityNotFound`] for a proposal that is not open.
    pub fn decline_display_edit(
        &self,
        owner: &AuthenticatedOwner,
        proposal: EntityId,
    ) -> Result<DisplayEditProposal> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut row = PROPOSALS
                .get(&self.store, txn, &proposal)?
                .ok_or(Error::EntityNotFound)?;
            settle_notices_in_txn(self, txn, &mut row)?;
            PROPOSALS.delete(&self.store, txn, &proposal)?;
            Ok(row.proposal(proposal))
        })
    }
}

/// The agent's why: one line of 1..=[`DISPLAY_EDIT_TEXT_MAX_BYTES`] bytes
/// after trimming, with no credential in it, as a reveal's why.
fn proposal_why(why: &str) -> Result<String> {
    let why = why.trim();
    if why.is_empty() {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a display-edit proposal says why",
        )));
    }
    if why.len() > DISPLAY_EDIT_TEXT_MAX_BYTES || why.contains(['\n', '\r', '\0']) {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a display-edit proposal's why is one line of at most 512 bytes",
        )));
    }
    crate::batch::secret_scan::scan_metadata_field(why)?;
    Ok(why.to_owned())
}

/// The proposed text, trimmed: `None` for a clear (none, or blank), else one
/// line without NUL within the cap of the owner's door it goes to, with no
/// credential in it.
fn proposed_value(target: DisplayEditTarget, value: Option<&str>) -> Result<Option<String>> {
    let Some(text) = value.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    let cap = match target {
        DisplayEditTarget::SecretLabel => crate::secret_custody::SECRET_NAME_MAX_BYTES,
        DisplayEditTarget::SecretPurpose => DISPLAY_EDIT_TEXT_MAX_BYTES,
        DisplayEditTarget::MachineName => crate::machine_names::MACHINE_NAME_MAX_BYTES,
    };
    if text.len() > cap {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a proposed value is longer than the owner's door takes",
        )));
    }
    if text.contains(['\n', '\r', '\0']) {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a proposed value is one line without NUL",
        )));
    }
    crate::batch::secret_scan::scan_metadata_field(text)?;
    Ok(Some(text.to_owned()))
}

/// Raises a proposal's inbox Asks: one [`NotificationKind::Ask`] notice per
/// live owner, keyed by the proposal and the owner, whose result names the
/// proposal and whose subjects name the secret's record or the machine. The
/// ids land on the row.
fn notify_owners_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    proposal: &EntityId,
    row: &mut ProposalRow,
) -> Result<()> {
    let proposal_hex = proposal.to_hex();
    let mut notices = Vec::new();
    for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
        notices.push(vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_DISPLAY_EDIT.to_owned(),
                    event: format!("{proposal_hex}:{}", owner.to_hex()),
                    result: Some(proposal_hex.clone()),
                    detail: Some(DISPLAY_EDIT_NOTICE_DETAIL.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: vec![row.subject_ref],
                recipient: Some(owner),
                created_at: row.proposed_at,
                origin_conversation: None,
            },
        )?);
    }
    row.notices = notices;
    Ok(())
}

/// Settles the inbox Asks `row` raised: each id still a live NOTIFICATION is
/// marked seen and acked for the owner it was raised for, as a settled
/// reveal ask's are; then the row holds none. A notice already acked, or
/// gone, stays as it is.
fn settle_notices_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &mut ProposalRow) -> Result<()> {
    for notice in &row.notices {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*txn, notice)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let Some(owner) = body.recipient.clone() else {
            continue;
        };
        if body.acked_by.get(&owner) == Some(&true) {
            continue;
        }
        body.seen_by.insert(owner.clone(), true);
        body.acked_by.insert(owner, true);
        vault.put_notification_in_txn(txn, notice, &body)?;
    }
    row.notices.clear();
    Ok(())
}

/// The actor scrub of the proposal table: an erased agent's
/// open proposals are deleted, and their Asks settled (FIX 3520).
///
/// # Errors
/// Storage errors.
pub(crate) fn erase_display_edit_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    for (id, mut row) in PROPOSALS.scan(&vault.store, txn)? {
        if row.proposer == *actor {
            settle_notices_in_txn(vault, txn, &mut row)?;
            PROPOSALS.delete(&vault.store, txn, &id)?;
        }
    }
    Ok(())
}
