//! The owner's setting proposals (stage 7b-3; DESIGN 1.6, "Receipts"): every setting act that
//! waits for his proof (row CARRIER-OWNER-PROOF), with the row it names and the value it would
//! leave.
//!
//! Each is one of the fold's waiting owner choices, which the held-answer list names by entry
//! (`HeldAnswerListing::waiting_choices`); this list shows what each would change. A proposal
//! changes nothing on any machine, and its row reads `Pending` while it asks. The owner applies
//! one with one tap: his own change of the row to that value, made on an install that can prove
//! it (his own machine, or one that holds his owner key). That change sees every head of the row,
//! and an owner's own recorded act on the row ends the ask of every proposal on it. An install
//! that cannot prove it refuses the tap (`OwnerKeyRequired`), and the proposal keeps asking. A
//! tap on a proposal whose value the row already holds as the owner's writes nothing (the
//! setter's no-op rule), so that proposal keeps asking until his next change of the row.

use oneiron_authority::authority::{AuthorityEntryHash, OwnerActKind};
use oneiron_setting_contract::RowKey;

use super::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{Vault, authority::SettingSlotHead};

/// The proposal a tap named is not one the list holds now: the owner answered it since, or it
/// never was one.
const STALE: &str = "the setting proposals changed since they were read: read the list again";

/// One setting act that waits for the owner's proof, as his list shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingProposal {
    /// The act's log entry: what a tap names.
    pub entry: AuthorityEntryHash,
    /// The key's name.
    pub key: String,
    pub item: Option<String>,
    pub mode: SettingMode,
    pub scope: SettingScope,
    /// The value the act would leave, as its JSON; `None` for a clear.
    pub value: Option<serde_json::Value>,
    /// The machine that carried it.
    pub carrier: EntityId,
}

/// The proposal `head` is, read back from the log: `None` for an act that names no row, or one
/// whose value is only a digest (stage 7a-1), which no tap can make again.
fn proposal_of(head: &SettingSlotHead) -> Option<SettingProposal> {
    let set = head.set.as_ref()?;
    if set.act.act != OwnerActKind::PolicySetting {
        return None;
    }
    let value = match (&set.value, &set.inline) {
        (None, _) => None,
        (Some(_), Some(bytes)) => Some(serde_json::from_slice(bytes).ok()?),
        (Some(_), None) => return None,
    };
    let slot = set.slot.clone().unwrap_or_else(|| RowKey {
        name: set.setting.clone(),
        item: None,
        mode: SettingMode::Value,
        scope: SettingScope::Vault,
    });
    Some(SettingProposal {
        entry: head.act,
        key: slot.name,
        item: slot.item,
        mode: slot.mode,
        scope: slot.scope,
        value,
        carrier: set.machine,
    })
}

impl Vault {
    /// Every setting act that waits for the owner's proof and still asks, each with its row and
    /// the value it would leave, by entry (module doc). Empty in a vault with no authority root.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn setting_proposals(&self) -> Result<Vec<SettingProposal>> {
        let txn = self.store.env.read_txn()?;
        let mut proposals = Vec::new();
        for (target, entry) in self.asking_setting_acts_in_txn(&txn)? {
            let head = self.setting_slot_head_in_txn(&txn, target, entry)?;
            proposals.extend(proposal_of(&head));
        }
        proposals.sort_by_key(|proposal| proposal.entry);
        Ok(proposals)
    }

    /// The owner applies `proposal`, one his list showed, with one tap (module doc): his own
    /// change of its row to its value, from this install, judged by the setter's door like any
    /// change of his. A batch act that waits names several rows, each its own proposal under the
    /// one entry: the tap names the entry and the row, and changes that row alone.
    ///
    /// # Errors
    ///
    /// `ConcurrentWrite` when `proposal` is no proposal that still asks; the door's refusal,
    /// among them `OwnerKeyRequired` where this install cannot prove the owner's act; storage
    /// errors.
    pub fn apply_setting_proposal(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &SettingProposal,
    ) -> Result<SetSettingOutcome> {
        let proposal = self
            .setting_proposals()?
            .into_iter()
            .find(|listed| listed == proposal)
            .ok_or(Error::ConcurrentWrite(STALE))?;
        self.set_setting(
            SettingCaller::Owner(owner),
            SetSetting {
                key: proposal.key,
                item: proposal.item,
                scope: proposal.scope,
                mode: proposal.mode,
                value: proposal.value,
                expected_revision: None,
                why: None,
                check_in_ref: None,
                weight_runs: None,
                surface: None,
            },
        )
    }
}
