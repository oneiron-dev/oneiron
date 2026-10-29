//! The raw replacement of the inference defaults under the vault's policy
//! power (FIX 8211). Entry: `Vault::submit_purpose_default_table`,
//! `Vault::rule_purpose_default_proposal`.
//!
//! A live policy-power holder's table lands at once, as the owner's always
//! has: a live Owner, or an Admin or Delegate whose Owner-minted
//! `policy.change` grant names the defaults' exact target, found again in
//! the writing transaction. Anyone else's table is kept as an inert
//! proposal and the active defaults stay as they are; nothing is refused for
//! want of the power. A holder later approves or declines a kept proposal,
//! under the same check in the ruling's own transaction. The resident door's
//! no-widening rule is not this door's: a holder both tightens and loosens.

use serde::{Deserialize, Serialize};

use super::POLICY;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::llm::PurposeDefaultTable;
use crate::policy_model::{
    PolicyRowScope, holds_vault_policy_power_in_txn, policy_row_grant_target,
};
use crate::policy_setting_doors::{PolicySetting, record_policy_setting_act_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The tables kept for a holder's later say, by proposal id.
const PROPOSALS: SideTable<EntityId, PurposeDefaultProposal, Named> =
    SideTable::new(&side_table::LLM_PURPOSE_DEFAULT_PROPOSAL);

/// Who submits a replacement table.
#[derive(Debug, Clone, Copy)]
pub enum PurposeDefaultSubmitter<'a> {
    /// A person on their own proof, revalidated in the writing transaction:
    /// a live policy-power holder's table lands, anyone else's is kept.
    Person(&'a AuthenticatedOwner),
    /// A principal with no person proof, by its id. It holds no policy
    /// power, so its table is kept.
    Principal(EntityId),
}

/// Where a kept proposal stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeDefaultProposalStatus {
    /// No holder has answered it; it changes nothing.
    Pending,
    /// A holder approved it, and its table became the active defaults.
    Approved { holder: String, at: u64 },
    /// A holder declined it; the active defaults stayed as they were.
    Declined { holder: String, at: u64 },
}

/// A replacement table kept for a holder's say. It changes nothing unless a
/// holder approves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeDefaultProposal {
    /// The proposal's id, as hex.
    pub proposal_id: String,
    /// Who submitted it, as hex.
    pub author: String,
    /// The validated table it proposes.
    pub table: PurposeDefaultTable,
    /// Vault clock seconds.
    pub at: u64,
    /// Whether a holder has answered it, and how.
    pub status: PurposeDefaultProposalStatus,
}

/// What one submission did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurposeDefaultSubmission {
    /// A holder's table: the active defaults now.
    Landed(PurposeDefaultTable),
    /// Anyone else's table, kept; the active defaults are unchanged.
    Proposed(PurposeDefaultProposal),
}

/// The defaults a replacement replaces, as its act records them: the stored
/// table, valid or not; the shipped rows where none is stored; the stored
/// text where it does not decode. The prior table's validity never admits
/// or refuses a replacement.
#[derive(Serialize)]
#[serde(untagged)]
enum StoredDefaults {
    Table(PurposeDefaultTable),
    Text(String),
}

/// The exact target of the power over the inference defaults: the
/// vault-scope row target of `settings.inference_defaults`, which an Owner's
/// `policy.change` grant names to give an Admin or Delegate this power.
#[must_use]
pub fn purpose_default_grant_target() -> String {
    policy_row_grant_target(
        &PolicyRowScope::Vault,
        PolicySetting::InferenceDefaults.as_str(),
    )
}

impl Vault {
    /// Whether `actor` holds the policy power over the defaults in `txn`.
    fn holds_defaults_power_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        now: u64,
    ) -> Result<bool> {
        holds_vault_policy_power_in_txn(self, txn, actor, &purpose_default_grant_target(), now)
    }

    /// Makes `table` the active defaults in `txn` for the holder `actor`,
    /// recording an owner's act where `surface` names one.
    fn land_defaults_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        table: &PurposeDefaultTable,
        surface: Option<ActSurface>,
    ) -> Result<()> {
        let prior = match POLICY.get_bytes(&self.store, txn, &())? {
            None => StoredDefaults::Table(PurposeDefaultTable::default()),
            Some(bytes) => match POLICY.decode_value(&bytes) {
                Ok(table) => StoredDefaults::Table(table),
                Err(_) => StoredDefaults::Text(String::from_utf8_lossy(&bytes).into_owned()),
            },
        };
        let signed = record_policy_setting_act_in_txn(
            self,
            txn,
            PolicySetting::InferenceDefaults,
            actor,
            surface,
            &prior,
            table,
        )?;
        POLICY.put(&self.store, txn, &(), table)?;
        // The signed record goes last, best effort (FIX 4624).
        if let Some(act) = signed {
            self.record_policy_setting_op_in_txn(txn, act);
        }
        Ok(())
    }

    /// Replaces the inference defaults with `table` when `submitter` holds
    /// the vault's policy power over them in the writing transaction, and
    /// otherwise keeps `table` as an inert proposal (FIX 8211). A holder who
    /// is the owner acting through `surface` has the act recorded with the
    /// table it replaces; with no `surface`, none is recorded.
    ///
    /// # Errors
    /// A table that does not validate, a person proof that no longer holds,
    /// or a store failure.
    pub fn submit_purpose_default_table(
        &self,
        submitter: PurposeDefaultSubmitter<'_>,
        table: &PurposeDefaultTable,
        surface: Option<ActSurface>,
        now: u64,
    ) -> Result<PurposeDefaultSubmission> {
        table.validate()?;
        let mut txn = self.store.env.write_txn()?;
        let author = match submitter {
            PurposeDefaultSubmitter::Person(person) => {
                let actor = person.revalidate_person_in_txn(self, &txn)?;
                if self.holds_defaults_power_in_txn(&txn, actor, now)? {
                    self.land_defaults_in_txn(&mut txn, actor, table, surface)?;
                    txn.commit()?;
                    return Ok(PurposeDefaultSubmission::Landed(table.clone()));
                }
                actor
            }
            PurposeDefaultSubmitter::Principal(actor) => actor,
        };
        let id = self.store.clock.entity_id()?;
        let proposal = PurposeDefaultProposal {
            proposal_id: id.to_hex(),
            author: author.to_hex(),
            table: table.clone(),
            at: now,
            status: PurposeDefaultProposalStatus::Pending,
        };
        PROPOSALS.put(&self.store, &mut txn, &id, &proposal)?;
        txn.commit()?;
        Ok(PurposeDefaultSubmission::Proposed(proposal))
    }

    /// A holder's answer to the kept proposal `proposal_id`: approved, its
    /// table becomes the active defaults through the holder's own landing
    /// (never the unchecked setter); declined, nothing changes. The holder's
    /// person proof and policy power are checked in the ruling's own
    /// transaction; the first holder to answer settles it.
    ///
    /// # Errors
    /// `Refused` for a person who holds no policy power over the defaults;
    /// `EntityNotFound` for no such proposal; `ConcurrentWrite` for one
    /// already answered; a proof that no longer holds, a table that no longer
    /// validates, or a store failure.
    pub fn rule_purpose_default_proposal(
        &self,
        holder: &AuthenticatedOwner,
        proposal_id: &str,
        approve: bool,
        surface: Option<ActSurface>,
        now: u64,
    ) -> Result<PurposeDefaultProposal> {
        let id = EntityId::from_hex(proposal_id).map_err(|_| Error::EntityNotFound)?;
        let mut txn = self.store.env.write_txn()?;
        let actor = holder.revalidate_person_in_txn(self, &txn)?;
        if !self.holds_defaults_power_in_txn(&txn, actor, now)? {
            return Err(Error::Refused(
                "a live policy-power holder is required".to_owned(),
            ));
        }
        let mut proposal = PROPOSALS
            .get(&self.store, &txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if proposal.status != PurposeDefaultProposalStatus::Pending {
            return Err(Error::ConcurrentWrite("the proposal is already answered"));
        }
        let holder = actor.to_hex();
        proposal.status = if approve {
            proposal.table.validate()?;
            self.land_defaults_in_txn(&mut txn, actor, &proposal.table, surface)?;
            PurposeDefaultProposalStatus::Approved { holder, at: now }
        } else {
            PurposeDefaultProposalStatus::Declined { holder, at: now }
        };
        PROPOSALS.put(&self.store, &mut txn, &id, &proposal)?;
        txn.commit()?;
        Ok(proposal)
    }

    /// Every kept inference-defaults proposal, oldest id first.
    ///
    /// # Errors
    /// A store read that fails.
    pub fn purpose_default_proposals(&self) -> Result<Vec<PurposeDefaultProposal>> {
        let txn = self.store.env.read_txn()?;
        Ok(PROPOSALS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, proposal)| proposal)
            .collect())
    }
}
