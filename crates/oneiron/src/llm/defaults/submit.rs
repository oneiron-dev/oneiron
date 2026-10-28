//! The raw replacement of the inference defaults under the vault's policy
//! power (FIX 8211). Entry: `Vault::submit_purpose_default_table`.
//!
//! A live policy-power holder's table lands at once, as the owner's always
//! has: a live Owner, or an Admin or Delegate whose Owner-minted
//! `policy.change` grant names the defaults' exact target, found again in
//! the writing transaction. Anyone else's table is kept as an inert
//! proposal and the active defaults stay as they are; nothing is refused for
//! want of the power. The resident door's no-widening rule is not this
//! door's: a holder both tightens and loosens.

use serde::{Deserialize, Serialize};

use super::{POLICY, read_effective_defaults};
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::llm::PurposeDefaultTable;
use crate::policy_model::{PolicyRowScope, holds_vault_policy_power_in_txn, policy_row_grant_target};
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

/// A replacement table kept for a holder's later say. It changes nothing
/// until a holder submits a table of their own.
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
}

/// What one submission did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurposeDefaultSubmission {
    /// A holder's table: the active defaults now.
    Landed(PurposeDefaultTable),
    /// Anyone else's table, kept; the active defaults are unchanged.
    Proposed(PurposeDefaultProposal),
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
                let target = purpose_default_grant_target();
                if holds_vault_policy_power_in_txn(self, &txn, actor, &target, now)? {
                    let prior = read_effective_defaults(&self.store, &txn)?;
                    record_policy_setting_act_in_txn(
                        self,
                        &mut txn,
                        PolicySetting::InferenceDefaults,
                        actor,
                        surface,
                        prior.table(),
                    )?;
                    POLICY.put(&self.store, &mut txn, &(), table)?;
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
        };
        PROPOSALS.put(&self.store, &mut txn, &id, &proposal)?;
        txn.commit()?;
        Ok(PurposeDefaultSubmission::Proposed(proposal))
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
