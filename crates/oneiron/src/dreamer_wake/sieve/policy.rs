//! The sieve's policy row: how much one pass reads, how interesting each kind
//! of span is, how sure each rule is, and where the uncertain band lies.
//! Every number is data the owner can change; the defaults ship as JSON.

use serde::{Deserialize, Serialize};

use super::rules::RuleClass;
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, SideTable};

const POLICY: SideTable<(), SievePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_SIEVE_POLICY);
const DEFAULT_POLICY: &str = include_str!("sieve_policy_defaults.json");

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_wake::sieve::policy::SievePolicy;
#[doc(hidden)]
use oneiron_verb_wire::dreamer_wake::sieve::policy::invalid;

pub(super) fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<SievePolicy> {
    let policy = match POLICY
        .get(&vault.store, txn, &())
        .map_err(|error| match error {
            Error::Store(crate::error::StoreError::SideTableRow { .. }) => invalid(),
            other => other,
        })? {
        Some(row) => row,
        None => serde_json::from_str(DEFAULT_POLICY).map_err(|_| invalid())?,
    };
    policy.validate()
}

impl Vault {
    /// The sieve policy row this vault reads, or the shipped defaults.
    pub fn dreamer_sieve_policy(&self) -> Result<SievePolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }

    /// An owner-authenticated sieve policy write. A new row scores the spans
    /// read after it; spans already queued keep the score they were given.
    pub fn set_dreamer_sieve_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: SievePolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            POLICY.put(&self.store, txn, &(), &policy)
        })
    }

    /// The owner, by its proof, or a holder of `engine.controls` lowers the
    /// sieve's per-pass budgets (untangle 6.6b, the B1 family; work budget;
    /// S66B-BUDGETS B1 = A; its verb is 6.6d's `vault.sieve.budgets.lower`).
    /// The values in force are the owner's cap: each new budget must be at
    /// or below its value in force, so this door never raises one. Raising a
    /// budget and every scoring field stay the owner's act, at
    /// `vault.sieve.policy.set`. Returns the receipt.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `actor` is neither the owner, by a proof that
    /// still holds, nor a live holder of `engine.controls`; for a budget
    /// above its value in force, or for a row the policy refuses; store
    /// failures.
    pub fn lower_dreamer_sieve_budgets_by(
        &self,
        actor: crate::federation::EngineControlActor<'_>,
        budgets: SievePassBudgets,
    ) -> Result<crate::entity_id::EntityId> {
        self.apply_engine_control(
            actor,
            crate::federation::EngineControlClass::WorkBudget,
            "DREAMER_SIEVE_POLICY",
            &crate::federation::rendered_change(&budgets)?,
            |txn| {
                let held = policy_in_txn(self, &*txn)?;
                if budgets.max_turns_per_pass > held.max_turns_per_pass
                    || budgets.max_scan_per_pass > held.max_scan_per_pass
                    || budgets.max_text_bytes_per_pass > held.max_text_bytes_per_pass
                {
                    return Err(Error::InvalidConfig(
                        "this door only lowers the sieve's per-pass budgets; raising one is the owner's act at vault.sieve.policy.set"
                            .into(),
                    ));
                }
                let policy = SievePolicy {
                    max_turns_per_pass: budgets.max_turns_per_pass,
                    max_scan_per_pass: budgets.max_scan_per_pass,
                    max_text_bytes_per_pass: budgets.max_text_bytes_per_pass,
                    ..held
                }
                .validate()?;
                POLICY.put(&self.store, txn, &(), &policy)
            },
        )
    }

    /// [`Self::lower_dreamer_sieve_budgets_by`] for a holder of
    /// `engine.controls` (untangle 6.6b).
    ///
    /// # Errors
    ///
    /// As [`Self::lower_dreamer_sieve_budgets_by`].
    pub fn lower_dreamer_sieve_budgets_as_holder(
        &self,
        holder: crate::entity_id::EntityId,
        budgets: SievePassBudgets,
    ) -> Result<crate::entity_id::EntityId> {
        self.lower_dreamer_sieve_budgets_by(
            crate::federation::EngineControlActor::Holder(holder),
            budgets,
        )
    }
}

/// The sieve's three per-pass work budgets, the part of its policy a holder
/// of `engine.controls` may lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SievePassBudgets {
    /// Turns one pass reads.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass reads.
    pub max_text_bytes_per_pass: u32,
}
