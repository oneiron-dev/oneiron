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
use oneiron_verb_wire::dreamer_wake::sieve::policy::invalid;

/// Per-vault sieve dials. Confidences and band edges are percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePolicy {
    /// Turns one pass reads; the rest wait for the next pass.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over looking for turns.
    /// The late sweep of the cursor's own second is not capped by it.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass hashes and reads for spans. A turn with
    /// more is read a segment at a time and keeps its place at a segment's
    /// end; the next pass reads on from there, so nothing past the bound is
    /// dropped. A pass's first segment reads whatever the bound, so every
    /// pass moves a read on.
    pub max_text_bytes_per_pass: u32,
    /// Interest of a date span at full confidence.
    pub date_interest: u32,
    /// Interest of a name span at full confidence.
    pub name_interest: u32,
    pub absolute_date_confidence: u8,
    pub relative_date_confidence: u8,
    pub vague_date_confidence: u8,
    pub name_confidence: u8,
    pub initial_name_confidence: u8,
    pub katakana_name_confidence: u8,
    /// Below this a span is low interest; it is still kept.
    pub uncertain_low: u8,
    /// From `uncertain_low` up to this a span is uncertain and owes the
    /// typing rung; at or above it the span is sure.
    pub uncertain_high: u8,
}

impl SievePolicy {
    fn validate(self) -> Result<Self> {
        let confidences = [
            self.absolute_date_confidence,
            self.relative_date_confidence,
            self.vague_date_confidence,
            self.name_confidence,
            self.initial_name_confidence,
            self.katakana_name_confidence,
            self.uncertain_high,
        ];
        if self.max_turns_per_pass == 0
            || self.max_text_bytes_per_pass == 0
            || self.max_scan_per_pass < self.max_turns_per_pass
            || confidences.iter().any(|value| *value > 100)
            || self.uncertain_low > self.uncertain_high
        {
            return Err(invalid());
        }
        Ok(self)
    }

    pub(super) const fn rule_confidence(&self, class: RuleClass) -> u8 {
        match class {
            RuleClass::AbsoluteDate => self.absolute_date_confidence,
            RuleClass::RelativeDate => self.relative_date_confidence,
            RuleClass::VagueDate => self.vague_date_confidence,
            RuleClass::Name => self.name_confidence,
            RuleClass::InitialName => self.initial_name_confidence,
            RuleClass::KatakanaName => self.katakana_name_confidence,
        }
    }

    /// BLAKE3 of the row's canonical JSON: which policy scored a span.
    pub(super) fn digest(&self) -> Result<[u8; 32]> {
        let json = serde_json::to_vec(self).map_err(|_| invalid())?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-sieve:policy:v1");
        hash.update(&json);
        Ok(*hash.finalize().as_bytes())
    }
}

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
