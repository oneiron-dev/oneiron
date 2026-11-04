//! A PERSON's own billing account, as that PERSON filed it (FIX 3332).
//!
//! Canon names no source for the account of a PERSON who is not one of the
//! vault's Owners (ARCH-0011: billing is one per owner, and the hosted cloud
//! holds the card token), so the PERSON files it: one row binding their own
//! principal to the account their room-paid calls bill. The host's payer
//! resolver reads it ([`PayerAccount::Person`](super::PayerAccount::Person));
//! a PERSON with no row keeps the owners' payer-needed ask.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
pub use crate::store::person_billing_account::FiledBillingAccount;
use crate::store::person_billing_account::PERSON_BILLING_ACCOUNT;

/// The longest account reference a PERSON may file, in bytes (CALLS).
pub const MAX_BILLING_ACCOUNT_BYTES: usize = 256;

/// `self.billing.account.file`'s input: the caller's own billing account.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BillingAccountFiling {
    /// The account the caller's room-paid calls bill, 1 to 256 bytes with no
    /// control character; empty withdraws the caller's filing.
    pub account: String,
}

impl Vault {
    /// Files `account` as `person`'s own billing account, replacing any the
    /// PERSON filed before; an empty `account` withdraws it. Answers the row
    /// that now stands.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an account over
    /// [`MAX_BILLING_ACCOUNT_BYTES`] or with a control character; storage
    /// errors.
    pub fn file_own_billing_account(
        &self,
        person: EntityId,
        account: &str,
    ) -> Result<Option<FiledBillingAccount>> {
        if account.len() > MAX_BILLING_ACCOUNT_BYTES || account.chars().any(char::is_control) {
            return Err(Error::InvalidConfig(
                "a billing account is at most 256 bytes with no control character".into(),
            ));
        }
        let filed = (!account.is_empty()).then(|| FiledBillingAccount {
            account: account.to_owned(),
            filed_at: self.now_recorded_at(),
        });
        self.with_write_txn(|wtxn| {
            match &filed {
                Some(row) => PERSON_BILLING_ACCOUNT.put(&self.store, wtxn, &person, row)?,
                None => {
                    PERSON_BILLING_ACCOUNT.delete(&self.store, wtxn, &person)?;
                }
            }
            Ok(())
        })?;
        Ok(filed)
    }

    /// The billing account `person` filed as their own, if any.
    ///
    /// # Errors
    ///
    /// Storage and decode errors.
    pub fn own_billing_account(&self, person: &EntityId) -> Result<Option<FiledBillingAccount>> {
        let rtxn = self.store.env.read_txn()?;
        PERSON_BILLING_ACCOUNT.get(&self.store, &rtxn, person)
    }
}

/// `self.billing.account.file`: the caller files its own billing account,
/// bound to its own principal, never another's.
///
/// # Errors
///
/// As [`Vault::file_own_billing_account`].
pub fn file_self_billing_account(
    memory: &Memory<'_>,
    input: &BillingAccountFiling,
) -> MemoryResult<Option<FiledBillingAccount>> {
    Ok(memory
        .vault()
        .file_own_billing_account(memory.actor(), &input.account)?)
}
