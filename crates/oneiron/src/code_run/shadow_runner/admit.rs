//! A shadow arm's writes, masked at write (FIX 5718 part 3; shadow items 2
//! and 5; CALLS C5718-21). Every arm write that can hold run or model
//! content goes through the side-row wall's Masker, under the custody of
//! the arm's source vault, as kept content of the arm's source run: a whole
//! write (a gateway call's request and answer, the step's answer, its
//! program, its trailing speech, its two traces) and a stream or spill (its
//! console, its finish, a value it stores, a query's spill, a reply too
//! large for one message) each take the spool adapter of ruling 3, whose
//! whole read is the side-part admission, and a stored value's path is
//! named from its admitted digest. The custody records the wall mints are
//! the source vault's, in a short writer of their own; the arm's files stay
//! plain, and no other vault write reaches the arm. Seeded source bodies are
//! copied as is: their source admitted them.
//!
//! The prompt and wait copies an arm's result publishes inline take the
//! same wall, in one writer ([`admit_published_inline`]).

use std::sync::{Arc, Weak};

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::types::{ShadowRunResult, ShadowStatus};
use crate::batch::secret_scan::{BodySpool, SpoolAdmission, admit_spool_in_txn, admit_typed};
use crate::error::GateError;
use crate::secret_custody::KnownValues;
use crate::{EntityId, Error, Result, Vault};

/// Where the custody records the wall mints from an arm's write name what
/// they lifted, beside the arm's source run.
const ARM_PLACE: &str = "side:SHADOW_ARM";

/// Where those it mints from an arm result's inline copies name them.
const PUBLISHED_PLACE: &str = "side:SHADOW_ARM:published";

/// The vault an arm's writes are admitted under, and the source run their
/// content is kept content of.
#[derive(Debug, Clone)]
pub(super) struct ShadowAdmission {
    vault: Weak<Vault>,
    run: EntityId,
}

impl ShadowAdmission {
    pub(super) const fn new(vault: Weak<Vault>, run: EntityId) -> Self {
        Self { vault, run }
    }

    /// `spool`, one write of the arm, through the spool adapter, in a writer
    /// of the source vault that commits the custody records it mints.
    ///
    /// # Errors
    ///
    /// A source vault that is gone, and storage and custody errors.
    pub(super) fn admit<'s>(&self, spool: &'s BodySpool) -> Result<SpoolAdmission<'s>> {
        let vault = self.vault.upgrade().ok_or_else(|| {
            Error::InvalidConfig("a shadow arm's source vault is gone".to_owned())
        })?;
        let at = (ARM_PLACE, self.run.as_bytes().as_slice());
        let mut wtxn = vault.store.env.write_txn()?;
        let known = KnownValues::load_in_writer(&vault.store, &wtxn)?.map(Arc::new);
        let admitted = admit_spool_in_txn(&vault, &mut wtxn, at, spool, (known.as_ref(), false))?;
        if matches!(admitted, SpoolAdmission::Copy(_)) {
            wtxn.commit()?;
        }
        Ok(admitted)
    }
}

/// The prompt and wait copies `result` publishes inline, admitted by the
/// side-row wall under `vault`'s custody in one writer (FIX 5718 part 3):
/// each model receipt's expected route prompt and a waiting arm's wait
/// prompt. Each is a copy of a row its source admitted, so the wall mostly
/// finds nothing. A copy the wall cannot place is published as it was, as
/// before (an Ask-first stop).
///
/// # Errors
///
/// Storage and custody errors.
pub fn admit_published_inline(vault: &Vault, result: &mut ShadowRunResult) -> Result<()> {
    let Some(step) = result.step else {
        return Ok(());
    };
    let waiting = matches!(result.status, ShadowStatus::Waiting { .. });
    if result.model_receipts.is_empty() && !waiting {
        return Ok(());
    }
    let at = (PUBLISHED_PLACE, step.run.as_bytes().as_slice());
    let mut wtxn = vault.store.env.write_txn()?;
    for receipt in &mut result.model_receipts {
        admit_or_keep(vault, &mut wtxn, at, &mut receipt.expected.captured)?;
    }
    if let ShadowStatus::Waiting { wait } = &mut result.status {
        admit_or_keep(vault, &mut wtxn, at, &mut **wait)?;
    }
    wtxn.commit()?;
    Ok(())
}

/// `value`, admitted in place; one the wall cannot place is kept as it was.
fn admit_or_keep<T: Serialize + DeserializeOwned>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    at: (&str, &[u8]),
    value: &mut T,
) -> Result<()> {
    match admit_typed(vault, wtxn, at, value) {
        Ok(_) | Err(Error::Gate(GateError::GateWriteRejected { .. })) => Ok(()),
        Err(error) => Err(error),
    }
}
