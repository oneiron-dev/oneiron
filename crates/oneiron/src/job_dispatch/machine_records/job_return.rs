//! `JOB_RETURN` (pass 33 row R4; EM-12 = A): what the issuer did with one ended key's outputs.
//! The row opens when the key's end is confirmed. It names each returnable output that landed
//! as a proposal and each that never will, and it is done once the node answered the
//! acknowledgement that lets it clean the payload. A result that binds a handoff manifest (row
//! RSI-ARTIFACT-HANDOFF) keeps the row owed after the acknowledgement until the manifest lands
//! or is refused.

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

const JOB_RETURNS: SideTable<String, JobReturn, Named> = SideTable::new(&side_table::JOB_RETURN);

/// One output that will never land, and why: the vault refused the proposal, the node refused
/// the fetch, or the bytes did not match the signed digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnRefusal {
    pub name: String,
    pub why: String,
}

/// What became of one ended key's handoff manifest (row RSI-ARTIFACT-HANDOFF).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffReturn {
    /// Every output is decided and the manifest has not landed yet: asked again at each
    /// housekeeping pass, also after the acknowledgement.
    Owed,
    /// Landed as a proposal on the manifest artifact.
    Landed,
    /// It never lands, and why.
    Refused { why: String },
}

/// What the issuer did with one ended key's outputs. Key: the dispatch key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReturn {
    pub key: String,
    pub machine: EntityId,
    pub job: EntityId,
    /// The outputs that landed as proposals, by name.
    #[serde(default)]
    pub landed: Vec<String>,
    /// The outputs that will never land.
    #[serde(default)]
    pub refused: Vec<ReturnRefusal>,
    /// When the node answered the acknowledgement; `None` while the issuer still owes it.
    #[serde(default)]
    pub acknowledged_at_ms: Option<u64>,
    /// The handoff manifest, when the key's result binds one; `None` when it binds none, and
    /// on every row written before it. Left out of the encoding when `None`, so such a row
    /// encodes as before.
    #[serde(default)]
    pub handoff: Option<HandoffReturn>,
    pub opened_at_ms: u64,
    pub updated_at_ms: u64,
}

impl JobReturn {
    /// Whether the output `name` landed or was refused: nothing more is asked for it.
    #[must_use]
    pub fn is_decided(&self, name: &str) -> bool {
        self.landed.iter().any(|landed| landed == name)
            || self.refused.iter().any(|refused| refused.name == name)
    }
}

impl Vault {
    /// The return of the dispatch key `key`; `None` before its end was confirmed.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_return(&self, key: &str) -> crate::Result<Option<JobReturn>> {
        let txn = self.store.env.read_txn()?;
        JOB_RETURNS.get(&self.store, &txn, &key.to_owned())
    }

    /// Every return the issuer still owes an acknowledgement or a handoff manifest for, in key
    /// order.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_returns_owed(&self) -> crate::Result<Vec<JobReturn>> {
        let txn = self.store.env.read_txn()?;
        let rows = JOB_RETURNS.scan_from(&self.store, &txn, b"")?;
        Ok(rows
            .into_iter()
            .map(|(_, row)| row)
            .filter(|row| {
                row.acknowledged_at_ms.is_none() || row.handoff == Some(HandoffReturn::Owed)
            })
            .collect())
    }

    /// Writes the return of `key` (on `machine`, for `job`) at `now_ms` in one durable write: a
    /// new row the first time, then `change` applied to the row that stands. Answers the row as
    /// written.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn record_job_return(
        &self,
        key: &str,
        machine: EntityId,
        job: EntityId,
        now_ms: u64,
        change: impl FnOnce(&mut JobReturn),
    ) -> crate::Result<JobReturn> {
        let row_key = key.to_owned();
        self.with_write_txn(|txn| {
            let mut row = JOB_RETURNS
                .get(&self.store, txn, &row_key)?
                .unwrap_or_else(|| JobReturn {
                    key: row_key.clone(),
                    machine,
                    job,
                    landed: Vec::new(),
                    refused: Vec::new(),
                    acknowledged_at_ms: None,
                    handoff: None,
                    opened_at_ms: now_ms,
                    updated_at_ms: now_ms,
                });
            change(&mut row);
            row.updated_at_ms = row.updated_at_ms.max(now_ms);
            JOB_RETURNS.put(&self.store, txn, &row_key, &row)?;
            Ok(row)
        })
    }
}
