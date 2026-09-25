//! Recoverable output references and local derived summaries (ARCH-0026).
//! The durable bytes never enter a decay operation. Only the context view changes.

use crate::side_table::{self, Raw, SideTable};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};

/// Vault-local content-addressed store of a recoverable full tool/agent output blob. Key: hash32.
const OUTPUT_BLOB: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::COMPACTION_OUTPUT_BLOB);

/// Immutable derived text summary of one output, keyed by source content hash and
/// summarization-recipe hash. Key: hash32 + hash32.
const OUTPUT_SUMMARY: SideTable<([u8; 32], [u8; 32]), String, Raw> =
    SideTable::new(&side_table::COMPACTION_OUTPUT_SUMMARY);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRef {
    pub hash: [u8; 32],
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputTier {
    Full,
    Overview,
    Stub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputAffordance {
    Reexpand(OutputRef),
    Summarize(OutputRef),
}

/// Working state carries references, never the raw tool or agent output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputContextEntry {
    pub source: OutputRef,
    pub created_turn: u64,
    pub overview: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputDecayPolicy {
    pub overview_after_turns: u64,
    pub stub_after_turns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputContextView {
    pub source: OutputRef,
    pub tier: OutputTier,
    pub bytes: Vec<u8>,
    pub affordances: [OutputAffordance; 2],
}

impl OutputContextEntry {
    pub fn view(
        &self,
        vault: &Vault,
        turn: u64,
        policy: OutputDecayPolicy,
    ) -> Result<OutputContextView> {
        if policy.overview_after_turns > policy.stub_after_turns {
            return Err(Error::InvalidConfig(
                "output decay tiers are reversed".into(),
            ));
        }
        let age = turn.saturating_sub(self.created_turn);
        let (tier, bytes) = if age >= policy.stub_after_turns {
            (OutputTier::Stub, Vec::new())
        } else if age >= policy.overview_after_turns {
            (OutputTier::Overview, self.overview.as_bytes().to_vec())
        } else {
            (OutputTier::Full, restore_output(vault, self.source)?)
        };
        Ok(OutputContextView {
            source: self.source,
            tier,
            bytes,
            affordances: [
                OutputAffordance::Reexpand(self.source),
                OutputAffordance::Summarize(self.source),
            ],
        })
    }
}

/// Vault-local content-addressed side store. No interpretation or claim write.
pub fn store_output(vault: &Vault, bytes: &[u8]) -> Result<OutputRef> {
    let source = OutputRef {
        hash: *blake3::hash(bytes).as_bytes(),
        byte_len: bytes.len() as u64,
    };
    vault.with_write_txn(|txn| {
        if let Some(existing) = OUTPUT_BLOB.get(&vault.store, txn, &source.hash)? {
            if existing.as_slice() != bytes {
                return Err(Error::CorruptedIndex("output content address"));
            }
        } else {
            OUTPUT_BLOB.put(&vault.store, txn, &source.hash, &bytes.to_vec())?;
        }
        Ok(())
    })?;
    Ok(source)
}

pub fn restore_output(vault: &Vault, source: OutputRef) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    let bytes = OUTPUT_BLOB
        .get(&vault.store, &txn, &source.hash)?
        .ok_or(Error::CorruptedIndex("missing recoverable output"))?;
    if bytes.len() as u64 != source.byte_len || blake3::hash(&bytes).as_bytes() != &source.hash {
        return Err(Error::CorruptedIndex("recoverable output integrity"));
    }
    Ok(bytes)
}

/// Summary is an immutable derived projection keyed by source and recipe version.
/// The callback runs outside the write transaction. A racing first writer wins.
pub fn summarize_output(
    vault: &Vault,
    source: OutputRef,
    recipe: &[u8],
    summarize: impl FnOnce(&[u8]) -> Result<String>,
) -> Result<String> {
    let bytes = restore_output(vault, source)?;
    let key = (source.hash, *blake3::hash(recipe).as_bytes());
    {
        let txn = vault.store.env.read_txn()?;
        if let Some(existing) = OUTPUT_SUMMARY.get(&vault.store, &txn, &key)? {
            return Ok(existing);
        }
    }
    let summary = summarize(&bytes)?;
    vault.with_write_txn(|txn| {
        if let Some(existing) = OUTPUT_SUMMARY.get(&vault.store, txn, &key)? {
            return Ok(existing);
        }
        OUTPUT_SUMMARY.put(&vault.store, txn, &key, &summary)?;
        Ok(summary)
    })
}

#[cfg(test)]
mod tests;
