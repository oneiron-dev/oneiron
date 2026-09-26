//! Recoverable output references and local derived summaries (ARCH-0026).
//! The durable bytes never enter a decay operation. Only the context view changes.

use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};

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

/// Host-owned working output span. Raw bytes live only in the vault side store;
/// entries keep source references across context assembly and compaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputWorkingContext {
    entries: Vec<WorkingOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkingOutput {
    entry: OutputContextEntry,
    recoverable_only: bool,
}

impl OutputWorkingContext {
    /// Capture an output at the host's turn boundary. Only its reference and
    /// overview enter working state; the original remains byte-exact on disk.
    pub fn record(
        &mut self,
        vault: &Vault,
        turn: u64,
        bytes: &[u8],
        overview: impl Into<String>,
    ) -> Result<OutputRef> {
        if self
            .entries
            .last()
            .is_some_and(|last| turn < last.entry.created_turn)
        {
            return Err(Error::InvalidConfig("output turns must be ordered".into()));
        }
        let source = store_output(vault, bytes)?;
        self.entries.push(WorkingOutput {
            entry: OutputContextEntry {
                source,
                created_turn: turn,
                overview: overview.into(),
            },
            recoverable_only: false,
        });
        Ok(source)
    }

    /// Assemble the ordered working-context output views at the current turn.
    /// Compacted spans stay as actionable stubs, even when still young.
    pub fn assemble(
        &self,
        vault: &Vault,
        turn: u64,
        policy: OutputDecayPolicy,
    ) -> Result<Vec<OutputContextView>> {
        if policy.overview_after_turns > policy.stub_after_turns {
            return Err(Error::InvalidConfig(
                "output decay tiers are reversed".into(),
            ));
        }
        self.entries
            .iter()
            .filter(|item| item.entry.created_turn <= turn)
            .map(|item| {
                if item.recoverable_only {
                    Ok(item.entry.stub_view())
                } else {
                    item.entry.view(vault, turn, policy)
                }
            })
            .collect()
    }

    /// Move exactly the committed turn span to recoverable references.
    /// Does not remove entries or mutate the side-store bytes.
    pub(super) fn compact_span(&mut self, first: u64, last: u64) {
        for item in &mut self.entries {
            if (first..=last).contains(&item.entry.created_turn) {
                item.recoverable_only = true;
            }
        }
    }
}

impl OutputContextEntry {
    fn stub_view(&self) -> OutputContextView {
        OutputContextView {
            source: self.source,
            tier: OutputTier::Stub,
            bytes: Vec::new(),
            affordances: [
                OutputAffordance::Reexpand(self.source),
                OutputAffordance::Summarize(self.source),
            ],
        }
    }

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

fn output_key(source: OutputRef) -> Vec<u8> {
    [b"context:output:v1:".as_slice(), &source.hash].concat()
}

/// Vault-local content-addressed side store. No interpretation or claim write.
pub fn store_output(vault: &Vault, bytes: &[u8]) -> Result<OutputRef> {
    let source = OutputRef {
        hash: *blake3::hash(bytes).as_bytes(),
        byte_len: bytes.len() as u64,
    };
    let key = output_key(source);
    vault.with_write_txn(|txn| {
        if let Some(existing) = vault.store.vault_meta.get(txn, &key)? {
            if existing.as_ref() != bytes {
                return Err(Error::CorruptedIndex("output content address"));
            }
        } else {
            vault.store.vault_meta.put(txn, &key, bytes)?;
        }
        Ok(())
    })?;
    Ok(source)
}

pub fn restore_output(vault: &Vault, source: OutputRef) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    let bytes = vault
        .store
        .vault_meta
        .get(&txn, &output_key(source))?
        .ok_or(Error::CorruptedIndex("missing recoverable output"))?;
    if bytes.len() as u64 != source.byte_len || blake3::hash(&bytes).as_bytes() != &source.hash {
        return Err(Error::CorruptedIndex("recoverable output integrity"));
    }
    Ok(bytes.to_vec())
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
    let key = [
        b"context:summary:v1:".as_slice(),
        &source.hash,
        blake3::hash(recipe).as_bytes(),
    ]
    .concat();
    {
        let txn = vault.store.env.read_txn()?;
        if let Some(raw) = vault.store.vault_meta.get(&txn, &key)? {
            return String::from_utf8(raw.to_vec())
                .map_err(|_| Error::CorruptedIndex("output summary"));
        }
    }
    let summary = summarize(&bytes)?;
    vault.with_write_txn(|txn| {
        if let Some(raw) = vault.store.vault_meta.get(txn, &key)? {
            return String::from_utf8(raw.to_vec())
                .map_err(|_| Error::CorruptedIndex("output summary"));
        }
        vault.store.vault_meta.put(txn, &key, summary.as_bytes())?;
        Ok(summary)
    })
}

#[cfg(test)]
mod tests;
