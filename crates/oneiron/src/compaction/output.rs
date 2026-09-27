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

impl OutputContextEntry {
    /// Persist a raw tool or agent result before handing context to a model.
    /// The returned working entry contains only a handle and host-supplied
    /// overview; callers explicitly reexpand the source when needed.
    pub fn capture(
        vault: &Vault,
        bytes: &[u8],
        created_turn: u64,
        overview: String,
    ) -> Result<Self> {
        Ok(Self {
            source: store_output(vault, bytes)?,
            created_turn,
            overview,
        })
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

impl OutputRef {
    /// Portable handle for an output that stays valid after context compaction.
    #[must_use]
    pub fn handle(self) -> String {
        format!(
            "output:blake3:{}:{}",
            blake3::Hash::from(self.hash).to_hex(),
            self.byte_len
        )
    }

    /// Parse a handle before trying to restore the named bytes.
    pub fn from_handle(handle: &str) -> Result<Self> {
        let invalid = || Error::CorruptedIndex("recoverable output handle");
        let rest = handle.strip_prefix("output:blake3:").ok_or_else(invalid)?;
        let (hex, len) = rest.split_once(':').ok_or_else(invalid)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid());
        }
        let hash = blake3::Hash::from_hex(hex).map_err(|_| invalid())?;
        let byte_len = len.parse::<u64>().map_err(|_| invalid())?;
        if len != byte_len.to_string() {
            return Err(invalid());
        }
        Ok(Self {
            hash: *hash.as_bytes(),
            byte_len,
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
