//! Recoverable output references and local derived summaries (ARCH-0026).
//! The durable bytes never enter a decay operation. Only the context view changes.

use crate::{Error, Result, Vault};
use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Host-owned working output span. Raw bytes live in the owning routed side store;
/// entries keep source references across context assembly and compaction.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OutputWorkingContext {
    entries: Vec<WorkingOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkingOutput {
    entry: OutputContextEntry,
    recoverable_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWorkingContextWire {
    entries: Vec<WorkingOutput>,
}

impl<'de> Deserialize<'de> for OutputWorkingContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = OutputWorkingContextWire::deserialize(deserializer)?;
        if wire
            .entries
            .windows(2)
            .any(|pair| pair[0].entry.created_turn > pair[1].entry.created_turn)
        {
            return Err(de::Error::custom("output turns must be ordered"));
        }
        Ok(Self {
            entries: wire.entries,
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
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            hash: *blake3::hash(bytes).as_bytes(),
            byte_len: bytes.len() as u64,
        }
    }

    pub fn verify(self, bytes: &[u8]) -> Result<()> {
        if Self::from_bytes(bytes) != self {
            return Err(Error::CorruptedIndex("recoverable output integrity"));
        }
        Ok(())
    }
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
        self.record_referenced(turn, source, overview)?;
        Ok(source)
    }

    /// Register a reference already durably stored by the owning host route.
    /// The assembler verifies source bytes whenever it expands a full view.
    pub fn record_referenced(
        &mut self,
        turn: u64,
        source: OutputRef,
        overview: impl Into<String>,
    ) -> Result<()> {
        if self
            .entries
            .last()
            .is_some_and(|last| turn < last.entry.created_turn)
        {
            return Err(Error::InvalidConfig("output turns must be ordered".into()));
        }
        self.entries.push(WorkingOutput {
            entry: OutputContextEntry {
                source,
                created_turn: turn,
                overview: overview.into(),
            },
            recoverable_only: false,
        });
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Assemble the ordered working-context output views at the current turn.
    /// Compacted spans stay as actionable stubs, even when still young.
    pub fn assemble(
        &self,
        vault: &Vault,
        turn: u64,
        policy: OutputDecayPolicy,
    ) -> Result<Vec<OutputContextView>> {
        self.assemble_with(turn, policy, |source| restore_output(vault, source))
    }

    /// Assemble through the owner's own routed raw-output store. The callback
    /// is invoked for full views only; overview and stub never read raw bytes.
    pub fn assemble_with(
        &self,
        turn: u64,
        policy: OutputDecayPolicy,
        mut restore: impl FnMut(OutputRef) -> Result<Vec<u8>>,
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
                    item.entry.view_with(turn, policy, &mut restore)
                }
            })
            .collect()
    }

    /// Move exactly the committed turn span to recoverable references.
    /// Does not remove entries or mutate the side-store bytes.
    pub(crate) fn compact_span(&mut self, first: u64, last: u64) {
        for item in &mut self.entries {
            if (first..=last).contains(&item.entry.created_turn) {
                item.recoverable_only = true;
            }
        }
    }
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
        self.view_with(turn, policy, &mut |source| restore_output(vault, source))
    }

    fn view_with(
        &self,
        turn: u64,
        policy: OutputDecayPolicy,
        restore: &mut impl FnMut(OutputRef) -> Result<Vec<u8>>,
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
            let bytes = restore(self.source)?;
            self.source.verify(&bytes)?;
            (OutputTier::Full, bytes)
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
    let source = OutputRef::from_bytes(bytes);
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
    source.verify(&bytes)?;
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
