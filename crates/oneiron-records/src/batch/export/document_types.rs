//! Moved from `crates/oneiron/src/batch/export/document_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

pub const WHOLE_VAULT_DOCUMENT_VERSION: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSourceVault {
    pub vault_id: Option<String>,
    pub exported_at: u64,
}

/// Where one lineage's highest removed epoch summary left the count
/// (OF-013): its epoch and the turn it ended at, nothing it said. A lineage
/// is a session's own log, or one conversation's turns within a session
/// (FIX 5029). An import raises the local floor to it and never lowers one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEpochFloor {
    /// The session's id, hex.
    pub session: String,
    /// The conversation's id, hex, for a conversation's lineage; absent for
    /// the session's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    pub epoch: u64,
    pub turn_end: u64,
}

/// The code runs' results (OF-190 B++): each run's result manifests, and
/// each body they name once. An off-record run's results never reach the
/// base vault, so no export holds them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRunResults {
    pub runs: Vec<ExportRun>,
    pub bodies: Vec<ExportResultBody>,
}

/// One run's results, as its replay record names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRun {
    pub run_id: String,
    /// Host-witnessed birth world, or required `null` when unknown. Not a
    /// residence receipt or a complete served-world capture.
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    pub birth_world: Option<String>,
    pub outputs: Vec<ExportRunOutput>,
    /// The run's live result names. A binding whose occurrence was withheld
    /// keeps its name and reason but no handle.
    pub bindings: Vec<ExportRunBinding>,
    /// Frozen nondeterministic inputs when the replay record supplied them.
    /// Required on export and import; `null` means unknown, not zero.
    #[serde(deserialize_with = "Option::<ExportDeterminism>::deserialize")]
    pub determinism: Option<ExportDeterminism>,
    /// The run's fold receipts (ARCH-0079 #reader-forks), each beside the
    /// manifest of the occurrence it describes.
    pub receipts: Vec<ExportReaderFold>,
}

/// One archived result name and the occurrence it names: its path and its
/// output handle. Same bytes under different paths are distinct
/// occurrences, so the path is required. The handle is absent exactly when
/// the occurrence's egress judgment withheld it; the name, path and reason
/// still travel then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRunBinding {
    pub name: String,
    pub path: String,
    pub handle: Option<String>,
    pub withheld: Option<String>,
}

/// The replay record's frozen nondeterministic inputs. No bridge calls or
/// checkpoints travel here; full replayability remains FIX 12543.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDeterminism {
    pub frozen_unix_ms: u64,
    /// Lowercase hex, 64 characters.
    pub rng_seed: String,
}

/// One fold receipt: the path of the folded occurrence in its run, and the
/// receipt. A withheld occurrence's receipt carries its marker and its
/// occurrence refs only, and `withheld` says why; it holds no content
/// either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReaderFold {
    pub path: String,
    pub receipt: serde_json::Value,
    pub withheld: Option<String>,
}

/// One result occurrence's manifest. Its preview and line index are derived
/// from the body, so an import rebuilds them rather than reading them here.
/// The egress door judges each occurrence on its own (Docs Q08): a withheld
/// one says why and names no body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRunOutput {
    pub path: String,
    /// The body's BLAKE3, lowercase hex: its key in `bodies`. `None` when
    /// this occurrence is withheld.
    pub blake3: Option<String>,
    pub bytes: u64,
    pub kind: String,
    pub lines: u64,
    pub complete: bool,
    /// Why this occurrence is withheld: the secret scan marked it, or it
    /// carries taint refs.
    pub withheld: Option<String>,
}

/// One result body, which a clean occurrence names. Its text goes out
/// through the release door's scan; `content` is `None` when the body is
/// withheld, and `withheld` says why: the release scan found a credential
/// in it, or no row holds it any longer (`absent`). A body that is no UTF-8
/// text goes in the archive's `files/` with neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportResultBody {
    pub blake3: String,
    pub bytes: u64,
    pub content: Option<String>,
    pub withheld: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEdge {
    pub source: String,
    pub kind: u8,
    pub target: String,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<[f32; 3]>,
    pub provenance: Option<[u8; 2]>,
}

/// Built-in adapters are code registrations, not runtime SKILL records. The
/// descriptor identifies the decoder; it does not claim to contain its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportAdapterDescriptor {
    pub source_id: String,
    pub adapter_skill_id: Option<String>,
    pub adapter_version: Option<String>,
}
