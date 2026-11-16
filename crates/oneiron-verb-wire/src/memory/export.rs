//! Moved from `crates/oneiron/src/memory/export.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::serialize::export_format::EXPORT_TARGET_ARCHIVE;
pub use oneiron_store::serialize::export_format::EXPORT_TARGET_OKF;
use serde::Deserialize;
use serde::Serialize;

/// The export target. `archive` (the default) is the whole vault: one ZIP of
/// one JSONL file per record kind, each attached file once by BLAKE3, and a
/// manifest. It re-imports into a fresh vault. `okf` is "Export to OKF": a
/// ZIP of markdown concepts with YAML frontmatter (Open Knowledge Format
/// v0.1) for other tools, lossy and labelled as not a full copy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportOptions {
    #[serde(default)]
    pub format: Option<String>,
    /// Whether the archive carries custody secret values. Absent means yes:
    /// "all your data is all your data" (owner, 2026-10-17). `false` exports
    /// each custody record as its handle only; a re-import lists those as
    /// missing secrets to re-enter.
    #[serde(default)]
    pub include_secrets: Option<bool>,
    /// How a server hands the export over (FIX 3676): absent or `inline`
    /// answers with the archive in the reply, as before; `transfer` keeps the
    /// built archive on the server and answers with an [`ExportTransfer`]
    /// naming it, read whole or in byte ranges. An embedded caller writes its
    /// own file through [`Memory::export_to`].
    #[serde(default)]
    pub delivery: Option<ExportDelivery>,
    /// FIX 4624(b): the linked machine the owner names to receive, sealed to
    /// it alone, each custody secret the archive carries as its handle
    /// because it did not open here; its holder seals it there. Absent, the
    /// export is as before and its receipt lists each such secret as
    /// unassigned: no recipient named.
    #[serde(default)]
    pub secrets_recipient: Option<EntityId>,
    /// Whether a code run calls this export: set by the host's run dispatch
    /// alone, never by a request. Such an export follows the world settings
    /// as it did before owner ruling 1-EXPORT = B (FIX 9591): it carries no
    /// row of a world they withhold from its destination and names none.
    /// The owner's own call keeps every world.
    #[serde(skip)]
    pub in_code_run: bool,
}

/// How a server hands one export over: in its reply, or as a transfer the
/// caller reads after it (FIX 3676).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExportDelivery {
    /// The archive in the reply, base64 (the default).
    #[default]
    Inline,
    /// The archive kept on the server, named by an [`ExportTransfer`].
    Transfer,
}
