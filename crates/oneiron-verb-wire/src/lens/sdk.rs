//! Moved from `crates/oneiron/src/lens/sdk.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_lens_wire::lens::generated_ui::GeneratedUiSurfaceCapabilities;
use serde::Deserialize;
use serde::Serialize;

/// One dossier section: its source and the title the caller gives it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDossierSource {
    /// A 32-hex entity id.
    pub entity_ref: String,
    pub title: String,
}

/// `vault.lenses.default`'s input: the sheet's title and the sources of its
/// ledger rows, dossier sections and thread entries, as 32-hex entity ids.
/// Thread sources are MESSAGE entities.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDefaultRequest {
    pub title: String,
    #[serde(default)]
    pub ledger: Vec<String>,
    #[serde(default)]
    pub dossiers: Vec<LensDossierSource>,
    #[serde(default)]
    pub threads: Vec<String>,
    /// An as-of instant in unix seconds: only sources that had occurred and
    /// been learned by then are selected, before composition. Omitted, the
    /// sources read live.
    #[serde(default)]
    pub as_of: Option<u64>,
    /// The surface profile this one call's card is lowered for (FIX 7969):
    /// its catalog and semver, the primitives and app components it draws
    /// and its stream profile. Omitted, a transport session's negotiated
    /// profile applies, else the whole atom kit. It selects a rendering and
    /// grants nothing.
    #[serde(default)]
    pub surface: Option<GeneratedUiSurfaceCapabilities>,
}

/// `vault.weave.lens`'s input: the weave report's sections, in order, as
/// `vault.weave.report` takes them, and the surface profile this one call's
/// card is lowered for (FIX 7969). Omitted, the profile the caller's MCP
/// call declared applies, else the whole atom kit. It selects a rendering
/// and grants nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensRequest {
    pub sections: Vec<crate::claim::WeaveSectionInput>,
    #[serde(default)]
    pub surface: Option<GeneratedUiSurfaceCapabilities>,
}
