//! The `pptx-live-v1` case manifest and the two fixture manifests it names.

use super::record::Res;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::path::Path;

/// The case manifest, relative to the repository root.
pub(super) const CASE_MANIFEST: &str = "scripts/office/pptx-live-v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseManifest {
    pub(super) profile: String,
    pub(super) version: u32,
    pub(super) baselines: Vec<BaselineSpec>,
    /// The live mutations step 2 exercises beside unknown XML.
    pub(super) edits: Vec<Recipe>,
    /// The concurrent cases step 4 merges in both orders.
    pub(super) concurrency: Vec<MergeCase>,
    /// The fixtures step 7 checks in PowerPoint beyond the PDF.
    pub(super) non_pdf: Vec<NonPdf>,
    pub(super) regression: RegressionSpec,
    pub(super) office: OfficeSpec,
}

/// One pinned baseline deck and the typed reads its import must give.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BaselineSpec {
    pub(super) id: String,
    /// Relative to the repository root.
    pub(super) path: String,
    pub(super) sha256: String,
    /// Per slide, in order: the plain text of each text shape in tree order.
    pub(super) typed: Vec<Vec<String>>,
}

/// One live mutation, applied to the baseline's first slide and its first
/// text shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Recipe {
    SetText,
    SetRunMarks,
    SetGeometry,
    SetPreset,
    AddShape,
    AddGroup,
    AddConnector,
    AddTable,
    AddChart,
    AddPicture,
    AddSlide,
    MoveShape,
    MoveCrossSlide,
    RemoveShape,
}

impl Recipe {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::SetText => "set_text",
            Self::SetRunMarks => "set_run_marks",
            Self::SetGeometry => "set_geometry",
            Self::SetPreset => "set_preset",
            Self::AddShape => "add_shape",
            Self::AddGroup => "add_group",
            Self::AddConnector => "add_connector",
            Self::AddTable => "add_table",
            Self::AddChart => "add_chart",
            Self::AddPicture => "add_picture",
            Self::AddSlide => "add_slide",
            Self::MoveShape => "move_shape",
            Self::MoveCrossSlide => "move_cross_slide",
            Self::RemoveShape => "remove_shape",
        }
    }
}

/// The seven concurrent cases of ARCH-0077 ("both move" split into its
/// differing and agreeing halves).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MergeCase {
    BothMove,
    BothMoveSame,
    DeleteGroupEditChild,
    ReparentGeometry,
    TextAnimationRange,
    ThemeInheritedStyle,
    BothReplaceOpaque,
    BothAddShape,
}

impl MergeCase {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::BothMove => "both_move",
            Self::BothMoveSame => "both_move_same",
            Self::DeleteGroupEditChild => "delete_group_edit_child",
            Self::ReparentGeometry => "reparent_geometry",
            Self::TextAnimationRange => "text_animation_range",
            Self::ThemeInheritedStyle => "theme_inherited_style",
            Self::BothReplaceOpaque => "both_replace_opaque",
            Self::BothAddShape => "both_add_shape",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum NonPdf {
    /// A modern comment on the edited slide, kept and read by PowerPoint.
    ModernComment,
    /// A paragraph build on the edited text shape.
    AnimatedText,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegressionSpec {
    pub(super) pptarena: CorpusSpec,
    pub(super) adversarial: AdversarialSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorpusSpec {
    /// The pinned PPTArena manifest, relative to the repository root.
    pub(super) manifest: String,
    pub(super) select: Selection,
    /// The cases a `listed` selection runs.
    #[serde(default)]
    pub(super) cases: Vec<String>,
    /// Cases ruled out of the profile, each with its reason.
    #[serde(default)]
    pub(super) exclude: Vec<Exclusion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Selection {
    All,
    Listed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exclusion {
    pub(super) id: String,
    pub(super) reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdversarialSpec {
    /// The Office fixture manifest, relative to the repository root.
    pub(super) manifest: String,
    pub(super) cases: Vec<AdversarialCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdversarialCase {
    pub(super) id: String,
    pub(super) engine: EngineExpect,
    /// The Office budget for this fixture; the run's default when absent.
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

/// What the engine's import must do with an adversarial fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum EngineExpect {
    Refuses,
    Imports,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OfficeSpec {
    /// Seconds PowerPoint gets per candidate before the case is
    /// inconclusive.
    pub(super) timeout_seconds: u64,
    pub(super) observer: String,
    /// macOS accounts that never open an untrusted (corpus-derived)
    /// candidate.
    pub(super) owner_accounts: Vec<String>,
    /// The Office-side files copied into the run, relative to
    /// `scripts/office/`.
    pub(super) scripts: Vec<String>,
}

/// `scripts/office/fixtures.json`: the fields the runner reads.
#[derive(Debug, Deserialize)]
pub(super) struct FixtureList {
    pub(super) cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FixtureCase {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) expected_oracle: String,
    pub(super) sha256: String,
}

/// `scripts/office/pptarena.json`: the fields the runner reads.
#[derive(Debug, Deserialize)]
pub(super) struct Arena {
    pub(super) cases: Vec<ArenaCase>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ArenaCase {
    pub(super) id: String,
    pub(super) original: ArenaFile,
}

#[derive(Debug, Deserialize)]
pub(super) struct ArenaFile {
    pub(super) sha256: String,
}

/// Parse one JSON file, keeping its bytes for the run's hashes.
pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> Res<(T, Vec<u8>)> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok((value, bytes))
}
