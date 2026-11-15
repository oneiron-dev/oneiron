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
    /// The text shape's outline redrawn as a freeform (Edit Points).
    EditPoints,
    /// A live-born table from rows of unequal length, padded to its widest.
    RaggedTable,
    /// A live-born SmartArt outline.
    #[serde(rename = "smartart_birth")]
    SmartArtBirth,
    /// A node of a SmartArt the deck holds moved to the front, in a deck
    /// that first took a live-born one.
    #[serde(rename = "smartart_restructure")]
    SmartArtRestructure,
    /// A live-born picture showing an image part the deck holds.
    HeldPictureBirth,
    /// A live-born chart over two-level categories.
    MultiLevelCategories,
    /// A live-born chart one of whose series draws its own categories.
    PerSeriesCategories,
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
            Self::EditPoints => "edit_points",
            Self::RaggedTable => "ragged_table",
            Self::SmartArtBirth => "smartart_birth",
            Self::SmartArtRestructure => "smartart_restructure",
            Self::HeldPictureBirth => "held_picture_birth",
            Self::MultiLevelCategories => "multi_level_categories",
            Self::PerSeriesCategories => "per_series_categories",
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
    /// Two Loro peers of one body merged in both import orders by the
    /// engine (FIX 3773): step 4's convergence case.
    LoroPeers,
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
            Self::LoroPeers => "loro_peers",
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
    /// The Office-side files copied into the run, relative to
    /// `scripts/office/`. Their `environment.json` names the accounts that
    /// may open an untrusted (corpus-derived) candidate.
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

/// The names of `Recipe` and `MergeCase`, one line per row, generated from
/// `scripts/ratchet/hand_name_tables.py --names --only <this file>` before both became Registers
/// (Fable pass 25, the Register wave). Green on the hand tables and on the derive, so no manifest
/// name changed (M-1 keep). Each name is also pinned to the one serde reads. Here and not under
/// `tests/`: both enums are private to `oracle_run`.
#[cfg(test)]
mod register_names {
    use super::MergeCase;
    use super::Recipe;
    use serde::Deserialize;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error as ValueError, StrDeserializer};

    /// Every row of `Recipe`, as its hand table spelled it.
    const RECIPE_ROWS: [(Recipe, &str); 21] = [
        (Recipe::SetText, "set_text"),
        (Recipe::SetRunMarks, "set_run_marks"),
        (Recipe::SetGeometry, "set_geometry"),
        (Recipe::SetPreset, "set_preset"),
        (Recipe::AddShape, "add_shape"),
        (Recipe::AddGroup, "add_group"),
        (Recipe::AddConnector, "add_connector"),
        (Recipe::AddTable, "add_table"),
        (Recipe::AddChart, "add_chart"),
        (Recipe::AddPicture, "add_picture"),
        (Recipe::AddSlide, "add_slide"),
        (Recipe::MoveShape, "move_shape"),
        (Recipe::MoveCrossSlide, "move_cross_slide"),
        (Recipe::RemoveShape, "remove_shape"),
        (Recipe::EditPoints, "edit_points"),
        (Recipe::RaggedTable, "ragged_table"),
        (Recipe::SmartArtBirth, "smartart_birth"),
        (Recipe::SmartArtRestructure, "smartart_restructure"),
        (Recipe::HeldPictureBirth, "held_picture_birth"),
        (Recipe::MultiLevelCategories, "multi_level_categories"),
        (Recipe::PerSeriesCategories, "per_series_categories"),
    ];

    #[test]
    fn every_recipe_keeps_its_name() {
        assert_eq!(Recipe::SetText.name(), "set_text");
        assert_eq!(Recipe::SetRunMarks.name(), "set_run_marks");
        assert_eq!(Recipe::SetGeometry.name(), "set_geometry");
        assert_eq!(Recipe::SetPreset.name(), "set_preset");
        assert_eq!(Recipe::AddShape.name(), "add_shape");
        assert_eq!(Recipe::AddGroup.name(), "add_group");
        assert_eq!(Recipe::AddConnector.name(), "add_connector");
        assert_eq!(Recipe::AddTable.name(), "add_table");
        assert_eq!(Recipe::AddChart.name(), "add_chart");
        assert_eq!(Recipe::AddPicture.name(), "add_picture");
        assert_eq!(Recipe::AddSlide.name(), "add_slide");
        assert_eq!(Recipe::MoveShape.name(), "move_shape");
        assert_eq!(Recipe::MoveCrossSlide.name(), "move_cross_slide");
        assert_eq!(Recipe::RemoveShape.name(), "remove_shape");
        assert_eq!(Recipe::EditPoints.name(), "edit_points");
        assert_eq!(Recipe::RaggedTable.name(), "ragged_table");
        assert_eq!(Recipe::SmartArtBirth.name(), "smartart_birth");
        assert_eq!(Recipe::SmartArtRestructure.name(), "smartart_restructure");
        assert_eq!(Recipe::HeldPictureBirth.name(), "held_picture_birth");
        assert_eq!(
            Recipe::MultiLevelCategories.name(),
            "multi_level_categories"
        );
        assert_eq!(Recipe::PerSeriesCategories.name(), "per_series_categories");
    }

    #[test]
    fn every_recipe_name_is_its_serde_name() {
        for (row, name) in RECIPE_ROWS {
            let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
            let read = Recipe::deserialize(reader).expect("serde reads the name");
            assert_eq!(read, row, "{name}");
        }
    }

    /// Every row of `MergeCase`, as its hand table spelled it.
    const MERGE_CASE_ROWS: [(MergeCase, &str); 9] = [
        (MergeCase::BothMove, "both_move"),
        (MergeCase::BothMoveSame, "both_move_same"),
        (MergeCase::DeleteGroupEditChild, "delete_group_edit_child"),
        (MergeCase::ReparentGeometry, "reparent_geometry"),
        (MergeCase::TextAnimationRange, "text_animation_range"),
        (MergeCase::ThemeInheritedStyle, "theme_inherited_style"),
        (MergeCase::BothReplaceOpaque, "both_replace_opaque"),
        (MergeCase::BothAddShape, "both_add_shape"),
        (MergeCase::LoroPeers, "loro_peers"),
    ];

    #[test]
    fn every_merge_case_keeps_its_name() {
        assert_eq!(MergeCase::BothMove.name(), "both_move");
        assert_eq!(MergeCase::BothMoveSame.name(), "both_move_same");
        assert_eq!(
            MergeCase::DeleteGroupEditChild.name(),
            "delete_group_edit_child"
        );
        assert_eq!(MergeCase::ReparentGeometry.name(), "reparent_geometry");
        assert_eq!(MergeCase::TextAnimationRange.name(), "text_animation_range");
        assert_eq!(
            MergeCase::ThemeInheritedStyle.name(),
            "theme_inherited_style"
        );
        assert_eq!(MergeCase::BothReplaceOpaque.name(), "both_replace_opaque");
        assert_eq!(MergeCase::BothAddShape.name(), "both_add_shape");
        assert_eq!(MergeCase::LoroPeers.name(), "loro_peers");
    }

    #[test]
    fn every_merge_case_name_is_its_serde_name() {
        for (row, name) in MERGE_CASE_ROWS {
            let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
            let read = MergeCase::deserialize(reader).expect("serde reads the name");
            assert_eq!(read, row, "{name}");
        }
    }
}
