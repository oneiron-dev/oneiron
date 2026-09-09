//! LensAtom closed enum with wire codec and primitive/validate/budget dispatch.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::{
    AnswerSheetAtom, AsofScrubberAtom, ClaimLineAtom, CollectionAtom, GeneratedUiResultSetAtom,
    InspectorAtom, LedgerRowAtom, LensText, MediaAtom, MetaLineAtom, NeighborhoodGraphAtom,
    PackLineAtom, PostmarkAtom, QuickFilterAtom, RESULT_SET_ATOM_KIND, ReceiptAtom, SealAtom,
    SectionAtom, StatusDotAtom, TextBlockAtom, ThreadEntryAtom, ThrobberAtom, TwoClocksAtom,
    VoiceLineAtom,
};
use crate::Result;
use crate::lens::generated_ui::GeneratedUiPrimitive;
use crate::lens::self_ui::SelfUiControl;
use crate::lens::validate::{LensBudget, fallback_lens_text};
use crate::lens::wire_limits::serialize_tagged;

#[derive(Debug, Clone, PartialEq)]
pub enum LensAtom {
    TextBlock(TextBlockAtom),
    LedgerRow(LedgerRowAtom),
    ClaimLine(ClaimLineAtom),
    StatusDot(StatusDotAtom),
    Seal(SealAtom),
    MetaLine(MetaLineAtom),
    DossierSection(SectionAtom),
    ThreadEntry(ThreadEntryAtom),
    Sheet(CollectionAtom),
    Slip(SectionAtom),
    Receipt(ReceiptAtom),
    Charter(SectionAtom),
    Postmark(PostmarkAtom),
    PackLine(PackLineAtom),
    AnswerSheet(AnswerSheetAtom),
    TwoClocks(TwoClocksAtom),
    NeighborhoodGraph(NeighborhoodGraphAtom),
    AsofScrubber(AsofScrubberAtom),
    Throbber(ThrobberAtom),
    VoiceLine(VoiceLineAtom),
    QuickFilter(QuickFilterAtom),
    InspectorSheet(InspectorAtom),
    InspectorRail(InspectorAtom),
    InspectorTrail(InspectorAtom),
    SelfUi(SelfUiControl),
    Media(MediaAtom),
    ResultSet(GeneratedUiResultSetAtom),
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LensAtomWire {
    TextBlock(TextBlockAtom),
    LedgerRow(LedgerRowAtom),
    ClaimLine(ClaimLineAtom),
    StatusDot(StatusDotAtom),
    Seal(SealAtom),
    MetaLine(MetaLineAtom),
    DossierSection(SectionAtom),
    ThreadEntry(ThreadEntryAtom),
    Sheet(CollectionAtom),
    Slip(SectionAtom),
    Receipt(ReceiptAtom),
    Charter(SectionAtom),
    Postmark(PostmarkAtom),
    PackLine(PackLineAtom),
    AnswerSheet(AnswerSheetAtom),
    TwoClocks(TwoClocksAtom),
    NeighborhoodGraph(NeighborhoodGraphAtom),
    AsofScrubber(AsofScrubberAtom),
    Throbber(ThrobberAtom),
    VoiceLine(VoiceLineAtom),
    QuickFilter(QuickFilterAtom),
    InspectorSheet(InspectorAtom),
    InspectorRail(InspectorAtom),
    InspectorTrail(InspectorAtom),
    SelfUi(SelfUiControl),
    Media(MediaAtom),
    ResultSet(GeneratedUiResultSetAtom),
}

impl From<LensAtomWire> for LensAtom {
    fn from(value: LensAtomWire) -> Self {
        match value {
            LensAtomWire::TextBlock(atom) => Self::TextBlock(atom),
            LensAtomWire::LedgerRow(atom) => Self::LedgerRow(atom),
            LensAtomWire::ClaimLine(atom) => Self::ClaimLine(atom),
            LensAtomWire::StatusDot(atom) => Self::StatusDot(atom),
            LensAtomWire::Seal(atom) => Self::Seal(atom),
            LensAtomWire::MetaLine(atom) => Self::MetaLine(atom),
            LensAtomWire::DossierSection(atom) => Self::DossierSection(atom),
            LensAtomWire::ThreadEntry(atom) => Self::ThreadEntry(atom),
            LensAtomWire::Sheet(atom) => Self::Sheet(atom),
            LensAtomWire::Slip(atom) => Self::Slip(atom),
            LensAtomWire::Receipt(atom) => Self::Receipt(atom),
            LensAtomWire::Charter(atom) => Self::Charter(atom),
            LensAtomWire::Postmark(atom) => Self::Postmark(atom),
            LensAtomWire::PackLine(atom) => Self::PackLine(atom),
            LensAtomWire::AnswerSheet(atom) => Self::AnswerSheet(atom),
            LensAtomWire::TwoClocks(atom) => Self::TwoClocks(atom),
            LensAtomWire::NeighborhoodGraph(atom) => Self::NeighborhoodGraph(atom),
            LensAtomWire::AsofScrubber(atom) => Self::AsofScrubber(atom),
            LensAtomWire::Throbber(atom) => Self::Throbber(atom),
            LensAtomWire::VoiceLine(atom) => Self::VoiceLine(atom),
            LensAtomWire::QuickFilter(atom) => Self::QuickFilter(atom),
            LensAtomWire::InspectorSheet(atom) => Self::InspectorSheet(atom),
            LensAtomWire::InspectorRail(atom) => Self::InspectorRail(atom),
            LensAtomWire::InspectorTrail(atom) => Self::InspectorTrail(atom),
            LensAtomWire::SelfUi(control) => Self::SelfUi(control),
            LensAtomWire::Media(atom) => Self::Media(atom),
            LensAtomWire::ResultSet(atom) => Self::ResultSet(atom),
        }
    }
}

impl<'de> Deserialize<'de> for LensAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let atom = Self::from(LensAtomWire::deserialize(deserializer)?);
        atom.validate().map_err(de::Error::custom)?;

        let mut budget = LensBudget::default();
        atom.count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;

        Ok(atom)
    }
}

impl Serialize for LensAtom {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::TextBlock(props) => {
                serialize_tagged(serializer, "kind", "text_block", "props", props)
            }
            Self::LedgerRow(props) => {
                serialize_tagged(serializer, "kind", "ledger_row", "props", props)
            }
            Self::ClaimLine(props) => {
                serialize_tagged(serializer, "kind", "claim_line", "props", props)
            }
            Self::StatusDot(props) => {
                serialize_tagged(serializer, "kind", "status_dot", "props", props)
            }
            Self::Seal(props) => serialize_tagged(serializer, "kind", "seal", "props", props),
            Self::MetaLine(props) => {
                serialize_tagged(serializer, "kind", "meta_line", "props", props)
            }
            Self::DossierSection(props) => {
                serialize_tagged(serializer, "kind", "dossier_section", "props", props)
            }
            Self::ThreadEntry(props) => {
                serialize_tagged(serializer, "kind", "thread_entry", "props", props)
            }
            Self::Sheet(props) => serialize_tagged(serializer, "kind", "sheet", "props", props),
            Self::Slip(props) => serialize_tagged(serializer, "kind", "slip", "props", props),
            Self::Receipt(props) => serialize_tagged(serializer, "kind", "receipt", "props", props),
            Self::Charter(props) => serialize_tagged(serializer, "kind", "charter", "props", props),
            Self::Postmark(props) => {
                serialize_tagged(serializer, "kind", "postmark", "props", props)
            }
            Self::PackLine(props) => {
                serialize_tagged(serializer, "kind", "pack_line", "props", props)
            }
            Self::AnswerSheet(props) => {
                serialize_tagged(serializer, "kind", "answer_sheet", "props", props)
            }
            Self::TwoClocks(props) => {
                serialize_tagged(serializer, "kind", "two_clocks", "props", props)
            }
            Self::NeighborhoodGraph(props) => {
                serialize_tagged(serializer, "kind", "neighborhood_graph", "props", props)
            }
            Self::AsofScrubber(props) => {
                serialize_tagged(serializer, "kind", "asof_scrubber", "props", props)
            }
            Self::Throbber(props) => {
                serialize_tagged(serializer, "kind", "throbber", "props", props)
            }
            Self::VoiceLine(props) => {
                serialize_tagged(serializer, "kind", "voice_line", "props", props)
            }
            Self::QuickFilter(props) => {
                serialize_tagged(serializer, "kind", "quick_filter", "props", props)
            }
            Self::InspectorSheet(props) => {
                serialize_tagged(serializer, "kind", "inspector_sheet", "props", props)
            }
            Self::InspectorRail(props) => {
                serialize_tagged(serializer, "kind", "inspector_rail", "props", props)
            }
            Self::InspectorTrail(props) => {
                serialize_tagged(serializer, "kind", "inspector_trail", "props", props)
            }
            Self::SelfUi(props) => serialize_tagged(serializer, "kind", "self_ui", "props", props),
            Self::Media(props) => serialize_tagged(serializer, "kind", "media", "props", props),
            Self::ResultSet(props) => {
                serialize_tagged(serializer, "kind", RESULT_SET_ATOM_KIND, "props", props)
            }
        }
    }
}

impl LensAtom {
    #[must_use]
    pub const fn primitive(&self) -> GeneratedUiPrimitive {
        match self {
            Self::TextBlock(_) => GeneratedUiPrimitive::TextBlock,
            Self::LedgerRow(_) => GeneratedUiPrimitive::LedgerRow,
            Self::ClaimLine(_) => GeneratedUiPrimitive::ClaimLine,
            Self::StatusDot(_) => GeneratedUiPrimitive::StatusDot,
            Self::Seal(_) => GeneratedUiPrimitive::Seal,
            Self::MetaLine(_) => GeneratedUiPrimitive::MetaLine,
            Self::DossierSection(_) => GeneratedUiPrimitive::DossierSection,
            Self::ThreadEntry(_) => GeneratedUiPrimitive::ThreadEntry,
            Self::Sheet(_) => GeneratedUiPrimitive::Sheet,
            Self::Slip(_) => GeneratedUiPrimitive::Slip,
            Self::Receipt(_) => GeneratedUiPrimitive::Receipt,
            Self::Charter(_) => GeneratedUiPrimitive::Charter,
            Self::Postmark(_) => GeneratedUiPrimitive::Postmark,
            Self::PackLine(_) => GeneratedUiPrimitive::PackLine,
            Self::AnswerSheet(_) => GeneratedUiPrimitive::AnswerSheet,
            Self::TwoClocks(_) => GeneratedUiPrimitive::TwoClocks,
            Self::NeighborhoodGraph(_) => GeneratedUiPrimitive::NeighborhoodGraph,
            Self::AsofScrubber(_) => GeneratedUiPrimitive::AsofScrubber,
            Self::Throbber(_) => GeneratedUiPrimitive::Throbber,
            Self::VoiceLine(_) => GeneratedUiPrimitive::VoiceLine,
            Self::QuickFilter(_) => GeneratedUiPrimitive::QuickFilter,
            Self::InspectorSheet(_) => GeneratedUiPrimitive::InspectorSheet,
            Self::InspectorRail(_) => GeneratedUiPrimitive::InspectorRail,
            Self::InspectorTrail(_) => GeneratedUiPrimitive::InspectorTrail,
            Self::SelfUi(_) => GeneratedUiPrimitive::SelfUi,
            Self::Media(_) => GeneratedUiPrimitive::Media,
            Self::ResultSet(_) => GeneratedUiPrimitive::ResultSet,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.primitive().as_str()
    }

    /// Build a validated result-set atom. Row-id and action-bar uniqueness are proved
    /// here, exactly as they are on the wire.
    pub fn result_set(atom: GeneratedUiResultSetAtom) -> Result<Self> {
        let atom = Self::ResultSet(atom);
        atom.validate()?;
        Ok(atom)
    }

    #[must_use]
    pub fn result_set_payload(&self) -> Option<&GeneratedUiResultSetAtom> {
        match self {
            Self::ResultSet(atom) => Some(atom),
            _ => None,
        }
    }

    #[must_use]
    pub fn default_fallback_text(&self) -> LensText {
        let fallback = match self {
            Self::TextBlock(atom) => atom.fallback_text(),
            Self::LedgerRow(atom) => atom.cells.first().map_or_else(
                || "ledger row".to_string(),
                |cell| format!("{}: {}", cell.label.as_str(), cell.value.as_str()),
            ),
            Self::ClaimLine(atom) => format!(
                "{} {} {}",
                atom.subject.as_str(),
                atom.predicate.as_str(),
                atom.value.as_str()
            ),
            Self::StatusDot(atom) => atom.label.as_ref().map_or_else(
                || atom.status.as_str().to_string(),
                |label| label.as_str().to_string(),
            ),
            Self::Seal(atom) => atom.label.as_str().to_string(),
            Self::MetaLine(atom) => format!("{}: {}", atom.label.as_str(), atom.value.as_str()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => {
                atom.title.as_str().to_string()
            }
            Self::ThreadEntry(atom) => format!("{}: {}", atom.author.as_str(), atom.body.as_str()),
            Self::Sheet(atom) => atom.title.as_str().to_string(),
            Self::Receipt(atom) => atom.title.as_str().to_string(),
            Self::Postmark(atom) => format!("{} {}", atom.label.as_str(), atom.timestamp.as_str()),
            Self::PackLine(atom) => atom.summary.as_str().to_string(),
            Self::AnswerSheet(atom) => atom.answer.as_str().to_string(),
            Self::TwoClocks(atom) => {
                format!(
                    "{} / {}",
                    atom.occurred_at.as_str(),
                    atom.learned_at.as_str()
                )
            }
            Self::NeighborhoodGraph(atom) => format!("{} nodes", atom.nodes.len()),
            Self::AsofScrubber(atom) => atom.value.as_str().to_string(),
            Self::Throbber(atom) => atom.label.as_str().to_string(),
            Self::VoiceLine(atom) => atom.text.as_str().to_string(),
            Self::QuickFilter(atom) => atom.label.as_str().to_string(),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.title.as_str().to_string()
            }
            Self::SelfUi(control) => control.fallback_text(),
            Self::Media(atom) => atom.alt.as_str().to_string(),
            // Row labels are display data the host never parses, and a row count is
            // reach metadata. The fallback stays a static literal.
            Self::ResultSet(_) => "result set".to_string(),
        };
        fallback_lens_text(self.kind(), fallback)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::TextBlock(atom) => atom.validate(),
            Self::LedgerRow(atom) => atom.validate(),
            Self::ClaimLine(_) | Self::StatusDot(_) | Self::Seal(_) | Self::MetaLine(_) => Ok(()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => atom.validate(),
            Self::ThreadEntry(_) => Ok(()),
            Self::Sheet(atom) => atom.validate(),
            Self::Receipt(atom) => atom.validate(),
            Self::Postmark(_) | Self::PackLine(_) | Self::TwoClocks(_) | Self::Throbber(_) => {
                Ok(())
            }
            Self::AnswerSheet(atom) => atom.validate(),
            Self::NeighborhoodGraph(atom) => atom.validate(),
            Self::AsofScrubber(_) | Self::VoiceLine(_) => Ok(()),
            Self::QuickFilter(atom) => atom.validate(),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.validate()
            }
            Self::SelfUi(control) => control.validate(),
            Self::Media(atom) => atom.validate(),
            Self::ResultSet(atom) => atom.validate(),
        }
    }

    pub(in crate::lens) fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        match self {
            Self::TextBlock(atom) => budget.add_collection("text block spans", atom.spans.len()),
            Self::LedgerRow(atom) => budget.add_collection("ledger row cells", atom.cells.len()),
            Self::ClaimLine(_) | Self::StatusDot(_) | Self::Seal(_) | Self::MetaLine(_) => Ok(()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => {
                budget.add_collection("lens section lines", atom.lines.len())
            }
            Self::ThreadEntry(_) => Ok(()),
            Self::Sheet(atom) => atom.count_collection_items(budget),
            Self::Receipt(atom) => budget.add_collection("receipt lines", atom.lines.len()),
            Self::Postmark(_) | Self::PackLine(_) | Self::TwoClocks(_) | Self::Throbber(_) => {
                Ok(())
            }
            Self::AnswerSheet(atom) => {
                budget.add_collection("answer sheet citations", atom.citations.len())
            }
            Self::NeighborhoodGraph(atom) => {
                budget.add_collection("neighborhood graph nodes", atom.nodes.len())?;
                budget.add_collection("neighborhood graph edges", atom.edges.len())
            }
            Self::AsofScrubber(_) | Self::VoiceLine(_) => Ok(()),
            Self::QuickFilter(atom) => atom.count_collection_items(budget),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.count_collection_items(budget)
            }
            Self::SelfUi(control) => control.count_collection_items(budget),
            Self::Media(_) => Ok(()),
            Self::ResultSet(atom) => atom.count_collection_items(budget),
        }
    }
}
