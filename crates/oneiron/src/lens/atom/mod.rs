//! The closed [`LensAtom`] vocabulary: the atom enum, its leaf payload structs,
//! [`LensNode`] with its depth-bounded deserializer, and the per-atom
//! validate/fallback/budget impls. Interactive controls live in
//! [`super::self_ui`]; the free validators live in [`super::validate`].

mod atom_enum;
mod atom_leaves;
mod atom_node;
mod atom_scalars;

pub use self::atom_enum::LensAtom;
pub use self::atom_leaves::{
    AnswerSheetAtom, AsofScrubberAtom, ClaimLineAtom, CollectionAtom,
    GeneratedUiResultSetActionEvent, GeneratedUiResultSetAtom, GeneratedUiResultSetRow,
    GeneratedUiResultSetSelectAll, GeneratedUiResultSetSelection, GraphEdge, GraphNode,
    InspectorAtom, LedgerCell, LedgerRowAtom, LensStatus, LensTextSpan, MediaAtom, MetaLineAtom,
    NeighborhoodGraphAtom, PackLineAtom, PostmarkAtom, QuickFilterAtom, ReceiptAtom, SealAtom,
    SealLevel, SectionAtom, StatusDotAtom, TextBlockAtom, ThreadEntryAtom, ThrobberAtom,
    TwoClocksAtom, VadBadge, VoiceLineAtom,
};
pub use self::atom_node::LensNode;
pub use self::atom_scalars::{
    FiniteF64, GENERATED_LENS_ATOM_KINDS, LENS_ATOM_KIT_VERSION, LENS_RESULT_SET_UNSUPPORTED,
    LensText, RESULT_SET_ATOM_KIND,
};

pub(in crate::lens) use self::atom_node::LensNodeSeed;
#[cfg(test)]
pub(in crate::lens) use self::atom_scalars::MAX_LENS_TEXT_BYTES;
