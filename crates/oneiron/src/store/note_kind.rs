//! Shipped NOTE kind defaults and syntactic kind-name rules.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionDefault {
    Allowed,
    AfterSeal,
    PrivateStrategyOnly,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextDefault {
    OwnerOnly,
    RelationshipScoped,
    VaultReadable,
    /// Out of default context, not private: ordinary retrieval never returns
    /// it, and an explicit read admits it to every reader its policy admits.
    ExplicitOnly,
}

/// A reviewer's preserved dissent (OF-352): readable on an explicit read,
/// kept out of default context and out of extraction.
pub const DISSENT_NOTE_KIND: &str = "opinion/dissent";
/// The intent a compaction epoch is born from (OF-421): what the pass was
/// asked to keep and the records it read, by ref. Its summary's birth names
/// it as the prompt. Readable on an explicit read, kept out of default
/// context and out of extraction.
pub(crate) const COMPACTION_INTENT_NOTE_KIND: &str = "compaction/intent";
/// The authored prompt a lens is compiled from (FIX 9896): its CODE
/// kind=lens row's birth names it as the prompt. Readable on an explicit
/// read, kept out of default context and out of extraction.
pub(crate) const LENS_INTENT_NOTE_KIND: &str = "lens/intent";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDefault {
    Durable,
    SessionSealed,
    ArchiveAfterDays,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteKindDescriptor {
    pub pack: String,
    pub kind: String,
    pub extraction: ExtractionDefault,
    pub context: ContextDefault,
    pub retention: RetentionDefault,
    pub archive_after_days: Option<u32>,
}

pub(crate) const SHIPPED: &[(
    &str,
    ExtractionDefault,
    ContextDefault,
    RetentionDefault,
    Option<u32>,
)] = &[
    (
        "scratchpad",
        ExtractionDefault::AfterSeal,
        ContextDefault::OwnerOnly,
        RetentionDefault::SessionSealed,
        None,
    ),
    (
        "observation",
        ExtractionDefault::Allowed,
        ContextDefault::RelationshipScoped,
        RetentionDefault::Durable,
        None,
    ),
    (
        "handoff",
        ExtractionDefault::AfterSeal,
        ContextDefault::RelationshipScoped,
        RetentionDefault::ArchiveAfterDays,
        Some(60),
    ),
    (
        "research",
        ExtractionDefault::AfterSeal,
        ContextDefault::VaultReadable,
        RetentionDefault::Durable,
        None,
    ),
    (
        "reflection",
        ExtractionDefault::AfterSeal,
        ContextDefault::OwnerOnly,
        RetentionDefault::Durable,
        None,
    ),
    (
        "diary",
        ExtractionDefault::PrivateStrategyOnly,
        ContextDefault::OwnerOnly,
        RetentionDefault::Durable,
        None,
    ),
    (
        "opinion/take",
        ExtractionDefault::Allowed,
        ContextDefault::RelationshipScoped,
        RetentionDefault::Durable,
        None,
    ),
    (
        DISSENT_NOTE_KIND,
        ExtractionDefault::Disabled,
        ContextDefault::ExplicitOnly,
        RetentionDefault::Durable,
        None,
    ),
    (
        COMPACTION_INTENT_NOTE_KIND,
        ExtractionDefault::Disabled,
        ContextDefault::ExplicitOnly,
        RetentionDefault::Durable,
        None,
    ),
    (
        LENS_INTENT_NOTE_KIND,
        ExtractionDefault::Disabled,
        ContextDefault::ExplicitOnly,
        RetentionDefault::Durable,
        None,
    ),
];

pub(crate) fn shipped() -> Vec<NoteKindDescriptor> {
    SHIPPED
        .iter()
        .map(
            |&(kind, extraction, context, retention, archive_after_days)| NoteKindDescriptor {
                pack: "core.notes".into(),
                kind: kind.into(),
                extraction,
                context,
                retention,
                archive_after_days,
            },
        )
        .collect()
}
pub(crate) fn is_shipped_kind(raw: &str) -> bool {
    SHIPPED.iter().any(|(kind, ..)| *kind == raw)
}
pub(crate) fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._/-".contains(&c))
}
