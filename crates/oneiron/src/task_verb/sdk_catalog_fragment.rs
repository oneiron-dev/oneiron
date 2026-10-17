//! The code-mode catalog fragment (ONE-2510 S2): the whole verb set code mode
//! serves, as one TypeScript declaration text with nested input and reply
//! types, and the revision that names it. `scripts/sdk/generate.py` writes
//! both from the verb table (`catalog_fragment.d.ts`,
//! `catalog_fragment_revision.rs`), and `--check` keeps them in step with it.
//! The executor teaches the text in its cached prefix as prompt-side SDK
//! documentation and restates the revision after compaction
//! (EIRI-ARCH-0002 §The contract).

include!("catalog_fragment_revision.rs");

/// One revision of the code-mode catalog: its declaration text and the digest
/// that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogFragment {
    /// The TypeScript declarations: every code-mode row at its SDK path, with
    /// its typed input and reply, and every type they reach.
    pub text: &'static str,
    /// `sha256:` and the hex digest of `text`, computed by the generator.
    pub revision: &'static str,
}

/// The catalog fragment this build carries.
#[must_use]
pub const fn code_mode_catalog_fragment() -> CatalogFragment {
    CatalogFragment {
        text: include_str!("catalog_fragment.d.ts"),
        revision: CATALOG_FRAGMENT_REVISION,
    }
}
