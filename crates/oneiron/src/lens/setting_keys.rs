//! The owner Setting keys of the lens verbs' pages and cuts (DESIGN 15-setting-primitive): rows
//! the setting catalogue reads from this file. Each default is the fixed size these verbs had
//! before; a larger value loosens, so an agent holding a key's set line asks the owner before it
//! raises one.

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::LensText;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, Setting, SettingValue, lower_is_tighter};

/// A byte count one lens text holds whole: at most [`LensText::MAX_BYTES`], the wire's bound on a
/// lens text, so a larger value is refused when it is set rather than cut when it is read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct LensTextBytes(u32);

impl LensTextBytes {
    /// The count as a length.
    pub(crate) fn get(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl SettingValue for LensTextBytes {
    fn check(self) -> Result<Self> {
        if self.get() > LensText::MAX_BYTES {
            return Err(Error::InvalidConfig(format!(
                "a lens text holds at most {} bytes",
                LensText::MAX_BYTES
            )));
        }
        Ok(self)
    }
}

/// `vault.lenses.list`'s default page: 200 proposals.
fn lenses_list_page_max() -> NonZeroU32 {
    NonZeroU32::new(200).unwrap_or(NonZeroU32::MIN)
}

/// `vault.refs.resolve`'s default snippet: 280 characters.
fn refs_resolve_snippet_chars() -> u32 {
    280
}

/// `vault.lenses.default`'s default dossier section: 32 lines.
fn lenses_default_dossier_lines() -> u32 {
    32
}

/// `vault.lenses.default`'s default dossier line: 512 bytes.
fn lenses_default_dossier_line_bytes() -> LensTextBytes {
    LensTextBytes(512)
}

/// `vault.lenses.default`'s default excerpt: 1 KiB.
fn lenses_default_excerpt_bytes() -> LensTextBytes {
    LensTextBytes(1024)
}

crate::setting::setting_keys! {
    /// The most proposals one `vault.lenses.list` page returns; a longer inventory pages on
    /// through `after`. 200 by default.
    pub(crate) LENSES_LIST_PAGE_MAX: NonZeroU32 = "lenses.list.page_max" {
        kind: Kind::new(lenses_list_page_max)
            .strictest(lenses_list_page_max)
            .tighter(lower_is_tighter::<NonZeroU32>),
    };
    /// The most characters the snippet of a `vault.refs.resolve` preview carries, from the
    /// record's first text field; 0 shows no snippet. 280 by default.
    pub(crate) REFS_RESOLVE_SNIPPET_CHARS: u32 = "refs.resolve.snippet_chars" {
        kind: Kind::new(refs_resolve_snippet_chars)
            .strictest(refs_resolve_snippet_chars)
            .tighter(lower_is_tighter::<u32>),
    };
    /// The body lines one `vault.lenses.default` dossier section shows, blank lines skipped; the
    /// rest of the body is cut. 32 by default.
    pub(crate) LENSES_DEFAULT_DOSSIER_LINES: u32 = "lenses.default.dossier_lines" {
        kind: Kind::new(lenses_default_dossier_lines)
            .strictest(lenses_default_dossier_lines)
            .tighter(lower_is_tighter::<u32>),
    };
    /// The bytes each line of a `vault.lenses.default` dossier section shows, cut on a character
    /// boundary. 512 by default; at most 16 KiB, the bound on one lens text.
    pub(crate) LENSES_DEFAULT_DOSSIER_LINE_BYTES: LensTextBytes =
        "lenses.default.dossier_line_bytes" {
        kind: Kind::new(lenses_default_dossier_line_bytes)
            .strictest(lenses_default_dossier_line_bytes)
            .tighter(lower_is_tighter::<LensTextBytes>),
    };
    /// The bytes of a source's body a `vault.lenses.default` ledger row or thread entry shows,
    /// cut on a character boundary; at 0 a ledger row's value is empty and a thread entry is left
    /// out. 1 KiB by default; at most 16 KiB, the bound on one lens text.
    pub(crate) LENSES_DEFAULT_EXCERPT_BYTES: LensTextBytes = "lenses.default.excerpt_bytes" {
        kind: Kind::new(lenses_default_excerpt_bytes)
            .strictest(lenses_default_excerpt_bytes)
            .tighter(lower_is_tighter::<LensTextBytes>),
    };
}

/// The value in force for the vault-scoped `key`, in a read of its own.
///
/// # Errors
///
/// Storage errors.
pub(super) fn vault_value<T: SettingValue>(vault: &Vault, key: &Setting<T>) -> Result<T> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(key.read_in_txn(vault, &txn, &[], None)?.value)
}
