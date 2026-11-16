//! The lens' owner Setting keys (DESIGN 15-setting-primitive; restriction wave 21, C87-C89):
//! rows the setting catalogue reads from this file. Each key's default is the bound before it
//! became a key, so no page or excerpt changes until the owner moves it.
//!
//! An excerpt is cut from a body the caller's own scoped read already admitted, so a longer one
//! shows no record the caller could not read whole.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::sdk::DOSSIER_LINES;
use super::{LENS_LIST_MAX_PAGE, RECORD_REF_SNIPPET_MAX_CHARS};
use crate::setting::{Kind, PageMax, Setting, SettingValue, lower_is_tighter};
use crate::{Error, Result, Vault};

/// How much of an admitted record's text one lens excerpt shows, in its key's unit: characters
/// for a record-ref snippet, lines for a dossier section. At least one; a larger value is the
/// looser one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct LensExcerptSize(pub(crate) u32);

impl SettingValue for LensExcerptSize {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            Err(Error::InvalidConfig(
                "a lens excerpt shows at least one unit".into(),
            ))
        } else {
            Ok(self)
        }
    }
}

/// 200 rows: a `vault.lenses.list` page's maximum before it became a key.
fn lens_list_max_page_default() -> PageMax {
    PageMax(u32::try_from(LENS_LIST_MAX_PAGE).unwrap_or(u32::MAX))
}

/// 280 characters: a record-ref snippet's length before it became a key.
fn record_ref_snippet_chars_default() -> LensExcerptSize {
    LensExcerptSize(u32::try_from(RECORD_REF_SNIPPET_MAX_CHARS).unwrap_or(u32::MAX))
}

/// 32 lines: a dossier section's length before it became a key.
fn dossier_lines_shown_default() -> LensExcerptSize {
    LensExcerptSize(u32::try_from(DOSSIER_LINES).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most rows one `vault.lenses.list` page holds (default 200). An ask for more is served
    /// this many, with `after` to the rest; an ask that names no limit is still served 200, and
    /// an ask of zero is served one row. A maximum of zero is refused. A larger value is looser,
    /// so only the owner raises it; an agent's raise waits on the owner's answer.
    pub(crate) LENS_LIST_MAX_PAGE_KEY: PageMax = "lens.list.max_page" {
        kind: Kind::new(lens_list_max_page_default)
            .strictest(lens_list_max_page_default)
            .tighter(lower_is_tighter::<PageMax>),
    };

    /// The most characters of a record's admitted text a `vault.refs.resolve` preview snippet
    /// carries (default 280). At least one. A larger value is looser, so only the owner raises
    /// it; an agent's raise waits on the owner's answer.
    pub(crate) RECORD_REF_SNIPPET_CHARS_KEY: LensExcerptSize = "lens.refs.snippet_chars" {
        kind: Kind::new(record_ref_snippet_chars_default)
            .strictest(record_ref_snippet_chars_default)
            .tighter(lower_is_tighter::<LensExcerptSize>),
    };

    /// The most non-blank body lines one `vault.lenses.default` dossier section shows (default
    /// 32), each still clipped to 512 bytes. At least one. A larger value is looser, so only the
    /// owner raises it; an agent's raise waits on the owner's answer.
    pub(crate) DOSSIER_LINES_SHOWN_KEY: LensExcerptSize = "lens.dossier.lines_shown" {
        kind: Kind::new(dossier_lines_shown_default)
            .strictest(dossier_lines_shown_default)
            .tighter(lower_is_tighter::<LensExcerptSize>),
    };
}

impl Vault {
    /// The excerpt size in force for `key`, read in its own read transaction: the owner's row, a
    /// key holder's tighter row within it, or the key's default when no row stands. Its callers
    /// read it before they open any other read.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn lens_excerpt_size_in_force(
        &self,
        key: &Setting<LensExcerptSize>,
    ) -> Result<usize> {
        let txn = self.store.env.read_txn()?;
        let size = key.read_in_txn(self, &txn, &[], None)?.value;
        Ok(usize::try_from(size.0).unwrap_or(usize::MAX))
    }
}
