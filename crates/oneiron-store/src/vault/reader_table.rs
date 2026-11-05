//! The LMDB reader table a vault's environment got, against what it asked for.

/// A vault whose LMDB reader table holds fewer slots than its config asked
/// for (see [`crate::config::READER_SLOTS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderTableShortfall {
    /// The slots this vault's config asked for.
    pub requested: u32,
    /// The slots its reader table holds.
    pub granted: u32,
}

