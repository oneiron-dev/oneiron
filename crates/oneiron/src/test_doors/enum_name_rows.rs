//! Door for `tests/resident_nightly_reveal_register_names.rs` (Fable pass 25, register
//! conversion wave C4): the rows of four crate-private name tables (`MessageClass`,
//! `SenderKind`, `NightlyLinkVerdict`, `RepoFileRevealScope`), read where each enum lives, so
//! the test pins them on the hand tables and again once the enums are Registers. None of the
//! first three is reachable from here, so the module that holds each adds its rows to
//! [`PrivateNames`] in an inherent impl of its own.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::secret_custody::RepoFileRevealScope;

/// One row of a name table: the variant (its `Debug`), the name the table writes, what serde
/// writes for the variant, and what serde reads back from the name (the variant's `Debug`, or
/// the error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRow {
    /// The variant, as `Debug` writes it.
    pub variant: String,
    /// The name the table writes for it.
    pub name: &'static str,
    /// What serde writes for the variant.
    pub written: Value,
    /// What serde reads from `name`: the read variant's `Debug`, or `unread: <error>`.
    pub read: String,
}

impl NameRow {
    /// The row of `variant`, whose table writes `name`.
    pub(crate) fn of<T>(variant: T, name: &'static str) -> Self
    where
        T: Debug + Serialize + DeserializeOwned,
    {
        let written = serde_json::to_value(&variant)
            .unwrap_or_else(|error| Value::String(format!("unwritten: {error}")));
        let read = match serde_json::from_value::<T>(Value::String(name.to_owned())) {
            Ok(read) => format!("{read:?}"),
            Err(error) => format!("unread: {error}"),
        };
        Self {
            variant: format!("{variant:?}"),
            name,
            written,
            read,
        }
    }
}

/// The crate-private name tables, one fn per enum. `message_class` and `sender_kind` are
/// in `agent_dispatch/resident/message_class.rs`, `nightly_link_verdict` in
/// `dreamer_consolidation/nightly_links/pairs.rs`.
pub struct PrivateNames;

impl PrivateNames {
    /// Every `RepoFileRevealScope` with the name its crate-private `as_str` writes.
    pub fn repo_file_reveal_scope() -> Vec<NameRow> {
        [
            RepoFileRevealScope::File,
            RepoFileRevealScope::FileTask,
            RepoFileRevealScope::Repo,
            RepoFileRevealScope::RepoTask,
        ]
        .into_iter()
        .map(|scope| NameRow::of(scope, scope.as_str()))
        .collect()
    }
}
