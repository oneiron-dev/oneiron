//! Authority-log rows carried beside a row being imported.

use std::collections::BTreeMap;

use oneiron_authority::authority::{AuthorityEntryHash, AuthorityLogEntry};

use crate::error::Result;

/// The rows an import carries beside the ones a door judges (FIX 2535,
/// 2989), read only where the fold with the judged rows alone needs history.
/// A row already stored, or one the judged rows hold, is left out.
pub(crate) type RowsBeside<'a> =
    &'a dyn Fn() -> Result<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>>;
