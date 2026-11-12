//! Moved from `crates/oneiron/src/settings/snapshot_read.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// The bounds every snapshot handle is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReadSettings {
    /// Handles one actor may hold open at once.
    pub open_per_actor: u32,
    /// A handle's lifetime when its opener names none, in seconds.
    pub default_lifetime_secs: u64,
    /// The longest lifetime an opener may ask for, in seconds.
    pub max_lifetime_secs: u64,
    /// The most rows one page serves.
    pub page_rows: u32,
    /// The most bytes of rows one page serves.
    pub page_bytes: u64,
    /// The most rows one handle serves over all its pages.
    pub handle_rows: u64,
}

impl SnapshotReadSettings {
    /// The defaults (lead 19:4x): 8 open per actor, 10 min by default and
    /// 60 min at most, 200 rows and 4 MiB per page, 20,000 rows per handle.
    pub const DEFAULT: Self = Self {
        open_per_actor: 8,
        default_lifetime_secs: 600,
        max_lifetime_secs: 3_600,
        page_rows: 200,
        page_bytes: 4 * 1024 * 1024,
        handle_rows: 20_000,
    };

    /// Refuses a zero bound, and a default lifetime above the most lifetime.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the bound.
    pub fn validate(&self) -> Result<()> {
        let zero = [
            ("open_per_actor", u64::from(self.open_per_actor)),
            ("default_lifetime_secs", self.default_lifetime_secs),
            ("max_lifetime_secs", self.max_lifetime_secs),
            ("page_rows", u64::from(self.page_rows)),
            ("page_bytes", self.page_bytes),
            ("handle_rows", self.handle_rows),
        ]
        .into_iter()
        .find(|(_, bound)| *bound == 0);
        if let Some((name, _)) = zero {
            return Err(Error::InvalidConfig(format!(
                "the snapshot bound {name} must be above zero"
            )));
        }
        if self.default_lifetime_secs > self.max_lifetime_secs {
            return Err(Error::InvalidConfig(
                "the default snapshot lifetime must not exceed the most lifetime".to_owned(),
            ));
        }
        Ok(())
    }

    /// The first bound of `self` that is above the same bound of `held`.
    fn first_bound_above(&self, held: &Self) -> Option<&'static str> {
        [
            (
                "open_per_actor",
                u64::from(self.open_per_actor),
                u64::from(held.open_per_actor),
            ),
            (
                "default_lifetime_secs",
                self.default_lifetime_secs,
                held.default_lifetime_secs,
            ),
            (
                "max_lifetime_secs",
                self.max_lifetime_secs,
                held.max_lifetime_secs,
            ),
            (
                "page_rows",
                u64::from(self.page_rows),
                u64::from(held.page_rows),
            ),
            ("page_bytes", self.page_bytes, held.page_bytes),
            ("handle_rows", self.handle_rows, held.handle_rows),
        ]
        .into_iter()
        .find(|(_, bound, in_force)| bound > in_force)
        .map(|(name, _, _)| name)
    }
}

impl Default for SnapshotReadSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}
