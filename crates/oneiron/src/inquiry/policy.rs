//! The `inquiry` policy row (federation.md #inquiry-keep; Engine ruling
//! INQUIRE-SHAPE Q8 = A): one versioned row in the vault's policy manifest
//! that holds the company setting `inquiry_keep`. Its only writer today is
//! the Owner's manifest install; change verbs come later, as for the
//! `check_in` row.
//!
//! Wire shape, version 1:
//!
//! ```text
//! inquiry: { version: 1, keep: "task" | "copy" }
//! ```
//!
//! No row means `task`, canon's default. A row with an unknown version, an
//! unknown or missing field or an unknown keep makes the whole manifest
//! unreadable, as every other manifest key does.

use rmpv::Value;

use super::record::InquiryKeep;
use crate::Vault;
use crate::error::Result;

/// The policy-manifest key of the inquiry row.
pub(crate) const INQUIRY_ROW_KEY: &str = "inquiry";

/// The only version of the row this build reads.
pub const INQUIRY_ROW_VERSION: u16 = 1;

/// The decoded `inquiry` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InquiryPolicy {
    keep: InquiryKeep,
}

impl InquiryPolicy {
    /// What the company keeps of an answer.
    #[must_use]
    pub const fn keep(self) -> InquiryKeep {
        self.keep
    }

    /// Decodes the manifest row. `None` for anything but a well-formed
    /// version 1 row (module doc).
    pub(crate) fn decode_row(value: &Value) -> Option<Self> {
        let fields = value.as_map()?;
        if fields.len() != 2 {
            return None;
        }
        let version = u16::try_from(map_field(fields, "version")?.as_u64()?).ok()?;
        if version != INQUIRY_ROW_VERSION {
            return None;
        }
        let keep = InquiryKeep::from_token(map_field(fields, "keep")?.as_str()?)?;
        Some(Self { keep })
    }
}

/// What the vault's resolved policy says about the inquiry row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InquiryPolicyRead {
    /// No trusted manifest names the row.
    NoRow,
    Row(InquiryPolicy),
    /// The resolved policy failed closed.
    Unreadable,
}

/// Where the vault's `inquiry_keep` came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InquiryKeepSource {
    /// No row: canon's default, `task`.
    Default,
    /// The `inquiry` row of the vault's policy.
    Row,
    /// The policy failed closed: `task`, the setting that keeps least. The
    /// sending verb decides whether an inquiry goes out at all.
    Unreadable,
}

/// The vault's `inquiry_keep` and its source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InquiryKeepSetting {
    pub keep: InquiryKeep,
    pub source: InquiryKeepSource,
}

impl Vault {
    /// The company setting `inquiry_keep`, as this vault's policy resolves
    /// it now.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_keep(&self) -> Result<InquiryKeepSetting> {
        let txn = self.store.env.read_txn()?;
        let read = crate::gate::resolve_policy_manifest(&self.store, &txn)?.inquiry_policy();
        Ok(match read {
            InquiryPolicyRead::NoRow => InquiryKeepSetting {
                keep: InquiryKeep::Task,
                source: InquiryKeepSource::Default,
            },
            InquiryPolicyRead::Row(policy) => InquiryKeepSetting {
                keep: policy.keep(),
                source: InquiryKeepSource::Row,
            },
            InquiryPolicyRead::Unreadable => InquiryKeepSetting {
                keep: InquiryKeep::Task,
                source: InquiryKeepSource::Unreadable,
            },
        })
    }
}

/// The value of the one `name` field of a manifest map; `None` when it is
/// absent or repeated.
fn map_field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
    let (_, value) = found.next()?;
    found.next().is_none().then_some(value)
}
