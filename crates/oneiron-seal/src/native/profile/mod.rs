//! PAdES profile assembly: B-B / B-T / B-LT / B-LTA (§7.2, §7.4–§7.6).
//!
//! Missing timestamp or validation-material services produce the highest
//! valid lower profile plus a structured degradation warning; B-B is the
//! availability floor.

mod assembly;
mod dss;
mod material;
#[cfg(test)]
mod tests;

// Re-exports keep every path used outside `profile` unchanged: the engine
// owns `SealContext`/`assemble`, and the verifier-side LTA tests build DSS
// material through `DssMaterial`/`build_dss_objects`. The remaining
// `pub(crate)` items are consumed inside `profile` (directly, or by the
// test shim below), so re-exporting them would trip `unused_imports`.
pub(crate) use self::assembly::{SealContext, assemble};
pub(crate) use self::dss::DssMaterial;
// `build_dss_objects` is only named by path from test code (the profile
// tests and the verifier-side LTA tests); without the gate the re-export
// trips `unused_imports` in non-test builds.
#[cfg(test)]
pub(crate) use self::dss::build_dss_objects;

// The flat profile.rs module used to provide these names to the sibling test
// module through `use super::*`: every profile-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::{assembly::*, dss::*, material::*};
