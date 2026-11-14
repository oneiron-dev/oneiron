//! A door to one home-move section, for the home narrowing test: the owner's
//! narrowing history carried from one vault to another as a move carries it.

use crate::{EntityId, Result, Vault};

/// Carries the narrowing history section from `source` to `target`
/// (`crate::sync::home_handoff::carry_section_for_doors`), withholding the
/// actor parts of `withheld`. Whether the section applied.
///
/// # Errors
///
/// `InvalidConfig` when this build's home move carries no such section; the
/// section's own errors.
#[doc(hidden)]
pub fn carry_narrowing_history(
    source: &Vault,
    target: &Vault,
    withheld: &[EntityId],
) -> Result<bool> {
    crate::sync::home_handoff::carry_section_for_doors(
        source,
        target,
        crate::side_table::FEDERATION_SYSTEM_AGENT_NARROWING.name,
        withheld,
    )
}
