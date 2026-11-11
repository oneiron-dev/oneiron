//! Outbound verb-class membership, re-exported from the one registry.
//!
//! A grant stores a verb class name, never the verbs in it (DEC-0006
//! invariant 3): membership resolves when an effect arrives. A class name
//! also covers its own literal spelling, so a grant minted for one verb keeps
//! covering exactly that verb. The registry lives beside the consent bound in
//! the store crate, so the outbound scope matcher and the bound's class axis
//! resolve membership through the same table.

pub(super) use crate::store::consent_bound::classes_of;
pub(crate) use crate::store::consent_bound::verb_in_class;
