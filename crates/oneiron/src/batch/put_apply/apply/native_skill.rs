//! Owned per-put data. Only the later builder continuation produces final inputs.

use super::admission::FixedPut;

mod pending;
pub(in crate::batch) use pending::PendingNativeSkillPut;
