//! BRIDGE-01 (ONE-1454): napi lift of the engine memory facade.
//!
//! `VaultBridge.open(path)` → `asActor("<actor_class>:<entity_ref>")` →
//! `ActorScopedVault` carrying every facade verb (W3 ABI). All methods are
//! sync `&self` (W2 — no async FFI, no `&mut`). Facade vocabulary only:
//! short-id refs, registry kind strings, typed DTOs — no byte buffers, no
//! type bytes, no JSON-as-bytes anywhere on this surface (S1; enforced by
//! the fitness scan). Blob content crosses as standard base64 strings.
//!
//! Errors cross the boundary as `napi::Error` whose reason is the
//! JSON-serialized engine `MemoryError` (`{code, message, suggestions}`),
//! so the TS wrapper (deferred this wave) can rehydrate typed errors.

mod boundary;
mod bridge;
mod client;
mod convert;
mod dtos;
mod input_error;
mod numeric;
#[cfg(test)]
mod tests;
mod verbs_claims;
mod verbs_services;

pub(crate) use self::boundary::{BoundaryResult, boundary_error, facade_error, ts_to_engine};

/// Every door of this binding that opens a vault calls this first. Crash
/// output never carries world text (owner ruling 2026-10-14, fix 6), so the
/// engine's panic hook goes in before any vault opens.
pub(crate) fn before_vault_open() {
    oneiron::panic_report::install_panic_hook();
}
pub use self::bridge::{ActorScopedVault, VaultBridge};
// `numeric.rs` names this DTO through `super::`, as it did when both lived in
// the flat file; it is the only DTO the rest of the crate reaches via `facade::`.
pub(crate) use self::dtos::NapiClaimInput;
// The legacy `NapiVault` context pack takes `vault.recall`'s media object and
// lowers it the same way (OF-370), so the binding has one media shape.
pub(crate) use self::{convert::recall_media_to_engine, dtos::NapiRecallMedia};

// The flat facade.rs module used to provide these names to the inline test
// module through `use super::*`: the DTO/convert/boundary items the tests
// name bare. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{boundary::*, convert::*, dtos::*};
