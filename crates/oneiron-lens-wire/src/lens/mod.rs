//! Closed generated-lens wire vocabulary, moved out of `oneiron::lens`.
//!
//! - `wire_ids` — bounded newtype tokens and the shared collection budgets.
//! - `wire_limits` — generic bounded-collection serde plumbing.
//! - `atom` — the `LensAtom` vocabulary and `LensNode` tree.
//! - `self_ui` — the `self.ui` interactive control family.
//! - `generated_ui` — the Generated-UI card/segment/`$state` protocol.
//! - `validate` — cross-cutting validators and the surface compiler.

pub mod atom;
pub mod generated_ui;
pub mod self_ui;
pub mod validate;
pub mod wire_ids;
pub mod wire_limits;
