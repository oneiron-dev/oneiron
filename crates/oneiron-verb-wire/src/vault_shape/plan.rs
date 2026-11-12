//! Moved from `crates/oneiron/src/vault_shape/plan.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::ShapeCeiling;
use crate::vault_shape::approval::ShapeApprovalDependencies;
use crate::vault_shape::invalid;
use crate::vault_shape::member::ShapeMemberRole;
use crate::vault_shape::reach::ShapePlanReach;
use crate::vault_shape::seed::hex;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// What an item does to the named structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeChange {
    /// The structure is missing and is created.
    Create,
    /// The structure exists and takes the declared values.
    Update,
    /// The structure leaves, by an explicit retire line.
    Retire,
}

/// How an item lands (ARCH-0070 `shape:plan-apply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeItemClass {
    /// A narrowing, or an ordinary setup write that widens nothing (a new
    /// world, a roster row at a proposed ceiling): lands with a receipt.
    Receipted,
    /// Any new grant, raised ceiling, retire line, new power or kind on the
    /// wire: lands Proposed and waits for the owner's stamp. A widening never
    /// rides autonomy, whatever the rung.
    Widening,
    /// A key binding, an ownership transfer or a co-sign change: goes to the
    /// AUTHORITY_LOG ceremony unchanged. A member row moving a role to or
    /// from Owner compiles to one.
    Authority,
}
