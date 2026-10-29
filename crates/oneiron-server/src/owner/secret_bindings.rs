//! The owner binds a secret to an effector, and withdraws a binding (OF-560,
//! FIX 2620): shared by `POST /v1/owner/secrets/bind`, `POST
//! /v1/owner/secrets/unbind` and `oneiron secrets bind|unbind`. The reply
//! names the handle and every binding the record now holds, the Gate
//! receipt, and the custody rewrap that carries the bindings to the owner's
//! other machines, or why they stayed here. Never the value.

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{CustodyTier, RevealTarget, SecretBindRequest, SecretBound};
use serde::Serialize;

use super::secrets::CustodyReply;
use super::{OwnerError, OwnerResult};

/// One binding as the owner reads it.
#[derive(Debug, Serialize)]
pub(crate) struct BindingView {
    effector: String,
    tier_ceiling: u8,
    scopes: Vec<String>,
}

/// What a bind or an unbind left.
#[derive(Debug, Serialize)]
pub(crate) struct BoundView {
    secret_id: String,
    handle: String,
    name: String,
    bindings: Vec<BindingView>,
    /// The Gate record that keeps the binding or its withdrawal,
    /// `gate:<hex>`.
    receipt_ref: String,
    /// The custody rewrap that carries the bindings to the owner's other
    /// machines, as a register's or a rotation's reply does, or why it
    /// stayed here.
    custody: CustodyReply,
}

impl From<SecretBound> for BoundView {
    fn from(bound: SecretBound) -> Self {
        Self {
            secret_id: bound.secret_id.to_hex(),
            handle: bound.handle,
            name: bound.name,
            bindings: bound
                .bindings
                .into_iter()
                .map(|binding| BindingView {
                    effector: binding.effector,
                    tier_ceiling: binding.tier_ceiling.as_u8(),
                    scopes: binding.scopes,
                })
                .collect(),
            receipt_ref: format!("gate:{}", bound.receipt.to_hex()),
            custody: bound.custody.into(),
        }
    }
}

/// The secret by exactly one of its handle or its custody name.
pub(crate) fn target(handle: Option<String>, name: Option<String>) -> OwnerResult<RevealTarget> {
    match (handle, name) {
        (Some(handle), None) => Ok(RevealTarget::Handle(handle)),
        (None, Some(name)) => Ok(RevealTarget::Name(name)),
        _ => Err(OwnerError::Invalid(
            "name the secret by exactly one of handle or name".to_owned(),
        )),
    }
}

/// A binding's rung: 0 doored when none is named.
pub(crate) fn rung(grade: Option<u8>) -> OwnerResult<CustodyTier> {
    match grade {
        None => Ok(CustodyTier::T0Doored),
        Some(grade) => CustodyTier::from_u8(grade).ok_or_else(|| {
            OwnerError::Invalid(
                "a rung is 0 (doored), 1 (leased) or 2 (local-registered)".to_owned(),
            )
        }),
    }
}

/// Binds through the engine door, as `owner` from `surface`: audit only
/// (FIX 4650).
pub(crate) fn bind(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    request: &SecretBindRequest,
) -> OwnerResult<BoundView> {
    Ok(vault
        .bind_secret_as_owner(owner, surface, request, vault.now_recorded_at())?
        .into())
}

/// Withdraws the binding of `target` to `effector` through the engine
/// door, as `owner` from `surface`; every other binding stays (FIX 2620).
pub(crate) fn unbind(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    target: &RevealTarget,
    effector: &str,
) -> OwnerResult<BoundView> {
    Ok(vault
        .unbind_secret_as_owner(owner, surface, target, effector, vault.now_recorded_at())?
        .into())
}
