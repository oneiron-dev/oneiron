//! The owner's display edits on one secret as typed rows (FIX
//! [SECRETS-LABEL-PURPOSE-VERBS]): `vault.secrets.label.set` and
//! `vault.secrets.purpose.set`. Each runs the engine door its `POST
//! /v1/owner/secrets/label` or `/secrets/purpose` route runs
//! ([`Vault::set_secret_handle_label`], [`Vault::set_secret_handle_purpose`]),
//! with the same request and reply fields, under the owner's proof; the door
//! checks the live owner again in its writer and keeps the act in a Gate
//! record.
//!
//! A request names the secret by its custody record's id, as `POST
//! /v1/owner/secrets/payment-mark` and `GET /v1/owner/secrets/custody`'s
//! `secret_id` do; the row reads the record's handle and hands the door that.
//! Both edits are display only: neither grants, reveals, rotates nor moves
//! custody, and no authority or policy decision reads them.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};
use crate::secret_custody::{SecretHandleLabelSet, SecretHandlePurposeSet};

#[doc(hidden)]
use oneiron_verb_wire::verbs::secret_custody::entity_id;

/// `vault.secrets.label.set`'s input: the body `POST
/// /v1/owner/secrets/label` takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLabelSetRequest {
    /// The custody record's id, 32 hex.
    pub secret_id: String,
    /// The owner's one-line name for it; `null` or blank clears it, and the
    /// secret is named by its service or kind again.
    #[serde(default)]
    pub label: Option<String>,
}

/// `vault.secrets.purpose.set`'s input: the body `POST
/// /v1/owner/secrets/purpose` takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretPurposeSetRequest {
    /// The custody record's id, 32 hex.
    pub secret_id: String,
    /// What the secret is for, in the owner's words; `null` or blank clears
    /// it.
    #[serde(default)]
    pub purpose: Option<String>,
}

/// Where a secret's label stands after the act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLabelSetReply {
    /// The secret's handle, such as `sc12`.
    pub handle: String,
    /// The stored label; `null` once cleared.
    pub label: Option<String>,
    /// The kind label a scan suggests (`OpenAI key`), what names the
    /// secret while it has no label of its own.
    pub suggested_label: Option<String>,
    /// The act's Gate receipt.
    pub receipt: String,
}

/// Where a secret's purpose stands after the act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPurposeSetReply {
    /// The secret's handle, such as `sc12`.
    pub handle: String,
    /// The text the side-row wall stored, never an unmasked copy of the
    /// input; `null` once cleared.
    pub purpose: Option<String>,
    /// The act's Gate receipt.
    pub receipt: String,
}

/// `vault.secrets.label.set`: sets or clears the owner's label on one
/// secret.
///
/// # Errors
/// A `secret_id` that is not 32 hex, or names no record with a secret
/// handle; every refusal of [`Vault::set_secret_handle_label`].
pub fn set_secret_label_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SecretLabelSetRequest,
) -> MemoryResult<SecretLabelSetReply> {
    let handle = secret_handle(vault, &input.secret_id)?;
    let set: SecretHandleLabelSet =
        vault.set_secret_handle_label(owner, &handle, input.label.as_deref())?;
    Ok(SecretLabelSetReply {
        handle,
        label: set.label,
        suggested_label: set.suggested_label,
        receipt: set.receipt,
    })
}

/// `vault.secrets.purpose.set`: sets or clears what one secret is for.
///
/// # Errors
/// A `secret_id` that is not 32 hex, or names no record with a secret
/// handle; every refusal of [`Vault::set_secret_handle_purpose`].
pub fn set_secret_purpose_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SecretPurposeSetRequest,
) -> MemoryResult<SecretPurposeSetReply> {
    let handle = secret_handle(vault, &input.secret_id)?;
    let set: SecretHandlePurposeSet =
        vault.set_secret_handle_purpose(owner, &handle, input.purpose.as_deref())?;
    Ok(SecretPurposeSetReply {
        handle,
        purpose: set.purpose,
        receipt: set.receipt,
    })
}

/// The handle of the record `secret_id` names: its short id. The door
/// resolves the handle again in its writer and refuses one that names no
/// custody record (a short id of another kind fails its prefix check).
fn secret_handle(vault: &Vault, secret_id: &str) -> MemoryResult<String> {
    let id: EntityId = entity_id("secret_id", secret_id)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, &id)?
        .map(|(short, _)| short)
        .ok_or_else(|| MemoryError::not_found("no secret has this secret_id"))
}
