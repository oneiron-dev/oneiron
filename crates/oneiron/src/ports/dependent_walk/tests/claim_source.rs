//! The redaction door's source for the every-door walk test: a CLAIM with a
//! two-field value map, and the redaction of one field.

use super::{at, entity};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Result, Vault,
};
use rmpv::Value;

pub(super) fn put(vault: &Vault, source: &EntityId) -> Result<()> {
    let subject = entity(0x74);
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"subject",
    )?;
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::Map(vec![
            (Value::from("secret_note"), Value::from("the door code")),
            (Value::from("public_note"), Value::from("likes tea")),
        ]),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(source, &body, at(1), 1)
}

pub(super) fn redact(vault: &Vault, source: &EntityId) -> Result<()> {
    vault
        .with_write_txn_grouped(|txn| {
            crate::vault::entity_revision::redact_claim_value_fields_in_txn(
                vault,
                txn,
                *source,
                &["secret_note".to_owned()],
            )
        })
        .map(drop)
}
