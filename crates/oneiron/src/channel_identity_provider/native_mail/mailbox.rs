//! The native mailbox record: the claim the native mail pack writes once its
//! MTA holds an identity's mailbox. A named address (`eiri@`, ARCH-0063 R6)
//! carries no identity id, so this record is how the Gate and the send doors
//! know the identity is a native mailbox. A derived `mail-<id>` address names
//! its identity itself and needs no record to be known.
use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// The record's predicate: subject the identity, value the mailbox address
/// the MTA holds.
pub const PREDICATE_NATIVE_MAIL_MAILBOX: &str = "native_mail.mailbox";

/// The one id an identity's mailbox record takes, so a retried provision
/// writes it once.
fn mailbox_record_id(identity_ref: EntityId) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron.native_mail.mailbox.v1",
        &[identity_ref.as_bytes().as_slice()],
    )
}

/// Whether the identity's live mailbox record names `address`.
pub(super) fn native_mailbox_recorded_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
    address: &str,
) -> Result<bool> {
    let id = mailbox_record_id(identity_ref)?;
    let Some(raw) = store.port_entity_record(txn, &id)? else {
        return Ok(false);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let body = crate::claim::decode_claim_body(&raw.body, true)?;
    Ok(body.predicate == PREDICATE_NATIVE_MAIL_MAILBOX
        && body.subject == ClaimSubject::Entity(identity_ref)
        && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale
        && body.value.as_str() == Some(address)
        && !store.port_deletion_state(txn, &id)?.deleted)
}

impl Vault {
    /// Records that the native mail MTA holds `identity_ref`'s mailbox at
    /// `address`. A record already naming that address stands as it is.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the identity's record names another
    /// address or was retracted; store and claim validation failures.
    pub(super) fn record_native_mailbox(
        &self,
        identity_ref: EntityId,
        address: &str,
        now: u64,
    ) -> Result<()> {
        let id = mailbox_record_id(identity_ref)?;
        let body = ClaimBody::new(
            PREDICATE_NATIVE_MAIL_MAILBOX,
            ClaimSubject::Entity(identity_ref),
            Value::from(address),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(existing) = self.get_claim_in_txn(&wtxn, &id)? {
            if existing.value == body.value && existing.lifecycle == ClaimLifecycleStatus::Active {
                return Ok(());
            }
            return Err(Error::InvalidConfig(
                "native mailbox record names another address or was retracted".into(),
            ));
        }
        self.put_reserved_claim_in_txn(
            &mut wtxn,
            &id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}
