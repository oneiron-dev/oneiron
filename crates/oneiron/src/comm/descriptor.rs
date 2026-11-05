//! ARCH-0057 claim-class descriptors as synced maintenance entities (OF-272).
//!
//! One CLAIM_CLASS_DESCRIPTOR row (type byte 91) per claim class, at an id
//! derived from its predicate, so every node that seeds or puts the class's
//! descriptor names the same entity. Descriptors travel on the ordinary
//! entity plane, so the vocabulary syncs with the data it describes: shared
//! semantics. Posture stays local: the gate keeps its compiled policy, and a
//! descriptor's `enforcement` counts only when a stamp binds its semantics
//! hash ([`ClaimClassDescriptor::enforced`]).
//!
//! The compiled `comm.*` table ([`claim_class_descriptors`]) is the seed and
//! the fallback: the open-time seed writes each compiled row that is not
//! already there, and a reader with no readable synced row gets the compiled
//! row. The compiled table is the build's own stamp for its own semantics, so
//! a seeded or synced row with exactly those semantics keeps the compiled
//! enforcement; any other `enforcement=true` needs an owner stamp minted by
//! [`Vault::put_claim_class_descriptor`].
//!
//! A descriptor also says how its class's claims are checked (ARCH-0057
//! §validation): the subject kind they may name, and either `generic`, where
//! its schema checks the value, or `builtin`, where the build's own family
//! validator does. Every claim write and sync replay checks a claim against a
//! descriptor that declares a subject kind or a schema
//! ([`check_claim_against_descriptor_in_txn`]); the family validators run
//! unchanged beside it. The seeds are `builtin` of any subject, except the
//! classes the build compiles as `generic` (`comm.do_not_contact`), whose
//! check also runs without a store
//! ([`check_claim_against_compiled_descriptor`]).

use super::claims::claim_class_descriptors;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR;
use crate::store::Store;
use crate::temporal::TimeRange;

pub use crate::store::claim_descriptors::CLAIM_CLASS_DESCRIPTOR_BODY_KEYS;
pub use crate::store::claim_descriptors::ClaimClassDescriptor;
pub use crate::store::claim_descriptors::ClaimSubjectKind;
pub use crate::store::claim_descriptors::ClaimValidatorKind;
pub use crate::store::claim_descriptors::ClaimWriteClass;
pub use crate::store::claim_descriptors::EnforcementStamp;
use crate::store::claim_descriptors::{
    DESCRIPTOR_PUT_OPERATION, compiled_descriptor, compiled_row, generic_class_seed, hash_hex,
    invalid, json_value, value_meets_schema,
};

/// Checks `body` against its class's descriptor where the descriptor
/// declares a subject kind or a schema: the subject it names, and for a
/// `generic` class its value against the schema. A predicate with no
/// descriptor, or one that declares neither, is left to the family
/// validators, which run beside this unchanged.
///
/// # Errors
/// A subject the class does not admit, a value JSON cannot hold, or one the
/// schema refuses.
pub(crate) fn check_claim_against_descriptor_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    let Some(descriptor) = claim_class_descriptor_in_txn(store, txn, &body.predicate)?
        .filter(ClaimClassDescriptor::declares_validation)
    else {
        return Ok(());
    };
    if !descriptor.subject_kind.admits(store, txn, &body.subject)? {
        return Err(invalid("the claim's subject is not one its class admits"));
    }
    if let (ClaimValidatorKind::Generic, Some(schema)) =
        (descriptor.validator_kind, &descriptor.schema)
    {
        let value = json_value(&body.value)
            .ok_or_else(|| invalid("the claim's value is not JSON for its class's schema"))?;
        if !value_meets_schema(&body.predicate, schema, &value)? {
            return Err(invalid(
                "the claim's value does not meet its class's schema",
            ));
        }
    }
    Ok(())
}

/// Checks `body` against the class the build compiles as `generic` for its
/// predicate, reading no store: the subject it names, and its value against
/// the class's schema, compiled once. This is the descriptor check for a
/// caller without a transaction (the stateless claim validator). A predicate
/// the build does not compile as `generic` passes here.
///
/// # Errors
/// A subject the class does not admit, a value JSON cannot hold, or one the
/// schema refuses.
pub(crate) fn check_claim_against_compiled_descriptor(
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    let Some(seed) = generic_class_seed(&body.predicate) else {
        return Ok(());
    };
    if !seed.subject_kind.admits_without_store(&body.subject) {
        return Err(invalid("the claim's subject is not one its class admits"));
    }
    let value = json_value(&body.value)
        .ok_or_else(|| invalid("the claim's value is not JSON for its class's schema"))?;
    if !seed.admits_value(&value)? {
        return Err(invalid(
            "the claim's value does not meet its class's schema",
        ));
    }
    Ok(())
}

/// Whether the build compiles `predicate`'s class as `generic`: a class
/// [`check_claim_against_compiled_descriptor`] checks.
pub(crate) fn is_compiled_generic_claim_predicate(predicate: &str) -> bool {
    generic_class_seed(predicate).is_some()
}

pub use crate::store::claim_descriptors::claim_class_descriptor_id;
pub use crate::store::claim_descriptors::decode_claim_class_descriptor;
pub use crate::store::claim_descriptors::encode_claim_class_descriptor;

/// The synced descriptor at `predicate`'s id, when one is there and reads.
/// A soft-erased shell, a body this build cannot decode or a row naming
/// another predicate leaves the compiled row standing.
fn synced_descriptor_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
) -> Result<Option<ClaimClassDescriptor>> {
    let Some(raw) = store.port_entity_record(txn, &claim_class_descriptor_id(predicate)?)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR {
        return Ok(None);
    }
    Ok(decode_claim_class_descriptor(&raw.body)
        .ok()
        .filter(|descriptor| descriptor.predicate == predicate))
}

/// The descriptor for `predicate`: the synced entity when one reads, else
/// the compiled `comm.*` row, else none.
pub(crate) fn claim_class_descriptor_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
) -> Result<Option<ClaimClassDescriptor>> {
    if let Some(synced) = synced_descriptor_in_txn(store, txn, predicate)? {
        return Ok(Some(synced));
    }
    Ok(compiled_descriptor(predicate))
}

/// Whether `predicate` is a restrictive `comm.*` class: its heads only add
/// suppression. The class must be one of the compiled `comm.*` rows; its
/// `restrictive` flag is read from the synced descriptor when one reads.
pub(crate) fn is_restrictive_comm_predicate(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
) -> Result<bool> {
    if compiled_row(predicate).is_none() {
        return Ok(false);
    }
    Ok(claim_class_descriptor_in_txn(store, txn, predicate)?
        .is_some_and(|descriptor| descriptor.restrictive))
}

/// Writes `descriptor` at `id` on the engine-owned setting, in the caller's
/// transaction. `enforcement=true` is refused unless a stamp covers these
/// semantics: the one the row carries, the stored row's stamp over the same
/// semantics (an identical rebuild carries it), or the compiled table's.
fn stage_claim_class_descriptor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    descriptor: &ClaimClassDescriptor,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    descriptor.validate()?;
    if *id != claim_class_descriptor_id(&descriptor.predicate)? {
        return Err(invalid(
            "claim-class descriptor id is not its predicate's derived id",
        ));
    }
    let mut row = descriptor.clone();
    if row.enforcement
        && row.enforcement_stamp.is_none()
        && let Some(stored) = synced_descriptor_in_txn(&vault.store, &*wtxn, &row.predicate)?
        && let Some(stamp) = stored.enforcement_stamp
        && stamp.semantics_hash == row.semantics_hash()
    {
        row.enforcement_stamp = Some(stamp);
    }
    if row.enforcement && !row.enforced() {
        return Err(invalid(
            "claim-class enforcement needs an owner stamp over its semantics hash",
        ));
    }
    let data = encode_claim_class_descriptor(&row)?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
            occurred,
            learned_at,
            row_version: None,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

/// Seeds the compiled `comm.*` rows as descriptor entities. Each id, body and
/// time is fixed, so two nodes that seed write the same bytes. A row already
/// there (seeded, synced in or owner-revised) is never reverted, and an
/// erased one does not come back.
pub(crate) fn seed_claim_class_descriptors(vault: &Vault) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        for row in claim_class_descriptors() {
            let id = claim_class_descriptor_id(row.predicate)?;
            if vault.store.port_entity_present(&*wtxn, &id)?
                || vault.local_hard_delete_marker_exists_in_txn(&*wtxn, &id)?
            {
                continue;
            }
            stage_claim_class_descriptor_in_txn(
                vault,
                wtxn,
                &id,
                &ClaimClassDescriptor::from_compiled(&row),
                TimeRange { start: 0, end: 0 },
                0,
            )?;
        }
        Ok(())
    })
}

impl Vault {
    /// The descriptor for `predicate`: the synced entity when one reads,
    /// else the compiled `comm.*` row, else none.
    pub fn claim_class_descriptor(&self, predicate: &str) -> Result<Option<ClaimClassDescriptor>> {
        let txn = self.store.env.read_txn()?;
        claim_class_descriptor_in_txn(&self.store, &txn, predicate)
    }

    /// Puts one claim class's descriptor on an authenticated owner decision.
    ///
    /// The owner's approve-once binds the class's id, its semantics hash, its
    /// `enforcement` and `learned_at`. With `enforcement=true` that approval
    /// is the human stamp: the row is written stamped over its semantics
    /// hash, and a later change to those semantics reads as not enforced
    /// until the owner stamps again. Any stamp the caller passes is replaced.
    pub fn put_claim_class_descriptor(
        &self,
        owner: &AuthenticatedOwner,
        descriptor: &ClaimClassDescriptor,
        learned_at: u64,
    ) -> Result<ConsentReceipt> {
        descriptor.validate()?;
        let id = claim_class_descriptor_id(&descriptor.predicate)?;
        let semantics = descriptor.semantics_hash();
        let effect =
            crate::consent::ComposedEffect::new(crate::consent::EffectFacts::new(format!(
                "{DESCRIPTOR_PUT_OPERATION}:{}:{}:{}:{learned_at}",
                id.to_hex(),
                hash_hex(&semantics),
                u8::from(descriptor.enforcement),
            ))?)
            .digest();
        self.with_write_txn_grouped(|wtxn| {
            let receipt = self.approve_once_in_txn(wtxn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, wtxn, &effect)?
                    .ok_or(Error::InvariantViolation(
                        "claim-class descriptor consent missing",
                    ))?;
            let mut row = descriptor.clone();
            row.enforcement_stamp = row.enforcement.then_some(EnforcementStamp {
                semantics_hash: semantics,
                approval: *effect.as_bytes(),
            });
            stage_claim_class_descriptor_in_txn(
                self,
                wtxn,
                &id,
                &row,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )?;
            crate::consent::spend_approve_once_in_txn(&self.store, wtxn, &authorization)?;
            Ok(receipt)
        })
    }
}
