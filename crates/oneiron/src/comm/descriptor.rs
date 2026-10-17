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

use rmpv::Value;

use super::claims::{ClaimClassDescriptorRow, claim_class_descriptors};
use super::records::{
    elided_string, encode_value, required_bool, required_string, validate_keys_with_optional,
    value_map,
};
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CLAIM_CLASS_DESCRIPTOR;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR;
use crate::store::Store;
use crate::temporal::TimeRange;

const KEY_PREDICATE: &str = "predicate";
const KEY_WRITE_CLASS: &str = "write_class";
const KEY_ENFORCEMENT: &str = "enforcement";
const KEY_RESTRICTIVE: &str = "restrictive";
const KEY_PROJECTOR_ONLY: &str = "projector_only";
const KEY_SEMANTICS_HASH: &str = "semantics_hash";
const KEY_STAMP_SEMANTICS_HASH: &str = "stamp_semantics_hash";
const KEY_STAMP_APPROVAL: &str = "stamp_approval";

/// Pinned MessagePack keys every CLAIM_CLASS_DESCRIPTOR body carries.
pub const CLAIM_CLASS_DESCRIPTOR_BODY_KEYS: [&str; 6] = [
    KEY_PREDICATE,
    KEY_WRITE_CLASS,
    KEY_ENFORCEMENT,
    KEY_RESTRICTIVE,
    KEY_PROJECTOR_ONLY,
    KEY_SEMANTICS_HASH,
];

/// The stamp keys: both present (a stamped row) or both elided.
const STAMP_KEYS: [&str; 2] = [KEY_STAMP_SEMANTICS_HASH, KEY_STAMP_APPROVAL];

/// Domain of the semantics hash. Changing it changes every hash, and so
/// unbinds every stamp.
const SEMANTICS_HASH_DOMAIN: &str = "oneiron comm claim-class descriptor semantics v1";

/// Operation kind the owner's approve-once binds for one descriptor put.
const DESCRIPTOR_PUT_OPERATION: &str = "comm.claim_class_descriptor.put";

/// ARCH-0057 §4 write class of a claim class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimWriteClass {
    /// Written only from recorded evidence (a projector's own records).
    Recorded,
    /// Written only on a human ruling.
    HumanRuled,
    /// Written by ordinary claim doors.
    Ordinary,
}

impl ClaimWriteClass {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::HumanRuled => "human_ruled",
            Self::Ordinary => "ordinary",
        }
    }

    /// Parses the pinned wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "recorded" => Some(Self::Recorded),
            "human_ruled" => Some(Self::HumanRuled),
            "ordinary" => Some(Self::Ordinary),
            _ => None,
        }
    }
}

/// The human stamp that lets a descriptor's `enforcement=true` count: the
/// semantics hash it was minted over, and the owner approve-once digest that
/// minted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementStamp {
    /// The semantics hash the owner stamped.
    pub semantics_hash: [u8; 32],
    /// The owner approve-once effect digest that minted this stamp.
    pub approval: [u8; 32],
}

/// One claim class, as the synced descriptor entity describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimClassDescriptor {
    /// The predicate this class describes.
    pub predicate: String,
    /// Who may write a head of this class.
    pub write_class: ClaimWriteClass,
    /// Whether the gate may consult this class's claim state. Counts only
    /// when stamped ([`Self::enforced`]).
    pub enforcement: bool,
    /// Whether a head of this class can only add suppression.
    pub restrictive: bool,
    /// Whether only a projector authors this class.
    pub projector_only: bool,
    /// The owner's stamp over the semantics hash, when one was minted.
    pub enforcement_stamp: Option<EnforcementStamp>,
}

impl ClaimClassDescriptor {
    /// The compiled row as an unstamped descriptor.
    #[must_use]
    pub fn from_compiled(row: &ClaimClassDescriptorRow) -> Self {
        Self {
            predicate: row.predicate.to_owned(),
            write_class: ClaimWriteClass::parse(row.write_class)
                .unwrap_or(ClaimWriteClass::Ordinary),
            enforcement: row.enforcement,
            restrictive: row.restrictive,
            projector_only: row.projector_only,
            enforcement_stamp: None,
        }
    }

    /// The hash a stamp binds: predicate, write class, `restrictive` and
    /// `projector_only`. `enforcement` is what a stamp approves, so it is not
    /// part of what the stamp binds; changing any bound field needs a new stamp.
    #[must_use]
    pub fn semantics_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SEMANTICS_HASH_DOMAIN);
        for field in [
            self.predicate.as_bytes(),
            self.write_class.as_str().as_bytes(),
        ] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        hasher.update(&[u8::from(self.restrictive), u8::from(self.projector_only)]);
        *hasher.finalize().as_bytes()
    }

    /// Whether `enforcement=true` counts here: an owner stamp over exactly
    /// this semantics hash, or the compiled row for this predicate enforcing
    /// the same semantics (an identical rebuild carries the build's stamp).
    /// A stamp over other semantics reads as not enforced.
    #[must_use]
    pub fn enforced(&self) -> bool {
        if !self.enforcement {
            return false;
        }
        let semantics = self.semantics_hash();
        self.enforcement_stamp
            .is_some_and(|stamp| stamp.semantics_hash == semantics)
            || compiled_row(&self.predicate).is_some_and(|row| {
                row.enforcement && Self::from_compiled(&row).semantics_hash() == semantics
            })
    }

    fn validate(&self) -> Result<()> {
        crate::claim::validate_predicate(&self.predicate, false)
    }
}

fn compiled_row(predicate: &str) -> Option<ClaimClassDescriptorRow> {
    claim_class_descriptors()
        .into_iter()
        .find(|row| row.predicate == predicate)
}

/// The compiled `comm.*` row for `predicate` as a descriptor.
fn compiled_descriptor(predicate: &str) -> Option<ClaimClassDescriptor> {
    compiled_row(predicate).map(|row| ClaimClassDescriptor::from_compiled(&row))
}

/// The one descriptor entity id for `predicate`, the same on every node.
pub fn claim_class_descriptor_id(predicate: &str) -> Result<EntityId> {
    EntityId::derive(CLAIM_CLASS_DESCRIPTOR, &[predicate.as_bytes()])
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn hash_hex(bytes: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*bytes).to_hex().to_string()
}

fn hash_from_hex(value: &str) -> Result<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .map(|hash| *hash.as_bytes())
        .map_err(|_| invalid("claim-class descriptor hash is not 32-byte hex"))
}

/// Encodes a CLAIM_CLASS_DESCRIPTOR body in canonical key order.
pub fn encode_claim_class_descriptor(descriptor: &ClaimClassDescriptor) -> Result<Vec<u8>> {
    descriptor.validate()?;
    let mut entries = vec![
        (
            Value::from(KEY_PREDICATE),
            Value::from(descriptor.predicate.as_str()),
        ),
        (
            Value::from(KEY_WRITE_CLASS),
            Value::from(descriptor.write_class.as_str()),
        ),
        (
            Value::from(KEY_ENFORCEMENT),
            Value::from(descriptor.enforcement),
        ),
        (
            Value::from(KEY_RESTRICTIVE),
            Value::from(descriptor.restrictive),
        ),
        (
            Value::from(KEY_PROJECTOR_ONLY),
            Value::from(descriptor.projector_only),
        ),
        (
            Value::from(KEY_SEMANTICS_HASH),
            Value::from(hash_hex(&descriptor.semantics_hash())),
        ),
    ];
    if let Some(stamp) = descriptor.enforcement_stamp {
        entries.push((
            Value::from(KEY_STAMP_SEMANTICS_HASH),
            Value::from(hash_hex(&stamp.semantics_hash)),
        ));
        entries.push((
            Value::from(KEY_STAMP_APPROVAL),
            Value::from(hash_hex(&stamp.approval)),
        ));
    }
    encode_value(&Value::Map(entries))
}

/// Decodes a CLAIM_CLASS_DESCRIPTOR body: exact keys, a known write class, a
/// valid predicate, a stored semantics hash that matches its fields, and the
/// stamp's two keys together or not at all.
pub fn decode_claim_class_descriptor(bytes: &[u8]) -> Result<ClaimClassDescriptor> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| invalid("claim-class descriptor body is not valid MessagePack"))?;
    let entries = value_map(&value)?;
    validate_keys_with_optional(entries, &CLAIM_CLASS_DESCRIPTOR_BODY_KEYS, &STAMP_KEYS)?;
    let stamp = match (
        elided_string(entries, KEY_STAMP_SEMANTICS_HASH)?,
        elided_string(entries, KEY_STAMP_APPROVAL)?,
    ) {
        (Some(semantics_hash), Some(approval)) => Some(EnforcementStamp {
            semantics_hash: hash_from_hex(semantics_hash)?,
            approval: hash_from_hex(approval)?,
        }),
        (None, None) => None,
        _ => return Err(invalid("claim-class descriptor stamp is half present")),
    };
    let descriptor = ClaimClassDescriptor {
        predicate: required_string(entries, KEY_PREDICATE)?.to_owned(),
        write_class: ClaimWriteClass::parse(required_string(entries, KEY_WRITE_CLASS)?)
            .ok_or_else(|| invalid("claim-class descriptor write class is unknown"))?,
        enforcement: required_bool(entries, KEY_ENFORCEMENT)?,
        restrictive: required_bool(entries, KEY_RESTRICTIVE)?,
        projector_only: required_bool(entries, KEY_PROJECTOR_ONLY)?,
        enforcement_stamp: stamp,
    };
    descriptor.validate()?;
    if hash_from_hex(required_string(entries, KEY_SEMANTICS_HASH)?)? != descriptor.semantics_hash()
    {
        return Err(invalid(
            "claim-class descriptor semantics hash does not match its fields",
        ));
    }
    Ok(descriptor)
}

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
            if vault.store.port_entity_raw(&*wtxn, &id)?.is_some()
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
