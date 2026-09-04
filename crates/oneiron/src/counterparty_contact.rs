//! Counterparty contact record substrate (OF-347 CID-7).
//!
//! A CounterpartyContactRecord is a vault-resident per-(channel identity,
//! counterparty) consent/contact row plus a typed `counterparty_contact.*`
//! claim family. Provider adapters and multiplayer graph expansion are
//! intentionally outside this module.

use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::channel_identity::decode_channel_identity_body;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

/// Current CounterpartyContactRecord body schema version.
pub const COUNTERPARTY_CONTACT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for CounterpartyContactRecord bodies.
pub const COUNTERPARTY_CONTACT_BODY_KEYS: [&str; 11] = [
    "schema_version",
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "created_at",
    "updated_at",
    "revoked_at",
    "opt_out",
    "promo_consent",
    "notes",
];

pub(crate) const COUNTERPARTY_CONTACT_FIELDS_MINIMAL: &[&str] = &[
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "opt_out",
];
pub(crate) const COUNTERPARTY_CONTACT_FIELDS_STANDARD: &[&str] = &[
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "updated_at",
    "opt_out",
    "promo_consent",
];
pub(crate) const COUNTERPARTY_CONTACT_FIELDS_FULL: &[&str] = &COUNTERPARTY_CONTACT_BODY_KEYS;

const KEY_SCHEMA_VERSION: &str = COUNTERPARTY_CONTACT_BODY_KEYS[0];
const KEY_IDENTITY_REF: &str = COUNTERPARTY_CONTACT_BODY_KEYS[1];
const KEY_COUNTERPARTY: &str = COUNTERPARTY_CONTACT_BODY_KEYS[2];
const KEY_FIRST_TOUCH: &str = COUNTERPARTY_CONTACT_BODY_KEYS[3];
const KEY_STATUS: &str = COUNTERPARTY_CONTACT_BODY_KEYS[4];
const KEY_CREATED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[5];
const KEY_UPDATED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[6];
const KEY_REVOKED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[7];
const KEY_OPT_OUT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[8];
const KEY_PROMO_CONSENT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[9];
const KEY_NOTES: &str = COUNTERPARTY_CONTACT_BODY_KEYS[10];

const OPT_OUT_KEYS: [&str; 3] = ["reason", "recorded_at", "receipt_reason"];
const KEY_OPT_OUT_REASON: &str = OPT_OUT_KEYS[0];
const KEY_OPT_OUT_RECORDED_AT: &str = OPT_OUT_KEYS[1];
const KEY_OPT_OUT_RECEIPT_REASON: &str = OPT_OUT_KEYS[2];

const MAX_COUNTERPARTY_BYTES: usize = 512;
const MAX_NOTES: usize = 32;
const MAX_NOTE_BYTES: usize = 2_048;
const COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX: &[u8] = b"counterparty_contact.index.v1:";

/// Vault-meta prefix of the identity-INDEPENDENT `(party_ref, channel_class)`
/// contact index (ONE-1868 / ARCH-0057 §3).
///
/// Index only: no entity, no type byte, no second copy of opt-out truth. Its
/// value is the canonical de-duplicated set of every contact ref recorded for
/// the pair, because one party can be reachable on one channel class through
/// several sending identities and the send-time aggregate is RESTRICTIVE.
pub const COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX: &[u8] =
    b"counterparty.contact.party_channel.v1:";

/// Pinned `counterparty_contact.*` claim predicates for owner-visible fields.
pub const COUNTERPARTY_CONTACT_CLAIM_PREDICATES: [&str; 10] = [
    PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
    PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH,
    PREDICATE_COUNTERPARTY_CONTACT_STATUS,
    PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT,
    PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT,
    PREDICATE_COUNTERPARTY_CONTACT_NOTES,
];

pub const PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF: &str = "counterparty_contact.identity_ref";
pub const PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY: &str = "counterparty_contact.counterparty";
pub const PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH: &str = "counterparty_contact.first_touch";
pub const PREDICATE_COUNTERPARTY_CONTACT_STATUS: &str = "counterparty_contact.status";
pub const PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT: &str = "counterparty_contact.created_at";
pub const PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT: &str = "counterparty_contact.updated_at";
pub const PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT: &str = "counterparty_contact.revoked_at";
pub const PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT: &str = "counterparty_contact.opt_out";
pub const PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT: &str = "counterparty_contact.promo_consent";
pub const PREDICATE_COUNTERPARTY_CONTACT_NOTES: &str = "counterparty_contact.notes";

/// How the counterparty first became reachable through this identity.
///
/// The serde derive is wire-only (interlocutor echo, ILD-1); the on-disk
/// MessagePack body encoding stays `as_str()` based.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CounterpartyFirstTouch {
    UserIntroduction,
    InboundFirst,
    Public,
}

impl CounterpartyFirstTouch {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserIntroduction => "user_introduction",
            Self::InboundFirst => "inbound_first",
            Self::Public => "public",
        }
    }

    #[must_use]
    pub const fn receipt_reason(self) -> &'static str {
        match self {
            Self::UserIntroduction => "counterparty_first_touch_user_introduction",
            Self::InboundFirst => "counterparty_first_touch_inbound_first",
            Self::Public => "counterparty_first_touch_public",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user_introduction" => Some(Self::UserIntroduction),
            "inbound_first" => Some(Self::InboundFirst),
            "public" => Some(Self::Public),
            _ => None,
        }
    }
}

/// Owner-visible contact lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CounterpartyContactStatus {
    Active,
    Revoked,
}

impl CounterpartyContactStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Platform-specific opt-out event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CounterpartyOptOutReason {
    Stop,
    Unsubscribe,
    BlockOrFriendRemoval,
}

impl CounterpartyOptOutReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Unsubscribe => "unsubscribe",
            Self::BlockOrFriendRemoval => "block_or_friend_removal",
        }
    }

    #[must_use]
    pub const fn receipt_reason(self) -> &'static str {
        match self {
            Self::Stop => "counterparty_opt_out_stop",
            Self::Unsubscribe => "counterparty_opt_out_unsubscribe",
            Self::BlockOrFriendRemoval => "counterparty_opt_out_block_or_friend_removal",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stop" => Some(Self::Stop),
            "unsubscribe" => Some(Self::Unsubscribe),
            "block_or_friend_removal" => Some(Self::BlockOrFriendRemoval),
            _ => None,
        }
    }

    /// Exact inverse of [`Self::receipt_reason`] — the RECEIPT vocabulary, not
    /// the [`Self::as_str`] one. `comm.opt_out` heads store receipt tokens, so
    /// this is how a head's reason comes back as a typed reason when the
    /// type-132 cache is re-derived. An unknown token is `None`, never a
    /// guess.
    #[must_use]
    pub(crate) fn from_receipt_reason(token: &str) -> Option<Self> {
        match token {
            "counterparty_opt_out_stop" => Some(Self::Stop),
            "counterparty_opt_out_unsubscribe" => Some(Self::Unsubscribe),
            "counterparty_opt_out_block_or_friend_removal" => Some(Self::BlockOrFriendRemoval),
            _ => None,
        }
    }
}

/// Recorded counterparty opt-out state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterpartyOptOut {
    pub reason: CounterpartyOptOutReason,
    pub recorded_at: u64,
}

impl CounterpartyOptOut {
    #[must_use]
    pub const fn new(reason: CounterpartyOptOutReason, recorded_at: u64) -> Self {
        Self {
            reason,
            recorded_at,
        }
    }

    #[must_use]
    pub const fn receipt_reason(self) -> &'static str {
        self.reason.receipt_reason()
    }
}

/// Vault-resident per-(identity, counterparty) contact record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterpartyContactRecord {
    pub identity_ref: EntityId,
    pub counterparty: String,
    pub first_touch: CounterpartyFirstTouch,
    pub status: CounterpartyContactStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
    pub opt_out: Option<CounterpartyOptOut>,
    pub promo_consent: bool,
    pub notes: Vec<String>,
}

impl CounterpartyContactRecord {
    /// Constructs a contact authorized by an owner-supplied introduction.
    pub fn user_introduction(
        identity_ref: EntityId,
        counterparty: impl Into<String>,
        created_at: u64,
    ) -> Result<Self> {
        Self::new(
            identity_ref,
            counterparty,
            CounterpartyFirstTouch::UserIntroduction,
            created_at,
        )
    }

    /// Constructs a contact first observed through inbound traffic.
    pub fn inbound_first(
        identity_ref: EntityId,
        counterparty: impl Into<String>,
        created_at: u64,
    ) -> Result<Self> {
        Self::new(
            identity_ref,
            counterparty,
            CounterpartyFirstTouch::InboundFirst,
            created_at,
        )
    }

    /// Constructs a contact discovered from a public address or handle.
    pub fn public(
        identity_ref: EntityId,
        counterparty: impl Into<String>,
        created_at: u64,
    ) -> Result<Self> {
        Self::new(
            identity_ref,
            counterparty,
            CounterpartyFirstTouch::Public,
            created_at,
        )
    }

    fn new(
        identity_ref: EntityId,
        counterparty: impl Into<String>,
        first_touch: CounterpartyFirstTouch,
        created_at: u64,
    ) -> Result<Self> {
        let record = Self {
            identity_ref,
            counterparty: normalize_counterparty(counterparty.into())?,
            first_touch,
            status: CounterpartyContactStatus::Active,
            created_at,
            updated_at: created_at,
            revoked_at: None,
            opt_out: None,
            promo_consent: false,
            notes: Vec::new(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns this record with an appended owner-visible note.
    pub fn with_note(mut self, note: impl Into<String>, updated_at: u64) -> Result<Self> {
        if updated_at < self.updated_at {
            return Err(invalid_contact());
        }
        self.notes.push(normalize_note(note.into())?);
        self.updated_at = updated_at;
        self.validate()?;
        Ok(self)
    }

    /// Returns this record with promotional consent set by documented prior consent.
    pub fn with_promo_consent(mut self, promo_consent: bool, updated_at: u64) -> Result<Self> {
        if updated_at < self.updated_at {
            return Err(invalid_contact());
        }
        self.promo_consent = promo_consent;
        self.updated_at = updated_at;
        self.validate()?;
        Ok(self)
    }

    /// Returns this record after a legal/platform opt-out event.
    pub fn opted_out(mut self, reason: CounterpartyOptOutReason, recorded_at: u64) -> Result<Self> {
        if recorded_at < self.updated_at {
            return Err(invalid_contact());
        }
        self.opt_out = Some(CounterpartyOptOut::new(reason, recorded_at));
        self.updated_at = recorded_at;
        self.validate()?;
        Ok(self)
    }

    /// Returns this record after owner revocation.
    pub fn revoked(mut self, revoked_at: u64) -> Result<Self> {
        if revoked_at < self.updated_at {
            return Err(invalid_contact());
        }
        self.status = CounterpartyContactStatus::Revoked;
        self.revoked_at = Some(revoked_at);
        self.updated_at = revoked_at;
        self.validate()?;
        Ok(self)
    }

    /// Returns whether this contact is legally/platform opted out.
    #[must_use]
    pub const fn is_opted_out(&self) -> bool {
        self.opt_out.is_some()
    }

    /// Returns whether the record matches a send target.
    #[must_use]
    pub fn matches_counterparty(&self, identity_ref: &EntityId, counterparty: &str) -> bool {
        self.identity_ref.as_bytes() == identity_ref.as_bytes() && self.matches_party(counterparty)
    }

    /// Returns whether the record is about `party_ref`, whatever identity it
    /// was recorded through.
    ///
    /// The send-time opt-out aggregate is keyed by party and channel class, not
    /// by sending identity: a counterparty who said STOP said it to the owner,
    /// not to one mailbox.
    #[must_use]
    pub fn matches_party(&self, party_ref: &str) -> bool {
        self.counterparty == party_ref.trim()
    }

    /// Validates CID-7 record invariants.
    pub fn validate(&self) -> Result<()> {
        validate_counterparty(&self.counterparty)?;
        if self.updated_at < self.created_at {
            return Err(invalid_contact());
        }
        match (self.status, self.revoked_at) {
            (CounterpartyContactStatus::Active, None) => {}
            (CounterpartyContactStatus::Active, Some(_)) => return Err(invalid_contact()),
            (CounterpartyContactStatus::Revoked, Some(revoked_at))
                if revoked_at >= self.created_at && self.updated_at >= revoked_at => {}
            (CounterpartyContactStatus::Revoked, Some(_))
            | (CounterpartyContactStatus::Revoked, None) => return Err(invalid_contact()),
        }
        if let Some(opt_out) = self.opt_out
            && (opt_out.recorded_at < self.created_at || self.updated_at < opt_out.recorded_at)
        {
            return Err(invalid_contact());
        }
        validate_notes(&self.notes)?;
        Ok(())
    }

    /// Builds typed `counterparty_contact.*` claim bodies for this record.
    #[must_use]
    pub fn claim_bodies(&self, contact_id: EntityId) -> Vec<ClaimBody> {
        COUNTERPARTY_CONTACT_CLAIM_PREDICATES
            .iter()
            .map(|predicate| {
                ClaimBody::new(
                    *predicate,
                    ClaimSubject::Entity(contact_id),
                    self.claim_value(predicate)
                        .expect("predicate drawn from counterparty contact family"),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
            })
            .collect()
    }

    fn claim_value(&self, predicate: &str) -> Option<Value> {
        match predicate {
            PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF => {
                Some(Value::from(self.identity_ref.to_hex()))
            }
            PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY => {
                Some(Value::from(self.counterparty.as_str()))
            }
            PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH => {
                Some(Value::from(self.first_touch.as_str()))
            }
            PREDICATE_COUNTERPARTY_CONTACT_STATUS => Some(Value::from(self.status.as_str())),
            PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT => Some(Value::from(self.created_at)),
            PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT => Some(Value::from(self.updated_at)),
            PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT => {
                Some(self.revoked_at.map_or(Value::Nil, Value::from))
            }
            PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT => Some(encode_opt_out(self.opt_out)),
            PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT => {
                Some(Value::Boolean(self.promo_consent))
            }
            PREDICATE_COUNTERPARTY_CONTACT_NOTES => Some(encode_notes(&self.notes)),
            _ => None,
        }
    }
}

/// Encodes a CounterpartyContactRecord body in canonical MessagePack field order.
pub fn encode_counterparty_contact_body(record: &CounterpartyContactRecord) -> Result<Vec<u8>> {
    record.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COUNTERPARTY_CONTACT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(record.identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_COUNTERPARTY),
            Value::from(record.counterparty.as_str()),
        ),
        (
            Value::from(KEY_FIRST_TOUCH),
            Value::from(record.first_touch.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
        (
            Value::from(KEY_REVOKED_AT),
            record.revoked_at.map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_OPT_OUT), encode_opt_out(record.opt_out)),
        (
            Value::from(KEY_PROMO_CONSENT),
            Value::Boolean(record.promo_consent),
        ),
        (Value::from(KEY_NOTES), encode_notes(&record.notes)),
    ]);

    encode_msgpack_value(
        &value,
        "counterparty contact body MessagePack encode failed",
    )
}

/// Decodes and validates a CounterpartyContactRecord body.
pub fn decode_counterparty_contact_body(bytes: &[u8]) -> Result<CounterpartyContactRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_contact())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_contact());
    }

    decode_counterparty_contact_value(&value)
}

pub(crate) fn counterparty_contact_index_key(
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Vec<u8>> {
    let counterparty = normalize_counterparty(counterparty.to_owned())?;
    let counterparty_hash = Sha256::digest(counterparty.as_bytes());
    let mut key = Vec::with_capacity(
        COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX.len() + ENTITY_ID_LEN + counterparty_hash.len(),
    );
    key.extend_from_slice(COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX);
    key.extend_from_slice(identity_ref.as_bytes());
    key.extend_from_slice(&counterparty_hash);
    Ok(key)
}

pub(crate) fn counterparty_contact_index_key_for_record(
    record: &CounterpartyContactRecord,
) -> Result<Vec<u8>> {
    counterparty_contact_index_key(&record.identity_ref, &record.counterparty)
}

pub(crate) fn encode_counterparty_contact_index_value(id: &EntityId) -> [u8; ENTITY_ID_LEN] {
    *id.as_bytes()
}

/// Canonical channel-class normalization for the party-channel index.
///
/// Shared by the index writer, the record-class resolver, and the
/// external-effect gate so a stored class and a queried class can never
/// disagree over case or padding. Mirrors `campaign::claims`'s token rule, the
/// one CA-01's `comm.do_not_contact` matching already uses.
#[must_use]
pub fn normalize_channel_class(channel: &str) -> String {
    channel.trim().to_ascii_lowercase()
}

/// Vault-meta key of the `(party_ref, channel_class)` contact index.
///
/// The party is length-prefixed before the class so no `(party, class)` pair
/// can collide with a different split of the same bytes.
pub fn counterparty_contact_party_channel_index_key(
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<u8>> {
    let party = normalize_counterparty(party_ref.to_owned())?;
    let channel_class = normalize_channel_class(channel_class);
    let mut hasher = Sha256::new();
    hasher.update((party.len() as u64).to_be_bytes());
    hasher.update(party.as_bytes());
    hasher.update(channel_class.as_bytes());
    let digest = hasher.finalize();
    let mut key =
        Vec::with_capacity(COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    Ok(key)
}

fn encode_party_channel_index_value(refs: &[EntityId]) -> Vec<u8> {
    let mut sorted: Vec<[u8; ENTITY_ID_LEN]> = refs.iter().map(|id| *id.as_bytes()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.concat()
}

fn decode_party_channel_index_value(raw: &[u8]) -> Result<Vec<EntityId>> {
    if !raw.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex(
            "counterparty contact party/channel index value",
        ));
    }
    raw.chunks_exact(ENTITY_ID_LEN)
        .map(|chunk| {
            let bytes: [u8; ENTITY_ID_LEN] = chunk.try_into().map_err(|_| {
                Error::CorruptedIndex("counterparty contact party/channel index value")
            })?;
            EntityId::from_bytes(bytes).map_err(|_| {
                Error::CorruptedIndex("counterparty contact party/channel index value")
            })
        })
        .collect()
}

/// Appends `contact_ref` to the canonical de-duplicated set for this pair.
pub(crate) fn put_counterparty_contact_party_channel_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    contact_ref: EntityId,
) -> Result<()> {
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let mut refs = match store.vault_meta.get(&*wtxn, &key)? {
        Some(raw) => decode_party_channel_index_value(&raw)?,
        None => Vec::new(),
    };
    refs.push(contact_ref);
    let value = encode_party_channel_index_value(&refs);
    store.vault_meta.put(wtxn, &key, &value)?;
    Ok(())
}

/// Resolves the channel class a contact record belongs to, or `None` when the
/// record's sending identity does not resolve to a ChannelIdentity row.
///
/// `None` means UNKNOWN, never "no class": see
/// [`counterparty_contact_matches_channel_class`].
pub(crate) fn counterparty_contact_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CounterpartyContactRecord,
) -> Result<Option<String>> {
    let Some(raw) = store.entities.get(txn, record.identity_ref.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    Ok(Some(normalize_channel_class(&identity.channel)))
}

/// Whether a record participates in the `(party_ref, channel_class)` aggregate.
///
/// A record whose class is UNKNOWN matches EVERY class. This is the same
/// uncertainty rule CA-01 pins in `campaign::claims::do_not_contact_applies`: a
/// reader who cannot prove the suppression is irrelevant must treat it as
/// relevant. Resolving the other way would turn every unresolvable identity
/// into a false negative — the exact failure this index exists to prevent.
pub(crate) fn counterparty_contact_matches_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CounterpartyContactRecord,
    channel_class: &str,
) -> Result<bool> {
    Ok(counterparty_contact_channel_class(store, txn, record)?
        .is_none_or(|stored| stored == normalize_channel_class(channel_class)))
}

/// The contact records the party-channel index names for this party/class pair.
///
/// The index is a CANDIDATE source, never a verdict source: a hit is re-validated
/// against the party, so an entry left behind by a record that later changed
/// identity is filtered rather than mis-attributed. Channel scope is NOT applied
/// here — every candidate source funnels through the single class predicate in
/// `gate::counterparty_contacts_for_send`, so no source can ship a row into the
/// aggregate that skipped it.
pub(crate) fn counterparty_contacts_by_party_channel(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let Some(raw) = store.vault_meta.get(txn, &key)? else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for id in decode_party_channel_index_value(&raw)? {
        let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
            return Err(Error::CorruptedIndex(
                "counterparty contact party/channel index entity row",
            ));
        };
        if record.matches_party(party_ref) {
            records.push((id, record));
        }
    }
    Ok(records)
}

/// Every contact record for this party, found by scanning ALL COUNTERPARTY_CONTACT rows.
///
/// Unbounded and mandatory: the party-channel index cannot prove its own
/// completeness at HEAD (rows written before it existed are absent, and so is
/// any row whose identity had no resolvable channel class at write time), and a
/// bounded lookup that missed one opted-out row would answer a false "no".
/// ONE-1752's cutover owns retiring this scan.
pub(crate) fn counterparty_contacts_by_party_full_scan(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
    let mut records = Vec::new();
    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
            return Err(Error::CorruptedIndex("counterparty contact entity row"));
        };
        if record.matches_party(party_ref) {
            records.push((id, record));
        }
    }
    Ok(records)
}

/// Reads one contact record inside a caller-owned transaction.
pub(crate) fn read_counterparty_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CounterpartyContactRecord>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
        return Err(Error::CorruptedIndex("counterparty contact entity type"));
    }
    decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

pub(crate) fn decode_counterparty_contact_index_value(raw: &[u8]) -> Result<EntityId> {
    if raw.len() != ENTITY_ID_LEN {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index value",
        ));
    }
    EntityId::from_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("counterparty contact lookup index value"))?,
    )
    .map_err(|_| Error::CorruptedIndex("counterparty contact lookup index value"))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_counterparty_contact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_counterparty_contact_body(bytes).map(|_| ())
}

/// Closes `old_id` in favour of `new_id` for one claim whose FAMILY DOOR owns
/// the transition, inside the caller's write transaction.
///
/// The transition itself is the ordinary ARCH-0003 one — the old body is closed
/// `superseded` with `valid_to = now`, its envelope end is refreshed, and the
/// `supersedes` edge is written from the replacement — on the engine-owned
/// setting, for the same reason the family's head writer uses it: the door
/// already decided and validated this write, and a criticality ladder that
/// could REFUSE the close would leave the family with two live heads for one
/// predicate, which is the one state its readers must never see. The general
/// public door (`Vault::supersede_claim_in_txn`) remains the door for claims
/// nobody's family owns, and the reserved door stays scoped to the engine's own
/// `skill.*`/`actor.*` namespaces.
pub(crate) fn supersede_family_owned_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    new_id: &EntityId,
    old_id: &EntityId,
    now: u64,
) -> Result<()> {
    if new_id == old_id {
        return Err(Error::ClaimSelfSupersession);
    }
    let raw = vault
        .store
        .entities
        .get(&*wtxn, old_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    let mut body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody(
            "family-owned supersession target is not active",
        ));
    }
    body.lifecycle = ClaimLifecycleStatus::Superseded;
    body.valid_to = Some(now);
    let data = crate::claim::encode_claim_body(&body)?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: now.max(header.occurred_start),
                },
                learned_at: header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: crate::edge::EdgeKind::Supersedes,
                tgt: *old_id,
                weight: crate::vault::SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

/// Re-derives the type-132 cache row for `contact_id` from claims, inside the
/// caller's write transaction (ONE-1752).
///
/// This is the SOLE rebuild engine for the type-132 row, and the only
/// production caller of `apply_counterparty_contact_body`. Every writer of
/// contact or opt-out truth supersedes claim heads and then calls this in the
/// SAME transaction, so the direction of truth is always claims → cache and a
/// reader can never observe the two disagreeing.
///
/// The rebuilt opt-out is a RESTRICTIVE OR-fold over two sources: this
/// contact's own `counterparty_contact.opt_out` head, and every live
/// `comm.opt_out` head for the resolved party that COVERS this contact's
/// channel class — party-wide heads cover all of them, a channel-scoped STOP
/// head covers only its own class, and a contact with no resolvable class is
/// covered by every head. If any covering source stands, the rebuilt record is
/// opted out. Reason and timestamp come from the newest standing source by
/// `issued_at`; on a tie the contact-family head wins as the more specific one.
///
/// Because the scope decision lives in the fold rather than in each caller's
/// choice of which contacts to re-derive, ANY writer may re-derive ANY row of
/// the party without a foreign-channel head bleeding into it.
///
/// The row is rebuilt DETERMINISTICALLY from heads — `now` stamps the envelope,
/// never the body — so re-running this on unchanged claims reproduces
/// byte-identical `encode_counterparty_contact_body` output.
pub(crate) fn rematerialize_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    contact_id: &EntityId,
    now: u64,
) -> Result<()> {
    let mut record = counterparty_contact_record_from_claims_in_txn(vault, &*wtxn, contact_id)?;
    fold_party_opt_out_heads_in_txn(vault, &*wtxn, &mut record)?;
    let data = encode_counterparty_contact_body(&record)?;
    vault.apply_counterparty_contact_body(wtxn, contact_id, now, data)
}

/// Re-derives the type-132 cache for EVERY contact of `party_ref` a head on
/// `channel_class` can reach, inside the caller's write transaction (ONE-1752).
///
/// `None` is the party-wide key: every contact of the party, whatever channel
/// it sends on. A named class re-derives the contacts that class covers —
/// including any whose identity resolves to no class, because unknown is
/// covered by every head and its row must therefore follow every head.
///
/// A writer that moved PARTY-scoped opt-out truth must use this rather than
/// re-deriving the one contact it was handed: a party-wide head that left a
/// sibling contact's row not-opted-out would leave the gate reading a stale
/// "no" for a party that said stop (fail-open). The enumeration is the same
/// mandatory full scan the send-time aggregate uses — the party-channel index
/// cannot prove its own completeness at HEAD, and a bounded lookup that missed
/// one row would reintroduce exactly that hole. Which heads then apply to each
/// row stays the fold's decision, so re-deriving a row is never a suppression
/// source of its own.
pub(crate) fn rematerialize_party_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: Option<&str>,
    now: u64,
) -> Result<()> {
    let mut targets = Vec::new();
    for (contact_id, record) in
        counterparty_contacts_by_party_full_scan(&vault.store, &*wtxn, party_ref)?
    {
        if let Some(channel_class) = channel_class
            && !counterparty_contact_matches_channel_class(
                &vault.store,
                &*wtxn,
                &record,
                channel_class,
            )?
        {
            continue;
        }
        targets.push(contact_id);
    }
    for contact_id in targets {
        rematerialize_contact_cache_in_txn(vault, wtxn, &contact_id, now)?;
    }
    Ok(())
}

/// Rebuilds the record a contact's `counterparty_contact.*` heads describe.
///
/// Every predicate in the family must have exactly one head that is ACTIVE and
/// not stale — approval rung is deliberately not filtered on, because a head
/// the write gate downgraded to `proposed` is still the truth the owner's
/// writer recorded, and dropping it would silently lose opt-out state. A
/// missing or doubled head is a corrupted projection and fails closed.
fn counterparty_contact_record_from_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
) -> Result<CounterpartyContactRecord> {
    let mut heads: Vec<Option<Value>> = vec![None; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()];
    for claim_id in vault.claims_for_subject_in_txn(rtxn, contact_id)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        let Some(index) = COUNTERPARTY_CONTACT_CLAIM_PREDICATES
            .iter()
            .position(|predicate| *predicate == body.predicate)
        else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active || body.stale {
            continue;
        }
        if heads[index].is_some() {
            return Err(Error::InvalidCounterpartyContactBody(
                "counterparty contact claim family has two live heads for one predicate",
            ));
        }
        heads[index] = Some(body.value);
    }

    let mut entries = vec![(
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(COUNTERPARTY_CONTACT_SCHEMA_VERSION),
    )];
    for (index, predicate) in COUNTERPARTY_CONTACT_CLAIM_PREDICATES.iter().enumerate() {
        let value = heads[index]
            .take()
            .ok_or(Error::InvalidCounterpartyContactBody(
                "counterparty contact claim family is missing a live head",
            ))?;
        entries.push((Value::from(counterparty_contact_body_key(predicate)), value));
    }
    // Straight back through the canonical decoder, so the rebuilt record clears
    // exactly the validation a stored body clears.
    decode_counterparty_contact_value(&Value::Map(entries))
}

/// The body field one `counterparty_contact.*` predicate projects.
fn counterparty_contact_body_key(predicate: &str) -> &'static str {
    match predicate {
        PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF => KEY_IDENTITY_REF,
        PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY => KEY_COUNTERPARTY,
        PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH => KEY_FIRST_TOUCH,
        PREDICATE_COUNTERPARTY_CONTACT_STATUS => KEY_STATUS,
        PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT => KEY_CREATED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT => KEY_UPDATED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT => KEY_REVOKED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT => KEY_OPT_OUT,
        PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT => KEY_PROMO_CONSENT,
        PREDICATE_COUNTERPARTY_CONTACT_NOTES => KEY_NOTES,
        _ => unreachable!("predicate drawn from the counterparty contact family"),
    }
}

/// OR-folds every live `comm.opt_out` head for this record's party that COVERS
/// this record's channel class into it.
///
/// Monotonic: this can only ADD suppression, never clear what the contact's own
/// head established. An unknown comm reason token falls back to the contact
/// head's reason; when NEITHER source decodes, the fold fails closed rather
/// than dropping opt-out truth on the floor.
///
/// Channel scope is the head's, applied once here (ONE-1752): a party-wide head
/// covers every contact — the party said it to the owner, not to one mailbox —
/// and a channel-scoped STOP head covers only contacts on its own class, so an
/// email STOP can never suppress a telegram contact no matter which writer
/// re-derives the row. A contact whose identity resolves to no class is UNKNOWN,
/// and unknown matches EVERY head: the same CA-01 uncertainty rule
/// [`counterparty_contact_matches_channel_class`] states, resolved restrictively.
fn fold_party_opt_out_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    record: &mut CounterpartyContactRecord,
) -> Result<()> {
    let Some(party_ref) = crate::comm::resolve_party_ref_in_txn(vault, rtxn, &record.counterparty)
        .map_err(comm_fold_error)?
    else {
        return Ok(());
    };
    // Resolved ONCE: the class comes from the record's sending identity, which
    // no head in this loop can move.
    let contact_class = counterparty_contact_channel_class(&vault.store, rtxn, record)?;
    for head in crate::comm::standing_opt_out_heads_in_txn(vault, rtxn, party_ref)
        .map_err(comm_fold_error)?
    {
        if let Some(contact_class) = contact_class.as_deref()
            && !head.matches_channel(contact_class)
        {
            continue;
        }
        // Newest standing source wins; the contact head keeps a tie, being the
        // more specific statement about this exact contact.
        if record
            .opt_out
            .is_some_and(|opt_out| head.occurred_at <= opt_out.recorded_at)
        {
            continue;
        }
        let reason = match CounterpartyOptOutReason::from_receipt_reason(&head.reason) {
            Some(reason) => reason,
            None => match record.opt_out {
                Some(opt_out) => opt_out.reason,
                None => {
                    return Err(Error::InvalidCounterpartyContactBody(
                        "comm.opt_out reason is outside the receipt vocabulary",
                    ));
                }
            },
        };
        // Clamped into the record's own window: the head is the SOURCE of the
        // opt-out, and the record's invariants are what a stored body must
        // satisfy.
        let recorded_at = head.occurred_at.max(record.created_at);
        record.opt_out = Some(CounterpartyOptOut::new(reason, recorded_at));
        record.updated_at = record.updated_at.max(recorded_at);
    }
    Ok(())
}

/// Lowers a comm-family read failure into the contact error type. An engine
/// error travels unchanged; a comm-shaped one becomes the contact family's own
/// fail-closed class.
fn comm_fold_error(error: crate::comm::CommError) -> Error {
    match error {
        crate::comm::CommError::Engine(error) => error,
        _ => Error::InvalidCounterpartyContactBody("comm opt-out head failed to decode"),
    }
}

/// Re-derives the type-132 cache row for `contact_id` from claims, in its own
/// write transaction, and returns the rebuilt record. The ops path, and the
/// proof that the cache is reproducible from claims alone.
pub fn rematerialize_contact_cache(
    vault: &Vault,
    contact_id: &EntityId,
) -> Result<CounterpartyContactRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = crate::unix_seconds_now();
    rematerialize_contact_cache_in_txn(vault, &mut wtxn, contact_id, now)?;
    let record = read_counterparty_contact_in_txn(&vault.store, &wtxn, contact_id)?
        .ok_or(Error::EntityNotFound)?;
    wtxn.commit()?;
    Ok(record)
}

/// Drops the type-132 CACHE row for `contact_id` and its lookup index entries.
///
/// It touches NO claim: the contact's `counterparty_contact.*` heads and the
/// party's `comm.opt_out` heads are the truth, and they are exactly what
/// [`rematerialize_contact_cache`] rebuilds the row from afterwards. This is
/// what makes type-132 a dial rather than a wall — dropping it loses nothing.
///
/// Both index legs go with the row: leaving either pointing at a row that no
/// longer exists would make the send-time aggregate REFUSE rather than answer,
/// and the rematerializer writes both back.
pub fn drop_contact_cache_row(vault: &Vault, contact_id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let Some(record) = read_counterparty_contact_in_txn(&vault.store, &wtxn, contact_id)? else {
        return Ok(());
    };
    let index_key = counterparty_contact_index_key_for_record(&record)?;
    vault.store.vault_meta.delete(&mut wtxn, &index_key)?;
    if let Some(channel_class) = counterparty_contact_channel_class(&vault.store, &wtxn, &record)? {
        remove_counterparty_contact_party_channel_index(
            &vault.store,
            &mut wtxn,
            &record.counterparty,
            &channel_class,
            *contact_id,
        )?;
    }
    vault
        .store
        .entities
        .delete(&mut wtxn, contact_id.as_bytes())?;
    let type_key =
        crate::store::Store::encode_type_key(ENTITY_TYPE_COUNTERPARTY_CONTACT, contact_id);
    vault.store.type_index.delete(&mut wtxn, &type_key)?;
    wtxn.commit()?;
    Ok(())
}

/// Removes `contact_ref` from the canonical de-duplicated set for this pair,
/// deleting the entry entirely when nothing is left in it.
fn remove_counterparty_contact_party_channel_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    contact_ref: EntityId,
) -> Result<()> {
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Ok(());
    };
    let mut refs = decode_party_channel_index_value(&raw)?;
    refs.retain(|id| *id != contact_ref);
    if refs.is_empty() {
        store.vault_meta.delete(wtxn, &key)?;
    } else {
        let value = encode_party_channel_index_value(&refs);
        store.vault_meta.put(wtxn, &key, &value)?;
    }
    Ok(())
}

/// Returns whether `predicate` belongs to the CounterpartyContact claim family.
#[must_use]
pub fn is_counterparty_contact_claim_predicate(predicate: &str) -> bool {
    COUNTERPARTY_CONTACT_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `counterparty_contact.*` claim body.
pub(crate) fn validate_counterparty_contact_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "counterparty_contact claim subject must be an entity",
        ));
    }
    if !is_counterparty_contact_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown counterparty_contact claim predicate",
        ));
    }
    if body.predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidClaimBody(
            "counterparty_contact predicate exceeds max predicate bytes",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF => decode_entity_ref(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("counterparty_contact identity_ref invalid")),
        PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY => validate_claim_string(
            &body.value,
            MAX_COUNTERPARTY_BYTES,
            "counterparty_contact.counterparty value must be non-empty string",
        ),
        PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH => body
            .value
            .as_str()
            .and_then(CounterpartyFirstTouch::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "counterparty_contact.first_touch value must be pinned",
            )),
        PREDICATE_COUNTERPARTY_CONTACT_STATUS => body
            .value
            .as_str()
            .and_then(CounterpartyContactStatus::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "counterparty_contact.status value must be active|revoked",
            )),
        PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT | PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "counterparty_contact timestamp value must be u64",
                ))
        }
        PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT => {
            if matches!(body.value, Value::Nil) || body.value.as_u64().is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "counterparty_contact.revoked_at value must be nil or u64",
                ))
            }
        }
        PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT => decode_opt_out(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("counterparty_contact.opt_out invalid")),
        PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT => {
            if matches!(body.value, Value::Boolean(_)) {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "counterparty_contact.promo_consent value must be boolean",
                ))
            }
        }
        PREDICATE_COUNTERPARTY_CONTACT_NOTES => validate_notes_value(&body.value),
        _ => unreachable!("predicate membership checked above"),
    }
}

fn decode_counterparty_contact_value(value: &Value) -> Result<CounterpartyContactRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_contact());
    };
    validate_keys(entries, &COUNTERPARTY_CONTACT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(COUNTERPARTY_CONTACT_SCHEMA_VERSION)
    {
        return Err(invalid_contact());
    }

    let identity_ref = decode_entity_ref(required_value(entries, KEY_IDENTITY_REF)?)?;
    let counterparty = required_string(entries, KEY_COUNTERPARTY)?.to_owned();
    let first_touch = CounterpartyFirstTouch::parse(required_string(entries, KEY_FIRST_TOUCH)?)
        .ok_or_else(invalid_contact)?;
    let status = CounterpartyContactStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(invalid_contact)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    let updated_at = required_value(entries, KEY_UPDATED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    let revoked_value = required_value(entries, KEY_REVOKED_AT)?;
    let revoked_at = if matches!(revoked_value, Value::Nil) {
        None
    } else {
        Some(revoked_value.as_u64().ok_or_else(invalid_contact)?)
    };
    let opt_out = decode_opt_out(required_value(entries, KEY_OPT_OUT)?)?;
    let promo_consent = match required_value(entries, KEY_PROMO_CONSENT)? {
        Value::Boolean(value) => *value,
        _ => return Err(invalid_contact()),
    };
    let notes = decode_notes(required_value(entries, KEY_NOTES)?)?;

    let record = CounterpartyContactRecord {
        identity_ref,
        counterparty,
        first_touch,
        status,
        created_at,
        updated_at,
        revoked_at,
        opt_out,
        promo_consent,
        notes,
    };
    record.validate()?;
    Ok(record)
}

fn encode_opt_out(opt_out: Option<CounterpartyOptOut>) -> Value {
    opt_out.map_or(Value::Nil, |opt_out| {
        Value::Map(vec![
            (
                Value::from(KEY_OPT_OUT_REASON),
                Value::from(opt_out.reason.as_str()),
            ),
            (
                Value::from(KEY_OPT_OUT_RECORDED_AT),
                Value::from(opt_out.recorded_at),
            ),
            (
                Value::from(KEY_OPT_OUT_RECEIPT_REASON),
                Value::from(opt_out.receipt_reason()),
            ),
        ])
    })
}

fn decode_opt_out(value: &Value) -> Result<Option<CounterpartyOptOut>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(invalid_contact());
    };
    validate_keys(entries, &OPT_OUT_KEYS)?;
    let reason = required_value(entries, KEY_OPT_OUT_REASON)?
        .as_str()
        .and_then(CounterpartyOptOutReason::parse)
        .ok_or_else(invalid_contact)?;
    let recorded_at = required_value(entries, KEY_OPT_OUT_RECORDED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    if required_value(entries, KEY_OPT_OUT_RECEIPT_REASON)?.as_str()
        != Some(reason.receipt_reason())
    {
        return Err(invalid_contact());
    }
    Ok(Some(CounterpartyOptOut {
        reason,
        recorded_at,
    }))
}

fn encode_notes(notes: &[String]) -> Value {
    Value::Array(
        notes
            .iter()
            .map(|note| Value::from(note.as_str()))
            .collect(),
    )
}

fn decode_notes(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_contact());
    };
    let notes = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(invalid_contact)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_notes(&notes)?;
    Ok(notes)
}

fn validate_notes_value(value: &Value) -> Result<()> {
    decode_notes(value)
        .map(|_| ())
        .map_err(|_| Error::InvalidClaimBody("counterparty_contact.notes invalid"))
}

fn validate_notes(notes: &[String]) -> Result<()> {
    if notes.len() > MAX_NOTES {
        return Err(invalid_contact());
    }
    for note in notes {
        validate_note(note)?;
    }
    Ok(())
}

fn normalize_counterparty(value: String) -> Result<String> {
    let trimmed = value.trim().to_owned();
    validate_counterparty(&trimmed)?;
    Ok(trimmed)
}

fn validate_counterparty(value: &str) -> Result<()> {
    validate_non_empty_bounded(
        value,
        MAX_COUNTERPARTY_BYTES,
        "counterparty must be non-empty and at most 512 bytes",
    )
}

fn normalize_note(value: String) -> Result<String> {
    let trimmed = value.trim().to_owned();
    validate_note(&trimmed)?;
    Ok(trimmed)
}

fn validate_note(value: &str) -> Result<()> {
    validate_non_empty_bounded(
        value,
        MAX_NOTE_BYTES,
        "note must be non-empty and at most 2048 bytes",
    )
}

fn validate_claim_string(value: &Value, max_bytes: usize, reason: &'static str) -> Result<()> {
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidClaimBody(reason));
    };
    if value.trim().is_empty() || value.trim() != value || value.len() > max_bytes {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn validate_non_empty_bounded(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.trim() != value || value.len() > max {
        Err(Error::InvalidCounterpartyContactBody(reason))
    } else {
        Ok(())
    }
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_contact)?;
    EntityId::from_hex(hex).map_err(|_| invalid_contact())
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_contact)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_contact)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_contact());
        };
        if seen[index] {
            return Err(invalid_contact());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_contact())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_contact)
}

fn encode_msgpack_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

fn invalid_contact() -> Error {
    Error::InvalidCounterpartyContactBody("body failed validation")
}

impl Vault {
    /// Creates a per-(identity, counterparty) contact record.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_COUNTERPARTY_CONTACT` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-7 body and enforces a single consent row per target.
    pub fn create_counterparty_contact(
        &self,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<()> {
        // Validate the record before anything is written, exactly as the
        // encode-first shape did.
        encode_counterparty_contact_body(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || self.counterparty_contact_assignment_conflict_in_txn(&wtxn, id, record)?
        {
            return Err(Error::CounterpartyContactAlreadyExists);
        }
        // Claims first, cache second, one transaction (ONE-1752): the heads are
        // the truth and the row is derived from them. The claim_of edges point
        // at a row this same transaction is about to write.
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn,
            id,
            record,
            record.updated_at,
        )?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, record.updated_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Records a legal/platform opt-out event on a counterparty contact.
    ///
    /// Contact-level and party-level truth move TOGETHER: the same transaction
    /// supersedes this contact's `counterparty_contact.*` heads and one
    /// party-scoped `comm.opt_out` head with no channel class — the party said
    /// it to the owner, not to one mailbox — and then re-derives the cache.
    pub fn opt_out_counterparty_contact(
        &self,
        id: &EntityId,
        reason: CounterpartyOptOutReason,
        recorded_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.counterparty_contact_for_update_in_txn(&wtxn, id)?;
        let opted_out = current.opted_out(reason, recorded_at)?;
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn,
            id,
            &opted_out,
            recorded_at,
        )?;
        crate::comm::supersede_party_opt_out_head_in_txn(
            self,
            &mut wtxn,
            &opted_out.counterparty,
            reason,
            recorded_at,
        )
        .map_err(comm_fold_error)?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, recorded_at)?;
        // The head just written carries NO channel class, so it covers every
        // contact this party has — and every one of their cache rows has to say
        // so in this same transaction. Re-deriving only `id` would leave a
        // sibling contact on another channel identity reading not-opted-out,
        // and the gate, which folds type-132 rows rather than `comm.opt_out`
        // heads, would allow a send the party's own opt-out forbids.
        rematerialize_party_contact_cache_in_txn(
            self,
            &mut wtxn,
            &opted_out.counterparty,
            None,
            recorded_at,
        )?;
        let record = read_counterparty_contact_in_txn(&self.store, &wtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Revokes owner visibility/reachability for a counterparty contact.
    pub fn revoke_counterparty_contact(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.counterparty_contact_for_update_in_txn(&wtxn, id)?;
        let revoked = current.revoked(revoked_at)?;
        self.supersede_counterparty_contact_claim_heads_in_txn(
            &mut wtxn, id, &revoked, revoked_at,
        )?;
        rematerialize_contact_cache_in_txn(self, &mut wtxn, id, revoked_at)?;
        let record = read_counterparty_contact_in_txn(&self.store, &wtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// The current record a contact writer is about to move forward.
    ///
    /// The snapshot is rebuilt from this contact's OWN `counterparty_contact.*`
    /// heads, never from the type-132 row, even though the writer holds the row
    /// already: the row is a cache the party's `comm.opt_out` heads have been
    /// folded into, and superseding contact heads from it would write that
    /// party-scoped suppression back out as contact-family truth — cache →
    /// claims, the one direction ONE-1752 forbids. A revoke that followed an
    /// inbound STOP would otherwise mint a `counterparty_contact.opt_out` head
    /// the contact family never asserted, and the family-owned CLEAR would then
    /// have a channel-scoped STOP to undo that no CLEAR is scoped to reach.
    ///
    /// The row is still READ first, so a missing subject and a wrong entity
    /// type fail exactly as they did when the body came from it.
    fn counterparty_contact_for_update_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CounterpartyContactRecord> {
        let raw = self
            .store
            .entities
            .get(wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        counterparty_contact_record_from_claims_in_txn(self, wtxn, id)
    }

    /// Moves this contact's `counterparty_contact.*` heads to `record`.
    ///
    /// One head per predicate. A head whose value is already exactly what the
    /// record projects is LEFT ALONE — a supersession that changes nothing is
    /// churn, not history — and every other predicate gets a new head that
    /// supersedes the old one inside this transaction, so the family never has
    /// two live heads for one predicate.
    fn supersede_counterparty_contact_claim_heads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        contact_id: &EntityId,
        record: &CounterpartyContactRecord,
        now: u64,
    ) -> Result<()> {
        let mut live: Vec<(EntityId, ClaimBody)> = Vec::new();
        for claim_id in self.claims_for_subject_in_txn(&*wtxn, contact_id)? {
            let Some(body) = self.get_claim_in_txn(&*wtxn, &claim_id)? else {
                continue;
            };
            if is_counterparty_contact_claim_predicate(&body.predicate)
                && body.lifecycle == ClaimLifecycleStatus::Active
                && !body.stale
            {
                live.push((claim_id, body));
            }
        }

        for body in record.claim_bodies(*contact_id) {
            let existing = live
                .iter()
                .find(|(_, live_body)| live_body.predicate == body.predicate);
            if existing.is_some_and(|(_, live_body)| live_body.value == body.value) {
                continue;
            }
            let new_id = EntityId::now();
            self.put_counterparty_contact_claim_in_txn(wtxn, &new_id, &body, now)?;
            if let Some((old_id, _)) = existing {
                supersede_family_owned_claim_in_txn(self, wtxn, &new_id, old_id, now)?;
            }
        }
        Ok(())
    }

    /// Crate-visible test door onto the family head writer above.
    ///
    /// The contact family has no public CLEAR verb yet, and a test that moved
    /// the heads itself would be asserting against its own copy of the door's
    /// rules rather than the door. This changes nothing about the door: it is
    /// the same call the shipping writers make, reachable from the sibling
    /// module that pins the opt-out coexistence ladder.
    #[cfg(test)]
    pub(crate) fn supersede_counterparty_contact_claim_heads_for_test(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        contact_id: &EntityId,
        record: &CounterpartyContactRecord,
        now: u64,
    ) -> Result<()> {
        self.supersede_counterparty_contact_claim_heads_in_txn(wtxn, contact_id, record, now)
    }

    /// The family-owned door for one `counterparty_contact.*` head.
    ///
    /// It writes through the same `apply_ops` chokepoint (and the same
    /// structural validation) as every other claim, on the ENGINE-OWNED
    /// setting: this family door already decided the write when it validated
    /// the record, exactly like `put_reserved_claim_in_txn`'s callers, so the
    /// public criticality ladder must not re-ask the question and turn a
    /// recorded contact fact into an owner review.
    ///
    /// It deliberately does NOT pre-check that the subject row exists: on
    /// create, the type-132 row is written by this SAME transaction's
    /// rematerialization, immediately after the heads it is derived from.
    fn put_counterparty_contact_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        now: u64,
    ) -> Result<()> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvalidClaimBody(
                "counterparty_contact claim subject must be an entity",
            ));
        };
        let data = crate::claim::encode_claim_body(body)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![
                BatchOp::Put {
                    id: *id,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: *id,
                    kind: crate::edge::EdgeKind::ClaimOf,
                    tgt: subject,
                    weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                    vad: crate::affect::Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// Reads and decodes a CounterpartyContact record.
    pub fn get_counterparty_contact(
        &self,
        id: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Finds one contact record by `(identity_ref, counterparty)`.
    pub fn find_counterparty_contact(
        &self,
        identity_ref: &EntityId,
        counterparty: &str,
    ) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let index_key = counterparty_contact_index_key(identity_ref, counterparty)?;
        if let Some(raw_id) = self.store.vault_meta.get(&rtxn, &index_key)? {
            let id = decode_counterparty_contact_index_value(&raw_id)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity row",
                ));
            };
            let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex(
                "counterparty contact lookup index entity header",
            ))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity type",
                ));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if !record.matches_counterparty(identity_ref, counterparty) {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index assignment",
                ));
            }
            return Ok(Some((id, record)));
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.matches_counterparty(identity_ref, counterparty) {
                return Ok(Some((id, record)));
            }
        }
        Ok(None)
    }

    /// Lists contact records visible for a channel identity.
    pub fn counterparty_contacts_for_identity(
        &self,
        identity_ref: &EntityId,
    ) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.identity_ref.as_bytes() == identity_ref.as_bytes() {
                records.push((id, record));
            }
        }
        Ok(records)
    }

    fn counterparty_contact_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<bool> {
        let index_key = counterparty_contact_index_key_for_record(record)?;
        if let Some(raw_id) = self.store.vault_meta.get(txn, &index_key)? {
            let existing_id = decode_counterparty_contact_index_value(&raw_id)?;
            if existing_id != *id {
                return Ok(true);
            }
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let existing_id = entity_id_from_type_index_key(&key)?;
            if existing_id == *id {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, existing_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let stored = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored.matches_counterparty(&record.identity_ref, &record.counterparty) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn apply_counterparty_contact_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let record = decode_counterparty_contact_body(&data)?;
        let new_index_key = counterparty_contact_index_key_for_record(&record)?;
        if let Some(raw_id) = self.store.vault_meta.get(&*wtxn, &new_index_key)? {
            let existing_id = decode_counterparty_contact_index_value(&raw_id)?;
            if existing_id != *id {
                return Err(Error::CounterpartyContactAlreadyExists);
            }
        }

        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let old_record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(counterparty_contact_index_key_for_record(&old_record)?)
        } else {
            None
        };

        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_COUNTERPARTY_CONTACT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        let index_value = encode_counterparty_contact_index_value(id);
        self.store
            .vault_meta
            .put(wtxn, &new_index_key, &index_value)?;

        // Identity-independent leg. A record whose identity has no resolvable
        // channel class is simply not indexed — the send-time full scan is what
        // covers it, so this is an accelerator, never a gate.
        if let Some(channel_class) =
            counterparty_contact_channel_class(&self.store, &*wtxn, &record)?
        {
            put_counterparty_contact_party_channel_index(
                &self.store,
                wtxn,
                &record.counterparty,
                &channel_class,
                *id,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
