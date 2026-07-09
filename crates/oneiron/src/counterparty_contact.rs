//! Counterparty contact record substrate (OF-347 CID-7).
//!
//! A CounterpartyContactRecord is a vault-resident per-(channel identity,
//! counterparty) consent/contact row plus a typed `counterparty_contact.*`
//! claim family. Provider adapters and multiplayer graph expansion are
//! intentionally outside this module.

use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        self.identity_ref.as_bytes() == identity_ref.as_bytes()
            && self.counterparty == counterparty.trim()
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

#[cfg(test)]
mod tests;
