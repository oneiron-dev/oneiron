//! Counterparty contact domain vocabulary: schema version, body and predicate keys, record types.

use super::codec::{
    encode_notes, encode_opt_out, invalid_contact, normalize_counterparty, normalize_note,
    validate_counterparty, validate_notes,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;
use rmpv::Value;

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

pub(super) const KEY_SCHEMA_VERSION: &str = COUNTERPARTY_CONTACT_BODY_KEYS[0];

pub(super) const KEY_IDENTITY_REF: &str = COUNTERPARTY_CONTACT_BODY_KEYS[1];

pub(super) const KEY_COUNTERPARTY: &str = COUNTERPARTY_CONTACT_BODY_KEYS[2];

pub(super) const KEY_FIRST_TOUCH: &str = COUNTERPARTY_CONTACT_BODY_KEYS[3];

pub(super) const KEY_STATUS: &str = COUNTERPARTY_CONTACT_BODY_KEYS[4];

pub(super) const KEY_CREATED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[5];

pub(super) const KEY_UPDATED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[6];

pub(super) const KEY_REVOKED_AT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[7];

pub(super) const KEY_OPT_OUT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[8];

pub(super) const KEY_PROMO_CONSENT: &str = COUNTERPARTY_CONTACT_BODY_KEYS[9];

pub(super) const KEY_NOTES: &str = COUNTERPARTY_CONTACT_BODY_KEYS[10];

pub(super) const OPT_OUT_KEYS: [&str; 3] = ["reason", "recorded_at", "receipt_reason"];

pub(super) const KEY_OPT_OUT_REASON: &str = OPT_OUT_KEYS[0];

pub(super) const KEY_OPT_OUT_RECORDED_AT: &str = OPT_OUT_KEYS[1];

pub(super) const KEY_OPT_OUT_RECEIPT_REASON: &str = OPT_OUT_KEYS[2];

pub(super) const MAX_COUNTERPARTY_BYTES: usize = 512;

pub(super) const MAX_NOTES: usize = 32;

pub(super) const MAX_NOTE_BYTES: usize = 2_048;

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
