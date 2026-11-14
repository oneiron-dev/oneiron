//! Per-recipient booking links (BK-PERSONAL-LINKS; ARCH-0062:157-159, §7 v1.5).
//!
//! A personal link is a long-lived opaque capability on the public-face
//! domain, minted per ask and per recipient. It serves exactly the page its
//! live publication serves, so every recipient gets the same offer, and it
//! names who it is for: the booker email is locked to the recipient, and the
//! recipient's "not you?" ends the link and tells whoever minted it.
//!
//! The vault keeps only a domain digest of the token. The raw token exists
//! once, in the mint's return value, as companion participant tokens do. A
//! link only ever ends: neither a void nor a revocation can be undone, and a
//! lost or mis-sent link is replaced by minting a new one.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::BookingError;
use crate::booking::lifecycle::{booking_writer, digest_with, hex_lower, mint_raw_token};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, SideTable, VersionedNamed};
use crate::{EntityId, Vault};

/// The prefix of a personal link token: `bkr_` and 64 lower-hex characters.
/// A page token is `bkp_` and 32, so the two kinds never share a shape.
pub const PERSONAL_LINK_TOKEN_PREFIX: &str = "bkr_";
/// Width of the token's random part, in lower-hex characters: what the
/// booking CSPRNG minter emits.
const PERSONAL_LINK_TOKEN_HEX_LEN: usize = 64;
/// Longest recipient email a link accepts, in bytes (RFC 5321 path limit,
/// the public confirm's own cap).
pub const MAX_PERSONAL_LINK_EMAIL_BYTES: usize = 254;
/// Longest recipient name a link accepts, in characters.
pub const MAX_PERSONAL_LINK_NAME_CHARS: usize = 120;
/// The producer a "not you?" notice names.
pub const PERSONAL_LINK_NOTICE_PRODUCER: &str = "booking.personal_link";
/// Domain of the stored token digest, so it can never be replayed as a hold,
/// participant or session digest.
const PERSONAL_LINK_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.personal_link.v1\0";
/// Row-format byte of a stored link.
const PERSONAL_LINK_ROW_VERSION: u8 = 1;

/// One link per row. Key: hash32 (the token digest).
const LINKS: SideTable<[u8; 32], PersonalLinkRow, VersionedNamed<PERSONAL_LINK_ROW_VERSION>> =
    SideTable::new(&side_table::BOOKING_PERSONAL_LINK);

/// Who a link is for. `email` is stored trimmed and in lower case, the same
/// normalization the booker contact is derived from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalLinkRecipient {
    pub email: String,
    pub name: String,
}

impl PersonalLinkRecipient {
    /// The recipient as stored, or why it cannot be.
    fn normalized(&self) -> Result<Self, BookingError> {
        let email = normalize_booker_email(&self.email);
        if email.len() > MAX_PERSONAL_LINK_EMAIL_BYTES || !plausible_email(&email) {
            return Err(refused(
                "a personal link needs one plausible recipient email",
            ));
        }
        let name = self.name.trim().to_owned();
        if name.is_empty()
            || name.chars().count() > MAX_PERSONAL_LINK_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(refused(format!(
                "a personal link names its recipient in 1..={MAX_PERSONAL_LINK_NAME_CHARS} characters"
            )));
        }
        Ok(Self { email, name })
    }
}

/// Why a link ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalLinkEndReason {
    /// Its recipient answered "not you?".
    NotRecipient,
    /// Its minter or an owner revoked it.
    Revoked,
}

/// When and why a link ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalLinkEnd {
    pub at: u64,
    pub reason: PersonalLinkEndReason,
}

/// One link as its minter reads it. `link_ref` is the lower-hex token
/// digest: the handle a revocation names, never the token itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonalBookingLink {
    pub link_ref: String,
    pub page_ref: EntityId,
    pub recipient: PersonalLinkRecipient,
    pub minted_by: EntityId,
    pub minted_at: u64,
    pub ended: Option<PersonalLinkEnd>,
}

/// What a mint returns: the raw token, here and nowhere else, and the link.
/// Deliberately not `Serialize` and not `Debug`: a raw token has no wire
/// form and no log form.
pub struct PersonalLinkMint {
    pub token: String,
    pub link: PersonalBookingLink,
}

#[derive(Serialize, Deserialize)]
struct PersonalLinkRow {
    #[serde(with = "entity_ref_serde")]
    page_ref: EntityId,
    recipient: PersonalLinkRecipient,
    #[serde(with = "entity_ref_serde")]
    minted_by: EntityId,
    minted_at: u64,
    ended: Option<PersonalLinkEnd>,
}

impl PersonalLinkRow {
    fn view(&self, digest: &[u8; 32]) -> PersonalBookingLink {
        PersonalBookingLink {
            link_ref: hex_lower(digest),
            page_ref: self.page_ref,
            recipient: self.recipient.clone(),
            minted_by: self.minted_by,
            minted_at: self.minted_at,
            ended: self.ended,
        }
    }
}

/// Whether `token` has the shape of a personal link token. Shape only: it
/// says nothing about whether such a link was ever minted.
#[must_use]
pub fn is_personal_link_token(token: &str) -> bool {
    token
        .strip_prefix(PERSONAL_LINK_TOKEN_PREFIX)
        .is_some_and(|hex| {
            hex.len() == PERSONAL_LINK_TOKEN_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// The one email normalization a personal link compares by: trimmed, lower
/// case, as the booker contact subject is derived.
#[must_use]
pub fn normalize_booker_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Mints a personal link to `page_ref` for `recipient`.
///
/// The minter is `minter`'s actor, rechecked in the write transaction as a
/// live actor holding live authority in this vault (as a companion proposal's
/// creator is): canon has the companion mint these, and the owner may too.
/// The page must have a live published publication now; serving checks it
/// again on every request.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] for an unusable recipient, an
/// unpublished page or a minter without authority; [`BookingError::Surface`]
/// for a storage failure.
pub fn mint_personal_booking_link(
    minter: &crate::memory::Memory<'_>,
    page_ref: EntityId,
    recipient: &PersonalLinkRecipient,
    now: u64,
) -> Result<PersonalLinkMint, BookingError> {
    let recipient = recipient.normalized()?;
    let vault = minter.vault();
    let minted_by = minter.actor();
    if surface(crate::booking::load_public_booking_page(
        vault, page_ref, now,
    ))?
    .is_none()
    {
        return Err(refused(
            "a personal link needs a live published booking page",
        ));
    }
    let token = format!("{PERSONAL_LINK_TOKEN_PREFIX}{}", mint_raw_token());
    let digest = token_digest(&token);
    let row = PersonalLinkRow {
        page_ref,
        recipient,
        minted_by,
        minted_at: now,
        ended: None,
    };
    booking_writer(vault, |wtxn| {
        let live_type = surface(crate::vault::live_entity_row_in_txn(
            &vault.store,
            wtxn,
            &minted_by,
        ))?
        .live_type();
        if !live_type.is_some_and(|entity_type| {
            crate::provenance::validate_actor_class(entity_type, minter.actor_class()).is_ok()
        }) {
            return Err(refused("the minter is not a live actor of this vault"));
        }
        vault
            .observed_write_actor_in_txn(
                wtxn,
                crate::WriteActor::new(minted_by, minter.actor_class()),
            )
            .map_err(|_| refused("the minter holds no live authority in this vault"))?;
        surface(LINKS.put(&vault.store, wtxn, &digest, &row))
    })?;
    Ok(PersonalLinkMint {
        link: row.view(&digest),
        token,
    })
}

/// The live link `token` names: `None` for a token of another shape, one
/// never minted, or one that ended. Callers still check the page's live
/// publication, exactly as for a page token.
///
/// # Errors
///
/// [`BookingError::Surface`] for a storage failure.
pub fn resolve_personal_booking_link(
    vault: &Vault,
    token: &str,
) -> Result<Option<PersonalBookingLink>, BookingError> {
    if !is_personal_link_token(token) {
        return Ok(None);
    }
    let digest = token_digest(token);
    let rtxn = surface(vault.store.env.read_txn().map_err(crate::Error::from))?;
    let row = surface(LINKS.get(&vault.store, &rtxn, &digest))?;
    Ok(row
        .filter(|row| row.ended.is_none())
        .map(|row| row.view(&digest)))
}

/// The recipient's "not you?": ends the live link `token` names and, in the
/// same write, tells its minter with one Finding NOTIFICATION addressed to
/// them. `false` when no live link answers to `token` (nothing is written).
///
/// # Errors
///
/// [`BookingError::Surface`] for a storage failure.
pub fn void_personal_booking_link(
    vault: &Vault,
    token: &str,
    now: u64,
) -> Result<bool, BookingError> {
    if !is_personal_link_token(token) {
        return Ok(false);
    }
    let digest = token_digest(token);
    surface(vault.with_write_txn_grouped(|txn| {
        let Some(mut row) = LINKS.get(&vault.store, txn, &digest)? else {
            return Ok(false);
        };
        if row.ended.is_some() {
            return Ok(false);
        }
        row.ended = Some(PersonalLinkEnd {
            at: now,
            reason: PersonalLinkEndReason::NotRecipient,
        });
        LINKS.put(&vault.store, txn, &digest, &row)?;
        let link_ref = hex_lower(&digest);
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: PERSONAL_LINK_NOTICE_PRODUCER.to_owned(),
                    event: format!("{link_ref}:not_recipient"),
                    result: Some(link_ref),
                    detail: Some(format!(
                        "{} ({}) answered \"not you?\" on their booking link; the link is void.",
                        row.recipient.name, row.recipient.email
                    )),
                    ..NotificationSource::default()
                },
                subject_refs: vec![row.page_ref],
                recipient: Some(row.minted_by),
                created_at: now,
                origin_conversation: None,
            },
        )?;
        Ok(true)
    }))
}

/// Ends the link `link_ref` names, as its minter or an owner of the vault.
/// `false` when the link had already ended.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] for an unknown link or an actor who is
/// neither its minter nor an owner; [`BookingError::Surface`] for a storage
/// failure.
pub fn revoke_personal_booking_link(
    actor: &crate::memory::Memory<'_>,
    link_ref: &str,
    now: u64,
) -> Result<bool, BookingError> {
    let digest = parse_link_ref(link_ref).ok_or_else(|| refused("no such personal link"))?;
    let vault = actor.vault();
    let by = actor.actor();
    booking_writer(vault, |wtxn| {
        let Some(mut row) = surface(LINKS.get(&vault.store, wtxn, &digest))? else {
            return Err(refused("no such personal link"));
        };
        if row.minted_by != by
            && !surface(crate::policy_model::owners_in_txn(vault, wtxn))?.contains(&by)
        {
            return Err(refused("only the link's minter or an owner revokes it"));
        }
        if row.ended.is_some() {
            return Ok(false);
        }
        row.ended = Some(PersonalLinkEnd {
            at: now,
            reason: PersonalLinkEndReason::Revoked,
        });
        surface(LINKS.put(&vault.store, wtxn, &digest, &row))?;
        Ok(true)
    })
}

/// Every link minted to `page_ref`, live and ended, in key order.
///
/// # Errors
///
/// [`BookingError::Surface`] for a storage failure.
pub fn personal_booking_links(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<PersonalBookingLink>, BookingError> {
    let rtxn = surface(vault.store.env.read_txn().map_err(crate::Error::from))?;
    Ok(surface(LINKS.scan(&vault.store, &rtxn))?
        .into_iter()
        .filter(|(_, row)| row.page_ref == page_ref)
        .map(|(digest, row)| row.view(&digest))
        .collect())
}

fn token_digest(token: &str) -> [u8; 32] {
    digest_with(PERSONAL_LINK_DIGEST_DOMAIN, token.as_bytes())
}

fn parse_link_ref(link_ref: &str) -> Option<[u8; 32]> {
    let hex = link_ref.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        digest[index] = u8::try_from(high * 16 + low).ok()?;
    }
    Some(digest)
}

/// One `@` with something on each side, no whitespace and no control
/// character: a plausibility gate, not a deliverability check.
fn plausible_email(email: &str) -> bool {
    let mut parts = email.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty()
    ) && !email
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
}

fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

fn surface<T>(result: std::result::Result<T, crate::Error>) -> Result<T, BookingError> {
    result.map_err(|error| BookingError::Surface(error.to_string()))
}

/// Hex spelling for the `EntityId` fields of the stored row (the booking
/// module keeps this adapter per file, as `companion_preset` does).
mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}
