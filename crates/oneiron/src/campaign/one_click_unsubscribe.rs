//! The one-click unsubscribe link a bulk campaign email carries (ARCH-0059
//! #opt-out; RFC 8058; FIX [CAMPAIGN-BULK-SEND-MODE] PR 2).
//!
//! A bulk send carries List-Unsubscribe, and a bulk send without it blocks.
//! The link names one member of one campaign on email:
//! `<origin>/unsubscribe/one-click/<campaign hex>/<person hex>/<mac hex>`.
//! The mac is a keyed BLAKE3 hash of the campaign, the person and the
//! channel under a 32-byte key the vault makes once and keeps in its own
//! side table; it never leaves the vault, and nothing rotates it, so a link
//! keeps working for as long as the mail that carries it can be read.
//!
//! The origin is the serving host's public https base, installed on the
//! open vault at boot ([`Vault::install_one_click_unsubscribe_origin`]). A
//! vault with no origin installed mints no link, and its bulk email sends
//! block.
//!
//! Whoever holds a link may redeem it: that is what RFC 8058 one-click
//! means. A redemption writes the same suppression `vault.campaign.unsubscribe`
//! writes, in one transaction, before the route answers.

use crate::Vault;
use crate::campaign::send_hygiene::{
    EMAIL_CHANNEL, SuppressionCause, SuppressionInput, apply_suppression,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

/// The path every one-click link sits under, at the host's public origin.
pub const ONE_CLICK_UNSUBSCRIBE_PATH: &str = "/unsubscribe/one-click";

/// The vault's one-click link key. Key: `()`; value: 32 raw bytes, made on
/// the first origin install and never rotated.
const ONE_CLICK_KEY: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::CAMPAIGN_ONE_CLICK_UNSUBSCRIBE_KEY);

/// Domain separation for the link mac.
const MAC_DOMAIN: &[u8] = b"oneiron.campaign.one_click_unsubscribe.v1\0";

/// The longest origin a link is built on; the whole URI must stay well under
/// the header builder's 998-byte cap.
const MAX_ORIGIN_BYTES: usize = 512;

/// What one redemption of a one-click link did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneClickUnsubscribeOutcome {
    /// The link verified, and the member's suppression is written: the gate
    /// refuses the next send. A repeat redemption answers this too.
    Unsubscribed,
    /// The link does not verify on this vault: a malformed part, a mac this
    /// vault's key did not make, or a vault with no key. Nothing is written.
    NotRecognized,
}

/// The link mac for `person` in `campaign` on email.
fn link_mac(key: &[u8; 32], campaign: EntityId, person: EntityId) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(MAC_DOMAIN);
    hasher.update(campaign.as_bytes());
    hasher.update(person.as_bytes());
    hasher.update(EMAIL_CHANNEL.as_bytes());
    hasher.finalize()
}

/// The one-click link for `person` in `campaign`, read in `txn`; `None`
/// when no origin is installed on this vault or it holds no key. A pure
/// read: the same vault, campaign and person give the same bytes, so a
/// redrive freezes the same envelope.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn one_click_unsubscribe_uri_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign: EntityId,
    person: EntityId,
) -> Result<Option<String>> {
    let Some(origin) = vault.one_click_unsubscribe_origin.get() else {
        return Ok(None);
    };
    let Some(key) = ONE_CLICK_KEY.get(&vault.store, txn, &())? else {
        return Ok(None);
    };
    let mac = link_mac(&key, campaign, person);
    Ok(Some(format!(
        "{origin}{ONE_CLICK_UNSUBSCRIBE_PATH}/{}/{}/{}",
        campaign.to_hex(),
        person.to_hex(),
        mac.to_hex()
    )))
}

/// The origin as a link base: `https://` and a host, no query, fragment,
/// credentials, whitespace or header-breaking character, and no trailing
/// slash.
fn link_origin(origin: &str) -> Result<String> {
    let origin = origin.trim().trim_end_matches('/');
    let rest = origin.strip_prefix("https://").unwrap_or_default();
    let host_part = rest.split('/').next().unwrap_or_default();
    let usable = !host_part.is_empty()
        && !host_part.contains('@')
        && origin.len() <= MAX_ORIGIN_BYTES
        && origin.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'<' | b'>' | b',' | b'"')
        });
    if usable {
        Ok(origin.to_owned())
    } else {
        Err(Error::InvalidConfig(
            "a one-click unsubscribe origin must be an https base URL".into(),
        ))
    }
}

impl Vault {
    /// Installs the serving host's public https origin that this vault's
    /// one-click unsubscribe links name, once per open vault, and makes the
    /// vault's link key on first use. A second install keeps the first
    /// origin. With none installed, no link is minted and bulk campaign
    /// email blocks.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `origin` is not an https base URL;
    /// storage errors from making the key.
    pub fn install_one_click_unsubscribe_origin(&self, origin: &str) -> Result<()> {
        let origin = link_origin(origin)?;
        let held = {
            let txn = self.store.env.read_txn()?;
            ONE_CLICK_KEY.get(&self.store, &txn, &())?.is_some()
        };
        if !held {
            self.with_write_txn_grouped(|txn| {
                if ONE_CLICK_KEY.get(&self.store, txn, &())?.is_none() {
                    let mut key = [0; 32];
                    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
                    ONE_CLICK_KEY.put(&self.store, txn, &(), &key)?;
                }
                Ok(())
            })?;
        }
        let _ = self.one_click_unsubscribe_origin.set(origin);
        Ok(())
    }

    /// Whether the link parts `campaign`, `person` and `mac` (as the link
    /// spells them) verify under this vault's key. A read only: nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn one_click_unsubscribe_verifies(
        &self,
        campaign: &str,
        person: &str,
        mac: &str,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(verified_link(self, &txn, campaign, person, mac)?.is_some())
    }

    /// Redeems one one-click link (RFC 8058): when its parts verify under
    /// this vault's key, writes the member's email suppression at once, as
    /// `vault.campaign.unsubscribe` does, in one transaction; the next send
    /// is refused. A repeat redemption reuses the live heads it wrote.
    ///
    /// The link names no inbound row, so the suppression's evidence is the
    /// campaign whose link the mac proves this vault minted.
    ///
    /// # Errors
    ///
    /// Claim-validation and storage errors from the suppression write.
    pub fn redeem_one_click_unsubscribe(
        &self,
        campaign: &str,
        person: &str,
        mac: &str,
    ) -> Result<OneClickUnsubscribeOutcome> {
        let verified = {
            let txn = self.store.env.read_txn()?;
            verified_link(self, &txn, campaign, person, mac)?
        };
        let Some((campaign, person)) = verified else {
            return Ok(OneClickUnsubscribeOutcome::NotRecognized);
        };
        apply_suppression(
            self,
            SuppressionCause::Unsubscribe,
            &SuppressionInput {
                person_ref: person,
                campaign_ref: Some(campaign),
                channel: EMAIL_CHANNEL.to_owned(),
                sender_ref: None,
                evidence_ref: campaign,
                occurred_at: self.now_recorded_at(),
            },
        )?;
        Ok(OneClickUnsubscribeOutcome::Unsubscribed)
    }
}

/// The campaign and person a link names, when its mac verifies under the
/// vault's key; `None` for a malformed part, an unknown mac or no key. The
/// mac comparison is constant-time ([`blake3::Hash`]'s equality).
fn verified_link(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign: &str,
    person: &str,
    mac: &str,
) -> Result<Option<(EntityId, EntityId)>> {
    let (Ok(campaign), Ok(person), Ok(presented)) = (
        EntityId::from_hex(campaign),
        EntityId::from_hex(person),
        blake3::Hash::from_hex(mac),
    ) else {
        return Ok(None);
    };
    let Some(key) = ONE_CLICK_KEY.get(&vault.store, txn, &())? else {
        return Ok(None);
    };
    Ok((link_mac(&key, campaign, person) == presented).then_some((campaign, person)))
}
