//! Conversation-home clearance (DEC-0006 `#home-clearance`): stamped content is read only in
//! conversations homed in its own vault, unless its owner granted clearance.
//!
//! A conversation's home is the vault that holds its record: a room, a thread or a task
//! conversation lives in exactly one vault, and its turns are saved there. An assembly made for a
//! conversation of this vault is homed here ([`ConversationHome::ThisVault`]); one made for a
//! conversation another vault holds names that vault ([`ConversationHome::Vault`]). Homed
//! elsewhere, a CLAIM stamped with any band but public ([`claim_home_band`]) is withheld unless the
//! owner set a home clearance for that vault at or above the claim's band. The owner sets that row
//! ([`Vault::set_home_disclosure_clearance`]); no agent path writes it. The home only narrows: the
//! audience clamp of everyone present still applies on top.

use heed::RoTxn;
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::AuthorityVaultId;
use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::model_channel::DisclosureBand;

/// The owner's home clearances. Key: the home vault's id as 64 lower-case hex.
const HOME_CLEARANCES: SideTable<String, DisclosureBand, Named> =
    SideTable::new(&side_table::DISCLOSURE_HOME_CLEARANCE);

/// The scope-map key a claim's sensitivity stamp is written under.
const SENSITIVITY_STAMP_KEY: &str = "sensitivity";

/// Where the conversation an assembly serves is homed: the vault that holds its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationHome {
    /// A conversation of this vault. Every [`crate::DisclosureContext`] constructor homes its
    /// assembly here: a room's turns, voice sessions and checkpoint decisions are this vault's.
    ThisVault,
    /// A conversation another vault holds, named by that vault's authority id.
    Vault(AuthorityVaultId),
}

impl ConversationHome {
    /// The home of an assembly whose reader names no conversation of this vault and is not one
    /// the room rule already trusts (RULING L5-02-UNNAMED-HOME = A): another vault no owner can
    /// clear, so stamped claims stay out.
    pub const UNNAMED: Self = Self::Vault([0; 32]);

    /// The home a caller names by the home vault's authority id, 64 hex digits of either case;
    /// `None` when `hex` is not one. It does not fold this vault's own id:
    /// [`crate::DisclosureContext::homed_in`] does.
    #[must_use]
    pub fn from_vault_hex(hex: &str) -> Option<Self> {
        parse_vault_id(hex).map(Self::Vault)
    }
}

/// The owner's read or clear of one home clearance.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeClearanceRequest {
    /// The home vault's authority id, 64 hex.
    pub home_vault_id: String,
}

/// The owner's grant: a conversation homed in `home_vault_id` may read claims stamped up to
/// `band` from this vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeClearanceSet {
    /// The home vault's authority id, 64 hex.
    pub home_vault_id: String,
    /// The highest stamp band such a conversation may read here.
    pub band: DisclosureBand,
}

/// One home clearance as stored. `band` is `None` when the owner granted none, so the home reads
/// no stamped claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeClearanceView {
    /// The home vault's authority id, 64 lower-case hex.
    pub home_vault_id: String,
    pub band: Option<DisclosureBand>,
}

/// A claim's stamp as the home rule reads it: `None` for an unstamped claim (no `sensitivity` key)
/// and for a positively public stamp, which canon shows to anyone (DEC-0006 `#disclosure-built`);
/// otherwise the stamped band. A stamp that does not read as one band (a duplicate key, an unknown
/// value, a scope that is not a map) reads `Restricted`: it fails closed.
pub(crate) fn claim_home_band(body: &ClaimBody) -> Option<DisclosureBand> {
    scope_home_band(body.scope.as_ref())
}

/// [`claim_home_band`] of a claim whose scope map is `scope`: the scoped read judges a claim by its
/// read view, which holds the scope map and not the body.
pub(crate) fn scope_home_band(scope: Option<&Value>) -> Option<DisclosureBand> {
    let entries = match scope {
        None => return None,
        Some(Value::Map(entries)) => entries,
        Some(_) => return Some(DisclosureBand::Restricted),
    };
    let mut stamps = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(SENSITIVITY_STAMP_KEY));
    let (_, stamp) = stamps.next()?;
    if stamps.next().is_some() {
        return Some(DisclosureBand::Restricted);
    }
    match crate::claim::sensitivity_band_from_value(stamp) {
        Some(0) => None,
        Some(1) => Some(DisclosureBand::Private),
        Some(2) => Some(DisclosureBand::Sensitive),
        _ => Some(DisclosureBand::Restricted),
    }
}

/// Whether a conversation homed elsewhere, under the owner's clearance `cleared` for that home,
/// may read `body`.
pub(crate) fn home_admits_claim(body: &ClaimBody, cleared: Option<DisclosureBand>) -> bool {
    claim_home_band(body).is_none_or(|band| cleared.is_some_and(|cleared| band <= cleared))
}

/// The owner's clearance for `home` on the caller's transaction, as the clamp reads it. A row that
/// does not decode grants nothing: the clamp only narrows. Storage errors stay loud.
pub(super) fn home_clearance_in(
    store: &Store,
    rtxn: &RoTxn<'_>,
    home: &AuthorityVaultId,
) -> Result<Option<DisclosureBand>> {
    if *home == [0; 32] {
        return Ok(None);
    }
    match HOME_CLEARANCES.get(store, rtxn, &vault_id_hex(home)) {
        Err(Error::Store(StoreError::SideTableRow { .. })) => Ok(None),
        other => other,
    }
}

/// `id` as 64 lower-case hex, the row key and the stamp's spelling.
pub(super) fn vault_id_hex(id: &AuthorityVaultId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A vault id written as 64 hex digits, either case.
fn parse_vault_id(hex: &str) -> Option<AuthorityVaultId> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0_u8; 32];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(id)
}

impl Vault {
    /// The owner's home clearance for one home vault.
    pub fn home_disclosure_clearance(
        &self,
        owner: &AuthenticatedOwner,
        input: HomeClearanceRequest,
    ) -> Result<HomeClearanceView> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let home = self.home_vault_id_in(&txn, &input.home_vault_id)?;
        let key = vault_id_hex(&home);
        let band = HOME_CLEARANCES.get(&self.store, &txn, &key)?;
        Ok(HomeClearanceView {
            home_vault_id: key,
            band,
        })
    }

    /// The owner grants conversations homed in another vault the claims stamped up to `band`
    /// (DEC-0006 `#home-clearance`, "unless its owner granted clearance"; RULING
    /// L5-02-HOME-GRANT = A). A re-set replaces the band; [`Self::clear_home_disclosure_clearance`]
    /// revokes it.
    pub fn set_home_disclosure_clearance(
        &self,
        owner: &AuthenticatedOwner,
        input: HomeClearanceSet,
    ) -> Result<HomeClearanceView> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let home = self.home_vault_id_in(txn, &input.home_vault_id)?;
            let key = vault_id_hex(&home);
            HOME_CLEARANCES.put(&self.store, txn, &key, &input.band)?;
            Ok(HomeClearanceView {
                home_vault_id: key,
                band: Some(input.band),
            })
        })
    }

    /// The owner revokes the home clearance of one home vault: its conversations read no stamped
    /// claim from this vault again.
    pub fn clear_home_disclosure_clearance(
        &self,
        owner: &AuthenticatedOwner,
        input: HomeClearanceRequest,
    ) -> Result<HomeClearanceView> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let home = self.home_vault_id_in(txn, &input.home_vault_id)?;
            let key = vault_id_hex(&home);
            HOME_CLEARANCES.delete(&self.store, txn, &key)?;
            Ok(HomeClearanceView {
                home_vault_id: key,
                band: None,
            })
        })
    }

    /// A home vault the owner may clear: 64 hex, never this vault's own id (its conversations need
    /// no clearance) and never the all-zero id, which stands for [`ConversationHome::UNNAMED`].
    fn home_vault_id_in(&self, txn: &RoTxn<'_>, hex: &str) -> Result<AuthorityVaultId> {
        let home = parse_vault_id(hex).ok_or_else(|| {
            Error::InvalidConfig("home_vault_id is a vault id of 64 hex digits".to_owned())
        })?;
        if home == [0; 32] {
            return Err(Error::InvalidConfig(
                "the all-zero home_vault_id stands for an unnamed home, which no clearance opens"
                    .to_owned(),
            ));
        }
        if self.authority_view_readonly_in_txn(txn)?.vault_id == Some(home) {
            return Err(Error::InvalidConfig(
                "this vault's own conversations need no home clearance".to_owned(),
            ));
        }
        Ok(home)
    }
}
