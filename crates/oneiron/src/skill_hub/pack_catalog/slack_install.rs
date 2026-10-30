//! Pending Slack OAuth installs (OF-519): the owner's proof snapshot waiting under one
//! single-use state for Slack's redirect. The install door holds the row; the keyless redirect
//! redeems it once, trading the code for the bot token under a fresh proof minted from the row.
//! The row is the delegation: the state is unguessable, and only the owner who started the
//! install holds it. Every issued state stays until redeemed or expired; there is no count cap.
//!
//! A row past its `expires_at` reads as absent and is deleted when seen. Redemption also
//! requires the owner to still own the vault and, when the starting proof carried one, its
//! credential and host action to still hold, so a slip revoked meanwhile stops the install.

use serde::{Deserialize, Serialize};

use super::invalid;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::secret_custody::{CustodyClass, CustodyTier};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault, error::Result};

/// One install awaiting its redirect, keyed by the install state string.
const SLACK_PENDING: SideTable<String, SlackPendingInstall, Named> =
    SideTable::new(&side_table::SKILL_HUB_PACK_SLACK_INSTALL);

/// The stored install: who started it and what its token takes, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackPendingInstall {
    owner: EntityId,
    principal_ref: String,
    /// The starting proof's credential, when it carried one.
    credential_slip: Option<[u8; 32]>,
    /// The starting proof's host action, when it was authenticated from one:
    /// its owner, and its root slip id (`None` for the dev mode).
    host_owner: Option<EntityId>,
    host_root_slip: Option<[u8; 32]>,
    /// Where the owner's install request reached this install, audit only.
    surface: ActSurface,
    /// The setup's exact source, as the install door was asked.
    source: Option<String>,
    client_id: String,
    redirect_url: String,
    /// Vault seconds the state stays redeemable.
    expires_at: u64,
    /// The custody a fresh bot token takes; a live name rotates instead.
    class: CustodyClass,
    device_only: bool,
    rung: CustodyTier,
}

/// What the install door holds under one state.
#[derive(Debug, Clone)]
pub struct SlackInstallHold<'a> {
    pub owner: &'a AuthenticatedOwner,
    pub state: &'a str,
    pub surface: ActSurface,
    pub source: Option<&'a str>,
    pub client_id: &'a str,
    pub redirect_url: &'a str,
    pub class: CustodyClass,
    pub device_only: bool,
    pub rung: CustodyTier,
    /// How long the state stays redeemable, in seconds.
    pub ttl_secs: u64,
}

/// One redeemed state: a fresh proof minted from the row, and what the
/// install needs. The row is gone; the state never redeems again.
#[derive(Debug)]
pub struct SlackInstallRedeemed {
    pub owner: AuthenticatedOwner,
    pub surface: ActSurface,
    pub source: Option<String>,
    pub client_id: String,
    pub redirect_url: String,
    pub class: CustodyClass,
    pub device_only: bool,
    pub rung: CustodyTier,
}

impl Vault {
    /// Holds one install under `state` until redeemed or expired. The owner
    /// is revalidated as a live owner in the writing transaction.
    pub fn hold_slack_install(&self, install: SlackInstallHold<'_>) -> Result<()> {
        if install.state.is_empty()
            || install.client_id.is_empty()
            || install.redirect_url.is_empty()
        {
            return Err(invalid(
                "the Slack install names no state, client id or redirect",
            ));
        }
        let principal_ref = install.owner.principal_ref_for_read(self)?.to_owned();
        let credential_slip = install.owner.credential_slip_id_for_persist();
        let (host_owner, host_root_slip) = match install.owner.host_action_for_persist() {
            Some((root, owner)) => (Some(owner), root),
            None => (None, None),
        };
        let surface = install.surface;
        let source = install.source.map(str::to_owned);
        let client_id = install.client_id.to_owned();
        let redirect_url = install.redirect_url.to_owned();
        let class = install.class;
        let device_only = install.device_only;
        let rung = install.rung;
        let state = install.state.to_owned();
        let ttl = install.ttl_secs;
        self.with_write_txn_grouped(|txn| {
            let owner = install.owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let expires_at = self.now_recorded_at().saturating_add(ttl);
            SLACK_PENDING.put(
                &self.store,
                txn,
                &state,
                &SlackPendingInstall {
                    owner,
                    principal_ref,
                    credential_slip,
                    host_owner,
                    host_root_slip,
                    surface,
                    source,
                    client_id,
                    redirect_url,
                    expires_at,
                    class,
                    device_only,
                    rung,
                },
            )
        })
    }

    /// Redeems one state, once: the row is read and deleted in one
    /// transaction. An unknown or expired state reads as absent, and an
    /// expired one is deleted when seen, as is one whose owner, credential
    /// or host action no longer holds.
    pub fn take_slack_install(&self, state: &str) -> Result<Option<SlackInstallRedeemed>> {
        let row = self.with_write_txn_grouped(|txn| {
            let key = state.to_owned();
            let Some(row) = SLACK_PENDING.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            let credential_lapsed = match row.credential_slip {
                Some(slip) => !self.capability_slip_id_is_live_in_txn(txn, &slip)?,
                None => false,
            };
            let lapsed = self.now_recorded_at() >= row.expires_at
                || !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &row.owner)?
                || credential_lapsed
                || !self.slack_install_host_holds_in_txn(txn, &row)?;
            SLACK_PENDING.delete(&self.store, txn, &key)?;
            Ok((!lapsed).then_some(row))
        })?;
        let Some(row) = row else {
            return Ok(None);
        };
        // The row authorized this mint, the way a pairing link's owner does:
        // the state reached only the owner who started the install.
        let owner = match self.authenticate_owner(
            row.owner,
            &row.principal_ref,
            true,
            crate::store::GateDecisionId::now(),
        ) {
            Ok(owner) => owner,
            Err(_) => return Ok(None),
        };
        Ok(Some(SlackInstallRedeemed {
            owner,
            surface: row.surface,
            source: row.source,
            client_id: row.client_id,
            redirect_url: row.redirect_url,
            class: row.class,
            device_only: row.device_only,
            rung: row.rung,
        }))
    }

    /// Whether the host action a row's starting proof carried still holds:
    /// the dev mode still acts as its owner, or the root slip is still
    /// live. `true` for a row with no host action.
    fn slack_install_host_holds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &SlackPendingInstall,
    ) -> Result<bool> {
        let Some(host_owner) = row.host_owner else {
            return Ok(true);
        };
        match row.host_root_slip {
            None => Ok(self.host_action_owner_in_txn(txn, None)? == host_owner),
            Some(root) => Ok(self.capability_slip_id_is_live_in_txn(txn, &root)?),
        }
    }
}
