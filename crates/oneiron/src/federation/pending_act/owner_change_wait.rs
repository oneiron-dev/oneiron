//! The vault's common owner-change wait: one scalar, not per-act rows.
//!
//! Membership acts --- adding, removing, or transferring ownership --- share
//! one wait, so an owner sets a single number instead of repeating it across
//! rows. The stored manifest carries `owner_change_wait_secs` as an optional
//! top-level scalar in seconds; this setter converts the days it is given
//! into seconds, and start deadlines run in seconds.
//!
//! Reading: [`Vault::owner_change_wait_secs`] resolves the current trusted
//! manifest and returns the scalar. Writing:
//! [`Vault::set_owner_change_wait_days`] revalidates the caller as a person,
//! requires live Owner membership in the vault, and replaces the scalar on
//! the current trusted default manifest body. `None` removes the key;
//! `Some(0)` persists an explicit zero, which completes a stored owner act
//! immediately; a holder keeps the stricter of its requested wait and the
//! common, and an explicit host selection is unaffected.
//!
//! Starting: [`resolve_start_wait_secs`] is the single precedence point the
//! generic start calls after policy validation. An absent common keeps the
//! old wait byte for byte; a stored row takes the common exactly (even for a
//! sole owner); a holder row takes the stricter of its requested wait and the
//! common; an explicit host selection (Host(Some(..)) or Host(None))
//! ignores the common.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::federation::FederationGrantRole as Role;
use crate::ports::{EntityStoreRead, recorded_at_in_txn};

use super::{check_vault, invalid};

/// Seconds in a day, for this setter's days-to-seconds conversion.
const SECS_PER_DAY: u64 = 86400;

/// Replace the manifest's common owner-change wait; `None` removes the key.
fn with_owner_change_wait(body: &[u8], secs: Option<u64>) -> Result<Vec<u8>> {
    let key = crate::gate::POLICY_OWNER_CHANGE_WAIT_SECS_KEY;
    let mut cursor = std::io::Cursor::new(body);
    let Ok(rmpv::Value::Map(mut entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(invalid());
    };
    entries.retain(|(name, _)| name.as_str() != Some(key));
    if let Some(secs) = secs {
        entries.push((key.into(), rmpv::Value::from(secs)));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).map_err(|_| invalid())?;
    Ok(out)
}

/// The single precedence point for the common wait at start time, called
/// after unchanged policy validation. `policy_wait_secs` is the validated
/// policy's own wait; `sole_owner` and `holder_selected` describe the
/// already-chosen setting, never a new refusal.
pub(super) fn resolve_start_wait_secs(
    common_wait_secs: Option<u64>,
    owner_change_act: bool,
    stored_row: bool,
    sole_owner: bool,
    holder_selected: bool,
    policy_wait_secs: u64,
) -> u64 {
    let legacy = if stored_row && sole_owner {
        0
    } else {
        policy_wait_secs
    };
    match (common_wait_secs, owner_change_act) {
        (Some(common), true) if stored_row => common,
        (Some(common), true) if holder_selected => policy_wait_secs.max(common),
        _ => legacy,
    }
}

impl Vault {
    /// The vault's common owner-change wait in seconds, if the trusted
    /// manifest names one. A fail-closed resolution refuses rather than
    /// answering from a manifest the gate cannot trust.
    pub fn owner_change_wait_secs(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let resolution = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        if resolution.is_fail_closed() {
            return Err(invalid());
        }
        Ok(resolution.owner_change_wait_secs)
    }

    /// Set the vault's common owner-change wait in whole days. `None`
    /// removes the key; `Some(0)` persists an explicit zero, which completes
    /// a stored owner act immediately (holder and explicit host selections
    /// keep their own waits). The caller revalidates as a person and must
    /// hold live Owner membership in the vault; the scalar replaces onto the
    /// current trusted default manifest body, never onto a received manifest.
    pub fn set_owner_change_wait_days(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
        days: Option<u64>,
    ) -> Result<()> {
        let secs = days
            .map(|days| days.checked_mul(SECS_PER_DAY).ok_or_else(invalid))
            .transpose()?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if !holders
            .iter()
            .any(|holder| holder.member == actor && holder.role == Role::Owner)
        {
            return Err(invalid());
        }
        let id = crate::gate::default_policy_manifest_id()?;
        let raw = EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?.ok_or_else(invalid)?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        // Build only on bytes that passed the owner door, never on a received manifest.
        if !crate::gate::manifest_authenticity::manifest_is_trusted(&self.store, &txn, &id, body)? {
            return Err(invalid());
        }
        let data = with_owner_change_wait(body, secs)?;
        self.write_holder_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        txn.commit()?;
        Ok(())
    }
}
