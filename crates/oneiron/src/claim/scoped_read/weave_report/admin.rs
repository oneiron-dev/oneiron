//! The weave Admin's lane and live report (OF-499 A3). An Admin reads only
//! on a lane its proof builds in the read's own transaction (L02's Admin
//! key, [`ScopedRead::for_weave_admin_in_txn`]), held to the asking
//! handle's destination and room turn. The proof is revalidated in every
//! such transaction, and no Admin key is carried into another one. A proof
//! that no longer holds refuses that Admin read alone, typed
//! `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)`; a Person, Owner or Agent read
//! never takes this path.
use super::super::{RoomTurnCeiling, ScopedRead, ScopedReadActorKey, ScopedReadResult};
use super::{WeaveReader, WeaveReport, WeaveSectionSpec};
use crate::Vault;
use crate::authority::AuthenticatedWeaveAdmin;
use crate::error::{Error, Result};
use crate::settings::ReadDestination;

/// The read ceilings an Admin read keeps from the handle that asked it:
/// where its rows go, and the room turn it reads inside. Resolved before
/// any Admin read transaction opens, since the room resolver opens its own
/// snapshots. They only narrow the Admin's own lane.
#[derive(Debug, Clone)]
pub(crate) struct WeaveAdminFrame {
    destination: ReadDestination,
    room_turn: Option<RoomTurnCeiling>,
}

impl WeaveAdminFrame {
    pub(crate) fn new(destination: ReadDestination, room_turn: Option<RoomTurnCeiling>) -> Self {
        Self {
            destination,
            room_turn,
        }
    }
}

/// A read transaction for one Admin read, its grants judged at the
/// refreshed persisted clock as every grant-bound read's are (FIX 8671).
pub(in crate::claim::scoped_read) fn weave_admin_read_txn(
    vault: &Vault,
) -> Result<heed::RoTxn<'_>> {
    vault.store.authorization_now()?;
    Ok(vault.store.env.read_txn()?)
}

impl<'v> ScopedRead<'v> {
    /// `admin`'s lane in `txn`: L02's Admin key, which revalidates the proof
    /// here, held to `frame`'s destination and room turn. Same transaction
    /// only.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold in `txn`; a storage fault as itself; `InvalidConfig` when the
    /// request builds no read key.
    pub(in crate::claim::scoped_read) fn weave_admin_lane_in(
        vault: &'v Vault,
        txn: &'v heed::RoTxn<'_>,
        admin: &'v AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
    ) -> Result<Self> {
        let mut lane = Self::for_weave_admin_in_txn(vault, txn, admin)?
            .ok_or_else(|| Error::InvalidConfig("a weave admin's request keys no read".into()))?;
        let key = lane.actor_key.clone().for_destination(&frame.destination);
        lane.actor_key = match &frame.room_turn {
            Some(turn) => key.in_room_turn(turn.clone()),
            None => key,
        };
        Ok(lane)
    }
}

impl ScopedRead<'_> {
    /// Binds `admin` to this lane in `txn`: its proof current here, and the
    /// lane its own Admin lane (its person's key, never the owner's, with no
    /// owner exemption, its authority inside the Scope the Admin reads
    /// within now).
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold; `InvalidConfig` when this lane is not the Admin's.
    pub(in crate::claim::scoped_read) fn bind_weave_admin_in(
        &self,
        txn: &heed::RoTxn<'_>,
        admin: &AuthenticatedWeaveAdmin,
    ) -> Result<()> {
        let scope = ScopedReadActorKey::read_authority(&admin.read_scope_in_txn(self.vault, txn)?);
        let key = &self.actor_key;
        if key.actor_ref() != admin.actor().to_hex()
            || key.reads_as_vault_owner()
            || key.owner_exemption.is_some()
            || !key
                .authority_scope()
                .is_some_and(|held| held.is_narrowing_of(&scope))
        {
            return Err(Error::InvalidConfig(
                "weave admin is not the scoped actor".into(),
            ));
        }
        Ok(())
    }
}

impl Vault {
    /// `admin`'s live weave report for `recipe`, as a served copy: its own
    /// lane in one transaction, its proof revalidated there, the admin
    /// policy row held by its person, each audit's decisions past its own
    /// floor (FIX 8322).
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold; the report's own refusals otherwise.
    pub(crate) fn weave_admin_report(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let txn = weave_admin_read_txn(self)?;
        let lane = ScopedRead::weave_admin_lane_in(self, &txn, admin, frame)?;
        let mut report = lane.weave_report_in_txn(&txn, WeaveReader::Admin(admin), recipe)?;
        let (filter, policy) = lane.resolve_retrieval_filter_in(&txn, None)?;
        lane.redact_sieve_decisions_in(&txn, &policy, &filter, &mut report.value);
        Ok(report)
    }
}
