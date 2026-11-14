//! A revoke this install could not carry for the owner when he made it (FIX
//! 4851). The revoke door, and a ruling that a found key is no secret,
//! revoke the record here and erase its value in their own commit, whether
//! or not this install can carry the owner's act. When it cannot, because
//! it has no live machine profile in the roster or its install key is not
//! loaded, the same commit keeps a value-free intent under the record's id:
//! the owner the revoke is by, the surface he decided on (audit only), the
//! second it was made at and the generation it revoked. No proof and no
//! value is kept.
//!
//! The next pass on which this install can sign carries it, with no other
//! step from the owner (CALLS CUSTODY_REVOKE_PENDING_CARRY): the owner work
//! pickup after an authority catch-up and on the served tick, and the moment
//! this install's key loads. Each intent is judged again in a writer
//! transaction of its own, and carried exactly as the door carries a revoke
//! it can carry at once.
//!
//! A writer's ruling that a key they wrote is no secret waits the same way,
//! as that person's own act ([`ActBy::Person`], Engine RULING
//! L6-03-WRITER-CARRY): the intent says so, and its pass checks that the
//! person is still live where the owner's checks the vault owner.

use super::super::read_secret_custody_meta_in_txn;
use super::super::transition::custody_portable;
use super::super::types::SecretCustodyStatus;
use super::revoked::CustodyRevokeAct;
use super::{CustodyKeptHere, SecretCustodyWork};
use crate::authority::{ActBy, AuthorityFold};
use crate::error::{Error, Result, SecretError};
use crate::store::pending_custody_revoke::{PENDING, PendingRevoke};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Vault};

pub(crate) use crate::store::pending_custody_revoke::erase_pending_revoke_actor_in_txn;

/// How a portable secret's revoke reaches the owner's other machines when
/// the install he revoked it on cannot carry his act yet (CALLS
/// CUSTODY_REVOKE_PENDING_CARRY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRevokePendingCarry {
    /// The revoke and its erase commit here at once, and the reply says the
    /// carry is pending. The carry waits, value-free, under the record's id,
    /// until a pass on which this install can sign: the owner work pickup
    /// after an authority catch-up and on the served tick, or the moment its
    /// install key loads. That pass checks the owner is still a live vault
    /// owner and records the ordinary byte-free revoke request, its enacted
    /// result and its revoked transition, as of the second he revoked it,
    /// dropping the intent in the same commit. A record superseded or gone,
    /// an id an admitted revoke already ended, or an owner no longer live
    /// drops it; an install that still cannot sign keeps it. A record that
    /// stays on its device is never carried.
    CarryWhenSignerLoads,
}

const CUSTODY_REVOKE_PENDING_CARRY: CustodyRevokePendingCarry =
    CustodyRevokePendingCarry::CarryWhenSignerLoads;

/// The Gate content kind of a pending revoke's carry outcome.
const REVOKE_CARRY_CONTENT_KIND: &str = "secret_custody_revoke_carry";
/// The owner no longer lives in the vault, so their pending revoke is not carried.
const REVOKE_CARRY_OWNER_NOT_LIVE_REASON: &str = "gate.secret.custody.revoke_carry.owner_not_live";
/// The person who wrote the key and revoked it is no longer live, so their
/// pending revoke is not carried in their name.
const REVOKE_CARRY_PERSON_NOT_LIVE_REASON: &str =
    "gate.secret.custody.revoke_carry.person_not_live";

/// Whether `error` says this install's signing keys are not loaded here:
/// the one failure a revoke's carry waits out.
fn signing_unavailable(error: &Error) -> bool {
    matches!(error, Error::Secret(SecretError::KeystoreUnavailable(_)))
}

/// Whether this install can carry an owner act in `txn` now: a live machine
/// profile under its loaded install key. Keys not loaded here are a "not
/// yet", never a failure.
pub(super) fn can_carry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<bool> {
    match vault.owner_work_carrier_in_txn(txn, fold) {
        Ok(carrier) => Ok(carrier.is_some()),
        Err(error) if signing_unavailable(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Keeps the carry of `act`'s revoke of record `id`, at `generation`, as the
/// act its `by` names (the owner's, or the writer's own [`ActBy::Person`]),
/// with its screen, pending in the revoke's own transaction (CALLS
/// CUSTODY_REVOKE_PENDING_CARRY), and returns the work that says so. A
/// revoke already owed for `id` that carries a found-key ruling's screen
/// stays as it is when `act` carries none (L6-03-RULED-SCREEN-LOCAL): its
/// carry ends the id on the other machines just the same, and the ruling
/// goes with it.
pub(super) fn defer_revoke_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    act: CustodyRevokeAct,
    generation: u32,
    at: u64,
) -> Result<SecretCustodyWork> {
    match CUSTODY_REVOKE_PENDING_CARRY {
        CustodyRevokePendingCarry::CarryWhenSignerLoads => {
            if act.screen.is_none()
                && PENDING
                    .get(&vault.store, txn, &id)?
                    .is_some_and(|owed| owed.screen.is_some())
            {
                return Ok(SecretCustodyWork::kept(CustodyKeptHere::CarryPending));
            }
            let pending = PendingRevoke {
                owner: act.actor,
                surface: act.surface,
                at,
                generation,
                by_person: act.by == ActBy::Person,
                screen: act.screen,
            };
            PENDING.put(&vault.store, txn, &id, &pending)?;
            Ok(SecretCustodyWork::kept(CustodyKeptHere::CarryPending))
        }
    }
}

impl Vault {
    /// The revoke door's key load before its transaction: keys that are not
    /// available here leave the revoke to stand here with its carry pending
    /// (CALLS CUSTODY_REVOKE_PENDING_CARRY), never refuse it.
    ///
    /// # Errors
    /// A load that fails for any other reason.
    pub(crate) fn load_signing_for_revoke(&self) -> Result<()> {
        match self.load_install_signing_if_minted() {
            Err(error) if !signing_unavailable(&error) => Err(error),
            _ => Ok(()),
        }
    }

    /// Carries every revoke this install still owes the owner's other
    /// machines (CALLS CUSTODY_REVOKE_PENDING_CARRY), each in a writer
    /// transaction of its own. The caller loads the install key first; what
    /// it records reaches the live windows on their next refresh or open.
    /// Returns how many it carried.
    ///
    /// # Errors
    /// The first carry that failed for a reason other than keys not loaded
    /// here; the others are still tried, and each that failed stays owed.
    fn carry_pending_revokes(&self) -> Result<usize> {
        let owed = {
            let txn = self.store.env.read_txn()?;
            PENDING.scan(&self.store, &txn)?
        };
        let mut carried = 0;
        let mut failed = None;
        for (id, _) in owed {
            match self.with_write_txn(|txn| self.carry_pending_revoke_in_txn(txn, id)) {
                Ok(true) => carried += 1,
                Ok(false) => {}
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        failed.map_or(Ok(carried), Err)
    }

    /// [`Self::carry_pending_revokes`] for a pass that goes on without it,
    /// such as the install key's load: a failure is logged by kind, never
    /// with a value.
    pub(crate) fn carry_pending_revokes_logged(&self) {
        match self.carry_pending_revokes() {
            Ok(carried) if carried > 0 => {
                tracing::debug!(carried, "pending custody revokes carried");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending custody revokes were not carried on this install"
                );
            }
        }
    }

    /// The owner work pickup's arm (CALLS CUSTODY_REVOKE_PENDING_CARRY):
    /// with a revoke owed, loads this install's key, carries what it can,
    /// and mirrors what it carried into the live windows. Nothing is read
    /// from the keystore while none is owed.
    pub(crate) fn carry_owed_revokes(&self) {
        let before = match self.owed_revokes() {
            Ok(0) => return,
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending custody revokes were not read on this install"
                );
                return;
            }
        };
        // A key that loads now carries them as it loads; this pass carries
        // them with a key loaded before.
        let _ = self.load_install_signing_if_minted();
        self.carry_pending_revokes_logged();
        #[cfg(feature = "sync")]
        if self.owed_revokes().is_ok_and(|after| after < before) {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = before;
    }

    /// How many revokes this install still owes.
    fn owed_revokes(&self) -> Result<usize> {
        let txn = self.store.env.read_txn()?;
        Ok(PENDING.scan(&self.store, &txn)?.len())
    }

    /// Carries the revoke owed for record `id` in `txn`, judged again here:
    /// dropped when the record is gone, no longer revoked at the generation
    /// it revoked, ended by an admitted revoke already (unless it carries a
    /// found-key ruling's screen no admitted revoke carries yet,
    /// L6-03-RULED-SCREEN-LOCAL: the other revoke does not carry the ruling),
    /// or its owner is no longer a live vault owner (a writer's own revoke:
    /// its person no longer live); kept while this install cannot sign.
    fn carry_pending_revoke_in_txn(&self, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<bool> {
        let Some(pending) = PENDING.get(&self.store, txn, &id)? else {
            return Ok(false);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let screen_owed = pending.screen.is_some_and(|screen| {
            !fold
                .custody_revoke_screens()
                .any(|carried| carried == screen)
        });
        let record = read_secret_custody_meta_in_txn(&self.store, txn, &id)?.filter(|record| {
            custody_portable(record)
                && record.status == SecretCustodyStatus::Revoked
                && record.rotation_generation == pending.generation
                && (!fold.custody_revoked(&id) || screen_owed)
        });
        let live = if pending.by_person {
            crate::consent::person_is_live_in_txn(self, txn, &pending.owner)?
        } else {
            crate::policy_model::is_live_vault_owner_in_txn(self, txn, &pending.owner)?
        };
        let Some(record) = record else {
            PENDING.delete(&self.store, txn, &id)?;
            return Ok(false);
        };
        if !live {
            self.append_not_live_receipt_in_txn(txn, id, &pending)?;
            PENDING.delete(&self.store, txn, &id)?;
            return Ok(false);
        }
        let act = CustodyRevokeAct {
            actor: pending.owner,
            by: pending.by(),
            surface: pending.surface,
            screen: pending.screen,
        };
        let carried = self
            .carry_revoke_for_in_txn(txn, act, id, &record, pending.at)?
            .is_some();
        if carried {
            PENDING.delete(&self.store, txn, &id)?;
        }
        Ok(carried)
    }

    /// Records that `pending` was not carried because the PERSON it is by,
    /// its owner or the writer whose own act it is, is no longer live. The
    /// caller deletes the intent in the same transaction.
    fn append_not_live_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        pending: &PendingRevoke,
    ) -> Result<()> {
        let (reason, author) = if pending.by_person {
            (REVOKE_CARRY_PERSON_NOT_LIVE_REASON, "person")
        } else {
            (REVOKE_CARRY_OWNER_NOT_LIVE_REASON, "owner")
        };
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: "deny".into(),
            reason_codes: vec![reason.into()],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                REVOKE_CARRY_CONTENT_KIND,
                vec![
                    format!("record:{}", id.to_hex()),
                    format!("{author}:{}", pending.owner.to_hex()),
                    format!("generation:{}", pending.generation),
                ],
            ),
            actor_class: "human".into(),
            actor_ref: Some(pending.owner.to_hex()),
            content_kind: REVOKE_CARRY_CONTENT_KIND.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: None,
            diff_handle: id.as_bytes().to_vec(),
            read_frontier_hash: [0; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)
    }
}
