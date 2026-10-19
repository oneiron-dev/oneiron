//! The authority a turn-woken program runs under (DOOR-141 §4): the waking
//! actor's own, sealed at the turn as witnesses (credential, delegation and
//! Grant refs and the effective scope's digest), never a bearer secret, and
//! judged again against the live vault before anything is admitted. Neither
//! the operator root nor a Dreamer stamp stands in for the actor.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::authority::VerifiedSlip;
use crate::dreamer_runner::DREAMER_TURN_PROGRAM_ATTEMPT_KIND;
use crate::error::{Error, Result};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

use super::types::TurnProgramAttemptStamp;
use super::{ADMISSION, ATTEMPT};

const SCOPE_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-scope:v1";

fn invalid() -> Error {
    Error::InvalidConfig("invalid turn program binding".into())
}

/// The waking actor's authority as one landed turn sealed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TurnProgramAuthority {
    actor: EntityId,
    actor_class: u8,
    proof: Proof,
}

/// How the waking actor proved itself on the turn: a reference and its
/// witness, never a secret and no authority on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Proof {
    /// The caller's own verified capability slip, by id: the slip it was
    /// delegated from, the FEDERATION_GRANT it was minted under, and the
    /// digest of the effective scope it was admitted with.
    Slip {
        slip_id: [u8; 32],
        parent: Option<[u8; 32]>,
        grant: Option<EntityId>,
        scope_digest: [u8; 32],
    },
    /// A self-hosted vault's host credential acting as the vault's owner
    /// (FIX 2222): the host root by id, or the explicit local dev mode.
    HostAction { root: Option<[u8; 32]> },
    /// The in-process host's own caller, which presents no credential: its
    /// live binding stands for it.
    Native,
}

impl TurnProgramAuthority {
    /// A caller's own slip: one that allows writes and that its holder, the
    /// actor, still holds. A transferred, single-use, invitee or support slip
    /// seals nothing, so its turn wakes no program.
    pub(crate) fn slip(
        actor: EntityId,
        class: EdgeActorClass,
        proof: &VerifiedSlip,
    ) -> Option<Self> {
        let claims = proof.claims();
        let writes = proof.allows_verb("write") || proof.allows_verb("core:write");
        if !writes
            || proof.is_transferred()
            || claims.single_use
            || claims.invitation_ref.is_some()
            || claims.delegation.is_some()
            || claims.holder_ref != actor.to_hex()
        {
            return None;
        }
        let grant = claims
            .grant_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .ok()?;
        let scope = rmp_serde::to_vec_named(proof.scope()).ok()?;
        let scope_digest = *blake3::Hasher::new()
            .update(SCOPE_DOMAIN)
            .update(&scope)
            .finalize()
            .as_bytes();
        Some(Self {
            actor,
            actor_class: class as u8,
            proof: Proof::Slip {
                slip_id: claims.slip_id,
                parent: claims.parent_id,
                grant,
                scope_digest,
            },
        })
    }

    /// A self-hosted host credential acting as the owner `actor`, under the
    /// host root `root` (`None`: the explicit local dev mode).
    pub(crate) fn host_action(
        actor: EntityId,
        class: EdgeActorClass,
        root: Option<[u8; 32]>,
    ) -> Self {
        Self {
            actor,
            actor_class: class as u8,
            proof: Proof::HostAction { root },
        }
    }

    /// The in-process host's own caller.
    pub(crate) fn native(actor: EntityId, class: EdgeActorClass) -> Self {
        Self {
            actor,
            actor_class: class as u8,
            proof: Proof::Native,
        }
    }

    pub(crate) fn actor(&self) -> EntityId {
        self.actor
    }

    pub(crate) fn class(&self) -> Result<EdgeActorClass> {
        EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(invalid)
    }

    pub(super) fn class_byte(&self) -> u8 {
        self.actor_class
    }

    /// The FEDERATION_GRANT the waking credential was minted under.
    pub(super) fn grant(&self) -> Option<EntityId> {
        match &self.proof {
            Proof::Slip { grant, .. } => *grant,
            Proof::HostAction { .. } | Proof::Native => None,
        }
    }

    /// The digest of the effective scope the waking credential carried.
    pub(super) fn scope_digest(&self) -> Option<[u8; 32]> {
        match &self.proof {
            Proof::Slip { scope_digest, .. } => Some(*scope_digest),
            Proof::HostAction { .. } | Proof::Native => None,
        }
    }

    /// Whether this authority still stands in `txn`: the actor is a live
    /// authority-bearing row whose binding no revocation took, and its
    /// witness still holds (the same slip live and held by the actor under
    /// the same delegation and live Grant; the host action still acting as
    /// this owner). `false` is a lapse; `Err` is a failure to judge it.
    pub(super) fn stands_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let writer = WriteActor::new(self.actor, self.class()?);
        if let Err(error) = vault.verify_native_write_actor_in_txn(txn, &writer) {
            return lapsed(error);
        }
        match &self.proof {
            Proof::Slip {
                slip_id,
                parent,
                grant,
                ..
            } => {
                if !vault.capability_slip_id_is_live_in_txn(txn, slip_id)? {
                    return Ok(false);
                }
                let fold = vault.authority_view_readonly_in_txn(txn)?;
                let Some(mint) = fold.slips.mints.get(slip_id) else {
                    return Ok(false);
                };
                let claims = &mint.action.claims;
                if claims.holder_ref != self.actor.to_hex()
                    || claims.parent_id != *parent
                    || claims.grant_ref != grant.as_ref().map(EntityId::to_hex)
                {
                    return Ok(false);
                }
                match grant {
                    Some(grant) => {
                        Ok(
                            crate::vault::live_entity_row_in_txn(&vault.store, txn, grant)?
                                .is_live(),
                        )
                    }
                    None => Ok(true),
                }
            }
            Proof::HostAction { root } => {
                match vault.host_action_owner_in_txn(txn, None) {
                    Ok(owner) if owner == self.actor => {}
                    Ok(_) => return Ok(false),
                    Err(error) if crate::authority::host_action_refused(&error) => {
                        return Ok(false);
                    }
                    Err(error) => return Err(error),
                }
                match root {
                    Some(root) => vault.capability_slip_id_is_live_in_txn(txn, root),
                    None => Ok(true),
                }
            }
            Proof::Native => Ok(true),
        }
    }
}

/// A writer check's refusal is a lapse of the authority, not a failure to
/// judge it.
fn lapsed(error: Error) -> Result<bool> {
    match error {
        Error::Claim(_) | Error::InvalidClaimBody(_) => Ok(false),
        error => Err(error),
    }
}

/// Binds a program attempt to the waking actor its admission sealed: the
/// enqueue law's program branch, beside the resident and dispatch carve-outs.
/// No base-agent stamp is minted for it. The admission row lands first, in
/// the same writer; a retry successor of the attempt binds to the same one.
pub(crate) fn stamp_program_attempt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != DREAMER_TURN_PROGRAM_ATTEMPT_KIND {
        return Err(invalid());
    }
    let rmpv::Value::Binary(bytes) = &payload.input else {
        return Err(invalid());
    };
    let admission: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid())?;
    let row = ADMISSION
        .get(vault, &*txn, &admission)?
        .ok_or_else(invalid)?;
    if row.refused.is_some() {
        return Err(invalid());
    }
    let actor = row.wake.authority.actor();
    if let Some(stamp) = ATTEMPT.get(vault, &*txn, &record.id)? {
        if stamp.attempt_id != *record.id.as_bytes()
            || stamp.admission != admission
            || stamp.actor != actor
            || stamp.receipt_id != row.receipt_id
        {
            return Err(invalid());
        }
        return Ok(());
    }
    ATTEMPT.put(
        vault,
        txn,
        &record.id,
        &TurnProgramAttemptStamp {
            attempt_id: *record.id.as_bytes(),
            admission,
            actor,
            actor_class: row.wake.authority.class_byte(),
            receipt_id: row.receipt_id,
        },
    )
}

/// A program attempt's milestones carry its waking actor and no other: the
/// writer `actor` must be the one the attempt's stamp names.
pub(crate) fn require_program_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    actor: WriteActor,
) -> Result<()> {
    let stamp = ATTEMPT.get(vault, txn, &attempt)?.ok_or_else(invalid)?;
    if stamp.attempt_id != *attempt.as_bytes()
        || stamp.actor != actor.entity_ref()
        || stamp.actor_class != actor.actor_class() as u8
    {
        return Err(invalid());
    }
    Ok(())
}

impl Vault {
    /// The actor a turn-woken program attempt runs as (DOOR-141): the one
    /// whose turn woke it, by the attempt's own stamp. Its milestones, model
    /// envelopes and effects carry this actor; the Dreamer's stamp never
    /// stands in for it (`dreamer_actor_for_attempt` finds none to read).
    pub fn program_actor_for_attempt(&self, id: AttemptId) -> Result<WriteActor> {
        let txn = self.store.env.read_txn()?;
        let stamp = ATTEMPT.get(self, &txn, &id)?.ok_or_else(invalid)?;
        if stamp.attempt_id != *id.as_bytes() {
            return Err(invalid());
        }
        let class = EdgeActorClass::try_from_u8(stamp.actor_class).ok_or_else(invalid)?;
        Ok(WriteActor::new(stamp.actor, class))
    }
}
