//! Who asks for the owner's repair of the authority clock, as its ingress
//! took them before anything read the clock (FIX 11190, FIX 11202).
//!
//! A damaged floor refuses every proof that is judged against it, so each
//! surface the owner speaks from hands the repair what it verified without
//! the clock: a slip and its holder proof as they arrived, a slip its
//! transport verified earlier, the owner a managed vault's supervisor
//! attested for this request, the self-hosted dev mode, or the embedded
//! owner of the handle that holds the writer lease. Each is judged, and a
//! holder proof's nonce spent, only in the repair's own writer, against the
//! floor it stages there ([`crate::Vault::repair_authority_clock_for`]). It
//! is no owner proof anywhere else: nothing here mints an
//! [`AuthenticatedOwner`] another door can hold.

use crate::EntityId;
use crate::authority::{CapabilitySlip, VerifiedSlip};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::store::GateDecisionId;

/// The holder a host credential names.
const HOST_HOLDER: &str = "host";

/// One repair invocation's caller, as its ingress verified it (FIX 11190,
/// FIX 11202). Consumed by [`crate::Vault::repair_authority_clock_for`]
/// alone, which judges it in the repair's writer.
pub struct ClockRepairCaller(Caller);

/// Names the caller's kind alone: a holder proof's signature and nonce stay
/// out of every log.
impl std::fmt::Debug for ClockRepairCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.0 {
            Caller::HolderProof { .. } => "holder_proof",
            Caller::Verified(_) => "verified",
            Caller::ManagedOwner(_) => "managed_owner",
            Caller::DevMode => "dev_mode",
            Caller::Embedded => "embedded",
        };
        f.debug_tuple("ClockRepairCaller").field(&kind).finish()
    }
}

enum Caller {
    /// A slip and its holder proof, unverified: the owner's own slip, or a
    /// self-hosted host root's, with the owner a managed vault's supervisor
    /// attested beside it, if any.
    HolderProof {
        proof: HolderProof,
        attested: Option<EntityId>,
    },
    /// A slip its transport verified when the call was admitted.
    Verified(Box<VerifiedSlip>),
    /// The owner a managed vault's supervisor attested for this request.
    ManagedOwner(EntityId),
    /// The explicit local dev mode of a self-hosted vault.
    DevMode,
    /// The embedded owner of the handle that holds the writer lease.
    Embedded,
}

/// A slip and its holder proof as a request carried them.
struct HolderProof {
    slip: Box<CapabilitySlip>,
    timestamp: u64,
    signature: Vec<u8>,
    nonce: Vec<u8>,
}

impl ClockRepairCaller {
    /// A request's slip and its holder proof (`timestamp`, `signature`,
    /// `nonce`), as they arrived: both are judged, and the nonce spent, in
    /// the repair's writer. The owner's own unattenuated human slip acts as
    /// the owner; a self-hosted host root acts as the owner its host action
    /// names; any other slip acts as nobody.
    #[must_use]
    pub fn holder_proof(
        slip: CapabilitySlip,
        timestamp: u64,
        signature: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self(Caller::HolderProof {
            proof: HolderProof {
                slip: Box::new(slip),
                timestamp,
                signature,
                nonce,
            },
            attested: None,
        })
    }

    /// This holder proof beside the owner `holder` a managed vault's
    /// supervisor attested for the same request: the repair's writer binds
    /// the slip only when it names that person, as a managed request's slip
    /// beside another person's attestation is refused everywhere (FIX
    /// 11190). Any other caller is left as it is.
    #[must_use]
    pub fn beside_attested_owner(self, holder: EntityId) -> Self {
        match self.0 {
            Caller::HolderProof { proof, .. } => Self(Caller::HolderProof {
                proof,
                attested: Some(holder),
            }),
            other => Self(other),
        }
    }

    /// A slip this call's transport verified when it admitted the call (a
    /// held socket's, or a request read on an anchored clock): its liveness
    /// and its holder's ownership are judged again in the repair's writer.
    #[must_use]
    pub fn verified(slip: VerifiedSlip) -> Self {
        Self(Caller::Verified(Box::new(slip)))
    }

    /// The owner `holder` a managed vault's supervisor attested for this one
    /// request (or the held socket it came on), as its managed ingress
    /// verified the attestation. Only that verified attestation names one;
    /// the repair's writer judges whether the vault records `holder` as its
    /// live owner.
    #[must_use]
    pub fn managed_owner(holder: EntityId) -> Self {
        Self(Caller::ManagedOwner(holder))
    }

    /// The explicit local dev mode, as a host's exact no-secret dev hatch
    /// admits it: on a self-hosted vault it acts as the owner its host action
    /// names, judged in the repair's writer.
    #[must_use]
    pub fn dev_mode() -> Self {
        Self(Caller::DevMode)
    }

    /// The embedded owner, for a handle [`crate::Memory`] checked holds the
    /// writer lease and binds that owner as a human.
    pub(crate) fn embedded() -> Self {
        Self(Caller::Embedded)
    }

    /// The person this caller says the repair acts for, before anything is
    /// judged: the person its slip names, the attested owner, or, for a host
    /// credential, the embedded owner its host action can name. The repair
    /// acts for no one else; its writer proves whether it acts for this one.
    /// `None` for a slip that names no person or host.
    #[must_use]
    pub fn person(&self) -> Option<EntityId> {
        let named = |holder: &str| {
            if holder == HOST_HOLDER {
                crate::vault::embedded_owner_actor_id().ok()
            } else {
                EntityId::from_hex(holder).ok()
            }
        };
        match &self.0 {
            Caller::HolderProof { proof, .. } => named(&proof.slip.claims.holder_ref),
            Caller::Verified(slip) => named(&slip.claims().holder_ref),
            Caller::ManagedOwner(holder) => Some(*holder),
            Caller::DevMode | Caller::Embedded => crate::vault::embedded_owner_actor_id().ok(),
        }
    }
}

/// What a caller is held to before the writer opens: nothing that reads the
/// authority clock.
enum Judged {
    /// The owner's identity, authenticated as `authenticate_owner` does,
    /// with the slip the writer binds to it.
    OwnerSlip(Box<AuthenticatedOwner>, Box<VerifiedSlip>),
    /// The owner's identity and the holder proof the writer verifies, beside
    /// the owner a managed vault's supervisor attested.
    AttestedProof {
        owner: Box<AuthenticatedOwner>,
        proof: HolderProof,
        attested: EntityId,
    },
    /// A self-hosted host root's holder proof; beside an attested owner it
    /// binds no one.
    HostProof {
        proof: HolderProof,
        attested: Option<EntityId>,
    },
    /// A verified host root.
    HostRoot(Box<VerifiedSlip>),
    /// A person the vault must record as its live owner.
    RecordedOwner(EntityId),
    DevMode,
}

/// The owner refusal of a caller the repair does not bind.
fn not_the_owner(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// The refusal of a slip beside another person's attestation.
fn conflicts_with_attested() -> Error {
    not_the_owner("the slip names another person than the owner its supervisor attested")
}

impl crate::Vault {
    /// [`Self::repair_authority_clock`] for `caller` as its ingress took it
    /// (FIX 11190, FIX 11202): the caller is judged only in the repair's
    /// writer, after it stages the floor it proves, so a damaged floor never
    /// refuses the owner first. A whole or absent floor is judged in the
    /// same writer and left as it is; a holder proof's nonce is spent there
    /// either way.
    ///
    /// # Errors
    /// The owner refusal when `caller` is not this vault's live owner, or
    /// its slip names another person than the owner attested beside it;
    /// [`Error::HostActionRequiresSupportGrant`] for a host credential on a
    /// vault that is not self-hosted; the repair's own errors otherwise.
    pub fn repair_authority_clock_for(
        &self,
        caller: ClockRepairCaller,
    ) -> Result<crate::authority::AuthorityClockRepair> {
        let judged = match caller.0 {
            Caller::HolderProof { proof, attested }
                if proof.slip.claims.holder_ref == HOST_HOLDER =>
            {
                Judged::HostProof { proof, attested }
            }
            Caller::HolderProof {
                proof,
                attested: None,
            } => {
                return self.repair_authority_clock_by_slip(
                    &proof.slip,
                    proof.timestamp,
                    &proof.signature,
                    &proof.nonce,
                );
            }
            Caller::HolderProof {
                proof,
                attested: Some(attested),
            } => {
                let holder = proof.slip.claims.holder_ref.clone();
                let actor = EntityId::from_hex(&holder)
                    .map_err(|_| not_the_owner("the slip names no person"))?;
                let owner = self.authenticate_owner(actor, &holder, true, GateDecisionId::now())?;
                Judged::AttestedProof {
                    owner: Box::new(owner),
                    proof,
                    attested,
                }
            }
            Caller::Verified(slip) if slip.claims().holder_ref == HOST_HOLDER => {
                Judged::HostRoot(slip)
            }
            Caller::Verified(slip) => {
                let holder = slip.claims().holder_ref.clone();
                let actor = EntityId::from_hex(&holder)
                    .map_err(|_| not_the_owner("the slip names no person"))?;
                let owner = self.authenticate_owner(actor, &holder, true, GateDecisionId::now())?;
                Judged::OwnerSlip(Box::new(owner), slip)
            }
            Caller::ManagedOwner(holder) => Judged::RecordedOwner(holder),
            Caller::DevMode => Judged::DevMode,
            Caller::Embedded => Judged::RecordedOwner(crate::vault::embedded_owner_actor_id()?),
        };
        let judge = |txn: &mut heed::RwTxn<'_>| self.judge_repair_caller_in_txn(txn, judged);
        let mut txn = self.store.env.write_txn()?;
        match super::floor_row_in_txn(&self.store, &txn)? {
            super::FloorRow::Whole(floor) => {
                judge(&mut txn)?;
                txn.commit()?;
                Ok(super::sound(floor))
            }
            super::FloorRow::Damaged(damaged) => self.repair_damaged_floor(txn, &damaged, judge),
        }
    }

    /// Judges `judged` in the repair's writer `txn`, answering the owner the
    /// repair acts for.
    fn judge_repair_caller_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        judged: Judged,
    ) -> Result<EntityId> {
        let owner = match judged {
            Judged::OwnerSlip(owner, slip) => {
                return self.bind_owner_credential_in_txn(txn, *owner, *slip);
            }
            Judged::AttestedProof {
                owner,
                proof,
                attested,
            } => {
                let slip = self.admit_holder_proof_in_txn(txn, &proof)?;
                if slip.claims().holder_ref != attested.to_hex() {
                    return Err(conflicts_with_attested());
                }
                return self.bind_owner_credential_in_txn(txn, *owner, slip);
            }
            Judged::HostProof { proof, attested } => {
                let root = self.admit_holder_proof_in_txn(txn, &proof)?;
                if attested.is_some() {
                    return Err(conflicts_with_attested());
                }
                self.host_action_owner_in_txn(txn, Some(&root))?
            }
            Judged::HostRoot(root) => self.host_action_owner_in_txn(txn, Some(&*root))?,
            Judged::RecordedOwner(holder) => {
                if !self.recorded_owner_is_live_in_txn(txn, holder)? {
                    return Err(not_the_owner(
                        "the attested owner is not this vault's live owner",
                    ));
                }
                return Ok(holder);
            }
            Judged::DevMode => self.host_action_owner_in_txn(txn, None)?,
        };
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &owner)? {
            return Err(not_the_owner(
                "the host action's owner is not an owner of this vault",
            ));
        }
        Ok(owner)
    }

    /// `proof` verified, and its nonce spent, in the repair's writer `txn`.
    fn admit_holder_proof_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        proof: &HolderProof,
    ) -> Result<VerifiedSlip> {
        self.admit_capability_slip_request_in_txn(
            txn,
            &proof.slip,
            proof.timestamp,
            &proof.signature,
            &proof.nonce,
        )
    }

    /// Whether this handle's authority readings refuse now: the clock floor
    /// is present and damaged, and the handle holds no anchor measured from a
    /// floor it read whole. Only the owner's repair, and an owner's
    /// restriction-only act, are judged over such a floor (FIX 11190, FIX
    /// 11201).
    pub fn authority_clock_refuses_readings(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(matches!(
            super::floor_row_in_txn(&self.store, &txn)?,
            super::FloorRow::Damaged(_)
        ) && crate::authority::authority_anchored_secs(&self.store).is_none())
    }
}
