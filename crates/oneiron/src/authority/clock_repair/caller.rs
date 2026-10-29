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
    /// self-hosted host root's.
    HolderProof {
        slip: Box<CapabilitySlip>,
        timestamp: u64,
        signature: Vec<u8>,
        nonce: Vec<u8>,
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
            slip: Box::new(slip),
            timestamp,
            signature,
            nonce,
        })
    }

    /// A slip this call's transport verified when it admitted the call (a
    /// held socket's, or a request read on an anchored clock): its liveness
    /// and its holder's ownership are judged again in the repair's writer.
    #[must_use]
    pub fn verified(slip: VerifiedSlip) -> Self {
        Self(Caller::Verified(Box::new(slip)))
    }

    /// The owner `holder` a managed vault's supervisor attested for this one
    /// request, as its managed ingress verified the attestation. Only that
    /// verified attestation names one; the repair's writer judges whether
    /// the vault records `holder` as its live owner.
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
}

/// What a caller is held to before the writer opens: nothing that reads the
/// authority clock.
enum Judged {
    /// The owner's identity, authenticated as `authenticate_owner` does,
    /// with the slip the writer binds to it.
    OwnerSlip(Box<AuthenticatedOwner>, Box<VerifiedSlip>),
    /// A self-hosted host root's holder proof.
    HostProof {
        slip: Box<CapabilitySlip>,
        timestamp: u64,
        signature: Vec<u8>,
        nonce: Vec<u8>,
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

impl crate::Vault {
    /// [`Self::repair_authority_clock`] for `caller` as its ingress took it
    /// (FIX 11190, FIX 11202): the caller is judged only in the repair's
    /// writer, after it stages the floor it proves, so a damaged floor never
    /// refuses the owner first. A whole or absent floor is judged in the
    /// same writer and left as it is; a holder proof's nonce is spent there
    /// either way.
    ///
    /// # Errors
    /// The owner refusal when `caller` is not this vault's live owner;
    /// [`Error::HostActionRequiresSupportGrant`] for a host credential on a
    /// vault that is not self-hosted; the repair's own errors otherwise.
    pub fn repair_authority_clock_for(
        &self,
        caller: ClockRepairCaller,
    ) -> Result<crate::authority::AuthorityClockRepair> {
        let judged = match caller.0 {
            Caller::HolderProof {
                slip,
                timestamp,
                signature,
                nonce,
            } if slip.claims.holder_ref != HOST_HOLDER => {
                return self.repair_authority_clock_by_slip(&slip, timestamp, &signature, &nonce);
            }
            Caller::HolderProof {
                slip,
                timestamp,
                signature,
                nonce,
            } => Judged::HostProof {
                slip,
                timestamp,
                signature,
                nonce,
            },
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
            Judged::HostProof {
                slip,
                timestamp,
                signature,
                nonce,
            } => {
                let root = self.admit_capability_slip_request_in_txn(
                    txn, &slip, timestamp, &signature, &nonce,
                )?;
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
