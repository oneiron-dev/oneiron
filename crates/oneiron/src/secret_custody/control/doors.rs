//! The owner's custody doors beside register, rotate and revoke (WILL L04
//! row 04): a rewrap, a register or rotate whose protected input his own
//! surface sealed, and the value-free view a surface reads to ask either.
//!
//! A rewrap seals the value a holder holds again, same generation and
//! status, to the recipients the owner names now: how a linked machine he
//! did not make his gets a secret (one he made his gets it from its holders'
//! own rewrap, CALLS CUSTODY_ROSTER_REWRAP). A sealed change
//! hands this install only ciphertext: the surface seals the metadata and
//! value to the holder's key under the binding the view gives it (the id,
//! generation, revision, holder and exact permits), so no console sees the
//! plaintext just to authorize. Each records a custody request through the
//! shared recorder ([`Vault::record_custody_change_in_txn`]), and none asks
//! where the owner said yes.

use zeroize::Zeroize;

use super::super::doors::{
    read_secret_custody_in_txn, register_generation_in_txn, resolve_secret_ref_in_txn,
};
use super::super::transition::{custody_portable, transition_named_in_txn};
use super::super::types::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use super::input::{MAX_INPUT_BYTES, attach_manifest};
use super::manifest::unstated_input;
use super::permits::candidate_for;
use super::{
    ActiveChange, CustodyDelivery, CustodyPlan, Material, SecretCustodyWork,
    refuse_revoked_use_in_txn, refused,
};
use crate::authority::{ActSurface, CustodyChange, CustodyRecipientPermit};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result, SecretError};
use crate::world_keys::OwnerWorkReceipt;
use crate::{EntityId, Vault};

/// One install a surface may offer as holder or recipient: a live linked
/// install, in any role, with an encryption key that imports. Offering it is
/// not the owner's consent; only the change he records permits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyCandidate {
    /// The exact permit a surface binds for it: its machine, profile entry
    /// and key digest.
    pub permit: CustodyRecipientPermit,
    /// Its encryption key, for a surface that seals the input itself: the
    /// canonical suite, then the public key bytes.
    pub suite: u16,
    pub encryption_key: Vec<u8>,
    /// It is this install.
    pub this_install: bool,
}

/// What a surface reads to ask a custody change of the secret a name
/// names: ids, digests, generations and keys, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyView {
    /// The vault an input binds.
    pub vault_id: [u8; 32],
    /// The secret's custody record id; a fresh one for a name nothing live
    /// holds, which a register binds.
    pub secret_id: EntityId,
    pub name: String,
    /// A live record or transition here holds the name.
    pub known: bool,
    /// This install holds the record itself.
    pub held_here: bool,
    /// The record may leave its device.
    pub portable: bool,
    pub status: Option<SecretCustodyStatus>,
    /// The record's generation: the one a rewrap approves, one below a
    /// rotate's; for an unknown name, the one a register approves.
    pub generation: u32,
    /// The custody revision a change states as seen, and its input binds.
    pub seen: [u8; 32],
    /// The secret's live custody requests.
    pub live: Vec<OwnerWorkReceipt>,
    pub candidates: Vec<CustodyCandidate>,
    /// Never known here (CALLS CUSTODY_REPLICATION_WITHOUT_ACK).
    pub delivery: CustodyDelivery,
}

/// A register or rotate whose protected input the owner's surface sealed to
/// the holder itself, under the binding [`SecretCustodyView`] gave it.
pub struct SealedCustodyChange<'a> {
    /// For a register, the `manifest_ref` the sealed record names, as the
    /// surface states it: this install attaches the manifest it resolves
    /// for it, for the holder to check the record against (CALLS
    /// CUSTODY_MANIFEST_RECHECK). A register that states none carries every
    /// secret manifest the vault publishes, or an explicit "no manifest" or
    /// "unread" mark (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI).
    pub manifest_ref: Option<&'a str>,
    pub change: CustodyChange,
    pub secret_id: EntityId,
    /// The generation the change approves.
    pub generation: u32,
    /// The custody revision the surface read.
    pub seen: [u8; 32],
    pub holder: EntityId,
    /// The exact permits the input binds, ascending by machine.
    pub recipients: &'a [CustodyRecipientPermit],
    /// The input's envelope bytes, sealed to the holder's key.
    pub input: &'a [u8],
}

// Never print the ciphertext.
impl std::fmt::Debug for SealedCustodyChange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedCustodyChange")
            .field("change", &self.change)
            .field("secret_id", &self.secret_id)
            .field("generation", &self.generation)
            .field("holder", &self.holder)
            .field("recipients", &self.recipients.len())
            .field("manifest_ref", &self.manifest_ref)
            .finish_non_exhaustive()
    }
}

/// A live record or transition under a name: its id, the record with its
/// value wiped, and whether this install holds the record itself.
struct Known {
    id: EntityId,
    record: SecretCustodyRecord,
    held_here: bool,
}

impl Drop for Known {
    fn drop(&mut self) {
        self.record.value_bytes.zeroize();
    }
}

fn live_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
    refusal: &'static str,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            refusal,
        )));
    }
    Ok(actor)
}

impl Vault {
    /// The live record or transition `name` names here, not ended by an
    /// admitted revoke: the record this install holds, else the latest
    /// transition it keeps of one, value out.
    fn known_custody_in_txn(&self, txn: &heed::RoTxn<'_>, name: &str) -> Result<Option<Known>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if let Some(id) = resolve_secret_ref_in_txn(&self.store, txn, name)?
            && let Some(mut record) = read_secret_custody_in_txn(&self.store, txn, &id)?
        {
            record.value_bytes.zeroize();
            if record.status != SecretCustodyStatus::Revoked && !fold.custody_revoked(&id) {
                return Ok(Some(Known {
                    id,
                    record,
                    held_here: true,
                }));
            }
        }
        Ok(transition_named_in_txn(self, txn, name)?
            .filter(|(id, _)| !fold.custody_revoked(id))
            .map(|(id, record)| Known {
                id,
                record,
                held_here: false,
            }))
    }

    /// What a surface needs to ask a custody change of the secret `name`
    /// names, value-free: its id, generation and custody revision, its live
    /// requests, and every live linked install with an importable key it may
    /// offer as holder or recipient. An owner's read: the proof is
    /// revalidated as a live vault owner's.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no
    /// longer the live owner's; a vault with no authority genesis; storage
    /// errors.
    pub fn secret_custody_view(
        &self,
        owner: &AuthenticatedOwner,
        name: &str,
    ) -> Result<SecretCustodyView> {
        let txn = self.store.env.read_txn()?;
        live_owner_in_txn(
            self,
            owner,
            &txn,
            "only the vault owner reads a secret's custody",
        )?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("this vault has no authority genesis"))?;
        let this = crate::identity::read_machine_id_in_txn(self, &txn)?;
        let known = self.known_custody_in_txn(&txn, name)?;
        let (secret_id, generation) = match &known {
            Some(known) => (known.id, known.record.rotation_generation),
            None => (
                self.store.clock.entity_id()?,
                register_generation_in_txn(&self.store, &txn, name)?,
            ),
        };
        let live: Vec<OwnerWorkReceipt> = fold
            .custody_heads(secret_id)
            .into_iter()
            .filter_map(|(hash, _)| OwnerWorkReceipt::of(&fold, hash))
            .collect();
        let candidates = fold
            .machines
            .keys()
            .filter_map(|machine| {
                candidate_for(&fold, *machine).map(|(permit, suite, encryption_key)| {
                    CustodyCandidate {
                        permit,
                        suite,
                        encryption_key,
                        this_install: this == Some(*machine),
                    }
                })
            })
            .collect();
        Ok(SecretCustodyView {
            vault_id,
            secret_id,
            name: name.to_owned(),
            known: known.is_some(),
            held_here: known.as_ref().is_some_and(|known| known.held_here),
            portable: known
                .as_ref()
                .is_none_or(|known| custody_portable(&known.record)),
            status: known.as_ref().map(|known| known.record.status),
            generation,
            seen: fold.custody_work_revision(secret_id),
            delivery: if live.is_empty() {
                CustodyDelivery::NotSent
            } else {
                CustodyDelivery::Unknown
            },
            live,
            candidates,
        })
    }

    /// Seals the portable secret `secret_ref` names again, at its generation
    /// and status, to the installs `plan` permits, by the holder it names,
    /// this install by default: a custody rewrap request, executed here in
    /// the same commit when this install is the holder. How a linked
    /// machine that is not his gets the secret: linking alone adds nobody.
    /// `surface` is audit only.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no
    /// longer the live owner's; [`SecretError::SecretRefNotFound`] for a
    /// name nothing live holds here; [`SecretError::SecretCustodyNotActive`]
    /// once an admitted revoke ended it; a record that stays on its device;
    /// no recipient, or one that is no live linked install with an
    /// importable key; a holder that is not one, or this install when it
    /// does not hold the record; this install carrying no owner act; a
    /// refusal of this install as holder; storage errors.
    pub fn rewrap_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        secret_ref: &str,
        plan: &CustodyPlan,
        at: u64,
    ) -> Result<SecretCustodyWork> {
        self.load_install_signing_if_minted()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = live_owner_in_txn(self, owner, &wtxn, "only the vault owner rewraps a secret")?;
        let known = self
            .known_custody_in_txn(&wtxn, secret_ref)?
            .ok_or_else(|| {
                Error::Secret(SecretError::SecretRefNotFound {
                    name: secret_ref.to_owned(),
                })
            })?;
        refuse_revoked_use_in_txn(
            self,
            &wtxn,
            &known.id,
            known.record.class,
            &known.record.name,
        )?;
        if !custody_portable(&known.record) {
            return Err(refused(
                "this secret stays on its device, so no rewrap sends it",
            ));
        }
        if plan.holder.is_none() && !known.held_here {
            return Err(refused(
                "this install does not hold the secret: name the install that holds it",
            ));
        }
        let recorded = self.record_custody_change_in_txn(
            &mut wtxn,
            actor,
            surface,
            ActiveChange {
                change: CustodyChange::Rewrap,
                id: known.id,
                generation: known.record.rotation_generation,
                plan,
                material: Material::Held,
                sealed: None,
                seen: None,
                permits: None,
            },
            at,
        )?;
        if let Some(why) = recorded.custody.kept_here {
            return Err(refused(why.text()));
        }
        wtxn.commit()?;
        self.mirror_custody_change(&recorded.custody);
        Ok(recorded.custody)
    }

    /// Records a register or rotate whose protected input the owner's
    /// surface sealed to the holder itself: this install sees only its
    /// ciphertext and digest. When this install is the holder it opens the
    /// input with its own secret and executes the change in the same commit;
    /// any other holder gets the input relayed. A register whose surface
    /// states the `manifest_ref` its record names gets the manifest this
    /// install resolves for it attached to its input, under the digest the
    /// request names, and its holder checks the record against it (CALLS
    /// CUSTODY_MANIFEST_RECHECK). One that states none gets every secret
    /// manifest the vault publishes attached there; its holder checks the
    /// record against the one it names, and its signed result says what it
    /// checked or why it registered without a manifest check. When the vault
    /// publishes none, or they cannot be read, an explicit mark says so
    /// (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI). An input past one row's bound
    /// travels in numbered parts; none is left out. The same input sent
    /// again is the request already recorded (CALLS CUSTODY_RETRY).
    /// `surface` is audit only.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no
    /// longer the live owner's; [`SecretError::SecretCustodyNotActive`] once
    /// an admitted revoke ended the secret; a change other than a register
    /// or rotate; an empty or oversized input;
    /// [`SecretError::SecretManifestNotFound`], naming it, for a stated
    /// `manifest_ref` this install does not resolve, and a rotate that states
    /// one; a revision that moved since
    /// the surface read it; a permit that no longer stands, or permits out
    /// of order; a holder that is no live linked install with an importable
    /// key; this install carrying no owner act; this install, the holder,
    /// refusing the input; storage errors.
    pub fn seal_custody_change_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        sealed: &SealedCustodyChange<'_>,
        at: u64,
    ) -> Result<SecretCustodyWork> {
        if !matches!(
            sealed.change,
            CustodyChange::Register | CustodyChange::Rotate
        ) {
            return Err(refused(
                "a sealed input carries a register or a rotate; a rewrap and a revoke need none",
            ));
        }
        if sealed.input.is_empty() || sealed.input.len() > MAX_INPUT_BYTES {
            return Err(refused("the sealed input is empty or larger than 4 MiB"));
        }
        // Read before the writer is taken: the manifest comes out of git.
        let (attached, manifest_check) = match (sealed.change, sealed.manifest_ref) {
            (CustodyChange::Register, None) => {
                let (attached, check) = unstated_input(self, sealed.input)?;
                (Some(attached), Some(check))
            }
            (_, None) => (None, None),
            (CustodyChange::Register, Some(manifest_ref)) => {
                let manifest = self.origin_secret_manifest_at(manifest_ref)?;
                let attached =
                    attach_manifest(sealed.input, &manifest.manifest_ref, &manifest.text)?;
                (Some(attached), None)
            }
            (_, Some(_)) => return Err(refused("only a register names a manifest")),
        };
        self.load_install_signing_if_minted()?;
        let this = {
            let rtxn = self.store.env.read_txn()?;
            crate::identity::read_machine_id_in_txn(self, &rtxn)?
        };
        // The holder's own secret opens the input in the request's commit;
        // it is read before the writer opens.
        let secret = if this == Some(sealed.holder) {
            Some(self.machine_secret_outside_txn()?)
        } else {
            None
        };
        let mut wtxn = self.store.env.write_txn()?;
        let actor = live_owner_in_txn(
            self,
            owner,
            &wtxn,
            "only the vault owner changes a secret's custody",
        )?;
        refuse_revoked_use_in_txn(
            self,
            &wtxn,
            &sealed.secret_id,
            CustodyClass::CustodyPortable,
            &sealed.secret_id.to_hex(),
        )?;
        let plan = CustodyPlan {
            holder: Some(sealed.holder),
            recipients: Vec::new(),
        };
        let recorded = self.record_custody_change_in_txn(
            &mut wtxn,
            actor,
            surface,
            ActiveChange {
                change: sealed.change,
                id: sealed.secret_id,
                generation: sealed.generation,
                plan: &plan,
                material: secret.as_ref().map_or(Material::Held, Material::Input),
                sealed: Some(attached.as_deref().unwrap_or(sealed.input)),
                seen: Some(sealed.seen),
                permits: Some(sealed.recipients),
            },
            at,
        )?;
        if let Some(why) = recorded.custody.kept_here {
            return Err(refused(why.text()));
        }
        wtxn.commit()?;
        self.mirror_custody_change(&recorded.custody);
        // What this install checked as the holder, else what it attached.
        let mut custody = recorded.custody;
        if custody.manifest.is_none() {
            custody.manifest = manifest_check;
        }
        Ok(custody)
    }
}
