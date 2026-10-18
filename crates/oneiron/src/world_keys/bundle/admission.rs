//! A late joiner's access to kept pad objects (FIX 4271). A pad object's outer
//! key is sealed to the machines that read the vault when its generation was
//! sealed, so a machine admitted since holds no capsule of it, and erase's
//! sweep would hold every requested erase back. An old reader of the object,
//! or the owner's kit, grants it the object's outer key instead.
//!
//! - A grant carries one 32-byte outer key, never a pad. It is a sealed object
//!   of its own (purpose `SealedPadAdmission`, magic `OSPG`, 4 KiB steps): the
//!   key and its binding under a fresh key, in capsules to the recipient and,
//!   where its record is here, to the generation's own kit root
//!   ([`SEALED_PAD_GRANT_RECIPIENTS`]). A pad object's own capsules are
//!   another purpose, and never open as a grant.
//! - Its binding ([`SEALED_PAD_GRANT_BINDING`]) is the vault, the generation,
//!   the pad object, the recipient machine and the digest of its encryption
//!   key; never the pad object's digest, which erase's rewrite changes while it
//!   keeps the outer key, the generation and the capsules. A grant outlives
//!   every rewrite.
//! - The binding and the issuer ride in the clear under the issuer's
//!   signature: a machine of the owner's (its install key) or the kit (its
//!   root's anchor). The home checks both before it keeps an offer, and the
//!   recipient checks them again under its own authority, then uses the key
//!   only once it opens the CURRENT pad object: anyone can seal 32 bytes to a
//!   public key.
//! - An issuer opens the current pad object itself (its capsule, a grant it
//!   holds, or the kit) and checks the recipient under its own authority: a
//!   machine the owner admitted, live here, under the key the grant names. A
//!   removed or re-keyed machine gets nothing. No check here asks where a
//!   machine runs or what class it is.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oneiron_crypto::{HybridPublicKey, HybridSecretKey, Purpose};
use zeroize::Zeroizing;

use super::{
    Cursor, EraseKey, GENERATION_LEN, Kind, OpenedKeyPads, PADS, SEALED_BUNDLE_ERASE_KEY_SOURCE,
    SealedBundleGeneration, SealedKeyPads, open_outer, parse_frame, put_counted, seal_outer,
    seal_slots,
};
use crate::Vault;
use crate::authority::{AuthorityFold, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::world_keys::{
    MachineSecret, RecoveryRootId, RecoveryRootSeed, WrapRecipient, base_world, os_fill,
    recipients, refused,
};

/// A grant's size step.
const SEALED_PAD_GRANT_STEP_BYTES: usize = 4 * 1024;

const GRANT_LABEL: &[u8] = b"oneiron/sealed-pad-admission/v1\0";
const GRANT_KEY_LABEL: &[u8] = b"oneiron/sealed-pad-admission-key/v1\0";
const GRANT_SIGNATURE_CONTEXT: &str = "oneiron/sealed-pad-admission-signature/v1";
const RECIPIENT_KEY_CONTEXT: &str = "oneiron/sealed-pad-admission-recipient-key/v1";

const ADMISSION: Kind = Kind {
    magic: b"OSPG",
    purpose: Purpose::SealedPadAdmission,
    step: SEALED_PAD_GRANT_STEP_BYTES,
};

/// What a grant is bound to (SEALED_PAD_GRANT_BINDING).
enum GrantBinding {
    /// The vault, the generation, its pad object, the recipient machine and
    /// the digest of its encryption key. Not the pad object's digest: a
    /// rewrite changes it and keeps the outer key.
    VaultGenerationPadsAndRecipientKey,
}

const SEALED_PAD_GRANT_BINDING: GrantBinding = GrantBinding::VaultGenerationPadsAndRecipientKey;

/// Whom a grant is sealed to (CALLS: SEALED_PAD_GRANT_RECIPIENTS).
enum GrantRecipients {
    /// The recipient machine, and the generation's own kit root when the
    /// issuer holds that root's record: never another root.
    TargetPlusOriginalKitWhenAvailable,
}

const SEALED_PAD_GRANT_RECIPIENTS: GrantRecipients =
    GrantRecipients::TargetPlusOriginalKitWhenAvailable;

/// A machine a kept pad object's outer key is granted to: its id and the
/// digest of the encryption key its owner-admitted profile names. A machine
/// that changes its key is another target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PadAdmissionTarget {
    pub machine: EntityId,
    pub encryption_key_digest: [u8; 32],
}

impl PadAdmissionTarget {
    /// `machine` under `key`, the encryption key its profile names.
    #[must_use]
    pub fn of(machine: EntityId, key: &MachineEncryptionKey) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(RECIPIENT_KEY_CONTEXT);
        hasher.update(&key.suite.to_be_bytes());
        hasher.update(&key.key);
        Self {
            machine,
            encryption_key_digest: *hasher.finalize().as_bytes(),
        }
    }

    /// `machine` as `fold` stands it: a machine the owner admitted, live and
    /// trusted under this install's pin, under the key its trusted identity
    /// names. `None` for any other machine.
    pub(crate) fn admitted(fold: &AuthorityFold, machine: EntityId) -> Option<Self> {
        let trusted = fold.trusted_machine(machine)?;
        Some(Self::of(machine, &trusted.profile.encryption_key))
    }

    /// This install's own machine, under the key its secret expands to.
    fn of_secret(secret: &MachineSecret) -> Self {
        Self::of(
            secret.machine,
            &MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: secret.secret.public_key().to_bytes(),
            },
        )
    }
}

/// Who issued a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Issuer {
    /// A machine of the owner's, by its install key.
    Machine(EntityId),
    /// The owner's kit: one of the vault's roots, by its anchor key.
    Kit {
        root: RecoveryRootId,
        anchor_key: [u8; 32],
    },
}

/// One kept pad object's outer key, sealed to a machine admitted after its
/// generation was sealed (FIX 4271), signed by its issuer.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPadAdmissionGrant {
    vault_id: [u8; 32],
    generation: SealedBundleGeneration,
    recipient: PadAdmissionTarget,
    /// The generation's kit root, also sealed to, when the issuer held its
    /// record.
    kit_root: Option<RecoveryRootId>,
    issuer: Issuer,
    /// The sealed object: the binding and the outer key.
    object: Vec<u8>,
    signature: [u8; 64],
}

impl std::fmt::Debug for SealedPadAdmissionGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedPadAdmissionGrant")
            .field("generation", &self.generation)
            .field("recipient", &self.recipient)
            .field("issuer", &self.issuer)
            .field("len", &self.object.len())
            .finish_non_exhaustive()
    }
}

impl SealedPadAdmissionGrant {
    /// The generation whose pad object the grant opens.
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The machine the grant is sealed to.
    #[must_use]
    pub fn recipient(&self) -> PadAdmissionTarget {
        self.recipient
    }

    /// The kit root the grant is also sealed to.
    pub(crate) fn kit_root(&self) -> Option<RecoveryRootId> {
        self.kit_root
    }

    /// Strict parse: the binding, the issuer, one sealed object of the
    /// grant's own kind and generation, and the signature, nothing after.
    /// Whether it is authorized is [`Self::issued_by_authority`]'s question.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || refused("malformed pad admission grant");
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(GRANT_LABEL.len()) != Some(GRANT_LABEL) {
            return Err(malformed());
        }
        let vault_id: [u8; 32] = cursor.array().ok_or_else(malformed)?;
        let generation =
            SealedBundleGeneration::from_bytes(cursor.take(GENERATION_LEN).ok_or_else(malformed)?)?;
        if cursor.take(PADS.magic.len()) != Some(&PADS.magic[..]) {
            return Err(malformed());
        }
        let machine =
            EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let recipient = PadAdmissionTarget {
            machine,
            encryption_key_digest: cursor.array().ok_or_else(malformed)?,
        };
        let kit_root = match cursor.take(1) {
            Some([0]) => None,
            Some([1]) => Some(RecoveryRootId(cursor.array().ok_or_else(malformed)?)),
            _ => return Err(malformed()),
        };
        let issuer = match cursor.take(1) {
            Some([0]) => Issuer::Machine(
                EntityId::from_bytes(cursor.array().ok_or_else(malformed)?)
                    .map_err(|_| malformed())?,
            ),
            Some([1]) => Issuer::Kit {
                root: RecoveryRootId(cursor.array().ok_or_else(malformed)?),
                anchor_key: cursor.array().ok_or_else(malformed)?,
            },
            _ => return Err(malformed()),
        };
        let object = cursor.counted().ok_or_else(malformed)?.to_vec();
        if parse_frame(ADMISSION, &object)?.generation != generation {
            return Err(malformed());
        }
        let signature: [u8; 64] = cursor.array().ok_or_else(malformed)?;
        if cursor.at != bytes.len() {
            return Err(malformed());
        }
        Ok(Self {
            vault_id,
            generation,
            recipient,
            kit_root,
            issuer,
            object,
            signature,
        })
    }

    /// The signed header ([`Self::from_bytes`]), then the signature.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.header()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Whether `fold` holds the grant's issuer as one that may grant this
    /// vault's pad objects, and the issuer signed it: a machine the owner
    /// admitted, live and trusted here, by the install key its trusted
    /// identity names, or one of the vault's roots, by its anchor.
    pub(crate) fn issued_by_authority(&self, fold: &AuthorityFold) -> bool {
        let Ok(header) = self.header() else {
            return false;
        };
        let digest = signed_digest(&header);
        let signature = Signature::from_bytes(&self.signature);
        let signed_by = |key: &[u8; 32]| {
            VerifyingKey::from_bytes(key)
                .is_ok_and(|key| key.verify_strict(&digest, &signature).is_ok())
        };
        fold.vault_id == Some(self.vault_id)
            && match self.issuer {
                Issuer::Machine(machine) => fold
                    .trusted_machine(machine)
                    .is_some_and(|trusted| signed_by(&trusted.profile.machine_key)),
                Issuer::Kit { root, anchor_key } => {
                    fold.root_anchors()
                        .get(&anchor_key)
                        .is_some_and(|roots| roots.contains(&root))
                        && signed_by(&anchor_key)
                }
            }
    }

    /// The outer key, with `secret`, the recipient's: its capsule opens and
    /// the sealed binding is the header's. Whether the key opens the pad
    /// object is the caller's check.
    fn open_key(&self, secret: &HybridSecretKey) -> Result<Zeroizing<[u8; 32]>> {
        let malformed = || refused("the pad admission grant is malformed");
        let opened = open_outer(ADMISSION, &self.vault_id, &self.object, secret)?;
        let binding = self.binding();
        let mut cursor = Cursor {
            bytes: &opened.body[..],
            at: 0,
        };
        if cursor.take(GRANT_KEY_LABEL.len()) != Some(GRANT_KEY_LABEL)
            || cursor.take(binding.len()) != Some(&binding[..])
        {
            return Err(refused("the grant's key is bound to another pad object"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(cursor.take(32).ok_or_else(malformed)?);
        if !cursor.rest_is_zero() {
            return Err(malformed());
        }
        Ok(key)
    }

    fn binding(&self) -> Vec<u8> {
        binding(
            &self.vault_id,
            self.generation,
            &self.recipient,
            self.kit_root,
        )
    }

    /// The binding ‖ the issuer (a tag, then a machine id, or a root id and
    /// its anchor key) ‖ the sealed object `u32`-length-prefixed.
    fn header(&self) -> Result<Vec<u8>> {
        let mut out = self.binding();
        match self.issuer {
            Issuer::Machine(machine) => {
                out.push(0);
                out.extend_from_slice(machine.as_bytes());
            }
            Issuer::Kit { root, anchor_key } => {
                out.push(1);
                out.extend_from_slice(&root.0);
                out.extend_from_slice(&anchor_key);
            }
        }
        put_counted(&mut out, &self.object)?;
        Ok(out)
    }
}

/// label ‖ vault (32) ‖ generation (24) ‖ the pad object's magic (4) ‖
/// machine (16) ‖ its key digest (32) ‖ 0, or 1 ‖ the kit root (32).
fn binding(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    recipient: &PadAdmissionTarget,
    kit_root: Option<RecoveryRootId>,
) -> Vec<u8> {
    match SEALED_PAD_GRANT_BINDING {
        GrantBinding::VaultGenerationPadsAndRecipientKey => {}
    }
    let mut out = Vec::with_capacity(GRANT_LABEL.len() + 32 + GENERATION_LEN + 4 + 16 + 32 + 33);
    out.extend_from_slice(GRANT_LABEL);
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&generation.to_bytes());
    out.extend_from_slice(PADS.magic);
    out.extend_from_slice(recipient.machine.as_bytes());
    out.extend_from_slice(&recipient.encryption_key_digest);
    match kit_root {
        None => out.push(0),
        Some(root) => {
            out.push(1);
            out.extend_from_slice(&root.0);
        }
    }
    out
}

fn signed_digest(header: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GRANT_SIGNATURE_CONTEXT);
    hasher.update(header);
    *hasher.finalize().as_bytes()
}

/// `pads`' outer key and its binding under a fresh key, in capsules to
/// `readers`, signed by `signing` as `issuer`.
fn seal_grant(
    pads: &OpenedKeyPads,
    recipient: PadAdmissionTarget,
    readers: &GrantReaders,
    issuer: Issuer,
    signing: &SigningKey,
) -> Result<SealedPadAdmissionGrant> {
    let binding = binding(
        &pads.vault_id,
        pads.generation,
        &recipient,
        readers.kit_root,
    );
    let mut body = Zeroizing::new(Vec::with_capacity(
        GRANT_KEY_LABEL.len() + binding.len() + 32,
    ));
    body.extend_from_slice(GRANT_KEY_LABEL);
    body.extend_from_slice(&binding);
    body.extend_from_slice(&pads.outer[..]);
    let mut fresh = Zeroizing::new([0u8; 32]);
    os_fill(&mut fresh[..])?;
    let slots = seal_slots(
        ADMISSION,
        &pads.vault_id,
        pads.generation,
        &fresh,
        &readers.keys,
    )?;
    let object = seal_outer(
        ADMISSION,
        &pads.vault_id,
        pads.generation,
        &fresh,
        &slots,
        body,
        None,
    )?;
    let mut grant = SealedPadAdmissionGrant {
        vault_id: pads.vault_id,
        generation: pads.generation,
        recipient,
        kit_root: readers.kit_root,
        issuer,
        object,
        signature: [0u8; 64],
    };
    grant.signature = signing.sign(&signed_digest(&grant.header()?)).to_bytes();
    Ok(grant)
}

/// The keys a grant is sealed to, and the kit root among them.
struct GrantReaders {
    keys: Vec<HybridPublicKey>,
    kit_root: Option<RecoveryRootId>,
}

/// The keys erase opens kept pad objects with ([`SEALED_BUNDLE_ERASE_KEY_SOURCE`]).
pub(super) struct EraseKeys {
    vault_id: [u8; 32],
    machine: Option<HybridSecretKey>,
    /// Each checked grant's outer key, by generation.
    granted: Vec<(SealedBundleGeneration, Zeroizing<[u8; 32]>)>,
    kit: Option<HybridSecretKey>,
}

impl EraseKeys {
    /// `pads` opened with the first key, in [`SEALED_BUNDLE_ERASE_KEY_SOURCE`]
    /// order, that opens it.
    pub(super) fn open(&self, pads: &SealedKeyPads) -> Result<OpenedKeyPads> {
        for source in SEALED_BUNDLE_ERASE_KEY_SOURCE {
            let opened = match source {
                EraseKey::Machine => self
                    .machine
                    .as_ref()
                    .and_then(|secret| pads.open_with(&self.vault_id, secret).ok()),
                EraseKey::AdmissionGrant => self
                    .granted
                    .iter()
                    .filter(|(generation, _)| *generation == pads.generation())
                    .find_map(|(_, outer)| pads.open_with_outer(&self.vault_id, outer).ok()),
                EraseKey::Kit => self
                    .kit
                    .as_ref()
                    .and_then(|secret| pads.open_with(&self.vault_id, secret).ok()),
            };
            if let Some(opened) = opened {
                return Ok(opened);
            }
        }
        Err(refused(
            "a kept pad object opens neither here, with a grant, nor with the kit",
        ))
    }
}

impl Vault {
    /// Every key erase may open kept pad objects with here: this machine's
    /// capsule key, the outer key of each of `grants` that is addressed to
    /// this machine under its current key and issued by authority here, and
    /// `kit`, the owner's kit for this call alone.
    pub(super) fn erase_keys(
        &self,
        kit: Option<&RecoveryRootSeed>,
        grants: &[SealedPadAdmissionGrant],
    ) -> Result<EraseKeys> {
        let vault_id = self.bundle_vault_id()?;
        // A kit restore runs before this install has a machine of its own.
        let machine = self.machine_secret_outside_txn().ok();
        let granted = match &machine {
            Some(machine) if !grants.is_empty() => self.granted_keys(machine, grants)?,
            _ => Vec::new(),
        };
        Ok(EraseKeys {
            vault_id,
            machine: machine.map(|machine| machine.secret),
            granted,
            kit: kit.map(RecoveryRootSeed::recovery_secret).transpose()?,
        })
    }

    /// The outer key of each of `grants` addressed to `machine` under its
    /// current key, issued by authority here, whose capsule opens with it.
    fn granted_keys(
        &self,
        machine: &MachineSecret,
        grants: &[SealedPadAdmissionGrant],
    ) -> Result<Vec<(SealedBundleGeneration, Zeroizing<[u8; 32]>)>> {
        let me = PadAdmissionTarget::of_secret(machine);
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(grants
            .iter()
            .filter(|grant| grant.recipient == me && grant.issued_by_authority(&fold))
            .filter_map(|grant| Some((grant.generation, grant.open_key(&machine.secret).ok()?)))
            .collect())
    }

    /// This machine as a grant's recipient, under its current key.
    pub(crate) fn pad_admission_self_target(&self) -> Result<PadAdmissionTarget> {
        Ok(PadAdmissionTarget::of_secret(
            &self.machine_secret_outside_txn()?,
        ))
    }

    /// Opens `pads`, a kept generation's current pad object, with `grant`
    /// alone: it must be addressed to this machine under its current key,
    /// issued by authority here, and its key must open the object.
    pub(crate) fn open_key_pads_with_grant(
        &self,
        pads: &SealedKeyPads,
        grant: &SealedPadAdmissionGrant,
    ) -> Result<OpenedKeyPads> {
        let machine = self.machine_secret_outside_txn()?;
        let vault_id = self.bundle_vault_id()?;
        self.granted_keys(&machine, std::slice::from_ref(grant))?
            .iter()
            .filter(|(generation, _)| *generation == pads.generation())
            .find_map(|(_, outer)| pads.open_with_outer(&vault_id, outer).ok())
            .ok_or_else(|| refused("the grant does not open the pad object"))
    }

    /// An old reader's grant: the outer key of `pads`, a kept generation's
    /// CURRENT pad object this machine opened itself, sealed to `target` and,
    /// where its record is here, to `kit_root`, the root the generation's
    /// publisher named ([`SEALED_PAD_GRANT_RECIPIENTS`]), signed with this
    /// machine's install key. Refused unless this machine and `target` both
    /// stand as the owner's in this machine's own authority, `target` under
    /// the key it names.
    pub(crate) fn seal_pad_admission_grant(
        &self,
        pads: &OpenedKeyPads,
        target: PadAdmissionTarget,
        kit_root: Option<RecoveryRootId>,
    ) -> Result<SealedPadAdmissionGrant> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let signing = self.door_signing_key_in_txn(&txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let mine = fold.trusted_machine(secret.machine).is_some_and(|trusted| {
            trusted.profile.machine_key == signing.verifying_key().to_bytes()
        });
        if fold.vault_id != Some(pads.vault_id) {
            return Err(refused("the key pads were opened for another vault"));
        }
        // The owner's recipient choice: only a machine he marked "yours"
        // grants the pads it opened, never a rule on who decides.
        if !mine {
            return Err(refused(
                "the owner-selected world read policy excludes this destination; use an allowed \
                 holder",
            ));
        }
        let readers = self.grant_readers_in_txn(&txn, &fold, target, kit_root)?;
        seal_grant(
            pads,
            target,
            &readers,
            Issuer::Machine(secret.machine),
            &signing,
        )
    }

    /// The kit's grant: `pads`, a kept generation's current pad object,
    /// opened with `seed`, the owner's kit for this call alone, its outer key
    /// sealed to `target` and to the kit's root, signed with that root's
    /// anchor. `owner` is revalidated, the kit's root must be one of the
    /// vault's, and `target` must stand as the owner's here under the key it
    /// names. Nothing is pinned, anchored or restored. A pad object the kit
    /// does not open is the typed `SecretError::SealedBundleNoCapsule`.
    pub(crate) fn seal_pad_admission_grant_with_kit(
        &self,
        owner: &AuthenticatedOwner,
        pads: &SealedKeyPads,
        seed: &RecoveryRootSeed,
        target: PadAdmissionTarget,
    ) -> Result<SealedPadAdmissionGrant> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let root = seed.public(&vault_id)?;
        if !fold
            .root_anchors()
            .get(&root.anchor_key)
            .is_some_and(|roots| roots.contains(&root.id))
        {
            return Err(refused("the kit's root is not one of the vault's"));
        }
        let readers = self.grant_readers_in_txn(&txn, &fold, target, Some(root.id))?;
        let opened = pads.open_with_kit(&vault_id, seed)?;
        seal_grant(
            &opened,
            target,
            &readers,
            Issuer::Kit {
                root: root.id,
                anchor_key: root.anchor_key,
            },
            &seed.anchor(),
        )
    }

    /// `target`'s key, when it stands as a machine of the owner's in `fold`
    /// under the key it names and reads the vault as a new pad object's
    /// reader would, and `kit_root`'s when its record is here
    /// ([`SEALED_PAD_GRANT_RECIPIENTS`]).
    fn grant_readers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        target: PadAdmissionTarget,
        kit_root: Option<RecoveryRootId>,
    ) -> Result<GrantReaders> {
        let refused_target = || refused("the target is not a machine of the owner's here");
        if PadAdmissionTarget::admitted(fold, target.machine) != Some(target) {
            return Err(refused_target());
        }
        let public = recipients(fold, base_world(), None)
            .into_iter()
            .find(|(recipient, _)| *recipient == WrapRecipient::Machine(target.machine))
            .map(|(_, public)| public)
            .ok_or_else(refused_target)?;
        let mut readers = GrantReaders {
            keys: vec![public],
            kit_root: None,
        };
        match SEALED_PAD_GRANT_RECIPIENTS {
            GrantRecipients::TargetPlusOriginalKitWhenAvailable => {
                if let Some(root) = kit_root
                    && let Some(record) = self.root_recipient_in_txn(txn, fold, root)?
                {
                    readers.keys.push(record.key);
                    readers.kit_root = Some(root);
                }
            }
        }
        Ok(readers)
    }
}
