//! Publication-scoped outer access for the install the owner asked to
//! publish (FIX 4785). A generation's outer capsules go to the machines mine
//! here and the pinned root, so an asked executor that is not mine here holds
//! no capsule of the home's newest generation: it could neither carry it nor
//! publish on top of it, and stayed pending.
//!
//! - A publisher mine here that seals a generation for a holder grants each
//!   of its two objects' outer keys to the executor of every counted bundle
//!   publication request to that holder that has no result yet, where that
//!   executor is not mine here ([`publication_grantees`]): sealed to the
//!   encryption key it proves itself by here, bound to the vault, the
//!   generation, the object and the request. The grant rides the generation
//!   it opens, as one more anonymous capsule as long as a reader's and padded
//!   with them, so no holder tells it from one. The request itself is an
//!   authority entry and carries no key.
//! - The executor opens a grant only to publish for that request, and only
//!   when no capsule of its own opens the object
//!   ([`Vault::open_latest_for_publication`]). The object's AEAD proves the
//!   key; the bundle's publisher check stands as for a capsule.
//! - A grant opens that one generation for that one request. It carries no
//!   world key (a section still opens only with a counted wrap to the
//!   executor) and no later generation: a later one carries a grant only
//!   while a request is still pending for it.

#[cfg(feature = "sync")]
use super::super::CapsuleRead;
use super::*;
use crate::authority::OwnerWorkBody;

/// The label a publication grant's capsule opens with, as long as a reader
/// capsule's.
const PUBLICATION_GRANT_LABEL: &[u8] = b"oneiron/publication-grant/v1\0";
const PUBLICATION_GRANT_CONTEXT: &str = "oneiron/publication-grant-binding/v1";

// A grant's capsule is exactly as long as a reader's: label, binding in the
// generation's place, key.
const _: () = assert!(PUBLICATION_GRANT_LABEL.len() == SLOT_LABEL.len());

/// One executor a publisher grants a generation's outer keys to (FIX 4785):
/// the request it publishes for, and the key it proves itself by here.
pub(super) struct PublicationGrantee {
    request: AuthorityEntryHash,
    executor: EntityId,
    key: HybridPublicKey,
}

/// The executor of each counted bundle publication request to `holder`
/// with no result yet that is not mine here, under the key it proves itself
/// by ([`executor_key`]). A machine mine here reads the generation through
/// its own capsule, or is kept out of it by the owner's read choice.
pub(super) fn publication_grantees(
    fold: &AuthorityFold,
    holder: Destination,
) -> Vec<PublicationGrantee> {
    let mut out = Vec::new();
    for &executor in fold.machines.keys() {
        if fold.trusted_machine(executor).is_some() {
            continue;
        }
        let Some(key) = executor_key(fold, executor) else {
            continue;
        };
        out.extend(
            fold.pending_owner_work_for(executor)
                .filter(|(_, request)| {
                    matches!(request.work, OwnerWorkBody::PublishBundle { home }
                        if Destination::Machine(home) == holder)
                })
                .map(|(request, _)| PublicationGrantee {
                    request,
                    executor,
                    key: key.clone(),
                }),
        );
    }
    out
}

/// The encryption key of the identity `machine` proves itself by here, as
/// [`AuthorityFold::machine_proof_key`] picks it for a machine not mine: its
/// live roster revision's, once the owner answered its role. `None` when it
/// proves none here, or the key does not import.
fn executor_key(fold: &AuthorityFold, machine: EntityId) -> Option<HybridPublicKey> {
    let roster = fold
        .machine(machine)?
        .roster
        .as_ref()
        .filter(|roster| roster.is_live() && roster.profile.role.answered())?;
    HybridPublicKey::from_bytes(&roster.profile.encryption_key.key).ok()
}

/// `BLAKE3-derive_key(context, vault ‖ generation ‖ object magic ‖ request ‖
/// executor)`, cut to the generation's length in a reader capsule.
fn grant_binding(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    request: &AuthorityEntryHash,
    executor: EntityId,
) -> [u8; GENERATION_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(PUBLICATION_GRANT_CONTEXT);
    hasher.update(vault_id);
    hasher.update(&generation.to_bytes());
    hasher.update(kind.magic);
    hasher.update(request);
    hasher.update(executor.as_bytes());
    let mut out = [0u8; GENERATION_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// The object's capsules ([`seal_slots`]), with a grant to each of
/// `grantees` in a blank's place, and a step of blanks more where they run
/// out: still a whole multiple of [`SLOT_STEP`].
pub(super) fn seal_slots_granting(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    readers: &[HybridPublicKey],
    grantees: &[PublicationGrantee],
) -> Result<Vec<Envelope>> {
    let mut slots = seal_slots(kind, vault_id, generation, outer, readers)?;
    while slots.len() < readers.len() + grantees.len() {
        slots.extend(seal_slots(kind, vault_id, generation, outer, &[])?);
    }
    slots.truncate(slots.len() - grantees.len());
    let id = generation.to_bytes();
    let params = seal_params(kind.purpose, vault_id, &id, SLOT_RECIPIENT);
    for grantee in grantees {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(SLOT_PLAINTEXT_LEN));
        plaintext.extend_from_slice(PUBLICATION_GRANT_LABEL);
        plaintext.extend_from_slice(&grant_binding(
            kind,
            vault_id,
            generation,
            &grantee.request,
            grantee.executor,
        ));
        plaintext.extend_from_slice(outer);
        let sealed = seal(
            &params,
            SealKey::Hybrid {
                recipient: &grantee.key,
                kem_suite: KEM,
            },
            &plaintext,
            &mut SysRng,
        )
        .map_err(|_| refused("sealing failed"))?;
        slots.push(sealed);
    }
    Ok(slots)
}

/// The outer key from the publication grant for `request` among `frame`'s
/// capsules that opens with `secret`, this machine's: the typed
/// `SecretError::SealedBundleNoCapsule` when none does.
#[cfg(feature = "sync")]
fn open_grant(
    kind: Kind,
    vault_id: &[u8; 32],
    frame: &Frame,
    secret: &MachineSecret,
    request: &AuthorityEntryHash,
) -> Result<Zeroizing<[u8; 32]>> {
    let id = frame.generation.to_bytes();
    let policy = OpenPolicy {
        purpose: kind.purpose,
        vault_id,
        recipient: SLOT_RECIPIENT,
        key_id: &id,
        wraps: HYBRID,
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let binding = grant_binding(kind, vault_id, frame.generation, request, secret.machine);
    let label = PUBLICATION_GRANT_LABEL.len();
    for slot in &frame.slots {
        let Ok(plaintext) = slot.open(OpenKey::Hybrid(&secret.secret), &policy) else {
            continue;
        };
        if plaintext.len() == SLOT_PLAINTEXT_LEN
            && plaintext.starts_with(PUBLICATION_GRANT_LABEL)
            && plaintext[label..label + GENERATION_LEN] == binding
        {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&plaintext[label + GENERATION_LEN..]);
            return Ok(key);
        }
    }
    Err(Error::Secret(SecretError::SealedBundleNoCapsule))
}

/// The outer layer of `bytes`, an object of `kind`, opened with the
/// publication grant for `request` it carries to `secret`'s machine.
#[cfg(feature = "sync")]
fn open_granted(
    kind: Kind,
    vault_id: &[u8; 32],
    bytes: &[u8],
    secret: &MachineSecret,
    request: &AuthorityEntryHash,
) -> Result<OpenedOuter> {
    let frame = parse_frame(kind, bytes)?;
    let outer = open_grant(kind, vault_id, &frame, secret, request)?;
    open_framed(kind, vault_id, frame, outer)
}

#[cfg(feature = "sync")]
fn no_capsule(error: &Error) -> bool {
    matches!(error, Error::Secret(SecretError::SealedBundleNoCapsule))
}

/// How this machine opened an object of a generation it publishes on top of
/// (FIX 4785).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OuterAccess {
    /// A capsule sealed to this machine.
    Capsule,
    /// The publication grant the object carries for the request this
    /// machine publishes for.
    PublicationGrant,
}

#[cfg(feature = "sync")]
impl CapsuleRead {
    /// How an object opened to publish on top of went: where no capsule of
    /// this machine's opens it, a publication grant that does is
    /// [`Self::PublicationGrant`].
    pub(super) fn of_publication<T>(opened: &Result<(T, OuterAccess)>) -> Self {
        match opened {
            Ok((_, OuterAccess::PublicationGrant)) => Self::PublicationGrant,
            _ => Self::of(opened),
        }
    }
}

#[cfg(feature = "sync")]
impl Vault {
    /// The home's newest generation, `bundle` and `pads` read from `holder`,
    /// opened to publish on top of: each object with this machine's capsule,
    /// else, publishing for `request`, with the publication grant the object
    /// carries for it to this machine (FIX 4785). The bundle's publisher is
    /// checked as [`Self::open_vault_bundle`] checks it. An object that opens
    /// neither way is the typed `SecretError::SealedBundleNoCapsule`, as with
    /// no request.
    pub(crate) fn open_latest_for_publication(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        holder: Destination,
        request: Option<AuthorityEntryHash>,
    ) -> Result<(OpenedVaultBundle, OpenedKeyPads)> {
        let (opened, _) = self.open_bundle_to_publish(bundle, holder, request)?;
        let (pads, _) = self.open_pads_to_publish(pads, request)?;
        if pads.generation() != opened.generation() {
            return Err(refused("the pad object is another generation's"));
        }
        Ok((opened, pads))
    }

    /// `bundle`, read from `holder`, opened with this machine's capsule
    /// ([`Self::open_vault_bundle`]), else, when none opens it, with the
    /// publication grant for `request` it carries, its publisher checked the
    /// same way.
    pub(super) fn open_bundle_to_publish(
        &self,
        bundle: &SealedVaultBundle,
        holder: Destination,
        request: Option<AuthorityEntryHash>,
    ) -> Result<(OpenedVaultBundle, OuterAccess)> {
        match (self.open_vault_bundle(bundle, holder), request) {
            (Err(error), Some(request)) if no_capsule(&error) => {
                let secret = self.machine_secret_outside_txn()?;
                let vault_id = self.bundle_vault_id()?;
                let outer = open_granted(BUNDLE, &vault_id, &bundle.0.bytes, &secret, &request)?;
                let opened = decode_bundle_body(&vault_id, outer.generation, &outer.body)?;
                let txn = self.store.env.read_txn()?;
                let fold = self.authority_view_readonly_in_txn(&txn)?;
                opened.require_publisher(&fold, Some(holder))?;
                Ok((opened, OuterAccess::PublicationGrant))
            }
            (opened, _) => Ok((opened?, OuterAccess::Capsule)),
        }
    }

    /// `pads` opened with this machine's capsule, else, when none opens it,
    /// with the publication grant for `request` it carries.
    pub(super) fn open_pads_to_publish(
        &self,
        pads: &SealedKeyPads,
        request: Option<AuthorityEntryHash>,
    ) -> Result<(OpenedKeyPads, OuterAccess)> {
        match (self.open_key_pads(pads), request) {
            (Err(error), Some(request)) if no_capsule(&error) => {
                let secret = self.machine_secret_outside_txn()?;
                let vault_id = self.bundle_vault_id()?;
                let outer = open_granted(PADS, &vault_id, &pads.0.bytes, &secret, &request)?;
                let opened = pads.opened(&vault_id, outer)?;
                Ok((opened, OuterAccess::PublicationGrant))
            }
            (opened, _) => Ok((opened?, OuterAccess::Capsule)),
        }
    }
}
