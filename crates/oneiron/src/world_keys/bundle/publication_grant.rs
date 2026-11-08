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
//! - An asked executor not mine here that seals a new generation grants
//!   itself its two fresh outer keys for that exact pending request. It can
//!   then recognize its own committed generation after a lost reply.
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

/// The exact native publication grantees, for the home's issuer pickup.
#[cfg(feature = "sync")]
pub(crate) fn publication_grant_requests(
    fold: &AuthorityFold,
    holder: Destination,
) -> Vec<(AuthorityEntryHash, EntityId)> {
    publication_grantees(fold, holder)
        .into_iter()
        .map(|grantee| (grantee.request, grantee.executor))
        .collect()
}

/// The creator's own pending publication request, using the same recipient
/// and key selection as a publisher mine here. No other request is granted.
pub(super) fn own_publication_grantee(
    fold: &AuthorityFold,
    holder: Destination,
    request: AuthorityEntryHash,
    executor: EntityId,
) -> Option<PublicationGrantee> {
    publication_grantees(fold, holder)
        .into_iter()
        .find(|grantee| grantee.request == request && grantee.executor == executor)
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
    for grantee in grantees {
        slots.push(seal_grant_envelope(
            kind, vault_id, generation, outer, grantee,
        )?);
    }
    Ok(slots)
}

/// One request-bound outer capsule, also used beside an existing generation.
fn seal_grant_envelope(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    grantee: &PublicationGrantee,
) -> Result<Envelope> {
    let id = generation.to_bytes();
    let params = seal_params(kind.purpose, vault_id, &id, SLOT_RECIPIENT);
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
    seal(
        &params,
        SealKey::Hybrid {
            recipient: &grantee.key,
            kem_suite: KEM,
        },
        &plaintext,
        &mut SysRng,
    )
    .map_err(|_| refused("sealing failed"))
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
    for slot in &frame.slots {
        if let Ok(outer) =
            open_grant_envelope(kind, vault_id, frame.generation, secret, request, slot)
        {
            return Ok(outer);
        }
    }
    Err(Error::Secret(SecretError::SealedBundleNoCapsule))
}

/// The same policy and binding for an in-object or supplied grant capsule.
#[cfg(feature = "sync")]
fn open_grant_envelope(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    secret: &MachineSecret,
    request: &AuthorityEntryHash,
    slot: &Envelope,
) -> Result<Zeroizing<[u8; 32]>> {
    let id = generation.to_bytes();
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
    let binding = grant_binding(kind, vault_id, generation, request, secret.machine);
    let label = PUBLICATION_GRANT_LABEL.len();
    if let Ok(plaintext) = slot.open(OpenKey::Hybrid(&secret.secret), &policy)
        && plaintext.len() == SLOT_PLAINTEXT_LEN
        && plaintext.starts_with(PUBLICATION_GRANT_LABEL)
        && plaintext[label..label + GENERATION_LEN] == binding
    {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plaintext[label + GENERATION_LEN..]);
        return Ok(key);
    }
    Err(Error::Secret(SecretError::SealedBundleNoCapsule))
}

#[cfg(feature = "sync")]
fn open_supplied_grant(
    kind: Kind,
    bytes: &[u8],
    secret: &MachineSecret,
    request: &AuthorityEntryHash,
    grant: &SealedPublicationGrant,
    fold: &AuthorityFold,
    holder: Destination,
) -> Result<OpenedOuter> {
    let vault_id = fold
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
    let frame = parse_frame(kind, bytes)?;
    if !grant.admitted_for(fold, holder)
        || grant.generation != frame.generation
        || grant.request != *request
        || grant.executor != secret.machine
    {
        return Err(Error::Secret(SecretError::SealedBundleNoCapsule));
    }
    let envelope = if kind.magic == BUNDLE.magic {
        &grant.bundle
    } else {
        &grant.pads
    };
    let outer = open_grant_envelope(kind, &vault_id, frame.generation, secret, request, envelope)?;
    open_framed(kind, &vault_id, frame, outer)
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

#[cfg(feature = "sync")]
const PUBLICATION_GRANT_PAIR_LABEL: &[u8] = b"oneiron/publication-grant-pair/v1\0";
// BLAKE3 derive-key context over the signed header bytes.
#[cfg(feature = "sync")]
const PUBLICATION_GRANT_PAIR_SIGNATURE_CONTEXT: &str =
    "oneiron/publication-grant-pair-signature/v1";
// BLAKE3 derive-key context over the recipient suite id plus canonical key bytes.
#[cfg(feature = "sync")]
const PUBLICATION_GRANT_RECIPIENT_KEY_CONTEXT: &str = "oneiron/publication-grant-recipient-key/v1";

/// One generation's request-bound outer grant pair, signed by its issuer.
/// The signature preserves attribution across home storage; native admission
/// and the actual objects' AEAD and publisher checks are still required.
#[cfg(feature = "sync")]
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPublicationGrant {
    generation: SealedBundleGeneration,
    request: AuthorityEntryHash,
    executor: EntityId,
    issuer: EntityId,
    recipient_key_digest: [u8; 32],
    bundle: Envelope,
    pads: Envelope,
    signature: [u8; 64],
}

#[cfg(feature = "sync")]
impl std::fmt::Debug for SealedPublicationGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedPublicationGrant")
            .field("generation", &self.generation)
            .field("request", &self.request)
            .field("executor", &self.executor)
            .field("issuer", &self.issuer)
            .field("recipient_key_digest", &self.recipient_key_digest)
            .field("bundle_len", &self.bundle.len())
            .field("pads_len", &self.pads.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "sync")]
impl SealedPublicationGrant {
    /// The kept generation both envelopes open.
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The pending request the pair publishes for.
    #[must_use]
    pub fn request(&self) -> &AuthorityEntryHash {
        &self.request
    }

    /// The executor the pair is sealed to.
    #[must_use]
    pub fn executor(&self) -> EntityId {
        self.executor
    }

    /// The machine that issued (signed) this pair.
    #[must_use]
    pub fn issuer(&self) -> EntityId {
        self.issuer
    }

    /// The digest of the recipient key the envelopes are sealed to, as
    /// [`grantee_key_digest`] spells it.
    #[must_use]
    pub fn recipient_key_digest(&self) -> &[u8; 32] {
        &self.recipient_key_digest
    }

    /// The vault both envelopes name, read key-free from the bundle header
    /// (no duplicate field). Authentic only after a successful open.
    #[must_use]
    pub fn vault_id(&self) -> &[u8] {
        &self.bundle.header().vault_id
    }

    /// Whether `fold` admits this pair for `holder`: both envelopes name this
    /// vault, the CURRENT trusted install key of the named issuer verifies the
    /// signature over the header, AND the unchanged [`publication_grantees`]
    /// predicate still names this exact request plus executor under a live key
    /// whose canonical digest equals the header's. A removed or re-keyed
    /// recipient, a retired issuer, or a resulted/closed request fails closed.
    /// The signature alone grants nothing: the envelopes still open only under
    /// their OpenPolicy, and the objects still prove themselves by body AEAD
    /// plus the bundle publisher check at use.
    pub(crate) fn admitted_for(&self, fold: &AuthorityFold, holder: Destination) -> bool {
        let vault_ok = match fold.vault_id {
            Some(id) => {
                self.bundle.header().vault_id[..] == id[..]
                    && self.pads.header().vault_id[..] == id[..]
            }
            None => false,
        };
        if !vault_ok {
            return false;
        }
        let Ok(header) = self.header() else {
            return false;
        };
        let digest = pair_signed_digest(&header);
        let signature = Signature::from_bytes(&self.signature);
        let issuer_ok = fold.trusted_machine(self.issuer).is_some_and(|trusted| {
            VerifyingKey::from_bytes(&trusted.profile.machine_key)
                .is_ok_and(|key| key.verify_strict(&digest, &signature).is_ok())
        });
        issuer_ok
            && publication_grantees(fold, holder).iter().any(|grantee| {
                grantee.request == self.request
                    && grantee.executor == self.executor
                    && grantee_key_digest(&grantee.key) == self.recipient_key_digest
            })
    }

    /// Strict parse of the native bytes: LABEL || generation || request ||
    /// executor || issuer || recipient key digest || u32-counted bundle
    /// envelope || u32-counted pads envelope || signature (64), exact end, no
    /// trailing bytes. Each envelope must parse under the native strict
    /// parser and its header must name the expected purpose (bundle/pads
    /// positionally), a hybrid capsule, this generation as key id, and the
    /// slot recipient; both envelopes must name the same vault. These header
    /// reads are garbage rejection only: admission is [`Self::admitted_for`]'s
    /// question, and use still runs the OpenPolicy plus body AEAD plus
    /// publisher checks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || refused("malformed publication grant pair");
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(PUBLICATION_GRANT_PAIR_LABEL.len()) != Some(PUBLICATION_GRANT_PAIR_LABEL) {
            return Err(malformed());
        }
        let generation =
            SealedBundleGeneration::from_bytes(cursor.take(GENERATION_LEN).ok_or_else(malformed)?)?;
        let request: AuthorityEntryHash = cursor.array().ok_or_else(malformed)?;
        let executor =
            EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let issuer =
            EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let recipient_key_digest: [u8; 32] = cursor.array().ok_or_else(malformed)?;
        let id = generation.to_bytes();
        let bundle =
            Envelope::parse(cursor.counted().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let pads =
            Envelope::parse(cursor.counted().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let signature: [u8; 64] = cursor.array().ok_or_else(malformed)?;
        if cursor.at != bytes.len() {
            return Err(malformed());
        }
        let bundle_header = bundle.header();
        let pads_header = pads.header();
        if bundle_header.purpose != BUNDLE.purpose
            || bundle_header.wrap != WrapType::HybridCapsule
            || bundle_header.key_id != id
            || bundle_header.recipient != SLOT_RECIPIENT
        {
            return Err(malformed());
        }
        if pads_header.purpose != PADS.purpose
            || pads_header.wrap != WrapType::HybridCapsule
            || pads_header.key_id != id
            || pads_header.recipient != SLOT_RECIPIENT
        {
            return Err(malformed());
        }
        if bundle_header.vault_id != pads_header.vault_id {
            return Err(malformed());
        }
        Ok(Self {
            generation,
            request,
            executor,
            issuer,
            recipient_key_digest,
            bundle,
            pads,
            signature,
        })
    }

    /// The signed header ([`Self::from_bytes`] minus the signature tail).
    fn header(&self) -> Result<Vec<u8>> {
        let bundle = self.bundle.to_bytes();
        let pads = self.pads.to_bytes();
        let mut out = Vec::with_capacity(
            PUBLICATION_GRANT_PAIR_LABEL.len()
                + GENERATION_LEN
                + self.request.len()
                + self.executor.as_bytes().len()
                + self.issuer.as_bytes().len()
                + self.recipient_key_digest.len()
                + 4
                + bundle.len()
                + 4
                + pads.len(),
        );
        out.extend_from_slice(PUBLICATION_GRANT_PAIR_LABEL);
        out.extend_from_slice(&self.generation.to_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(self.executor.as_bytes());
        out.extend_from_slice(self.issuer.as_bytes());
        out.extend_from_slice(&self.recipient_key_digest);
        put_counted(&mut out, &bundle)?;
        put_counted(&mut out, &pads)?;
        Ok(out)
    }

    /// The signed header ([`Self::header`]), then the signature.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.header()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
}

/// `BLAKE3-derive_key(PUBLICATION_GRANT_PAIR_SIGNATURE_CONTEXT, header)`: the
/// digest the issuer signs and [`SealedPublicationGrant::admitted_for`] verifies.
#[cfg(feature = "sync")]
fn pair_signed_digest(header: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PUBLICATION_GRANT_PAIR_SIGNATURE_CONTEXT);
    hasher.update(header);
    *hasher.finalize().as_bytes()
}

/// The canonical digest of a recipient hybrid key: `BLAKE3-derive_key(
/// PUBLICATION_GRANT_RECIPIENT_KEY_CONTEXT, suite id || canonical key bytes)`.
/// Binds the pair to the exact live key the grantee proves itself by; a
/// re-keyed machine is another recipient.
#[cfg(feature = "sync")]
fn grantee_key_digest(key: &HybridPublicKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PUBLICATION_GRANT_RECIPIENT_KEY_CONTEXT);
    hasher.update(&crate::authority::MACHINE_ENCRYPTION_SUITE_HYBRID_V1.to_be_bytes());
    hasher.update(&key.to_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "sync")]
impl Vault {
    /// Grants the actual kept objects this install opens with its own capsules
    /// to the exact pending publication executor for `holder`. No outer key
    /// leaves this call in plaintext. The issuer signs the exact tuple and both
    /// envelopes; the home must check its native admission before keeping or
    /// serving the grant.
    pub(crate) fn seal_bundle_publication_grant(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        holder: Destination,
        request: AuthorityEntryHash,
    ) -> Result<SealedPublicationGrant> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let signing = self.door_signing_key_in_txn(&txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !fold.trusted_machine(secret.machine).is_some_and(|trusted| {
            trusted.profile.machine_key == signing.verifying_key().to_bytes()
        }) {
            return Err(refused(
                "no current owner-machine issuer for the publication grant",
            ));
        }
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let grantee = publication_grantees(&fold, holder)
            .into_iter()
            .find(|grantee| grantee.request == request)
            .ok_or_else(|| refused("no pending publication grant recipient for this holder"))?;
        let (generation, bundle_key) = {
            let outer = open_outer(BUNDLE, &vault_id, &bundle.0.bytes, &secret.secret)?;
            decode_bundle_body(&vault_id, outer.generation, &outer.body)?
                .require_publisher(&fold, Some(holder))?;
            (outer.generation, outer.outer)
        };
        let (pads_generation, pads_key) = {
            let opened = pads.opened(
                &vault_id,
                open_outer(PADS, &vault_id, &pads.0.bytes, &secret.secret)?,
            )?;
            (opened.generation, opened.outer)
        };
        if pads_generation != generation {
            return Err(refused("the pad object is another generation's"));
        }
        let mut grant = SealedPublicationGrant {
            generation,
            request,
            executor: grantee.executor,
            issuer: secret.machine,
            recipient_key_digest: grantee_key_digest(&grantee.key),
            bundle: seal_grant_envelope(BUNDLE, &vault_id, generation, &bundle_key, &grantee)?,
            pads: seal_grant_envelope(PADS, &vault_id, generation, &pads_key, &grantee)?,
            signature: [0u8; 64],
        };
        grant.signature = signing
            .sign(&pair_signed_digest(&grant.header()?))
            .to_bytes();
        Ok(grant)
    }

    /// The existing capsule/in-object paths first; only their typed lack of a
    /// capsule falls through to the supplied request-bound envelope.
    pub(super) fn open_bundle_to_publish_with_grant(
        &self,
        bundle: &SealedVaultBundle,
        holder: Destination,
        request: AuthorityEntryHash,
        grant: &SealedPublicationGrant,
    ) -> Result<(OpenedVaultBundle, OuterAccess)> {
        match self.open_bundle_to_publish(bundle, holder, Some(request)) {
            Err(error) if no_capsule(&error) => {
                let secret = self.machine_secret_outside_txn()?;
                let txn = self.store.env.read_txn()?;
                let fold = self.authority_view_readonly_in_txn(&txn)?;
                let vault_id = fold
                    .vault_id
                    .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
                let outer = open_supplied_grant(
                    BUNDLE,
                    &bundle.0.bytes,
                    &secret,
                    &request,
                    grant,
                    &fold,
                    holder,
                )?;
                let opened = decode_bundle_body(&vault_id, outer.generation, &outer.body)?;
                opened.require_publisher(&fold, Some(holder))?;
                Ok((opened, OuterAccess::PublicationGrant))
            }
            opened => opened,
        }
    }

    pub(super) fn open_pads_to_publish_with_grant(
        &self,
        pads: &SealedKeyPads,
        holder: Destination,
        request: AuthorityEntryHash,
        grant: &SealedPublicationGrant,
    ) -> Result<(OpenedKeyPads, OuterAccess)> {
        match self.open_pads_to_publish(pads, Some(request)) {
            Err(error) if no_capsule(&error) => {
                let secret = self.machine_secret_outside_txn()?;
                let txn = self.store.env.read_txn()?;
                let fold = self.authority_view_readonly_in_txn(&txn)?;
                let vault_id = fold
                    .vault_id
                    .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
                let outer = open_supplied_grant(
                    PADS,
                    &pads.0.bytes,
                    &secret,
                    &request,
                    grant,
                    &fold,
                    holder,
                )?;
                Ok((
                    pads.opened(&vault_id, outer)?,
                    OuterAccess::PublicationGrant,
                ))
            }
            opened => opened,
        }
    }

    /// The same carry open, with a separately supplied pair only as a fallback.
    pub(crate) fn open_latest_for_publication_with_grant(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        holder: Destination,
        request: AuthorityEntryHash,
        grant: &SealedPublicationGrant,
    ) -> Result<(OpenedVaultBundle, OpenedKeyPads)> {
        let (opened, _) = self.open_bundle_to_publish_with_grant(bundle, holder, request, grant)?;
        let (pads, _) = self.open_pads_to_publish_with_grant(pads, holder, request, grant)?;
        if pads.generation() != opened.generation() {
            return Err(refused("the pad object is another generation's"));
        }
        Ok((opened, pads))
    }
}
