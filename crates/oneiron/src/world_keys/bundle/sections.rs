//! Opened world-section views and bundle section selection.
//! The entry type is `OpenedBundleSection`.
//! `super` owns sealed-section storage and the private section codec.

use super::*;

/// The most envelopes one world section holds: a 1 GiB section.
const MAX_SECTION_PARTS: usize = 128;

impl SealedBundleSection {
    pub(super) fn seal(vault_id: &[u8; 32], key: &WorldKey, payload: &[u8]) -> Result<Self> {
        let body = encode_section_body(vault_id, key.id(), payload);
        let count = body.len().div_ceil(CHUNK);
        if count > MAX_SECTION_PARTS {
            return Err(refused("the world is too large for one bundle section"));
        }
        let tag = section_digest(SECTION_TAG_CONTEXT, vault_id, key);
        let params = seal_params(BUNDLE.purpose, vault_id, &tag, SECTION_RECIPIENT);
        let kek = section_kek(vault_id, key);
        let mut parts = Vec::with_capacity(count);
        seal_parts(
            &params,
            &kek,
            &body,
            &even_sizes(body.len(), count),
            |part| {
                parts.push(part);
                Ok(())
            },
        )?;
        Ok(Self { tag, parts })
    }

    pub(super) fn open(&self, vault_id: &[u8; 32], key: &WorldKey) -> Result<OpenedBundleSection> {
        let policy = symmetric_policy(BUNDLE.purpose, vault_id, &self.tag, SECTION_RECIPIENT);
        let kek = section_kek(vault_id, key);
        let body = open_parts(&policy, &kek, &self.parts)?;
        decode_section_body(vault_id, key.id(), &body)
    }

    /// tag (32) ‖ count (2) ‖ each part `u32`-length-prefixed.
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.tag);
        let count = u16::try_from(self.parts.len()).map_err(|_| refused("too many parts"))?;
        out.extend_from_slice(&count.to_be_bytes());
        for part in &self.parts {
            put_counted(out, &part.to_bytes())?;
        }
        Ok(())
    }

    pub(super) fn parse(cursor: &mut Cursor<'_>, vault_id: &[u8; 32]) -> Result<Self> {
        let malformed = || refused("malformed bundle section");
        let tag: [u8; 32] = cursor.array().ok_or_else(malformed)?;
        let count = usize::from(u16::from_be_bytes(cursor.array().ok_or_else(malformed)?));
        if count == 0 || count > MAX_SECTION_PARTS {
            return Err(malformed());
        }
        let mut vault = Some(vault_id.to_vec());
        let mut parts = Vec::with_capacity(count);
        for _ in 0..count {
            parts.push(parse_envelope(
                cursor,
                BUNDLE.purpose,
                WrapType::SymmetricKek,
                &tag,
                SECTION_RECIPIENT,
                &mut vault,
            )?);
        }
        Ok(Self { tag, parts })
    }
}

impl std::fmt::Debug for SealedBundleSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedBundleSection")
            .field("parts", &self.parts.len())
            .finish_non_exhaustive()
    }
}

/// An opened world section: the key it was sealed under and its bytes, wiped on
/// drop.
pub struct OpenedBundleSection {
    pub key: WorldKeyId,
    pub payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedBundleSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedBundleSection")
            .field("key", &self.key)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl std::fmt::Debug for OpenedVaultBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedVaultBundle")
            .field("generation", &self.generation)
            .field("publisher", &self.publisher)
            .field("base_len", &self.base.len())
            .field("sections", &self.sections.len())
            .field("authorities", &self.authorities.len())
            .finish_non_exhaustive()
    }
}

impl OpenedVaultBundle {
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The machine that sealed the bundle, as the bundle claims it.
    #[must_use]
    pub fn publisher(&self) -> EntityId {
        self.publisher
    }

    /// Whether `machine_key`, the publisher's Ed25519 key, signed this bundle.
    #[must_use]
    pub fn signed_by(&self, machine_key: &[u8; 32]) -> bool {
        VerifyingKey::from_bytes(machine_key).is_ok_and(|key| {
            key.verify_strict(&self.signed, &Signature::from_bytes(&self.signature))
                .is_ok()
        })
    }

    /// The base section's bytes.
    #[must_use]
    pub fn base(&self) -> &[u8] {
        &self.base
    }

    /// The world sections, still sealed: what a publisher carries into the next
    /// generation for the worlds it cannot read.
    #[must_use]
    pub fn sections(&self) -> &[SealedBundleSection] {
        &self.sections
    }

    /// The section sealed under `key`, opened; `None` when the bundle holds none.
    pub fn open_section(&self, key: &WorldKey) -> Result<Option<OpenedBundleSection>> {
        let tag = section_digest(SECTION_TAG_CONTEXT, &self.vault_id, key);
        self.sections
            .iter()
            .find(|section| section.tag == tag)
            .map(|section| section.open(&self.vault_id, key))
            .transpose()
    }

    /// Each world section, still sealed, with the key it is sealed under where
    /// this machine knows it (FIX 3359): one of `keys`, which it holds, else
    /// the key `pads`, this generation's pad object, indexes the section's tag
    /// under. A publisher judges what it carries on by it, read here or not.
    #[cfg(feature = "sync")]
    #[must_use]
    pub(crate) fn sections_known(
        &self,
        keys: &[WorldKey],
        pads: &OpenedKeyPads,
    ) -> Vec<(Option<WorldKeyId>, &SealedBundleSection)> {
        let held: Vec<(WorldKeyId, [u8; 32])> = keys
            .iter()
            .map(|key| {
                (
                    *key.id(),
                    section_digest(SECTION_TAG_CONTEXT, &self.vault_id, key),
                )
            })
            .collect();
        self.sections
            .iter()
            .map(|section| {
                let known = held
                    .iter()
                    .chain(&pads.index)
                    .find(|(_, tag)| *tag == section.tag)
                    .map(|(key, _)| *key);
                (known, section)
            })
            .collect()
    }

    /// The world sections not sealed under any of `keys`, still sealed: what a
    /// publisher carries on when it replaces or drops the sections of those
    /// keys.
    #[must_use]
    pub fn sections_except(&self, keys: &[&WorldKey]) -> Vec<SealedBundleSection> {
        let tags: BTreeSet<[u8; 32]> = keys
            .iter()
            .map(|key| section_digest(SECTION_TAG_CONTEXT, &self.vault_id, key))
            .collect();
        self.sections
            .iter()
            .filter(|section| !tags.contains(&section.tag))
            .cloned()
            .collect()
    }

    /// Whether a machine the owner vouched for signed the bundle, mine here now
    /// or removed since: the key of its roster chain an owner-held key accepted,
    /// or of its chain under an owner anchor, in `fold`. An install whose own
    /// profile is still unanswered is no machine he vouched for (selfprofile).
    #[cfg(feature = "sync")]
    #[must_use]
    pub(crate) fn signed_by_owner_machine(&self, fold: &AuthorityFold) -> bool {
        fold.machine(self.publisher).is_some_and(|machine| {
            machine
                .roster_trusted
                .iter()
                .chain(machine.anchored.values())
                .filter(|chain| chain.profile.role.answered())
                .any(|chain| self.signed_by(&chain.profile.machine_key))
        })
    }
}
