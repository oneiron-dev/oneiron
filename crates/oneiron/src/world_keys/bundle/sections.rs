//! Opened world-section views and bundle section selection.
//! The entry type is `OpenedBundleSection`.
//! `super` owns sealed-section storage and the private section codec.

use super::*;

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
