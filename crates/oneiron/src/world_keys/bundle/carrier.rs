//! Bundle carrier entry points for sealing and opening one generation.
//! The entry point is `Vault::seal_vault_bundle`.
//! `super` owns the private frame codec and shared carrier storage.

use super::*;

impl SealedVaultBundle {
    /// Strict parse of a frame: a positive multiple of the size step, the bundle
    /// magic, then capsules and parts, each one canonical E0 envelope bound to the
    /// generation and one vault. Whether it opens is a reader's question.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let frame = parse_frame(BUNDLE, bytes)?;
        Ok(Self(SealedObject {
            generation: frame.generation,
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.0.generation
    }

    /// The padded byte length.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.bytes.len()
    }

    /// BLAKE3 of the bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0.bytes).as_bytes()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }

    /// Opens the bundle with the kit's root, for a restore with no machine. Its
    /// publisher is unchecked: the restore checks [`OpenedVaultBundle::signed_by`]
    /// once the base section's authority is back.
    pub fn open_with_kit(
        &self,
        vault_id: &[u8; 32],
        seed: &RecoveryRootSeed,
    ) -> Result<OpenedVaultBundle> {
        self.open_with(vault_id, &seed.recovery_secret()?)
    }
}

/// One upload: the bundle and the pad object of its generation.
#[derive(Debug)]
pub struct SealedVaultUpload {
    pub bundle: SealedVaultBundle,
    pub pads: SealedKeyPads,
    /// The pinned recovery root whose capsule the upload holds, read in the
    /// snapshot that sealed it: a commit names it for the kit door (FIX 3714).
    /// `None`: no root is pinned here, and no kit opens this upload.
    pub kit_root: Option<RecoveryRootId>,
    /// Each world whose capsule this upload does not seal fresh because the
    /// history held here, merged with the capsule it replaces, is incomplete
    /// (FIX 4497): the latest generation's capsule rides unchanged, or none.
    pub incomplete_authority: Vec<EntityId>,
}

/// What an ordinary take imported from the world capsules this machine opens
/// (FIX 4495).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorldCapsuleImport {
    /// Capsules that opened with this machine's key.
    pub opened: usize,
    /// Signed entries they carried that were not held here, imported.
    pub imported: usize,
    /// Capsules that did not open for a reason other than having no capsule
    /// for this machine, or whose entries the admission refused: the next
    /// generation files the world's capsule again, and its take tries again.
    pub refused: usize,
}

impl Vault {
    /// Seals this vault's bundle for upload `slot` ([`sealed_bundle_slot`]) and
    /// the pad object beside it, to every machine mine here and the pinned root,
    /// for `holder`, the home that keeps it. A publisher mine here also grants
    /// both outer keys to each asked executor not mine here, for its request
    /// (FIX 4785).
    ///
    /// `base` is the base section. It must hold no world key pad row: pads ride
    /// only the pad object, or erase would not reach old bundles. Each of `worlds`
    /// is sealed under its current key; this machine must read it now, and the
    /// bundle must carry it for `holder` ([`bundle_carries`]; owner ruling Q1).
    /// `carried` are sections of an earlier generation, kept unchanged unless one
    /// of `worlds` replaces it. The pad object holds the pad of every key here of
    /// every world the bundle carries for `holder`, but a world deleted here
    /// ([`SEALED_BUNDLE_NEW_PAD_DELETED_WORLD`]). It files no world authority
    /// capsule: the sync assembly seals those with its sections.
    pub fn seal_vault_bundle(
        &self,
        slot: u64,
        holder: Destination,
        base: &[u8],
        worlds: &[(EntityId, &[u8])],
        carried: &[SealedBundleSection],
    ) -> Result<SealedVaultUpload> {
        let carried: Vec<_> = carried.iter().map(|section| (None, section)).collect();
        self.seal_vault_bundle_carrying(
            slot,
            holder,
            base,
            worlds,
            &carried,
            &BundleCarry::default(),
        )
    }

    /// [`Self::seal_vault_bundle`] for a publisher that carries `carried` on
    /// from the generation whose pad object is `carry.latest`: the new pad
    /// object also holds each pad of `carry.latest` this machine has no row
    /// for, of a world the bundle still carries for `holder` (or whose settings
    /// are not here: FIX 4211), not deleted here and whose keys were not
    /// destroyed here, so a carried section's key still restores with the kit.
    /// Its index files each fresh section's tag under its key, and each carried
    /// one's under the key it names, where known
    /// ([`OpenedVaultBundle::sections_known`]). The body files a fresh capsule
    /// of each world in `carry.fresh_authority`, which the bundle must carry for
    /// `holder`, merged with its capsule in `carry.replaced_authority` and
    /// sealed only once whole (FIX 4497), and each of `carry.carried_authority`
    /// unchanged.
    pub(crate) fn seal_vault_bundle_carrying(
        &self,
        slot: u64,
        holder: Destination,
        base: &[u8],
        worlds: &[(EntityId, &[u8])],
        carried: &[(Option<WorldKeyId>, &SealedBundleSection)],
        carry: &BundleCarry<'_>,
    ) -> Result<SealedVaultUpload> {
        let secret = self.machine_secret_outside_txn()?;
        let mut keys: Vec<(Arc<WorldKey>, &[u8])> = Vec::with_capacity(worlds.len());
        for &(world, payload) in worlds {
            if keys.iter().any(|(key, _)| key.id().world == world) {
                return Err(refused("a world appears twice in one bundle"));
            }
            keys.push((self.world_key(world)?, payload));
        }
        let plan = self.seal_plan(&secret, holder, &keys, carry)?;
        let generation = SealedBundleGeneration::fresh(slot)?;
        let mut sections = Vec::with_capacity(keys.len() + carried.len());
        let mut index = Vec::with_capacity(keys.len() + carried.len());
        for (key, payload) in &keys {
            let section = SealedBundleSection::seal(&plan.vault_id, key, payload)?;
            index.push((*key.id(), section.tag));
            sections.push(section);
        }
        for (known, section) in carried {
            if !sections
                .iter()
                .any(|kept: &SealedBundleSection| kept.tag == section.tag)
            {
                if let Some(key) = known {
                    index.push((*key, section.tag));
                }
                sections.push((*section).clone());
            }
        }
        let (authorities, incomplete_authority) =
            self.seal_world_authorities(&secret.secret, &plan, generation, carry)?;
        let body = encode_bundle_body(&plan, generation, base, &sections, &authorities)?;
        drop(sections);
        let bundle = seal_object(BUNDLE, &plan, generation, body)?;
        let pads_body = encode_pads_body(&plan.vault_id, generation, &plan.pads, &index, None)?;
        let pads = seal_object(PADS, &plan, generation, pads_body)?;
        Ok(SealedVaultUpload {
            bundle: SealedVaultBundle(bundle),
            pads: SealedKeyPads(pads),
            kit_root: plan.kit_root,
            incomplete_authority,
        })
    }

    /// Opens `bundle`, read from `holder`, with this machine's capsule, and
    /// checks its publisher with the one verifier a take, a carry and a kit
    /// restore share ([`OpenedVaultBundle::require_publisher`]): a machine the
    /// owner vouched for, mine here now or removed since, so a latest
    /// generation that a machine removed since sealed does not stop the next
    /// upload; or the install his counted request asked to publish.
    #[cfg(feature = "sync")]
    pub fn open_vault_bundle(
        &self,
        bundle: &SealedVaultBundle,
        holder: Destination,
    ) -> Result<OpenedVaultBundle> {
        let secret = self.machine_secret_outside_txn()?;
        let opened = bundle.open_with(&self.bundle_vault_id()?, &secret.secret)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        opened.require_publisher(&fold, Some(holder))?;
        Ok(opened)
    }

    /// Every world a bundle for `holder` carries now ([`bundle_carries`]).
    #[cfg(feature = "sync")]
    pub(crate) fn sealed_bundle_worlds(&self, holder: Destination) -> Result<BTreeSet<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(known_worlds(&fold)
            .filter(|world| bundle_carries(&fold, *world, holder))
            .collect())
    }

    /// Every world this machine's authority names, by its settings or a key:
    /// the worlds a publisher knows whether a holder's bundle carries (FIX
    /// 3359). A section of any other world rides on.
    #[cfg(feature = "sync")]
    pub(crate) fn sealed_bundle_known_worlds(&self) -> Result<BTreeSet<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(known_worlds(&fold).collect())
    }

    /// Kit restore: stores each pad of `pads` whose key this vault's authority
    /// names and whose row is not here, so the root's wraps open again (the
    /// base section carries no pad row). Each row keeps the time it was first
    /// learned, so it rides the same month's window as on every other replica
    /// (FIX 3790). A world whose keys were destroyed here gets none. Returns
    /// how many it stored.
    #[cfg(feature = "sync")]
    pub(crate) fn restore_key_pads(&self, pads: &OpenedKeyPads) -> Result<usize> {
        self.with_write_txn(|txn| {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let mut stored = 0;
            for (key, pad, learned_at) in &pads.entries {
                if fold.world_key(key).is_none()
                    || pad_row_in_txn(&self.store, txn, key)?.is_some()
                    || world_keys_destroyed_in_txn(&self.store, txn, key.world)?
                {
                    continue;
                }
                let pad = WorldKeyPad::from_bytes(Zeroizing::new(**pad));
                self.put_pad_in_txn(txn, key, &pad, *learned_at)?;
                stored += 1;
            }
            Ok(stored)
        })
    }

    /// The sections of `opened` this machine may read now, opened. A key whose pad
    /// row is not here takes its pad from `pads`, the pad object of the bundle's
    /// generation. Whether to import a section, a deleted world's included, is the
    /// caller's question.
    pub fn open_vault_bundle_sections(
        &self,
        opened: &OpenedVaultBundle,
        pads: Option<&OpenedKeyPads>,
    ) -> Result<Vec<OpenedBundleSection>> {
        open_sections(opened, &self.bundle_reader_keys(pads, false)?)
    }

    /// Every key this machine opens of a world it may read now, its pad from
    /// this machine or else from `pads`, the pad object of the bundle's
    /// generation. A world read everywhere counts only with `public_too`.
    pub(crate) fn bundle_reader_keys(
        &self,
        pads: Option<&OpenedKeyPads>,
        public_too: bool,
    ) -> Result<Vec<WorldKey>> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let me = WrapRecipient::Machine(secret.machine);
        let mut keys = Vec::new();
        for key in fold.all_world_keys() {
            let world = key.id.world;
            if (!public_too && fold.world_privacy(world).read == EffectiveRead::Everywhere)
                || !fold.world_readable_on(world, Destination::Machine(secret.machine))
            {
                continue;
            }
            let pad = pad_in_txn(&self.store, &txn, &key.id)?
                .or_else(|| pads.and_then(|pads| pads.pad(&key.id)));
            if let Some(world_key) =
                pad.and_then(|pad| open_counted(&fold, key, me, &secret.secret, &pad))
            {
                keys.push(world_key);
            }
        }
        Ok(keys)
    }

    /// Kit restore: every section of `opened` whose key is wrapped to the kit's
    /// root, opened with that key's pad from `pads`, the pad object of the
    /// bundle's generation, or else this machine's own, from its row or its
    /// custody (FIX 346). This vault's authority must already hold the bundle's
    /// base and the world capsules the kit opens, which carry the root's wraps.
    pub fn open_vault_bundle_sections_with_kit(
        &self,
        opened: &OpenedVaultBundle,
        pads: &OpenedKeyPads,
        seed: &RecoveryRootSeed,
    ) -> Result<Vec<OpenedBundleSection>> {
        let secret = seed.recovery_secret()?;
        let keys: Vec<WorldKey> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold
                .vault_id
                .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
            let root = WrapRecipient::RecoveryRoot(seed.public(&vault_id)?.id);
            let mut keys = Vec::new();
            for key in fold.all_world_keys() {
                let pad = match pads.pad(&key.id) {
                    Some(pad) => Some(pad),
                    None => pad_in_txn(&self.store, &txn, &key.id)?,
                };
                if let Some(world_key) =
                    pad.and_then(|pad| open_counted(&fold, key, root, &secret, &pad))
                {
                    keys.push(world_key);
                }
            }
            keys
        };
        open_sections(opened, &keys)
    }

    /// Opens `pads` with this machine's capsule.
    pub fn open_key_pads(&self, pads: &SealedKeyPads) -> Result<OpenedKeyPads> {
        let secret = self.machine_secret_outside_txn()?;
        pads.open_with(&self.bundle_vault_id()?, &secret.secret)
    }

    /// Opens `pads`, a kept pad object, as erase's rewrite opens it
    /// ([`SEALED_BUNDLE_ERASE_KEY_SOURCE`]): with this machine's capsule, else
    /// with one of `grants` addressed to it (FIX 4271), else with `kit`, the
    /// owner's kit for this erase.
    #[cfg(feature = "sync")]
    pub(crate) fn open_key_pads_to_erase(
        &self,
        pads: &SealedKeyPads,
        kit: Option<&RecoveryRootSeed>,
        grants: &[SealedPadAdmissionGrant],
    ) -> Result<OpenedKeyPads> {
        self.erase_keys(kit, grants)?.open(pads)
    }

    /// Erase's rewrite, in one call: every kept pad object, the current one and
    /// every older one, without `world`'s pads, each opened with this machine's
    /// capsule, a grant of its outer key to this machine among `grants`, or
    /// else the kit's. A pad object holds pads only. The root wraps of
    /// the world's keys stay in each kept bundle's world capsule, and with the pads
    /// gone from every kept object they open to nothing, for the kit too, so the
    /// world's section in every kept bundle stops opening. Every other world's
    /// pads stay, so every kept bundle still restores them. Each object is
    /// rewritten at its own length, held the world or not.
    ///
    /// The holder keeps no prior object versions: a rewrite replaces the old
    /// object and deletes it (no versioning or object lock is assumed). Refused
    /// when one object opens with no key, before anything is rewritten.
    #[cfg(feature = "sync")]
    pub fn drop_world_from_key_pads(
        &self,
        world: EntityId,
        kept: &[SealedKeyPads],
        kit: Option<&RecoveryRootSeed>,
        grants: &[SealedPadAdmissionGrant],
    ) -> Result<Vec<SealedKeyPads>> {
        let keys = self.erase_keys(kit, grants)?;
        let opened = kept
            .iter()
            .map(|pads| keys.open(pads))
            .collect::<Result<Vec<_>>>()?;
        opened
            .iter()
            .map(|pads| pads.without_world(world))
            .collect()
    }
}
