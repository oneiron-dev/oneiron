//! What one bundle seal reads from the vault, and the sealing of one object
//! over it. The entry point is `Vault::seal_plan`.
//! `super` owns the frame codec and the carrier.

use super::*;

/// What one seal reads from the vault, in one snapshot.
pub(super) struct SealPlan {
    pub(super) vault_id: [u8; 32],
    pub(super) signing: SigningKey,
    pub(super) publisher: EntityId,
    /// The owner work request this upload publishes for.
    pub(super) request: Option<AuthorityEntryHash>,
    pub(super) readers: Vec<HybridPublicKey>,
    /// Each fresh world capsule's readers: the machines mine here that may read
    /// the world, and the root.
    pub(super) authority_readers: Vec<(EntityId, Vec<HybridPublicKey>)>,
    pub(super) kit_root: Option<RecoveryRootId>,
    /// Each pad, with the time its row was learned (FIX 3790).
    pub(super) pads: Vec<(WorldKeyId, Zeroizing<[u8; 32]>, u64)>,
}

impl Vault {
    pub(super) fn seal_plan(
        &self,
        secret: &MachineSecret,
        holder: Destination,
        keys: &[(Arc<WorldKey>, &[u8])],
        carry: &BundleCarry<'_>,
    ) -> Result<SealPlan> {
        let txn = self.store.env.read_txn()?;
        let signing = self.door_signing_key_in_txn(&txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let mine = fold.trusted_machine(secret.machine).is_some_and(|trusted| {
            trusted.profile.machine_key == signing.verifying_key().to_bytes()
        });
        // The install his counted request asked to publish to `holder`, in any
        // role (WILL L04 row 03), seals too: it still opens only the keys it
        // holds as an eligible reader.
        let asked = carry.request.is_some_and(|request| {
            publication::asks(&fold, &request, secret.machine, Some(holder))
        });
        // The owner's recipient choice: only a machine he marked "yours"
        // opens a world's key to seal it, never a rule on who decides.
        if !mine && !asked {
            return Err(refused(
                "the owner-selected world read policy excludes this destination; use an allowed \
                 holder",
            ));
        }
        for (key, _) in keys {
            let world = key.id().world;
            if !bundle_carries(&fold, world, holder) {
                return Err(refused(
                    "the world's sealed copies may not rest on the holder",
                ));
            }
            if fold
                .current_world_key(world)
                .is_none_or(|current| current.id != *key.id())
            {
                return Err(refused(
                    "the world's key changed while its section was sealed",
                ));
            }
        }
        let root = self.pinned_root_recipient_in_txn(&txn, &fold)?;
        let kit_root = root.as_ref().map(|root| root.id);
        let mut authority_readers = Vec::with_capacity(carry.fresh_authority.len());
        for &(world, _) in &carry.fresh_authority {
            if !bundle_carries(&fold, world, holder) {
                return Err(refused(
                    "the world's sealed copies may not rest on the holder",
                ));
            }
            let readers: Vec<HybridPublicKey> = recipients(&fold, world, root.clone())
                .into_iter()
                .map(|(_, public)| public)
                .collect();
            authority_readers.push((world, readers));
        }
        // Base reality reads on every machine mine here: its recipients are the
        // vault's own readers, and the root.
        let readers: Vec<HybridPublicKey> = recipients(&fold, base_world(), root)
            .into_iter()
            .map(|(_, public)| public)
            .collect();
        if readers.is_empty() {
            return Err(refused("no machine and no kit could open the bundle"));
        }
        let mut pads = Vec::new();
        for key in fold.all_world_keys() {
            if bundle_carries(&fold, key.id.world, holder)
                && new_pads_hold(&self.store, &txn, key.id.world)?
                && let Some((pad, learned_at)) = pad_row_in_txn(&self.store, &txn, &key.id)?
            {
                pads.push((key.id, Zeroizing::new(*pad.bytes()), learned_at));
            }
        }
        // A carried section's key keeps the pad the latest generation held for
        // it, unless the bundle no longer carries its world for this holder, or
        // the world was deleted or its keys destroyed here. A world whose
        // settings are not folded here yet rides blind with its section and
        // capsule: unknown is not ineligible (FIX 4211).
        for (key, pad, learned_at) in carry.latest.map_or(&[][..], |latest| &latest.entries[..]) {
            if (!fold.worlds.contains_key(&key.world) || bundle_carries(&fold, key.world, holder))
                && !pads.iter().any(|(held, _, _)| held == key)
                && !world_keys_destroyed_in_txn(&self.store, &txn, key.world)?
                && new_pads_hold(&self.store, &txn, key.world)?
            {
                pads.push((*key, Zeroizing::new(**pad), *learned_at));
            }
        }
        Ok(SealPlan {
            vault_id,
            signing,
            publisher: secret.machine,
            request: carry.request,
            readers,
            authority_readers,
            kit_root,
            pads,
        })
    }

    pub(super) fn bundle_vault_id(&self) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        self.authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))
    }
}

/// A fresh outer key, its capsules to the plan's readers, and `body` framed under
/// it.
pub(super) fn seal_object(
    kind: Kind,
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    body: Zeroizing<Vec<u8>>,
) -> Result<SealedObject> {
    let mut outer = Zeroizing::new([0u8; 32]);
    os_fill(&mut outer[..])?;
    let slots = seal_slots(kind, &plan.vault_id, generation, &outer, &plan.readers)?;
    let bytes = seal_outer(kind, &plan.vault_id, generation, &outer, &slots, body, None)?;
    Ok(SealedObject { generation, bytes })
}
