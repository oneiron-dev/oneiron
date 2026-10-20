//! What the vault's sealed cloud bundle carries (FIX 922 PR 2): the base section
//! and the section of each world the bundle carries for its holder that a
//! publisher seals, and how a reader takes a bundle back in. The carrier is `world_keys::bundle`; the holder and the wire
//! are `residence::bundle` and the residence client's.
//!
//! - The base section is base reality as the owner's machines hold it: the signed
//!   authority history, then every base window and every window of a world read
//!   everywhere, each the whole history-free snapshot the export door cuts for a
//!   machine that may read no private world. It carries no world key pad row
//!   and no key wrap: pads ride only the pad object, so erase's rewrite reaches
//!   every kept bundle, and wraps only their world's authority capsule. Before
//!   them rides the checkpoint image the vault adopted, if any (FIX 3583).
//! - A world section is every window of one carried world, each the whole mirror
//!   this machine keeps for it. A holder that is a machine of the owner's also
//!   gets the worlds whose sealed copies go to "My machines"
//!   (`world_keys::bundle`).
//! - A publisher seals a fresh section of each carried world it reads and holds
//!   whole ([`WindowManager::assemble_sealed_bundle`]), and
//!   carries every other section of the latest generation byte for byte, except
//!   those of a world it knows was deleted here or is no longer eligible for
//!   this holder ([`SEALED_BUNDLE_CARRY_FILTER`]), read here or not: it knows a
//!   section's world from a key it holds, or from the pad object's index (FIX
//!   3359). A section of a world it does not know rides on.
//! - A take opens the sections this machine may read and merges each window into
//!   its mirror. It never reads the base section: base syncs live between the
//!   owner's machines. A kit restore reads it all, on an install with no machine
//!   of its own yet ([`WindowManager::restore_sealed_bundle_with_kit`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use loro::LoroDoc;
use zeroize::Zeroizing;

use super::discover_local_window_keys;
use crate::Vault;
use crate::authority::{
    AuthorityEntryHash, Destination, EditOrigin, EffectiveRead, decode_authority_log_entry_body,
    side_world,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::ports::TombstoneStoreRead;
use crate::sync::WindowManager;
use crate::sync::loro_support::{import_doc, map_delete, map_for_each_value_bytes};
use crate::sync::schema::create_window_doc;
use crate::sync::types::{WindowKey, authority_wrap_world};
use crate::sync::window::{
    ReplacementByteBound, apply_pending_window_updates, export_history_free_window_snapshot,
    export_window_replacement, load_window_from_state, reverse_rematerialize,
};
use crate::world_keys::{
    BundleCarry, KitConfirmation, OpenedBundleSection, OpenedVaultBundle, RecoveryRootSeed,
    RootRestore, SealedKeyPads, SealedVaultBundle, SealedVaultUpload, WorldKey, pad_body_world,
    refused, world_keys_destroyed_in_txn,
};

mod checkpoint;
pub use checkpoint::RecoveryCheckpointTrust;

/// The base section's encoding version.
const SEALED_BUNDLE_BASE_VERSION: u8 = 2;
/// A world section's encoding version.
const SEALED_BUNDLE_WORLD_VERSION: u8 = 1;
const BASE_LABEL: &[u8] = b"oneiron/sealed-bundle-base\0";
const WORLD_LABEL: &[u8] = b"oneiron/sealed-bundle-world\0";

/// Why a publisher stops carrying a section of the latest generation whose
/// world it knows.
enum CarryDrop {
    /// The world was deleted here, or its keys destroyed here.
    DeletedHere,
    /// This machine's authority names the world, and a bundle for the holder
    /// no longer carries it.
    Ineligible,
}

/// The sections a publisher stops carrying, read here or not (CALLS:
/// SEALED_BUNDLE_CARRY_FILTER): those of a world known deleted here or known
/// ineligible for the holder. A section of an unknown or unmapped world stays
/// carried.
const SEALED_BUNDLE_CARRY_FILTER: &[CarryDrop] = &[CarryDrop::DeletedHere, CarryDrop::Ineligible];

/// How long a base window a kit restore installs may be (CALLS:
/// SEALED_KIT_REPLACEMENT_BYTE_BOUND): as long as the authenticated section
/// that carried it, already opened whole, not one network frame (FIX 3361).
const SEALED_KIT_REPLACEMENT_BYTE_BOUND: ReplacementByteBound =
    ReplacementByteBound::AuthenticatedSectionLength;

/// What one take moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealedBundleTake {
    /// World sections this machine opened.
    pub sections: usize,
    /// Windows merged and materialized here.
    pub merged: usize,
    /// Windows kept in their mirror only, on an opened-item machine.
    pub mirrored: usize,
    /// Windows whose mirror here already held all the section carries.
    pub unchanged: usize,
    /// Sections or windows that did not open or merge here.
    pub skipped: usize,
}

/// Each private world's signed key wrap entries held here, parents first: what
/// that world's authority capsule seals (FIX 4211). Its settings ride the main
/// log and the base (PR1a #2961).
type WorldSides = BTreeMap<EntityId, Vec<Vec<u8>>>;

/// What a kit restore from the sealed cloud bundle did.
#[derive(Debug, Default)]
pub struct SealedKitRestore {
    /// What the world keys' restore did with each key wrapped to the kit's
    /// root: usable here, kept on another machine, or withheld.
    pub keys: RootRestore,
    /// Signed authority entries the base section and the world capsules the
    /// kit opens carried, each once.
    pub authority: usize,
    /// Windows of the base section installed here.
    pub windows: usize,
    /// Windows of the base section that did not install: none, since one
    /// that does not install fails the restore (FIX 3361).
    pub windows_skipped: usize,
    /// Pads stored here from the pad object.
    pub pads: usize,
    /// What the world sections moved.
    pub take: SealedBundleTake,
}

impl WindowManager {
    /// Seals this machine's upload for UTC slot `slot`, for `holder`, the home
    /// that keeps it: the base section, a fresh section of every world the
    /// bundle carries for `holder` that this machine reads and holds whole
    /// ([`Self::complete_source`]), and every other section of `latest` (the
    /// holder's newest generation and its pad object) unchanged, minus the
    /// sections [`SEALED_BUNDLE_CARRY_FILTER`] drops. Each such world's
    /// authority capsule is sealed fresh from the entries held here, or, for a
    /// world this machine may not read whose capsule `latest` files, carried
    /// unchanged under the same filter (FIX 4211). `request` is the owner's
    /// counted ask this upload publishes for (WILL L04 row 03), signed into
    /// its provenance. `materialize` is a full machine's (effective residence
    /// mode All): the rows of each window `latest` carries land here too, as
    /// its take lands them (FIX 4788).
    pub fn assemble_sealed_bundle(
        &self,
        slot: u64,
        holder: Destination,
        latest: Option<(&SealedVaultBundle, &SealedKeyPads)>,
        request: Option<AuthorityEntryHash>,
        materialize: bool,
    ) -> Result<SealedVaultUpload> {
        let vault = self.vault();
        let windows = discover_local_window_keys(vault)?;
        let (base, eligible, sides) = self.sealed_bundle_base(&windows, holder)?;
        let latest = match latest {
            None => None,
            Some((bundle, pads)) => {
                let opened = vault.open_vault_bundle(bundle, holder)?;
                let pads = vault.open_key_pads(pads)?;
                if pads.generation() != opened.generation() {
                    return Err(refused("the pad object is another generation's"));
                }
                Some((opened, pads))
            }
        };
        let keys = match &latest {
            Some((_, pads)) => vault.bundle_reader_keys(Some(pads), true)?,
            None => Vec::new(),
        };
        let mut fresh = Vec::new();
        for &world in &eligible {
            // A world this machine does not read now, or does not hold whole,
            // keeps the section it has.
            if vault.world_key(world).is_err() {
                continue;
            }
            let opened = latest.as_ref().map(|(opened, _)| opened);
            let Some(held) = self.complete_source(world, &windows, opened, &keys, materialize)
            else {
                continue;
            };
            let mut snapshots = Vec::new();
            for window in &held {
                snapshots.push((window.clone(), self.sealed_mirror_snapshot(world, window)?));
            }
            fresh.push((world, encode_world_section(world, &snapshots)?));
        }
        // A section whose world this machine knows goes when that world has a
        // fresh one or the carry filter drops it.
        let known = vault.sealed_bundle_known_worlds()?;
        let mut carried = Vec::new();
        if let Some((opened, pads)) = &latest {
            for (key, section) in opened.sections_known(&keys, pads) {
                if let Some(key) = key
                    && (fresh.iter().any(|(sealed, _)| *sealed == key.world)
                        || carry_drops(vault, key.world, &eligible, &known)?)
                {
                    continue;
                }
                carried.push((key, section));
            }
        }
        let worlds: Vec<(EntityId, &[u8])> = fresh
            .iter()
            .map(|(world, payload)| (*world, payload.as_slice()))
            .collect();
        let mut carry = BundleCarry {
            latest: latest.as_ref().map(|(_, pads)| pads),
            request,
            ..BundleCarry::default()
        };
        // A machine that may not read a world never overwrites the capsule it
        // carries from what it holds of that world; a reader holds it whole.
        let capsules = latest
            .as_ref()
            .map_or(&[][..], |(opened, _)| opened.world_authorities());
        for (world, entries) in &sides {
            if capsules.iter().any(|capsule| capsule.world() == *world)
                && vault.world_key(*world).is_err()
            {
                continue;
            }
            carry.fresh_authority.push((*world, entries.as_slice()));
        }
        for capsule in capsules {
            let world = capsule.world();
            if carry
                .fresh_authority
                .iter()
                .any(|(fresh, _)| *fresh == world)
                || carry_drops(vault, world, &eligible, &known)?
            {
                continue;
            }
            carry.carried_authority.push(capsule);
        }
        vault.seal_vault_bundle_carrying(slot, holder, &base, &worlds, &carried, &carry)
    }

    /// Takes `bundle` and its pad object in, read from `holder`: opens every
    /// section this machine may read and merges each window into its mirror.
    /// A full machine materializes the rows; an `opened`-item machine keeps
    /// them in the mirror until a promotion materializes it.
    pub fn take_sealed_bundle(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        holder: Destination,
        opened: bool,
    ) -> Result<SealedBundleTake> {
        let vault = self.vault();
        let outer = vault.open_vault_bundle(bundle, holder)?;
        let pads = vault.open_key_pads(pads)?;
        if pads.generation() != outer.generation() {
            return Err(refused("the pad object is another generation's"));
        }
        let mut take = SealedBundleTake::default();
        for section in vault.open_vault_bundle_sections(&outer, Some(&pads))? {
            // An ordinary take never brings back a world deleted here.
            if deleted_here(vault, section.key.world)? {
                take.skipped += 1;
                continue;
            }
            self.take_section(&section, !opened, &mut take);
        }
        Ok(take)
    }

    /// Kit restore from the sealed cloud bundle, on an install that is no
    /// machine of the vault's yet: `bundle` and its pad object `pads` open with
    /// the kit's `seed` for the vault `vault_id`. The base section's signed
    /// authority history goes in first, with every world capsule's the kit
    /// opens (FIX 4211), so the root's wraps and every world's policy are here. Once the
    /// publisher check passes on that authority (a machine the owner vouched
    /// for, or the install he asked to publish), each base window installs as a replacement, of any
    /// length the section carried; one that does not install fails the
    /// restore, and the windows installed before it stay. The pad object's
    /// pads are stored, the world keys restore from the kit as
    /// [`Vault::restore_world_keys`] restores them (`owner`, `confirm`), and
    /// each section the kit opens merges into its windows' mirrors and
    /// materializes, for the worlds this machine may read now. The keys report
    /// names the keys usable here, those that need a re-home and those
    /// withheld. A checkpoint image the base carries is not adopted here: the
    /// tail imports alone, whole only from a hydrated publisher
    /// ([`Self::restore_sealed_bundle_with_kit_checkpoint`], FIX 3583).
    pub fn restore_sealed_bundle_with_kit(
        self: &Arc<Self>,
        owner: &AuthenticatedOwner,
        vault_id: &[u8; 32],
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<SealedKitRestore> {
        self.restore_with_kit(owner, vault_id, bundle, pads, seed, confirm, None)
    }

    /// [`Self::restore_sealed_bundle_with_kit`], adopting first the image the
    /// base carries once `trust` fixes its pin ([`checkpoint::adopt`]).
    #[expect(clippy::too_many_arguments)]
    fn restore_with_kit(
        self: &Arc<Self>,
        owner: &AuthenticatedOwner,
        vault_id: &[u8; 32],
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
        trust: Option<RecoveryCheckpointTrust>,
    ) -> Result<SealedKitRestore> {
        let vault = self.vault();
        refuse_machine_of_the_vault(vault, vault_id)?;
        let opened = bundle.open_with_kit(vault_id, seed)?;
        let pads = pads.open_with_kit(vault_id, seed)?;
        if pads.generation() != opened.generation() {
            return Err(refused("the pad object is another generation's"));
        }
        let base = decode_base(opened.base())?;
        let carried = base.checkpoint.as_ref();
        checkpoint::adopt(vault, vault_id, carried, trust, seed, confirm)?;
        let authority =
            with_world_authority(base.authority, opened.authority_history_with_kit(seed)?);
        let mut restore = SealedKitRestore {
            authority: authority.len(),
            ..SealedKitRestore::default()
        };
        vault.import_signed_authority_history(&authority)?;
        {
            let txn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            if fold.vault_id != Some(*vault_id) {
                return Err(refused("the bundle's authority is another vault's"));
            }
            opened.require_publisher(&fold, None)?;
        }
        // Base windows first: a window of a world read everywhere may name a
        // base row.
        let mut windows = base.windows;
        windows.sort_by_key(|(key, _)| key.world().is_some());
        for (key, snapshot) in &windows {
            let (window, _) = self.replace_window_bounded(
                key,
                snapshot,
                &HashMap::new(),
                || true,
                SEALED_KIT_REPLACEMENT_BYTE_BOUND,
            )?;
            drop(window);
            // A restore leaves no window open.
            self.unload_window(key)?;
            restore.windows += 1;
        }
        restore.pads = vault.restore_key_pads(&pads)?;
        restore.keys = vault.restore_world_keys(owner, EditOrigin::ThisMachine, seed, confirm)?;
        for section in vault.open_vault_bundle_sections_with_kit(&opened, &pads, seed)? {
            self.take_section(&section, true, &mut restore.take);
        }
        Ok(restore)
    }

    /// The windows a fresh section of `world` carries, so that it never
    /// carries less than the section of `latest` it replaces: each window of
    /// the world held here, and each window that section carries (opened with
    /// one of `keys`), merged into its mirror first. The actual source and key
    /// access decide, never the machine's residence mode (WILL L04 row 03):
    /// an opened-item machine seals what it holds whole. With `materialize`
    /// (a full machine) each window's rows land here too, merged or already
    /// held (FIX 4788); a window whose rows do not land stays in its mirror,
    /// as an opened-item machine keeps them all, and still rides. `None` when
    /// that section does not open, decode or merge here: it rides on
    /// unchanged.
    fn complete_source(
        &self,
        world: EntityId,
        windows: &[WindowKey],
        latest: Option<&OpenedVaultBundle>,
        keys: &[WorldKey],
        materialize: bool,
    ) -> Option<Vec<WindowKey>> {
        let mut held: Vec<WindowKey> = windows
            .iter()
            .filter(|window| window.world() == Some(world))
            .cloned()
            .collect();
        let Some(latest) = latest else {
            return Some(held);
        };
        for key in keys.iter().filter(|key| key.id().world == world) {
            let Some(section) = latest.open_section(key).ok()? else {
                continue;
            };
            let carried = decode_world_section(&section.payload, world).ok()?;
            for (window, snapshot) in carried {
                let landed = materialize
                    && self
                        .merge_bundle_mirror(world, &window, &snapshot, true)
                        .is_ok();
                if !landed {
                    self.merge_bundle_mirror(world, &window, &snapshot, false)
                        .ok()?;
                }
                if !held.contains(&window) {
                    held.push(window);
                }
            }
        }
        Some(held)
    }

    /// Merges each window of an opened world `section` into its mirror,
    /// materializing with `materialize`, and counts into `take`.
    fn take_section(
        &self,
        section: &OpenedBundleSection,
        materialize: bool,
        take: &mut SealedBundleTake,
    ) {
        let world = section.key.world;
        let Ok(windows) = decode_world_section(&section.payload, world) else {
            take.skipped += 1;
            return;
        };
        take.sections += 1;
        for (window, snapshot) in windows {
            match self.merge_bundle_mirror(world, &window, &snapshot, materialize) {
                Ok(false) => take.unchanged += 1,
                Ok(true) if materialize => take.merged += 1,
                Ok(true) => take.mirrored += 1,
                Err(_) => take.skipped += 1,
            }
        }
    }

    /// The base section ([`encode_base`]): the checkpoint image this vault
    /// adopted, read after the history so it covers every parent the history
    /// names that is not held, the signed authority history, then
    /// each of `windows` that is a base window or a window of a world read
    /// everywhere; and the worlds the bundle carries for `holder`
    /// ([`Vault::sealed_bundle_worlds`]), read after the history. A world's side
    /// branch (its key wraps) never rides the base (FIX 3871): only the reader
    /// capsule of a private world the bundle carries for `holder` seals it
    /// (FIX 4211, FIX 4271), and nothing outside the world names it. Its
    /// settings edits are main-log metadata (the Engine call "OwnerAct world
    /// metadata to every linked machine"), so the base always carries them.
    fn sealed_bundle_base(
        &self,
        windows: &[WindowKey],
        holder: Destination,
    ) -> Result<(Zeroizing<Vec<u8>>, BTreeSet<EntityId>, WorldSides)> {
        let vault = self.vault();
        // The rows held here: a vault not yet hydrated holds no covered row.
        let history = super::held_authority_history(vault)?;
        let adopted = checkpoint::carried(vault)?;
        // Read after the history, so a settings edit it holds is judged too.
        let eligible = vault.sealed_bundle_worlds(holder)?;
        let mut sides = WorldSides::new();
        let (public, authority) = {
            let txn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            let everywhere =
                |world: EntityId| fold.world_privacy(world).read == EffectiveRead::Everywhere;
            let public: BTreeSet<EntityId> = windows
                .iter()
                .filter_map(WindowKey::world)
                .filter(|world| everywhere(*world))
                .collect();
            let mut authority = Vec::with_capacity(history.len());
            for bytes in history {
                let op = decode_authority_log_entry_body(&bytes)?.op;
                if let Some(world) = side_world(&op) {
                    if !everywhere(world) && eligible.contains(&world) {
                        sides.entry(world).or_default().push(bytes);
                    }
                    continue;
                }
                authority.push(bytes);
            }
            (public, authority)
        };
        let mut snapshots = Vec::new();
        for key in windows {
            if key.world().is_some_and(|world| !public.contains(&world)) {
                continue;
            }
            // One that does not export fails the assembly: a bundle never
            // carries part of the base (FIX 3361).
            if let Some(snapshot) = self.base_window_snapshot(key)? {
                snapshots.push((key.clone(), snapshot));
            }
        }
        let base = encode_base(adopted.as_ref(), &authority, &snapshots)?;
        Ok((base, eligible, sides))
    }

    /// `key`'s whole state as the export door cuts it for a machine that may
    /// read no private world, less its world key pad and key wrap rows: the
    /// history-free replacement of a copy of the window (the live one, else its
    /// durable state) holding every row of the window here. `None` for a window
    /// that ships nothing.
    fn base_window_snapshot(&self, key: &WindowKey) -> Result<Option<Vec<u8>>> {
        let vault = self.vault();
        // A copy under a fresh peer: nothing done to it reaches the window.
        let doc = match self.window(key) {
            Some(live) => live.doc.fork(),
            None => match load_window_from_state(vault, "", key) {
                Ok(doc) => doc,
                Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                    let doc = create_window_doc("", key);
                    apply_pending_window_updates(vault, &doc, key)?;
                    doc
                }
                Err(error) => return Err(error),
            },
        };
        reverse_rematerialize(vault, &doc, key)?;
        let Some(snapshot) = export_window_replacement(vault, key, &doc, None)? else {
            return Ok(None);
        };
        without_key_rows(snapshot).map(Some)
    }
}

/// Whether [`SEALED_BUNDLE_CARRY_FILTER`] drops a section of `world` from the
/// next generation: `eligible` holds the worlds a bundle for its holder
/// carries, `known` every world this machine's authority names.
fn carry_drops(
    vault: &Vault,
    world: EntityId,
    eligible: &BTreeSet<EntityId>,
    known: &BTreeSet<EntityId>,
) -> Result<bool> {
    for filter in SEALED_BUNDLE_CARRY_FILTER {
        let drops = match filter {
            CarryDrop::DeletedHere => deleted_here(vault, world)?,
            CarryDrop::Ineligible => known.contains(&world) && !eligible.contains(&world),
        };
        if drops {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `base`, then capsule entries it does not hold, parents first. World wrap
/// side entries arrive only through their world's capsule.
fn with_world_authority(mut base: Vec<Vec<u8>>, capsules: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut held: BTreeSet<[u8; 32]> = base
        .iter()
        .map(|entry| *blake3::hash(entry).as_bytes())
        .collect();
    for entry in capsules {
        if held.insert(*blake3::hash(&entry).as_bytes()) {
            base.push(entry);
        }
    }
    base
}

/// Whether `world` was deleted here or its keys destroyed here: an ordinary take
/// never brings it back, and a publisher that opens its section stops carrying
/// it. Old bundles keep it until they age out.
fn deleted_here(vault: &Vault, world: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(world_keys_destroyed_in_txn(&vault.store, &txn, world)?
        || TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &world)?.deleted)
}

/// Refuses a kit restore on an install that holds another vault, or that is
/// already one of the owner's machines here: that one takes the bundle instead.
fn refuse_machine_of_the_vault(vault: &Vault, vault_id: &[u8; 32]) -> Result<()> {
    // No machine identity yet reads as none.
    let machine = vault
        .machine_secret_outside_txn()
        .ok()
        .map(|secret| secret.machine);
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    if fold.vault_id.is_some_and(|held| held != *vault_id) {
        return Err(refused("this install holds another vault"));
    }
    if machine.is_some_and(|machine| fold.trusted_machine(machine).is_some()) {
        return Err(refused(
            "this install is one of the owner's machines: take the bundle instead",
        ));
    }
    Ok(())
}

/// `snapshot` with no world key pad row and no key wrap entry: pads ride only
/// the pad object, wraps only their world's authority capsule, and a world's
/// settings entries stay. A snapshot that held one is cut again, history-free
/// at its newest operation, so its bytes are not in it.
fn without_key_rows(snapshot: Vec<u8>) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    import_doc(&doc, &snapshot)?;
    let entities = doc.get_map("entities");
    let mut keys = Vec::new();
    map_for_each_value_bytes(&entities, |key, raw| {
        if raw
            .is_some_and(|raw| pad_body_world(raw).is_some() || authority_wrap_world(raw).is_some())
        {
            keys.push(key.to_owned());
        }
    });
    if keys.is_empty() {
        return Ok(snapshot);
    }
    for key in &keys {
        map_delete(&entities, key)?;
    }
    crate::sync::row_birth::drop_orphan_births(&doc)?;
    export_history_free_window_snapshot(&doc)
}

/// What a base section holds.
struct BundleBase {
    /// The checkpoint image the publisher adopted, untrusted until a restore
    /// fixes its pin.
    checkpoint: Option<checkpoint::CarriedCheckpoint>,
    /// The signed authority entries, parents first.
    authority: Vec<Vec<u8>>,
    windows: Vec<(WindowKey, Vec<u8>)>,
}

/// label ‖ version (2) ‖ the adopted image ([`checkpoint::encode`]) ‖
/// authority entry count (4) ‖ each entry `u32`-length-prefixed ‖ windows
/// ([`encode_windows`]).
fn encode_base(
    adopted: Option<&checkpoint::CarriedCheckpoint>,
    authority: &[Vec<u8>],
    windows: &[(WindowKey, Vec<u8>)],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(BASE_LABEL);
    out.push(SEALED_BUNDLE_BASE_VERSION);
    checkpoint::encode(&mut out, adopted)?;
    put_u32(&mut out, authority.len())?;
    for entry in authority {
        put_u32(&mut out, entry.len())?;
        out.extend_from_slice(entry);
    }
    encode_windows(&mut out, windows)?;
    Ok(out)
}

fn decode_base(bytes: &[u8]) -> Result<BundleBase> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(BASE_LABEL.len())? != BASE_LABEL || reader.u8()? != SEALED_BUNDLE_BASE_VERSION {
        return Err(malformed());
    }
    let checkpoint = checkpoint::decode(&mut reader)?;
    let mut authority = Vec::new();
    for _ in 0..reader.u32()? {
        let len = reader.u32()? as usize;
        authority.push(reader.take(len)?.to_vec());
    }
    let windows = decode_windows(&mut reader, None)?;
    reader.finish()?;
    Ok(BundleBase {
        checkpoint,
        authority,
        windows,
    })
}

/// label ‖ version (1) ‖ world (16) ‖ windows ([`encode_windows`]).
fn encode_world_section(
    world: EntityId,
    windows: &[(WindowKey, Vec<u8>)],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(WORLD_LABEL);
    out.push(SEALED_BUNDLE_WORLD_VERSION);
    out.extend_from_slice(world.as_bytes());
    encode_windows(&mut out, windows)?;
    Ok(out)
}

/// The windows of `world`'s section, each one of the world's.
fn decode_world_section(bytes: &[u8], world: EntityId) -> Result<Vec<(WindowKey, Vec<u8>)>> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(WORLD_LABEL.len())? != WORLD_LABEL
        || reader.u8()? != SEALED_BUNDLE_WORLD_VERSION
        || reader.array::<16>()? != *world.as_bytes()
    {
        return Err(malformed());
    }
    let windows = decode_windows(&mut reader, Some(world))?;
    reader.finish()?;
    Ok(windows)
}

/// count (4) ‖ each window: its key `u16`-length-prefixed, then its snapshot
/// `u64`-length-prefixed.
fn encode_windows(out: &mut Vec<u8>, windows: &[(WindowKey, Vec<u8>)]) -> Result<()> {
    put_u32(out, windows.len())?;
    for (key, snapshot) in windows {
        let name = u16::try_from(key.as_str().len()).map_err(|_| malformed())?;
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(key.as_str().as_bytes());
        out.extend_from_slice(&(snapshot.len() as u64).to_be_bytes());
        out.extend_from_slice(snapshot);
    }
    Ok(())
}

/// [`encode_windows`] back: with `world`, each window must be one of that
/// world's; without, a base window or a world window.
fn decode_windows(
    reader: &mut Reader<'_>,
    world: Option<EntityId>,
) -> Result<Vec<(WindowKey, Vec<u8>)>> {
    let mut windows = Vec::new();
    for _ in 0..reader.u32()? {
        let name = usize::from(reader.u16()?);
        let key = std::str::from_utf8(reader.take(name)?)
            .ok()
            .and_then(WindowKey::try_new)
            .filter(|key| world.is_none_or(|world| key.world() == Some(world)))
            .ok_or_else(malformed)?;
        let len = usize::try_from(reader.u64()?).map_err(|_| malformed())?;
        windows.push((key, reader.take(len)?.to_vec()));
    }
    Ok(windows)
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| malformed())?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn malformed() -> Error {
    refused("a sealed bundle section is malformed")
}

/// A forward reader over a section's payload.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(malformed)?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| malformed())
    }

    fn u8(&mut self) -> Result<u8> {
        self.array().map(u8::from_be_bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// Nothing may follow the last field.
    fn finish(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}
