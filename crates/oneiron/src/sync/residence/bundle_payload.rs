//! What the vault's sealed cloud bundle carries (FIX 922 PR 2): the base section
//! and the section of each world the bundle carries for its holder that a
//! publisher seals, and how a reader takes a bundle back in. The carrier is `world_keys::bundle`; the holder and the wire
//! are `residence::bundle` and the residence client's.
//!
//! - The base section is base reality as the owner's machines hold it: the signed
//!   authority history, then every base window and every window of a world read
//!   everywhere, each the whole history-free snapshot the export door cuts for a
//!   machine that may read no private world. It carries no world key pad row:
//!   pads ride only the pad object, so erase's rewrite reaches every kept bundle.
//! - A world section is every window of one carried world, each the whole mirror
//!   this machine keeps for it. A holder that is a machine of the owner's also
//!   gets the worlds whose sealed copies go to "My machines"
//!   (`world_keys::bundle`).
//! - A publisher seals a fresh section of each carried world it reads, and
//!   carries every other section of the latest generation byte for byte, except
//!   the ones it opens of a world no longer eligible for this holder or deleted
//!   here.
//! - A take opens the sections this machine may read and merges each window into
//!   its mirror. It never reads the base section: base syncs live between the
//!   owner's machines. A kit restore reads it all, on an install with no machine
//!   of its own yet ([`WindowManager::restore_sealed_bundle_with_kit`]).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use loro::LoroDoc;
use zeroize::Zeroizing;

use super::discover_local_window_keys;
use super::policy::resolve_residence_mode;
use crate::Vault;
use crate::authority::{Destination, EditOrigin, EffectiveRead};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::ports::TombstoneStoreRead;
use crate::sync::loro_support::{import_doc, map_delete, map_for_each_value_bytes};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::{
    apply_pending_window_updates, export_history_free_window_snapshot, export_window_replacement,
    load_window_from_state, reverse_rematerialize,
};
use crate::sync::{SyncResidenceMode, WindowManager};
use crate::world_keys::{
    KitConfirmation, OpenedBundleSection, RecoveryRootSeed, RootRestore, SealedKeyPads,
    SealedVaultBundle, SealedVaultUpload, pad_body_world, refused, world_keys_destroyed_in_txn,
};

/// The base section's encoding version.
const SEALED_BUNDLE_BASE_VERSION: u8 = 1;
/// A world section's encoding version.
const SEALED_BUNDLE_WORLD_VERSION: u8 = 1;
const BASE_LABEL: &[u8] = b"oneiron/sealed-bundle-base\0";
const WORLD_LABEL: &[u8] = b"oneiron/sealed-bundle-world\0";

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

/// What a kit restore from the sealed cloud bundle did.
#[derive(Debug, Default)]
pub struct SealedKitRestore {
    /// What the world keys' restore did with each key wrapped to the kit's
    /// root: usable here, kept on another machine, or withheld.
    pub keys: RootRestore,
    /// Signed authority entries the base section carried.
    pub authority: usize,
    /// Windows of the base section installed here.
    pub windows: usize,
    /// Windows of the base section that did not install.
    pub windows_skipped: usize,
    /// Pads stored here from the pad object.
    pub pads: usize,
    /// What the world sections moved.
    pub take: SealedBundleTake,
}

impl WindowManager {
    /// Seals this machine's upload for UTC slot `slot`, for `holder`, the home
    /// that keeps it: the base section, a fresh section of every world the
    /// bundle carries for `holder` that this machine reads, and every other
    /// section of `latest` (the holder's newest generation and its pad object)
    /// unchanged, minus the sections of worlds this machine reads that are no
    /// longer eligible for `holder`. Refused on an opened-item machine.
    pub fn assemble_sealed_bundle(
        &self,
        slot: u64,
        holder: Destination,
        latest: Option<(&SealedVaultBundle, &SealedKeyPads)>,
    ) -> Result<SealedVaultUpload> {
        let vault = self.vault();
        // Judged from what this machine keeps, as its connection judges it, with
        // the host's default mode for a machine the owner never chose for.
        if resolve_residence_mode(vault, SyncResidenceMode::default())? == SyncResidenceMode::Opened
        {
            return Err(refused("an opened-item machine seals no bundle"));
        }
        let windows = discover_local_window_keys(vault)?;
        let base = self.sealed_bundle_base(&windows)?;
        let eligible = vault.sealed_bundle_worlds(holder)?;
        let mut fresh = Vec::new();
        for &world in &eligible {
            // A world this machine does not read now keeps the section it has.
            if vault.world_key(world).is_err() {
                continue;
            }
            let mut snapshots = Vec::new();
            for window in windows
                .iter()
                .filter(|window| window.world() == Some(world))
            {
                snapshots.push((window.clone(), self.sealed_mirror_snapshot(world, window)?));
            }
            fresh.push((world, encode_world_section(world, &snapshots)?));
        }
        let (carried, latest_pads) = match latest {
            None => (Vec::new(), None),
            Some((bundle, pads)) => {
                let opened = vault.open_vault_bundle_to_carry(bundle)?;
                let pads = vault.open_key_pads(pads)?;
                if pads.generation() != opened.generation() {
                    return Err(refused("the pad object is another generation's"));
                }
                // The sections this machine opens go unless their world is still
                // eligible for this holder, was not deleted here and has no fresh
                // one.
                let keys = vault.bundle_reader_keys(Some(&pads), true)?;
                let mut dropped = Vec::new();
                for key in &keys {
                    let world = key.id().world;
                    if fresh.iter().any(|(sealed, _)| *sealed == world)
                        || !eligible.contains(&world)
                        || deleted_here(vault, world)?
                    {
                        dropped.push(key);
                    }
                }
                (opened.sections_except(&dropped), Some(pads))
            }
        };
        let worlds: Vec<(EntityId, &[u8])> = fresh
            .iter()
            .map(|(world, payload)| (*world, payload.as_slice()))
            .collect();
        vault.seal_vault_bundle_carrying(
            slot,
            holder,
            &base,
            &worlds,
            &carried,
            latest_pads.as_ref(),
        )
    }

    /// Takes `bundle` and its pad object in: opens every section this machine
    /// may read and merges each window into its mirror. A full machine
    /// materializes the rows; an `opened`-item machine keeps them in the mirror
    /// until a promotion materializes it.
    pub fn take_sealed_bundle(
        &self,
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        opened: bool,
    ) -> Result<SealedBundleTake> {
        let vault = self.vault();
        let outer = vault.open_vault_bundle(bundle)?;
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
    /// authority history goes in first, so the root's wraps and every world's
    /// policy are here. Once a machine the owner vouched for proves to have
    /// signed the bundle, each base window installs as a replacement. The pad
    /// object's pads are stored, the world keys restore from the kit as
    /// [`Vault::restore_world_keys`] restores them (`owner`, `confirm`), and
    /// each section the kit opens merges into its windows' mirrors and
    /// materializes, for the worlds this machine may read now. The keys report
    /// names the keys usable here, those that need a re-home and those
    /// withheld.
    pub fn restore_sealed_bundle_with_kit(
        self: &Arc<Self>,
        owner: &AuthenticatedOwner,
        vault_id: &[u8; 32],
        bundle: &SealedVaultBundle,
        pads: &SealedKeyPads,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<SealedKitRestore> {
        let vault = self.vault();
        refuse_machine_of_the_vault(vault, vault_id)?;
        let opened = bundle.open_with_kit(vault_id, seed)?;
        let pads = pads.open_with_kit(vault_id, seed)?;
        if pads.generation() != opened.generation() {
            return Err(refused("the pad object is another generation's"));
        }
        let base = decode_base(opened.base())?;
        let mut restore = SealedKitRestore {
            authority: base.authority.len(),
            ..SealedKitRestore::default()
        };
        vault.import_signed_authority_history(&base.authority)?;
        {
            let txn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            if fold.vault_id != Some(*vault_id) {
                return Err(refused("the bundle's authority is another vault's"));
            }
            if !opened.signed_by_owner_machine(&fold) {
                return Err(refused("no machine of the owner's signed the bundle"));
            }
        }
        // Base windows first: a window of a world read everywhere may name a
        // base row.
        let mut windows = base.windows;
        windows.sort_by_key(|(key, _)| key.world().is_some());
        for (key, snapshot) in &windows {
            match self.replace_window(key, snapshot, &HashMap::new()) {
                Ok((window, _)) => {
                    drop(window);
                    // A restore leaves no window open.
                    self.unload_window(key)?;
                    restore.windows += 1;
                }
                Err(_) => restore.windows_skipped += 1,
            }
        }
        restore.pads = vault.restore_key_pads(&pads)?;
        restore.keys = vault.restore_world_keys(owner, EditOrigin::ThisMachine, seed, confirm)?;
        for section in vault.open_vault_bundle_sections_with_kit(&opened, &pads, seed)? {
            self.take_section(&section, true, &mut restore.take);
        }
        Ok(restore)
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

    /// The base section ([`encode_base`]): the signed authority history, then
    /// each of `windows` that is a base window or a window of a world read
    /// everywhere.
    fn sealed_bundle_base(&self, windows: &[WindowKey]) -> Result<Zeroizing<Vec<u8>>> {
        let vault = self.vault();
        // The rows held here: a vault not yet hydrated holds no covered row.
        let authority = super::held_authority_history(vault)?;
        let public: BTreeSet<EntityId> = {
            let txn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            windows
                .iter()
                .filter_map(WindowKey::world)
                .filter(|world| fold.world_privacy(*world).read == EffectiveRead::Everywhere)
                .collect()
        };
        let mut snapshots = Vec::new();
        for key in windows {
            if key.world().is_some_and(|world| !public.contains(&world)) {
                continue;
            }
            if let Some(snapshot) = self.base_window_snapshot(key)? {
                snapshots.push((key.clone(), snapshot));
            }
        }
        encode_base(&authority, &snapshots)
    }

    /// `key`'s whole state as the export door cuts it for a machine that may
    /// read no private world, less its world key pad rows: the history-free
    /// replacement of a copy of the window (the live one, else its durable
    /// state) holding every row of the window here. `None` for a window that
    /// ships nothing.
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
        without_pad_rows(snapshot).map(Some)
    }
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

/// `snapshot` with no world key pad row: pads ride only the pad object. A
/// snapshot that held one is cut again, history-free at its newest operation, so
/// the pad's bytes are not in it.
fn without_pad_rows(snapshot: Vec<u8>) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    import_doc(&doc, &snapshot)?;
    let entities = doc.get_map("entities");
    let mut pads = Vec::new();
    map_for_each_value_bytes(&entities, |key, raw| {
        if raw.is_some_and(|raw| pad_body_world(raw).is_some()) {
            pads.push(key.to_owned());
        }
    });
    if pads.is_empty() {
        return Ok(snapshot);
    }
    for key in &pads {
        map_delete(&entities, key)?;
    }
    crate::sync::row_birth::drop_orphan_births(&doc)?;
    export_history_free_window_snapshot(&doc)
}

/// What a base section holds.
struct BundleBase {
    /// The signed authority entries, parents first.
    authority: Vec<Vec<u8>>,
    windows: Vec<(WindowKey, Vec<u8>)>,
}

/// label ‖ version (1) ‖ authority entry count (4) ‖ each entry `u32`-length-
/// prefixed ‖ windows ([`encode_windows`]).
fn encode_base(
    authority: &[Vec<u8>],
    windows: &[(WindowKey, Vec<u8>)],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(BASE_LABEL);
    out.push(SEALED_BUNDLE_BASE_VERSION);
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
    let mut authority = Vec::new();
    for _ in 0..reader.u32()? {
        let len = reader.u32()? as usize;
        authority.push(reader.take(len)?.to_vec());
    }
    let windows = decode_windows(&mut reader, None)?;
    reader.finish()?;
    Ok(BundleBase { authority, windows })
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
