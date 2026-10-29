//! The vault's sealed cloud bundle through the home (DEC-0005 "Sealed copies",
//! FIX 922). Once in each fixed UTC slot a machine of the owner's takes the
//! home's newest generation in when it is newer than the last one it took. An
//! eligible publisher then uploads a fresh generation for the slot when the
//! slot has none yet, changed or not, once it holds the home's publisher turn
//! (`turn`): in parts the home stages, then a commit on the parent it took. A
//! take runs on that cadence only, never on a world opening or changing, and a
//! missed slot is not replayed. The slot and the last generation taken persist
//! across restarts and re-homes.
//!
//! Erase rewrites every kept pad: each upkeep tick strips every world whose
//! keys were destroyed here, and each key a hard erase of its pad row staged,
//! from every pad object the home keeps that its proof does not name yet
//! (`sweep`, `Vault::drop_world_from_key_pads`, FIX 8868). A pad
//! object sealed before this machine was added does not open with its key: it
//! opens with a grant of its outer key an old reader sealed to it since, which
//! each upkeep tick serves before the sweep (`access`, FIX 4271), or with the
//! owner's recovery kit on request
//! ([`SyncClient::sweep_sealed_bundle_erases_with_kit`]).
//!
//! A commit names the recovery root the upload was sealed to, so a kit-only
//! restore can read the generation through the home's kit door (`kit_fetch`).
//!
//! A phone takes no generation in and uploads none, and no machine relays to a
//! home it knows is a phone (FIX 3349, `holds_sealed_bundle`). A phone still
//! sweeps its erases from the kept pad objects. The owner's own ask to publish
//! runs first, on the install it names in any role (`publication`).

mod access;
mod attempt;
mod entries;
mod pad_sweep;
mod publication;
mod refill;
mod relay_observation;
mod sweep;
mod turn;

pub use self::access::PadAdmissionReport;
pub(crate) use self::relay_observation::observe_sealed_bundle_relay;
pub use self::relay_observation::{SealedBundleRelayObservation, sealed_bundle_relay_observation};

use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::kit_fetch::KitHome;
use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, Destination, PeerMachine};
use crate::error::{Error, SecretError};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::residence::{
    SEALED_BUNDLE_PUT_PART_MAX, SEALED_BUNDLE_READ_PART_MAX, SealedBundleObject, SealedBundleTake,
    holds_sealed_bundle, sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex,
    sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{
    RecoveryRootId, RecoveryRootSeed, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle,
    sealed_bundle_slot,
};

/// The slot this machine last finished and the generation it last took in.
const CURSOR: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_CURSOR);
/// How many times, in one slot, a publisher whose parent went stale takes the
/// new newest generation in and uploads again.
const STALE_PARENT_RETRIES: usize = 1;
/// How many times, in one slot, a publisher whose upload the home refused on
/// an unchanged parent (its disk floor, a slot ahead of its clock, a turn that
/// lapsed) assembles and uploads again (CALLS:
/// SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT). Past it the slot is
/// finished, and the next slot uploads again (FIX 3353).
const SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT: usize = 0;
/// What a read of a kept pad object fails with when the home lacks its bytes
/// (FIX 7106): never a missing generation.
const PADS_UNAVAILABLE: &str = "the home lacks the kept pad object's bytes";

/// What a slot does when no capsule of the newest generation opens here, as on
/// a machine added since (CALLS: SEALED_BUNDLE_NO_CAPSULE_ACTION).
enum NoCapsuleAction {
    /// The slot is finished and the relay fails, nothing taken or uploaded (FIX
    /// 4410): a later slot takes a generation sealed to this machine (FIX 4274).
    DeferSlot,
}

const SEALED_BUNDLE_NO_CAPSULE_ACTION: NoCapsuleAction = NoCapsuleAction::DeferSlot;

/// The publisher call (FIX 922): every eligible machine asks for the home's
/// publisher turn each slot, the holder publishes, and the rest take its
/// generation in (FIX 3351). Eligible: a machine mine here (the caller's
/// check) that syncs everything, not an opened-item machine or a federation
/// lane.
fn may_publish(config: &SyncClientConfig) -> bool {
    config.residence_mode != SyncResidenceMode::Opened && config.federation_peer.is_none()
}

/// The home that keeps the bundle, as a world-privacy destination: the
/// machine it proved on this socket while that proof still stands here, else
/// unknown. A home that is a machine of the owner's also keeps the worlds
/// whose sealed copies go to "My machines" (`world_keys::bundle`).
fn holder_destination(vault: &Vault, home: PeerMachine) -> Destination {
    match vault.peer_machine_stands(home) {
        PeerMachine::Proven { machine, .. } => Destination::Machine(machine),
        PeerMachine::Unknown => Destination::Unknown,
    }
}

/// Whether the home may keep the vault's sealed copies: false for a home whose
/// proof stands here on a phone's profile, the one its proof stands on
/// (`AuthorityFold::machine_proof_key`). A home this machine cannot name
/// judges itself: its own doors refuse when it is a phone.
fn home_holds_sealed_bundle(vault: &Vault, home: PeerMachine) -> crate::error::Result<bool> {
    let PeerMachine::Proven { machine, .. } = vault.peer_machine_stands(home) else {
        return Ok(true);
    };
    let fold = vault.authority_fold()?;
    let class = match fold.trusted_machine(machine) {
        Some(trusted) => Some(trusted.profile.device_class),
        None => fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .filter(|roster| roster.is_live())
            .map(|roster| roster.profile.device_class),
    };
    Ok(class.is_none_or(holds_sealed_bundle))
}

/// What one bundle relay moved.
#[derive(Debug, Clone, Default)]
pub struct SealedBundleRelay {
    /// The newest generation taken in this slot, and what its take moved.
    pub taken: Option<(SealedBundleGeneration, SealedBundleTake)>,
    /// The generation this machine published for the slot.
    pub published: Option<SealedBundleGeneration>,
    /// Erased worlds and hard-erased keys stripped from every pad object the
    /// home keeps.
    pub erased: usize,
    /// Grants of a kept pad object's key this machine sealed for a machine
    /// admitted since its generation, and the home took (FIX 4271).
    pub offered: usize,
    /// Kept pad objects that open with no key here yet: their access is
    /// pending with the home. Never a swept erase.
    pub pending_pad_access: usize,
    /// Erased worlds and keys held back, unswept, while a kept pad object
    /// opens with no key here.
    pub pending_erases: usize,
    /// The relay reached the home; one that did not counted nothing (FIX 4953).
    pub reached: bool,
    /// Erase's sweep ran, so the two pending counts were counted (FIX 4953).
    pub swept: bool,
}

/// The entry a commit's reply names: what the home acknowledged.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleCommitReply {
    generation: String,
    bundle_digest: String,
}

/// A generation the home acknowledged committing, and its bundle's digest.
#[derive(Clone, Copy, Debug)]
struct CommittedBundle {
    generation: SealedBundleGeneration,
    bundle_digest: [u8; 32],
}

#[derive(Deserialize)]
struct BundleGetReply {
    generation: String,
    object: String,
    total: u64,
    digest: String,
    offset: u64,
    last: bool,
    part: String,
}

/// This machine's cursor: the slot it last finished (0 for none) and the
/// generation it last took in.
#[derive(Clone, Copy, Default)]
struct Cursor {
    slot: u64,
    taken: Option<SealedBundleGeneration>,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

fn upload_refused() -> TransportError {
    TransportError::Storage("home refused the sealed bundle upload".into())
}

fn load_cursor(vault: &Vault) -> crate::error::Result<Cursor> {
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = CURSOR.get(&vault.store, &txn, &())? else {
        return Ok(Cursor::default());
    };
    let (slot, taken) = raw.split_at_checked(8).ok_or(crate::Error::InvalidKey)?;
    Ok(Cursor {
        slot: u64::from_be_bytes(slot.try_into().map_err(|_| crate::Error::InvalidKey)?),
        taken: if taken.is_empty() {
            None
        } else {
            Some(SealedBundleGeneration::from_bytes(taken)?)
        },
    })
}

fn store_cursor(vault: &Vault, cursor: Cursor) -> crate::error::Result<()> {
    let mut raw = cursor.slot.to_be_bytes().to_vec();
    if let Some(taken) = cursor.taken {
        raw.extend_from_slice(&taken.to_bytes());
    }
    vault.with_write_txn_grouped(|wtxn| CURSOR.put(&vault.store, wtxn, &(), &raw))
}

impl SyncClient {
    /// Runs this machine's sealed bundle upkeep through the home (FIX 922):
    /// the late joiners' grants it can issue (FIX 4271), erase's sweep of
    /// every kept pad object, then, once per UTC slot, the take of the home's
    /// newest generation and, on an eligible publisher, the slot's upload. A
    /// federation lane and a machine not mine here do nothing; a phone grants
    /// and sweeps only, and a home known to be a phone gets no sweep or
    /// upload.
    pub async fn relay_sealed_bundle(&self) -> Result<SealedBundleRelay, TransportError> {
        relay_sealed_bundle(&self.manager, &self.config).await
    }

    /// Erase's sweep of every pad object the home keeps, opened with this
    /// machine's key, a grant sealed to it since (FIX 4271), or else `seed`,
    /// the owner's recovery kit (FIX 3355): a pad object sealed before this
    /// machine was added does not open with its key, and holds every erased
    /// world back each slot until one of those opens it. The kit serves this
    /// call alone; nothing keeps it. Sweeps every world erased here and every
    /// key a hard erase staged from each kept object its proof does not name
    /// yet, held back this slot or not, and reports how many a kept object
    /// held, and what still waits. A federation lane and a machine not mine
    /// here sweep nothing, nor does a home known to be a phone, which keeps
    /// none.
    pub async fn sweep_sealed_bundle_erases_with_kit(
        &self,
        seed: &RecoveryRootSeed,
    ) -> Result<SealedBundleRelay, TransportError> {
        let vault = &self.vault;
        let mut relay = SealedBundleRelay::default();
        if self.config.federation_peer.is_some()
            || !vault
                .local_machine()
                .map_err(storage)?
                .is_some_and(|machine| machine.mine)
        {
            return Ok(relay);
        }
        let now_slot = sealed_bundle_slot(vault.store.clock.now_recorded_at());
        let owed = pad_sweep::owed_subjects(vault).map_err(storage)?;
        if owed.is_empty() {
            return Ok(relay);
        }
        // Held back in this slot counts as owed too.
        let slots = (now_slot, now_slot.saturating_add(1));
        let due = owed.iter().any(|owed| owed.due_unlisted(slots.1));
        let connected = match residence_budgets(vault) {
            Ok(budgets) => ResidenceRpc::connect(vault, &self.config, budgets).await,
            Err(error) => Err(error),
        };
        let mut rpc = match connected {
            Ok(Some(rpc)) => rpc,
            // With nothing due whatever the home lists, a home out of reach
            // is no failure.
            _ if !due => return Ok(relay),
            Ok(None) => return Err(TransportError::Storage("home node offline".into())),
            Err(error) => return Err(error),
        };
        relay.reached = true;
        if home_holds_sealed_bundle(vault, rpc.home).map_err(storage)? {
            sweep::sweep_erased(vault, &mut rpc, owed, slots, Some(seed), &mut relay).await?;
            relay.swept = true;
        }
        Ok(relay)
    }

    /// One generation's bundle and pad object as the home keeps them, for a
    /// restore from the cloud copy: `generation` names one, `None` the newest.
    /// `None` when the home keeps no such generation.
    pub async fn fetch_sealed_bundle(
        &self,
        generation: Option<SealedBundleGeneration>,
    ) -> Result<Option<(SealedVaultBundle, SealedKeyPads)>, TransportError> {
        let budgets = residence_budgets(&self.vault)?;
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        fetch_generation(&mut PartSource::Machine(&mut rpc), generation).await
    }
}

/// [`SyncClient::relay_sealed_bundle`] on the window manager and a client
/// config alone, for a task off the live sync loop. Every tick reaches for
/// the home, an erase or a slot due or not, so an old reader serves the
/// admissions waiting there (FIX 4271); a home out of reach is no error
/// unless an erase or the slot was due.
pub(crate) async fn relay_sealed_bundle(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<SealedBundleRelay, TransportError> {
    let vault = manager.vault();
    let mut relay = SealedBundleRelay::default();
    publication::publish_asked(manager, config).await;
    if config.federation_peer.is_some()
        || !vault
            .local_machine()
            .map_err(storage)?
            .is_some_and(|machine| machine.mine)
    {
        return Ok(relay);
    }
    let now_slot = sealed_bundle_slot(vault.store.clock.now_recorded_at());
    let cursor = load_cursor(vault).map_err(storage)?;
    let owed = pad_sweep::owed_subjects(vault).map_err(storage)?;
    let erase_due = owed.iter().any(|owed| owed.due_unlisted(now_slot));
    // A phone takes no generation in and uploads none (FIX 3349).
    let slot_due = cursor.slot < now_slot && holds_sealed_bundle(vault.config.machine_device_class);
    let connected = match residence_budgets(vault) {
        Ok(budgets) => ResidenceRpc::connect(vault, config, budgets).await,
        Err(error) => Err(error),
    };
    let mut rpc = match connected {
        Ok(Some(rpc)) => rpc,
        // With no erase or slot due, a home out of reach is no failure: the
        // next tick serves the admissions.
        _ if !erase_due && !slot_due => return Ok(relay),
        Ok(None) => return Err(TransportError::Storage("home node offline".into())),
        Err(error) => return Err(error),
    };
    relay.reached = true;
    // The admissions first: an old reader with no erase or slot work still
    // grants (FIX 4271). A home that refuses them still takes the rest.
    match access::serve_admissions(vault, &mut rpc).await {
        Ok(offered) => relay.offered = offered,
        Err(TransportError::InvalidPayload(_)) => {}
        Err(error) => return Err(error),
    }
    // A home this machine knows is a phone keeps no sealed copy: nothing goes
    // to it, and the slot is finished.
    if !home_holds_sealed_bundle(vault, rpc.home).map_err(storage)? {
        if slot_due {
            let cursor = Cursor {
                slot: now_slot,
                ..cursor
            };
            store_cursor(vault, cursor).map_err(storage)?;
        }
        return Ok(relay);
    }
    // Each erase is swept from the kept objects its proof does not name yet,
    // one committed since an earlier sweep included (FIX 8868).
    if !owed.is_empty() {
        let slots = (now_slot, now_slot);
        sweep::sweep_erased(vault, &mut rpc, owed, slots, None, &mut relay).await?;
        relay.swept = true;
    }
    if slot_due {
        let slot = SlotRelay {
            manager,
            slot: now_slot,
            mode: config.residence_mode,
            publisher: may_publish(config),
        };
        slot.run(&mut rpc, cursor, &mut relay).await?;
    }
    Ok(relay)
}

/// One slot's take and upload.
struct SlotRelay<'a> {
    manager: &'a Arc<WindowManager>,
    slot: u64,
    /// The host's configured mode. An opened-item machine's take keeps
    /// windows in their mirror.
    mode: SyncResidenceMode,
    publisher: bool,
}

impl SlotRelay<'_> {
    /// Takes the newest generation in when it is newer than the last taken,
    /// then publishes the slot's generation when the slot has none, this
    /// machine publishes and it holds the publisher turn. A publisher asks for
    /// the turn even once the slot is won, so it waits its turn for the next
    /// one. A take that fails here uploads nothing this slot: the upload would
    /// carry less than the home holds. The slot is finished once its upload is
    /// in, another machine's is, the take or the assembly failed here, or the
    /// home refused the upload on an unchanged parent past
    /// [`SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT`]; a machine waiting
    /// for the turn, or whose upload did not reach the home, tries again next
    /// tick. A take no capsule here opens fails, after a publisher gives up its
    /// turn ([`SEALED_BUNDLE_NO_CAPSULE_ACTION`]).
    async fn run(
        &self,
        rpc: &mut ResidenceRpc,
        mut cursor: Cursor,
        relay: &mut SealedBundleRelay,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let holder = holder_destination(vault, rpc.home);
        // The newest generation's objects, once fetched: an upload carries
        // what this machine cannot read from them.
        let mut held: Option<(SealedVaultBundle, SealedKeyPads)> = None;
        let mut retries = 0;
        let mut refusals = 0;
        loop {
            let listed = list_generations(rpc).await?;
            let latest = listed.first().copied();
            if let Some(newest) = latest.filter(|newest| {
                cursor
                    .taken
                    .is_none_or(|taken| entries::newer_than_taken(newest, taken, &listed))
            }) {
                let (bundle, pads) = fetch_generation(&mut PartSource::Machine(rpc), Some(newest))
                    .await?
                    .ok_or_else(refused)?;
                let manager = Arc::clone(self.manager);
                let opened = self.mode == SyncResidenceMode::Opened;
                let (took, bundle, pads) = tokio::task::spawn_blocking(move || {
                    let took = manager.take_sealed_bundle(&bundle, &pads, holder, opened);
                    (took, bundle, pads)
                })
                .await
                .map_err(|error| TransportError::Storage(error.to_string()))?;
                match took {
                    Ok(take) => {
                        cursor.taken = Some(newest);
                        relay.taken = Some((newest, take));
                    }
                    // Not taken: the next slot takes it again before any
                    // upload (FIX 3358).
                    Err(error) => {
                        cursor.slot = self.slot;
                        store_cursor(vault, cursor).map_err(storage)?;
                        if !matches!(error, Error::Secret(SecretError::SealedBundleNoCapsule)) {
                            return Err(storage(error));
                        }
                        match SEALED_BUNDLE_NO_CAPSULE_ACTION {
                            // The next machine waiting need not wait out the lease.
                            NoCapsuleAction::DeferSlot => {
                                if self.publisher {
                                    let _ = turn::ask_turn(rpc, true).await;
                                }
                                return Err(storage(error));
                            }
                        }
                    }
                }
                store_cursor(vault, cursor).map_err(storage)?;
                held = Some((bundle, pads));
            }
            if !self.publisher || latest.is_some_and(|newest| newest.slot >= self.slot) {
                if self.publisher {
                    turn::ask_turn(rpc, false).await?;
                }
                break;
            }
            // Another machine holds the turn: its generation comes in on a
            // later tick, or its turn lapses.
            if !turn::ask_turn(rpc, false).await? {
                return Ok(());
            }
            if let Some(newest) = latest
                && held
                    .as_ref()
                    .is_none_or(|(bundle, _)| bundle.generation() != newest)
            {
                held = Some(
                    fetch_generation(&mut PartSource::Machine(rpc), Some(newest))
                        .await?
                        .ok_or_else(refused)?,
                );
                // A long fetch renews the turn once it ends.
                if !turn::ask_turn(rpc, false).await? {
                    return Ok(());
                }
            }
            let manager = Arc::clone(self.manager);
            let slot = self.slot;
            // A full machine lands what the assembly merges (FIX 4788).
            let materialize = self.mode == SyncResidenceMode::All;
            let (upload, back) = turn::renewing_turn(rpc, move || {
                let upload = manager.assemble_sealed_bundle(
                    slot,
                    holder,
                    held.as_ref().map(|(bundle, pads)| (bundle, pads)),
                    None,
                    materialize,
                );
                (upload, held)
            })
            .await?;
            held = back;
            let upload = match upload {
                Ok(upload) => upload,
                Err(error) => {
                    cursor.slot = self.slot;
                    store_cursor(vault, cursor).map_err(storage)?;
                    // The next machine waiting need not wait out the lease.
                    let _ = turn::ask_turn(rpc, true).await;
                    return Err(storage(error));
                }
            };
            let generation = upload.bundle.generation();
            if put_object(
                rpc,
                &generation,
                SealedBundleObject::Bundle,
                upload.bundle.as_bytes(),
            )
            .await?
                && put_object(
                    rpc,
                    &generation,
                    SealedBundleObject::Pads,
                    upload.pads.as_bytes(),
                )
                .await?
                && commit_generation(rpc, &generation, latest, upload.kit_root, None)
                    .await?
                    .is_some()
            {
                cursor.taken = Some(generation);
                relay.published = Some(generation);
                break;
            }
            // A refused upload: when the newest generation moved meanwhile,
            // the parent went stale.
            let moved = list_generations(rpc).await?.first().copied() != latest;
            if moved {
                if retries == STALE_PARENT_RETRIES {
                    return Err(upload_refused());
                }
                retries += 1;
            } else {
                if refusals == SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT {
                    cursor.slot = self.slot;
                    store_cursor(vault, cursor).map_err(storage)?;
                    let _ = turn::ask_turn(rpc, true).await;
                    return Err(upload_refused());
                }
                refusals += 1;
            }
        }
        cursor.slot = self.slot;
        store_cursor(vault, cursor).map_err(storage)
    }
}

/// The generations the home keeps, newest first.
async fn list_generations(
    rpc: &mut ResidenceRpc,
) -> Result<Vec<SealedBundleGeneration>, TransportError> {
    list_generations_for(rpc, None).await
}

/// [`list_generations`], naming the owner's `request` this install is asked
/// to publish for, which the home admits it under in any role. Newest first
/// by commit order (FIX 8885).
async fn list_generations_for(
    rpc: &mut ResidenceRpc,
    request: Option<AuthorityEntryHash>,
) -> Result<Vec<SealedBundleGeneration>, TransportError> {
    Ok(entries::list_entries(rpc, request)
        .await?
        .into_iter()
        .map(|entry| entry.generation)
        .collect())
}

/// Where a read's slices come from: this machine's residence socket, or the
/// home's kit door for a restore with the kit alone (`kit_fetch`).
pub(super) enum PartSource<'a> {
    Machine(&'a mut ResidenceRpc),
    /// The same socket, naming the owner's request this install is asked to
    /// publish for, which the home admits it under in any role.
    Asked(&'a mut ResidenceRpc, AuthorityEntryHash),
    Kit(&'a KitHome),
}

impl PartSource<'_> {
    /// One slice of a kept object from `offset`, as the home sends it:
    /// `generation` names one, `None` the newest. A refused or missing slice
    /// is `InvalidPayload`.
    async fn get(
        &mut self,
        generation: Option<SealedBundleGeneration>,
        object: SealedBundleObject,
        offset: u64,
    ) -> Result<serde_json::Value, TransportError> {
        let (rpc, request) = match self {
            Self::Machine(rpc) => (rpc, None),
            Self::Asked(rpc, request) => (rpc, Some(*request)),
            Self::Kit(home) => return home.part(generation, object, offset).await,
        };
        let mut params = json!({
            "generation": generation.as_ref().map(sealed_generation_hex),
            "object": object.name(),
            "offset": offset,
        });
        if let Some(request) = request {
            params["request"] = json!(sealed_digest_hex(&request));
        }
        rpc.request("residence.bundle.get", params).await
    }
}

/// Reads one kept object in slices: `generation` names one, `None` the newest.
/// A kept pad object whose bytes the home lacks keeps the home's typed answer
/// (`refill`, FIX 9362).
async fn read_object(
    source: &mut PartSource<'_>,
    generation: Option<SealedBundleGeneration>,
    object: SealedBundleObject,
) -> Result<refill::ObjectRead, TransportError> {
    let mut named = generation;
    let mut bytes = Vec::new();
    let mut whole: Option<(u64, [u8; 32])> = None;
    loop {
        let reply = match source.get(named, object, bytes.len() as u64).await {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) if bytes.is_empty() => {
                return Ok(refill::ObjectRead::Missing);
            }
            Err(error) => return Err(error),
        };
        if let Some(unavailable) = refill::unavailable_of(&reply) {
            return unavailable.map(refill::ObjectRead::PadsUnavailable);
        }
        let reply: BundleGetReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let generation = sealed_generation_from_hex(&reply.generation).ok_or_else(refused)?;
        let digest = sealed_digest_from_hex(&reply.digest).ok_or_else(refused)?;
        if named.is_some_and(|named| named != generation)
            || reply.object != object.name()
            || reply.offset != bytes.len() as u64
            || *whole.get_or_insert((reply.total, digest)) != (reply.total, digest)
        {
            return Err(refused());
        }
        named = Some(generation);
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if part.is_empty()
            || part.len() > SEALED_BUNDLE_READ_PART_MAX
            || bytes.len() as u64 + part.len() as u64 > reply.total
        {
            return Err(refused());
        }
        bytes.extend_from_slice(&part);
        let done = bytes.len() as u64 == reply.total;
        if reply.last != done {
            return Err(refused());
        }
        if done {
            if *blake3::hash(&bytes).as_bytes() != digest {
                return Err(refused());
            }
            return Ok(refill::ObjectRead::Whole(generation, bytes));
        }
    }
}

/// One kept generation's bundle and pad object: `generation` names one, `None`
/// the newest. `None` when the home keeps no such generation.
pub(super) async fn fetch_generation(
    source: &mut PartSource<'_>,
    generation: Option<SealedBundleGeneration>,
) -> Result<Option<(SealedVaultBundle, SealedKeyPads)>, TransportError> {
    let Some((generation, bytes)) = read_object(source, generation, SealedBundleObject::Bundle)
        .await?
        .whole()?
    else {
        return Ok(None);
    };
    let bundle = SealedVaultBundle::from_bytes(&bytes).map_err(|_| refused())?;
    drop(bytes);
    let Some((_, bytes)) = read_object(source, Some(generation), SealedBundleObject::Pads)
        .await?
        .whole()?
    else {
        return Ok(None);
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
    if bundle.generation() != generation || pads.generation() != generation {
        return Err(refused());
    }
    Ok(Some((bundle, pads)))
}

/// Stages one object on the home in parts; `false` when the home refused a
/// part (FIX 3353). A part that did not reach the home is an error.
async fn put_object(
    rpc: &mut ResidenceRpc,
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    bytes: &[u8],
) -> Result<bool, TransportError> {
    let generation = sealed_generation_hex(generation);
    let digest = sealed_digest_hex(blake3::hash(bytes).as_bytes());
    let mut offset = 0;
    for part in bytes.chunks(SEALED_BUNDLE_PUT_PART_MAX) {
        let staged = rpc
            .call(
                "residence.bundle.put",
                json!({
                    "generation": generation.as_str(),
                    "object": object.name(),
                    "total": bytes.len(),
                    "digest": digest.as_str(),
                    "offset": offset,
                    "part": base64::engine::general_purpose::STANDARD.encode(part),
                }),
            )
            .await?;
        if staged.is_err() {
            return Ok(false);
        }
        offset += part.len();
    }
    Ok(true)
}

/// Commits the generation staged here on `parent`, naming `root`, the
/// recovery root whose kit may read it, and `request`, the owner's ask it
/// publishes for, which the home records it under (FIX 4787): the entry the
/// home acknowledged, or `None` when the home refused it. A commit that did
/// not reach the home, or a reply naming no entry, is an error.
async fn commit_generation(
    rpc: &mut ResidenceRpc,
    generation: &SealedBundleGeneration,
    parent: Option<SealedBundleGeneration>,
    root: Option<RecoveryRootId>,
    request: Option<AuthorityEntryHash>,
) -> Result<Option<CommittedBundle>, TransportError> {
    let mut params = json!({
        "generation": sealed_generation_hex(generation),
        "parent": parent.as_ref().map(sealed_generation_hex),
        "root": root.as_ref().map(|root| sealed_digest_hex(&root.0)),
    });
    if let Some(request) = request {
        params["request"] = json!(sealed_digest_hex(&request));
    }
    let Ok(reply) = rpc.call("residence.bundle.commit", params).await? else {
        return Ok(None);
    };
    let reply: BundleCommitReply = serde_json::from_value(reply).map_err(|_| refused())?;
    Ok(Some(CommittedBundle {
        generation: sealed_generation_from_hex(&reply.generation).ok_or_else(refused)?,
        bundle_digest: sealed_digest_from_hex(&reply.bundle_digest).ok_or_else(refused)?,
    }))
}

/// Replaces one kept pad object with its rewrite, on the digest of the object
/// it was made from; `false` when the home refused.
async fn replace_pads(
    rpc: &mut ResidenceRpc,
    old: &SealedKeyPads,
    new: &SealedKeyPads,
) -> Result<bool, TransportError> {
    let generation = new.generation();
    if !put_object(rpc, &generation, SealedBundleObject::Pads, new.as_bytes()).await? {
        return Ok(false);
    }
    match rpc
        .request(
            "residence.bundle.pads.replace",
            json!({
                "generation": sealed_generation_hex(&generation),
                "replaces": sealed_digest_hex(&old.digest()),
            }),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(TransportError::InvalidPayload(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
