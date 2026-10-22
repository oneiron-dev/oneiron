//! This machine's side of a late joiner's access to kept pad objects (FIX
//! 4271), over the home's one `residence.bundle.access` door:
//!
//! - Each upkeep, before erase's sweep ([`SEALED_PAD_GRANT_FULFIL`]), the
//!   admissions queued here go to the home, then this machine issues each
//!   pending grant it can: it opens the generation's current pad object
//!   itself, checks the recipient under its own authority, seals the outer
//!   key to it and offers the grant.
//! - Erase's sweep fetches this machine's own grant of each kept object its
//!   capsule does not open, uses it only once its key opens the current
//!   object, and asks the home for any it lacks or could not use.
//! - [`SyncClient::grant_sealed_bundle_pad_access_with_kit`] issues every kept
//!   generation's grant with the owner's kit, for a recipient no old reader
//!   serves yet.

use std::collections::BTreeMap;

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    PartSource, ResidenceRpc, SyncClient, list_generations, read_object, refused,
    residence_budgets, storage,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, SecretError};
use crate::sync::residence::{
    SealedBundleObject, sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex,
    sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{
    PadAdmissionTarget, RecoveryRootId, RecoveryRootSeed, SealedBundleGeneration, SealedKeyPads,
    SealedPadAdmissionGrant,
};

const ACCESS_RPC: &str = "residence.bundle.access";

/// When a machine serves admissions (CALLS: SEALED_PAD_GRANT_FULFIL).
enum GrantFulfil {
    /// Every upkeep tick, after authority catch-up and before erase's sweep,
    /// whether an erase or a slot is due or not: an old reader with neither
    /// still serves the admissions waiting on the home. No timer of its own.
    EveryUpkeepBeforeSweep,
}

const SEALED_PAD_GRANT_FULFIL: GrantFulfil = GrantFulfil::EveryUpkeepBeforeSweep;

/// What [`SyncClient::grant_sealed_bundle_pad_access_with_kit`] did, by kept
/// generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PadAdmissionReport {
    /// Generations whose grant the home took.
    pub offered: Vec<SealedBundleGeneration>,
    /// Of those, the ones whose grant this machine opened the current pad
    /// object with: only when the recipient is this machine. An offered grant
    /// is not yet access.
    pub usable: Vec<SealedBundleGeneration>,
    /// Generations the kit did not open, or whose offer the home refused:
    /// pending with the home for an old reader.
    pub pending: Vec<SealedBundleGeneration>,
}

/// The generations erase's sweep found no usable grant of, to ask the home
/// for: none held, or only offers that did not open.
#[derive(Default)]
pub(super) struct OwnAsks {
    missing: Vec<SealedBundleGeneration>,
    invalid: Vec<SealedBundleGeneration>,
}

#[derive(Deserialize)]
struct TakenReply {
    taken: Vec<TargetWire>,
}

#[derive(Deserialize)]
struct TargetWire {
    machine: String,
    key: String,
}

#[derive(Deserialize)]
struct PendingReply {
    pending: Vec<PendingWire>,
    /// Generations this machine waits on a grant of itself.
    waiting: Vec<String>,
}

#[derive(Deserialize)]
struct PendingWire {
    generation: String,
    machine: String,
    key: String,
    root: Option<String>,
}

#[derive(Deserialize)]
struct GetReply {
    grants: Vec<GrantWire>,
}

#[derive(Deserialize)]
struct GrantWire {
    key: String,
    grant: Option<String>,
}

fn target_json(target: &PadAdmissionTarget) -> Value {
    json!({
        "machine": target.machine.to_hex(),
        "key": sealed_digest_hex(&target.encryption_key_digest),
    })
}

fn target_from_wire(machine: &str, key: &str) -> Result<PadAdmissionTarget, TransportError> {
    Ok(PadAdmissionTarget {
        machine: crate::EntityId::from_hex(machine).map_err(|_| refused())?,
        encryption_key_digest: sealed_digest_from_hex(key).ok_or_else(refused)?,
    })
}

/// One upkeep's admissions ([`SEALED_PAD_GRANT_FULFIL`]): the admissions
/// queued here go to the home, then each pending grant this machine can issue
/// is sealed and offered. A generation whose grant this machine waits on
/// itself is fetched too (FIX 4566): the home's request for it is no proof
/// its capsule does not open the object. A failure on such a generation
/// leaves its grants for a later tick, and what this machine lacks there is
/// its sweep's to ask. Any other generation it finds it cannot open, it asks
/// access to. Returns how many grants the home took.
pub(super) async fn serve_admissions(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
) -> Result<usize, TransportError> {
    match SEALED_PAD_GRANT_FULFIL {
        GrantFulfil::EveryUpkeepBeforeSweep => {}
    }
    let queued = vault.queued_pad_admissions().map_err(storage)?;
    if !queued.is_empty() {
        let targets: Vec<Value> = queued.iter().map(target_json).collect();
        let reply = rpc
            .request(ACCESS_RPC, json!({"op": "ensure", "targets": targets}))
            .await?;
        let reply: TakenReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let taken = reply
            .taken
            .iter()
            .map(|target| target_from_wire(&target.machine, &target.key))
            .collect::<Result<Vec<_>, _>>()?;
        vault.acknowledge_pad_admissions(&taken).map_err(storage)?;
    }
    let reply = rpc.request(ACCESS_RPC, json!({"op": "pending"})).await?;
    let reply: PendingReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let waiting = reply
        .waiting
        .iter()
        .map(|generation| sealed_generation_from_hex(generation).ok_or_else(refused))
        .collect::<Result<Vec<_>, _>>()?;
    let mut by_generation: BTreeMap<SealedBundleGeneration, Vec<_>> = BTreeMap::new();
    for row in &reply.pending {
        let generation = sealed_generation_from_hex(&row.generation).ok_or_else(refused)?;
        let parsed = target_from_wire(&row.machine, &row.key).and_then(|target| {
            let root = row
                .root
                .as_deref()
                .map(|root| {
                    sealed_digest_from_hex(root)
                        .map(RecoveryRootId)
                        .ok_or_else(refused)
                })
                .transpose()?;
            Ok((target, root))
        });
        let (target, root) = match parsed {
            Ok(parsed) => parsed,
            // A generation this machine waits on itself went unread before:
            // a row of it that does not parse is passed over.
            Err(_) if waiting.contains(&generation) => continue,
            Err(error) => return Err(error),
        };
        by_generation
            .entry(generation)
            .or_default()
            .push((target, root));
    }
    let mut offered = 0;
    let mut asks = OwnAsks::default();
    for (generation, targets) in by_generation {
        if !waiting.contains(&generation) {
            offered += serve_generation(vault, rpc, generation, &targets, &mut asks).await?;
            continue;
        }
        let mut lacks = OwnAsks::default();
        match serve_generation(vault, rpc, generation, &targets, &mut lacks).await {
            Ok(taken) => offered += taken,
            Err(error) => tracing::warn!(
                %error,
                generation = %sealed_generation_hex(&generation),
                "pad admission grants left for a later tick"
            ),
        }
    }
    ask_own(vault, rpc, &asks).await?;
    Ok(offered)
}

/// Seals each of `targets` a grant of `generation`'s current pad object and
/// offers it. The object opens here with this machine's capsule, else a grant
/// it holds itself, noted on `asks` when it has none. Returns how many grants
/// the home took.
async fn serve_generation(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    generation: SealedBundleGeneration,
    targets: &[(PadAdmissionTarget, Option<RecoveryRootId>)],
    asks: &mut OwnAsks,
) -> Result<usize, TransportError> {
    let Some((_, bytes)) = read_object(
        &mut PartSource::Machine(rpc),
        Some(generation),
        SealedBundleObject::Pads,
    )
    .await?
    .whole()?
    else {
        return Ok(0);
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
    if pads.generation() != generation {
        return Err(refused());
    }
    // The current object, opened here: with this machine's capsule, or
    // a grant it holds itself.
    let mut grants = Vec::new();
    if vault.open_key_pads(&pads).is_err() {
        grants.extend(own_grant(vault, rpc, &pads, asks).await?);
    }
    let sealed: Vec<SealedPadAdmissionGrant> = {
        let Ok(opened) = vault.open_key_pads_to_erase(&pads, None, &grants) else {
            return Ok(0);
        };
        // A target this machine does not stand as the owner's under that
        // key stays pending.
        targets
            .iter()
            .filter_map(|(target, root)| {
                vault.seal_pad_admission_grant(&opened, *target, *root).ok()
            })
            .collect()
    };
    let mut offered = 0;
    for grant in &sealed {
        if offer(rpc, grant).await? {
            offered += 1;
        }
    }
    Ok(offered)
}

/// Offers `grant` to the home; `false` when the home refused it.
async fn offer(
    rpc: &mut ResidenceRpc,
    grant: &SealedPadAdmissionGrant,
) -> Result<bool, TransportError> {
    let bytes = grant.to_bytes().map_err(storage)?;
    Ok(rpc
        .call(
            ACCESS_RPC,
            json!({
                "op": "offer",
                "grant": base64::engine::general_purpose::STANDARD.encode(bytes),
            }),
        )
        .await?
        .is_ok())
}

/// This machine's usable grant of `pads`, a kept generation's current pad
/// object, from the home: addressed to it under its current key, issued by
/// authority here, and its key opens the object. A generation with none is
/// noted on `asks`: missing, or held only by offers that did not open.
pub(super) async fn own_grant(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    pads: &SealedKeyPads,
    asks: &mut OwnAsks,
) -> Result<Option<SealedPadAdmissionGrant>, TransportError> {
    let me = vault.pad_admission_self_target().map_err(storage)?;
    let generation = pads.generation();
    let reply = rpc
        .request(
            ACCESS_RPC,
            json!({"op": "get", "generation": sealed_generation_hex(&generation)}),
        )
        .await?;
    let reply: GetReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let mut offered = false;
    for row in reply.grants {
        if sealed_digest_from_hex(&row.key) != Some(me.encryption_key_digest) {
            continue;
        }
        let Some(grant) = row.grant else {
            continue;
        };
        offered = true;
        let Some(grant) = base64::engine::general_purpose::STANDARD
            .decode(grant)
            .ok()
            .and_then(|bytes| SealedPadAdmissionGrant::from_bytes(&bytes).ok())
        else {
            continue;
        };
        if grant.generation() == generation
            && grant.recipient() == me
            && vault.open_key_pads_with_grant(pads, &grant).is_ok()
        {
            return Ok(Some(grant));
        }
    }
    if offered {
        asks.invalid.push(generation);
    } else {
        asks.missing.push(generation);
    }
    Ok(None)
}

/// Asks the home for this machine's access to each generation on `asks`:
/// a pending row where it has none, and an offer it could not use back to
/// pending.
pub(super) async fn ask_own(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    asks: &OwnAsks,
) -> Result<(), TransportError> {
    if asks.missing.is_empty() && asks.invalid.is_empty() {
        return Ok(());
    }
    let me = vault.pad_admission_self_target().map_err(storage)?;
    ensure(rpc, &me, &asks.missing, &asks.invalid).await
}

/// Asks the home for `target`'s access to `generations`, and sets each of
/// `invalid` back to pending (the home takes that from the target alone).
async fn ensure(
    rpc: &mut ResidenceRpc,
    target: &PadAdmissionTarget,
    generations: &[SealedBundleGeneration],
    invalid: &[SealedBundleGeneration],
) -> Result<(), TransportError> {
    let mut wire = target_json(target);
    wire["generations"] = generations
        .iter()
        .map(sealed_generation_hex)
        .collect::<Vec<_>>()
        .into();
    wire["invalid"] = invalid
        .iter()
        .map(sealed_generation_hex)
        .collect::<Vec<_>>()
        .into();
    rpc.request(ACCESS_RPC, json!({"op": "ensure", "targets": [wire]}))
        .await
        .map(drop)
}

impl SyncClient {
    /// Grants `recipient` access to every pad object the home keeps, with
    /// `seed`, the owner's kit for this call alone (FIX 4271): each kept
    /// generation's current pad object is opened with the kit, and its outer
    /// key sealed to `recipient` and to the kit's root, signed with the
    /// root's anchor, and offered to the home. For a machine admitted after
    /// older generations were sealed that no old reader serves yet; it may
    /// call this for itself. `owner` is revalidated first and again for each
    /// grant, the kit's root must be one of the vault's, and `recipient` must
    /// stand as the owner's here under the key it names: those refusals are
    /// errors. Where this runs is never asked. A generation the kit does not
    /// open, or whose offer the home refused, stays pending for an old
    /// reader. Nothing is pinned, anchored or restored, and nothing keeps the
    /// kit. A federation lane grants nothing.
    pub async fn grant_sealed_bundle_pad_access_with_kit(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        recipient: PadAdmissionTarget,
    ) -> Result<PadAdmissionReport, TransportError> {
        let vault = &self.vault;
        owner.revalidate(vault).map_err(storage)?;
        let mut report = PadAdmissionReport::default();
        if self.config.federation_peer.is_some() {
            return Ok(report);
        }
        let budgets = residence_budgets(vault)?;
        let Some(mut rpc) = ResidenceRpc::connect(vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        let me = vault.pad_admission_self_target().ok();
        for generation in list_generations(&mut rpc).await? {
            let Some((_, bytes)) = read_object(
                &mut PartSource::Machine(&mut rpc),
                Some(generation),
                SealedBundleObject::Pads,
            )
            .await?
            .whole()?
            else {
                report.pending.push(generation);
                continue;
            };
            let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
            if pads.generation() != generation {
                return Err(refused());
            }
            let grant = match vault.seal_pad_admission_grant_with_kit(owner, &pads, seed, recipient)
            {
                Ok(grant) => grant,
                Err(Error::Secret(SecretError::SealedBundleNoCapsule)) => {
                    report.pending.push(generation);
                    continue;
                }
                Err(error) => return Err(storage(error)),
            };
            if !offer(&mut rpc, &grant).await? {
                report.pending.push(generation);
                continue;
            }
            report.offered.push(generation);
            if me == Some(recipient) && vault.open_key_pads_with_grant(&pads, &grant).is_ok() {
                report.usable.push(generation);
            }
        }
        if !report.pending.is_empty() {
            ensure(&mut rpc, &recipient, &report.pending, &[]).await?;
        }
        Ok(report)
    }
}
