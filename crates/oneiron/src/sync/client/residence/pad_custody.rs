//! Pad hydration from the home (KS-5, FIX 6706): a world's current pads as
//! capsules sealed to this machine (`residence.pad.fetch`), each opened with
//! its own machine key against the custody position and digest the home's
//! reply names, installed into this machine's custody and read back once
//! committed.
//!
//! A promotion or a retain asks for every pad of the promoted window's world
//! before its snapshot is imported, admitted as the promotion is; a promoted
//! window's catch-up asks the same way before it falls back on a promotion's
//! pad rows. A world window's first exchange on a connection asks, off the
//! sync loop and never awaited by it, for the keys whose pad is not here, an
//! equal version vector included: a full-sync machine's first open, or an
//! exact repair. Each ask only adds: pads still ride their rows, a failure is
//! logged and asked again on the next promotion, catch-up or connection, and
//! nothing that opens here today waits on it or is refused for it.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{
    ResidenceRpc, SyncClient, SyncClientConfig, home_reads_window, refused, residence_budgets,
};
use crate::entity_id::EntityId;
use crate::store::custody_protocol::CustodyPosition;
use crate::store::{SealedWorldPads, open_world_pad_compartment};
use crate::sync::residence::{pad_wire_from_hex, pad_wire_hex};
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::world_keys::{WorldKeyId, WrapRecipient, missing_world_pads_in_txn};
use crate::{Error, Vault};

/// The home's hydration door.
const PAD_FETCH_RPC: &str = "residence.pad.fetch";

/// The worlds whose exact repair runs now, by vault: a repeated first
/// exchange of the same world never stacks a second one.
static REPAIRING: LazyLock<Mutex<BTreeSet<(usize, EntityId)>>> = LazyLock::new(Mutex::default);

/// One page of the home's answer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PadFetchReply {
    window: String,
    world: String,
    recipient: String,
    position: Option<String>,
    required_keys: Vec<String>,
    total: u64,
    digest: Option<String>,
    capsule: Option<String>,
    #[serde(default)]
    position_moved: bool,
    next: Option<String>,
}

/// What a hydration asks for.
enum Ask<'a> {
    /// Every pad of the promoted window's world, admitted through `item` and
    /// the residence selector (`selector`, its wire form in base64).
    Promoted { selector: &'a str, item: EntityId },
    /// These pads, by full id.
    Keys(&'a [[u8; 40]]),
}

/// What one hydration did.
#[derive(Default)]
struct Hydrated {
    /// Pads installed here, or held here already, and read back.
    installed: usize,
    /// Pads a capsule held that stayed out: retired, or erased here.
    skipped: usize,
    /// Pads installed that did not read back.
    unread: usize,
}

fn storage(error: Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// One capsule of `reply`, checked against what the reply names, opened as
/// this machine and installed into its custody, then read back.
fn install_capsule(
    vault: &Vault,
    machine: &crate::world_keys::MachineSecret,
    world: EntityId,
    reply: &PadFetchReply,
    encoded: &str,
    hydrated: &mut Hydrated,
) -> Result<CustodyPosition, TransportError> {
    let position = reply
        .position
        .as_deref()
        .and_then(pad_wire_from_hex::<96>)
        .and_then(|bytes| CustodyPosition::from_bytes(&bytes))
        .ok_or_else(refused)?;
    let digest = reply
        .digest
        .as_deref()
        .and_then(pad_wire_from_hex::<32>)
        .ok_or_else(refused)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| refused())?;
    if bytes.len() as u64 != reply.total {
        return Err(refused());
    }
    let named = reply
        .required_keys
        .iter()
        .map(|key| pad_wire_from_hex::<40>(key))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(refused)?;
    // The capsule's claims are what the reply names; opening authenticates
    // them against the position and digest the reply pins.
    let sealed = SealedWorldPads::parse(bytes).map_err(|_| refused())?;
    let claimed: Vec<[u8; 40]> = sealed
        .required_keys
        .iter()
        .map(WorldKeyId::envelope_key_id)
        .collect();
    if sealed.world != world || claimed != named {
        return Err(refused());
    }
    let opened = open_world_pad_compartment(
        &sealed,
        &position,
        &digest,
        WrapRecipient::Machine(machine.machine),
        &machine.secret,
    )
    .map_err(storage)?;
    let installed = vault
        .with_write_txn_grouped(|wtxn| vault.store.install_current_world_pads_in_txn(wtxn, &opened))
        .map_err(storage)?;
    if vault
        .store
        .read_back_current_world_pads(&opened, &installed)
        .map_err(storage)?
    {
        hydrated.installed += installed.held.len();
    } else {
        hydrated.unread += installed.held.len();
    }
    // A restore's bare pad references this install now holds come to rest,
    // and its retired pads stand erased; then the carried pads (PAD-3) no
    // epoch owes any longer go. The install already committed, so a failure
    // here is logged, never the fetch's.
    if let Err(error) = vault
        .with_write_txn_grouped(|wtxn| {
            crate::recovery::checkpoint::reconcile_restore_pad_notes_in_txn(
                vault,
                wtxn,
                None,
                opened.retired(),
            )
        })
        .and_then(|_| crate::recovery::checkpoint::prune_carried_pads(vault))
    {
        tracing::warn!(
            %error,
            world = %world.to_hex(),
            "restore pad references not reconciled, or carried pads not pruned, after a pad fetch"
        );
    }
    hydrated.skipped += installed.skipped;
    Ok(position)
}

/// Hydrates the pads `ask` names of `window`'s world through `rpc`: every
/// page, each a whole capsule, installed and read back as it comes. A page
/// whose position moved from the one before still installs: each stands
/// alone.
async fn hydrate(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    window: &WindowKey,
    ask: Ask<'_>,
) -> Result<Hydrated, TransportError> {
    let world = window.world().ok_or_else(refused)?;
    let machine = vault.machine_secret_outside_txn().map_err(storage)?;
    let mut hydrated = Hydrated::default();
    let mut known: Option<[u8; 96]> = None;
    let mut after: Option<[u8; 40]> = None;
    loop {
        let mut params = json!({
            "window": window.as_str(),
            "recipient": machine.machine.to_hex(),
            "knownPosition": known.map(|position| pad_wire_hex(&position)),
            "after": after.map(|key| pad_wire_hex(&key)),
        });
        match &ask {
            Ask::Promoted { selector, item } => {
                params["selector"] = json!(selector);
                params["entityId"] = json!(item.to_hex());
            }
            Ask::Keys(keys) => {
                params["keys"] =
                    json!(keys.iter().map(|key| pad_wire_hex(key)).collect::<Vec<_>>());
            }
        }
        let reply: PadFetchReply =
            serde_json::from_value(rpc.request(PAD_FETCH_RPC, params).await?)
                .map_err(|_| refused())?;
        if reply.window != window.as_str()
            || EntityId::from_hex(&reply.world).ok() != Some(world)
            || EntityId::from_hex(&reply.recipient).ok() != Some(machine.machine)
        {
            return Err(refused());
        }
        if let Some(encoded) = &reply.capsule {
            if reply.position_moved {
                tracing::debug!(%window, "the home's pad custody moved between hydration pages");
            }
            let position = install_capsule(vault, &machine, world, &reply, encoded, &mut hydrated)?;
            known = Some(position.to_bytes());
        }
        let Some(next) = &reply.next else {
            return Ok(hydrated);
        };
        // Each page goes on past the last.
        let next = pad_wire_from_hex::<40>(next).ok_or_else(refused)?;
        if after.is_some_and(|after| next <= after) {
            return Err(refused());
        }
        after = Some(next);
    }
}

/// Logs what a hydration of `window` did.
fn log_hydrated(window: &WindowKey, hydrated: &Hydrated) {
    if hydrated.unread > 0 {
        tracing::warn!(
            %window,
            unread = hydrated.unread,
            "hydrated world pads did not read back from key custody; their rows still carry them"
        );
    }
    tracing::debug!(
        %window,
        installed = hydrated.installed,
        skipped = hydrated.skipped,
        "world pads hydrated"
    );
}

/// The exact repair of `keys`, pads of `window`'s world, on its own residence
/// socket: none while the home is out of reach or may not read the world.
async fn repair(
    vault: &Vault,
    config: &SyncClientConfig,
    window: &WindowKey,
    keys: &[[u8; 40]],
) -> Result<(), TransportError> {
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Ok(());
    };
    // A home that may not read the world is not told its name (FIX 922 item
    // 11).
    if !home_reads_window(vault, rpc.home, window) {
        return Ok(());
    }
    let hydrated = hydrate(vault, &mut rpc, window, Ask::Keys(keys)).await?;
    log_hydrated(window, &hydrated);
    Ok(())
}

impl SyncClient {
    /// Every pad of `window`'s world as capsules, through the promotion's own
    /// socket `rpc` and admission (`selector`, its wire form in base64, and
    /// `item`), while a key of the world this vault's authority names has no
    /// pad here. A failure is logged: the promotion's pad rows still land.
    pub(super) async fn hydrate_promoted_pads(
        &self,
        rpc: &mut ResidenceRpc,
        window: &WindowKey,
        selector: &str,
        item: EntityId,
    ) {
        let Some(world) = window.world() else {
            return;
        };
        match self.vault.world_pads_missing(world) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(%error, %window, "world pads to hydrate not read");
                return;
            }
        }
        match hydrate(&self.vault, rpc, window, Ask::Promoted { selector, item }).await {
            Ok(hydrated) => log_hydrated(window, &hydrated),
            Err(error) => tracing::warn!(%error, %window, "promoted world pads not hydrated"),
        }
    }

    /// Schedules the exact repair of the pads `window`'s world lacks here, the
    /// keys this vault's authority names with no pad here, on a task of its
    /// own: the caller never waits on it. Nothing for a base window, a
    /// federation lane, a client with no residence socket or no runtime to
    /// run it on, a world whose pads are all here, or one whose repair runs
    /// already.
    pub(crate) fn schedule_world_pad_repair(&self, window: &WindowKey) {
        let Some(world) = window.world() else {
            return;
        };
        if self.config.federation_peer.is_some()
            || self.config.note_session.is_none()
            || self.config.residence_selector.is_none()
        {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let missing = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| missing_world_pads_in_txn(&self.vault, &txn, world));
        let keys = match missing {
            Ok(keys) if keys.is_empty() => return,
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(%error, %window, "world pads to repair not read");
                return;
            }
        };
        let running = (Arc::as_ptr(&self.vault) as usize, world);
        if !REPAIRING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(running)
        {
            return;
        }
        let vault = Arc::clone(&self.vault);
        let config = self.config.clone();
        let window = window.clone();
        runtime.spawn(async move {
            if let Err(error) = repair(&vault, &config, &window, &keys).await {
                tracing::warn!(%error, %window, "world pads not repaired; the next connection asks again");
            }
            REPAIRING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&running);
        });
    }
}
