//! Sealed copies of private-world windows through the home (OF-534 G7,
//! DEC-0005 fix 8). The home may not read these worlds: it relays sealed
//! packets between the owner's machines that may. A relay takes the home's
//! new packets in first, so a replacement this machine puts next carries what
//! the others put, then puts each window that changed here since its last put.
//! Both cursors belong to one home: after a re-home the relay takes the new
//! home's shelf from its start and puts every window there whole again.
//! A packet past one request is put in parts the home stages and then shelves
//! whole, and every packet is read back in slices. An update whose base this
//! machine lacks asks the home for a replacement of its window, which another
//! machine that seals the window puts on its next relay. An opened-item
//! machine materializes only the windows it promoted: another window's packet
//! waits in its mirror until a promotion takes its rows in.

use std::collections::BTreeSet;

use base64::Engine;
use loro::VersionVector;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::authority::{Destination, PeerMachine, WorldPrivacyView};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::client::SyncClientConfig;
use crate::sync::manager::WindowManager;
use crate::sync::residence::{
    SEALED_PUT_PART_MAX, SEALED_READ_PART_MAX, SEALED_SHELF_PAGE_MAX, discover_local_window_keys,
};
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::world_keys::{SealedContentKind, SealedResidenceContent};
use crate::{EntityId, Vault};

/// The encoded version vector of this machine's last put of one window.
const PUT_PREFIX: &str = "rsp:";
/// Every window's last put, dropped when the home changes.
const PUTS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_SEALED_PUT);
/// The home this machine relays through (its machine id, 16 bytes) and the
/// last arrival it took in there (u64be).
const TAKEN_KEY: &str = "rst";

/// The id the taken cursor names `home` by: its proven machine, or zeros for
/// a home that proved none.
fn home_id(home: PeerMachine) -> [u8; 16] {
    match home {
        PeerMachine::Proven { machine, .. } => *machine.as_bytes(),
        PeerMachine::Unknown => [0; 16],
    }
}

/// What one relay moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealedRelay {
    /// Packets taken in from the home and merged here.
    pub taken: usize,
    /// Packets that did not open or merge here; each waits for a replacement.
    pub skipped: usize,
    /// Windows sealed and put on the home.
    pub put: usize,
}

#[derive(Deserialize)]
struct SealedListReply {
    entries: Vec<SealedListEntry>,
}

#[derive(Deserialize)]
struct SealedListEntry {
    id: String,
    window: String,
    seq: u64,
}

#[derive(Deserialize)]
struct SealedWantsReply {
    windows: Vec<String>,
}

/// How one packet from the home fared here.
enum Took {
    Merged(SealedContentKind),
    /// Not served, or it does not open or merge here.
    Skipped,
    /// An update of a world this machine reads, whose base it lacks.
    LacksBase,
}

#[derive(Deserialize)]
struct SealedReadReply {
    id: String,
    window: String,
    total: u64,
    part: String,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// Whether two encoded version vectors name the same history.
fn same_version(a: &[u8], b: &[u8]) -> bool {
    match (VersionVector::decode(a), VersionVector::decode(b)) {
        (Ok(a), Ok(b)) => a.includes_vv(&b) && b.includes_vv(&a),
        _ => false,
    }
}

impl SyncClient {
    /// Takes the home's new sealed packets in, then puts every private window
    /// this machine reads whose sealed copies may rest on the home and that
    /// changed since its last put. The home is judged as the machine it
    /// proved on the relay's own socket: one of the owner's machines takes
    /// "my machines" worlds too, and a home that proved none only worlds
    /// whose sealed copies go to the cloud and my machines. A vault with no
    /// private world opens no socket.
    pub async fn relay_sealed_windows(&self) -> Result<SealedRelay, TransportError> {
        relay_sealed_windows(&self.manager, &self.config).await
    }
}

/// [`SyncClient::relay_sealed_windows`] on the window manager and a client
/// config alone, for a task off the live sync loop.
pub(crate) async fn relay_sealed_windows(
    manager: &std::sync::Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<SealedRelay, TransportError> {
    let relayer = Relayer {
        vault: manager.vault(),
        manager,
        opened: config.residence_mode == crate::sync::SyncResidenceMode::Opened
            && config.federation_peer.is_none(),
    };
    let private = relayer.private_worlds().map_err(storage)?;
    if private.is_empty() {
        return Ok(SealedRelay::default());
    }
    let budgets = residence_budgets(relayer.vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(relayer.vault, config, budgets).await? else {
        return Err(TransportError::Storage("home node offline".into()));
    };
    let destination = match relayer.vault.peer_machine_stands(rpc.home) {
        crate::authority::PeerMachine::Proven { machine, .. } => Destination::Machine(machine),
        crate::authority::PeerMachine::Unknown => Destination::Unknown,
    };
    let sealable = relayer
        .sealable_worlds(&private, destination)
        .map_err(storage)?;
    if sealable.is_empty() {
        return Ok(SealedRelay::default());
    }
    let mut relay = SealedRelay::default();
    let through = relayer.take_sealed_windows(&mut rpc, &mut relay).await?;
    relayer
        .put_sealed_windows(&mut rpc, &sealable, through, &mut relay)
        .await?;
    Ok(relay)
}

struct Relayer<'a> {
    vault: &'a Vault,
    manager: &'a std::sync::Arc<WindowManager>,
    /// An opened-item machine: it materializes only the windows it promoted.
    opened: bool,
}

impl Relayer<'_> {
    /// The private worlds: those an unknown destination may not read.
    fn private_worlds(&self) -> crate::error::Result<BTreeSet<EntityId>> {
        let txn = self.vault.store.env.read_txn()?;
        WorldPrivacyView::load_in(self.vault, &txn)?.withheld_for(Destination::Unknown)
    }

    /// The worlds of `private` whose sealed copies may rest on the home,
    /// judged as `destination`.
    fn sealable_worlds(
        &self,
        private: &BTreeSet<EntityId>,
        destination: Destination,
    ) -> crate::error::Result<BTreeSet<EntityId>> {
        let txn = self.vault.store.env.read_txn()?;
        let mut sealable = BTreeSet::new();
        for world in private {
            if self
                .vault
                .sealed_copy_may_rest_on_in(&txn, *world, destination)?
            {
                sealable.insert(*world);
            }
        }
        Ok(sealable)
    }

    /// Takes in every live packet past the last arrival taken, in arrival
    /// order, then asks for a replacement of each window an update failed
    /// on for want of its base. Returns the last arrival taken.
    async fn take_sealed_windows(
        &self,
        rpc: &mut ResidenceRpc,
        relay: &mut SealedRelay,
    ) -> Result<u64, TransportError> {
        let home = home_id(rpc.home);
        let mut after = match self.vault.sync_state_get(TAKEN_KEY).map_err(storage)? {
            Some(raw) if raw.get(..16) == Some(home.as_slice()) => u64::from_be_bytes(
                raw.get(16..)
                    .and_then(|tail| tail.try_into().ok())
                    .ok_or_else(refused)?,
            ),
            // Another home's cursor: a re-home. This shelf starts over, and
            // the puts there begin again from whole windows.
            Some(_) => {
                self.vault
                    .with_write_txn_grouped(|txn| {
                        PUTS.delete_from(&self.vault.store, txn, &[]).map(drop)
                    })
                    .map_err(storage)?;
                0
            }
            None => 0,
        };
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        loop {
            let reply = rpc
                .request("residence.sealed.list", json!({"after": after}))
                .await?;
            let list: SealedListReply = serde_json::from_value(reply).map_err(|_| refused())?;
            if list.entries.len() > SEALED_SHELF_PAGE_MAX {
                return Err(refused());
            }
            let page = list.entries.len();
            for entry in list.entries {
                if entry.seq <= after {
                    return Err(refused());
                }
                after = entry.seq;
                let Some(window) = WindowKey::try_new(entry.window) else {
                    relay.skipped += 1;
                    continue;
                };
                match self.take_sealed_packet(rpc, &entry.id, &window).await? {
                    Took::Merged(kind) => {
                        relay.taken += 1;
                        if kind == SealedContentKind::Replacement {
                            wanted.remove(window.as_str());
                        }
                    }
                    Took::Skipped => relay.skipped += 1,
                    Took::LacksBase => {
                        relay.skipped += 1;
                        wanted.insert(window.as_str().to_owned());
                    }
                }
            }
            self.vault
                .with_write_txn_grouped(|txn| {
                    self.vault.store.sync_state.put(
                        txn,
                        TAKEN_KEY,
                        &[home.as_slice(), &after.to_be_bytes()].concat(),
                    )
                })
                .map_err(storage)?;
            if page < SEALED_SHELF_PAGE_MAX {
                for window in &wanted {
                    match rpc
                        .request("residence.sealed.want", json!({"window": window}))
                        .await
                    {
                        Ok(_) | Err(TransportError::InvalidPayload(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
                return Ok(after);
            }
        }
    }

    /// Fetches one packet and merges it here.
    async fn take_sealed_packet(
        &self,
        rpc: &mut ResidenceRpc,
        id: &str,
        window: &WindowKey,
    ) -> Result<Took, TransportError> {
        let Some(world) = window.world() else {
            return Ok(Took::Skipped);
        };
        let Some(bytes) = read_sealed_packet(rpc, id, window).await? else {
            return Ok(Took::Skipped);
        };
        let Ok(packet) = SealedResidenceContent::from_bytes(&bytes) else {
            return Ok(Took::Skipped);
        };
        if packet.id().to_hex() != id {
            return Err(refused());
        }
        // An opened-item machine materializes only a window it holds
        // promoted, judged again once the handle is held; any other window's
        // packet waits in its mirror for a promotion.
        let held = if self.opened && self.promoted(window)? {
            Some(self.manager.open_window(window).map_err(storage)?)
        } else {
            None
        };
        let materialize = !self.opened || (held.is_some() && self.promoted(window)?);
        let merged = if materialize {
            self.manager
                .import_sealed_residence_content(world, window, &packet)
        } else {
            self.manager
                .merge_sealed_residence_mirror(world, window, &packet)
        };
        drop(held);
        match merged {
            Ok(binding) => Ok(Took::Merged(binding.kind)),
            // It opened here, so this machine reads the world.
            Err(_)
                if self
                    .vault
                    .open_world_content(world, window.as_str(), &packet)
                    .is_ok_and(|opened| opened.binding.kind == SealedContentKind::Update) =>
            {
                Ok(Took::LacksBase)
            }
            Err(_) => Ok(Took::Skipped),
        }
    }

    /// Whether this opened-item machine holds `window` promoted (`rp:w:`).
    fn promoted(&self, window: &WindowKey) -> Result<bool, TransportError> {
        Ok(self
            .vault
            .sync_state_get(&format!("rp:w:{window}"))
            .map_err(storage)?
            .is_some())
    }

    /// Seals and puts each window that changed here since its last put, and a
    /// replacement of each window another machine asked one of. `through` is
    /// the last arrival taken in: a replacement retires the window's packets
    /// up to it.
    async fn put_sealed_windows(
        &self,
        rpc: &mut ResidenceRpc,
        sealable: &BTreeSet<EntityId>,
        through: u64,
        relay: &mut SealedRelay,
    ) -> Result<(), TransportError> {
        let wanted = wanted_replacements(rpc).await?;
        for window in discover_local_window_keys(self.vault).map_err(storage)? {
            let Some(world) = window.world().filter(|world| sealable.contains(world)) else {
                continue;
            };
            let put_key = format!("{PUT_PREFIX}{window}");
            let since = if wanted.contains(window.as_str()) {
                None
            } else {
                self.vault.sync_state_get(&put_key).map_err(storage)?
            };
            // Refused here when this machine does not read the world, or its
            // sealed copies are off.
            let Ok(packet) =
                self.manager
                    .export_sealed_residence_content(world, &window, since.as_deref())
            else {
                continue;
            };
            let binding = self
                .vault
                .open_world_content(world, window.as_str(), &packet)
                .map_err(storage)?
                .binding;
            if binding.kind == SealedContentKind::Update && same_version(&binding.from, &binding.to)
            {
                continue;
            }
            let retire_through =
                (binding.kind == SealedContentKind::Replacement).then_some(through);
            if !put_sealed_packet(rpc, &window, &packet.into_bytes(), retire_through).await? {
                continue;
            }
            self.vault
                .with_write_txn_grouped(|txn| {
                    self.vault.store.sync_state.put(txn, &put_key, &binding.to)
                })
                .map_err(storage)?;
            relay.put += 1;
        }
        Ok(())
    }
}

/// The windows other machines asked a replacement of.
async fn wanted_replacements(rpc: &mut ResidenceRpc) -> Result<BTreeSet<String>, TransportError> {
    let reply = match rpc.request("residence.sealed.wants", json!({})).await {
        Ok(reply) => reply,
        Err(TransportError::InvalidPayload(_)) => return Ok(BTreeSet::new()),
        Err(error) => return Err(error),
    };
    let reply: SealedWantsReply = serde_json::from_value(reply).map_err(|_| refused())?;
    if reply.windows.len() > SEALED_SHELF_PAGE_MAX {
        return Err(refused());
    }
    Ok(reply.windows.into_iter().collect())
}

/// Reads one shelved packet in slices. `None` when the home no longer serves
/// it.
async fn read_sealed_packet(
    rpc: &mut ResidenceRpc,
    id: &str,
    window: &WindowKey,
) -> Result<Option<Vec<u8>>, TransportError> {
    let mut bytes = Vec::new();
    let mut total = None;
    loop {
        let reply = match rpc
            .request(
                "residence.sealed.read",
                json!({"id": id, "offset": bytes.len()}),
            )
            .await
        {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let reply: SealedReadReply = serde_json::from_value(reply).map_err(|_| refused())?;
        if reply.id != id
            || reply.window != window.as_str()
            || *total.get_or_insert(reply.total) != reply.total
        {
            return Err(refused());
        }
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if part.is_empty()
            || part.len() > SEALED_READ_PART_MAX
            || (bytes.len() + part.len()) as u64 > reply.total
        {
            return Err(refused());
        }
        bytes.extend_from_slice(&part);
        if bytes.len() as u64 == reply.total {
            return Ok(Some(bytes));
        }
    }
}

/// Puts one sealed packet: whole when it fits one request, else in parts the
/// home stages and shelves as one. `false` when the home refused it.
async fn put_sealed_packet(
    rpc: &mut ResidenceRpc,
    window: &WindowKey,
    packet: &[u8],
    retire_through: Option<u64>,
) -> Result<bool, TransportError> {
    let sent = if packet.len() <= SEALED_PUT_PART_MAX {
        rpc.request(
            "residence.sealed.put",
            json!({
                "window": window.as_str(),
                "packet": base64::engine::general_purpose::STANDARD.encode(packet),
                "retireThrough": retire_through,
            }),
        )
        .await
    } else {
        let upload = blake3::hash(packet).to_hex();
        let mut offset = 0;
        for part in packet.chunks(SEALED_PUT_PART_MAX) {
            match rpc
                .request(
                    "residence.sealed.stage",
                    json!({
                        "window": window.as_str(),
                        "upload": upload.as_str(),
                        "offset": offset,
                        "part": base64::engine::general_purpose::STANDARD.encode(part),
                    }),
                )
                .await
            {
                Ok(_) => {}
                Err(TransportError::InvalidPayload(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
            offset += part.len();
        }
        rpc.request(
            "residence.sealed.commit",
            json!({
                "window": window.as_str(),
                "upload": upload.as_str(),
                "retireThrough": retire_through,
            }),
        )
        .await
    };
    match sent {
        Ok(_) => Ok(true),
        Err(TransportError::InvalidPayload(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
