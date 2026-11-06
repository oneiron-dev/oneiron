//! The QUIC flows of one proxy, by target, version and the Destination
//! Connection ID their keys derive from (FIX 8991), and the aliases the
//! server's replies taught them.
//!
//! A flow records the client's Source Connection ID from its first Initial,
//! and the largest packet number of every Initial of it the gate opened,
//! with CRYPTO or without. A server answers the client's Source Connection
//! ID and names its own, and the client's later Initials go to that ID
//! under the flow's keys (RFC 9001 5.2). So a reply to an admitted flow's
//! client teaches the flow one alias: the target, the version and the
//! server's Source Connection ID. A packet's flow is found by its own key or
//! through an alias. A new alias replaces the flow's old one, and a flow
//! that held the same alias loses it.
//!
//! A flow is pending until its ClientHello is whole. Then the one call that
//! made it whole judges it and sends the datagrams it held, while calls for
//! the same flow wait. An admitted flow keeps its ClientHello and a refused
//! flow keeps a tombstone, each for the egress config's datagram timeout.
//! A pending flow ends that long after its first datagram, and what it
//! held is dropped, never sent. A flow and its alias end together; a later
//! Initial of its connection opens under no flow's keys and is refused. The
//! table lock covers no DNS lookup, no policy check and no remote receive.
//!
//! A flow ends on its deadline whether or not another datagram comes: while
//! the table holds a flow, one sweeper thread, holding the table only
//! weakly, drops each ended flow at its deadline, so what a pending or
//! admitted flow holds on the host-net byte floor goes back without another
//! QUIC call. A table that cannot start its sweeper holds nothing: the
//! datagram is refused.

use super::EgressDatagramNameRefusal;
use super::initial::Version;
use super::reassembly::{self, BEYOND_FLOOR, CryptoStream};
use oneiron_container::{HostNetFloor, HostNetPermit};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// One QUIC connection as its opening Initial names it: the target, the
/// version and the Destination Connection ID. An alias has the same form,
/// with the server's Source Connection ID.
pub(super) type FlowKey = (SocketAddr, Version, Vec<u8>);

/// The CRYPTO frames of one datagram's Initials, as offset and bytes, or
/// why they cannot be read.
pub(super) type Frames = Result<Vec<(u64, Vec<u8>)>, &'static str>;

/// What one datagram's opened Initials, all of one connection, carry for
/// its flow.
pub(super) struct Opened {
    /// The flow: the key of the connection's first Initial.
    pub(super) key: FlowKey,
    /// The client's Source Connection ID in those Initials' headers.
    pub(super) client_scid: Vec<u8>,
    /// The largest packet number among those Initials.
    pub(super) number: u64,
    /// Their CRYPTO frames, none for Initials that carry no CRYPTO.
    pub(super) frames: Frames,
}

/// The QUIC flows of one proxy.
pub(in crate::code_sandbox::egress) struct FlowTable {
    maps: Mutex<FlowMaps>,
    /// Woken when a flow's release settles.
    settled: Condvar,
    /// How long a flow lives after it starts or settles: the egress
    /// config's datagram timeout.
    lifetime: Duration,
}

/// The flows by key, and each alias with the key of the flow it names.
#[derive(Default)]
struct FlowMaps {
    flows: HashMap<FlowKey, Flow>,
    aliases: HashMap<FlowKey, FlowKey>,
    /// A sweeper thread ends this table's flows on their deadlines.
    sweeping: bool,
}

struct Flow {
    /// When the flow, its alias and what it holds are dropped.
    expires: Instant,
    /// The largest packet number of its Initials the gate opened.
    largest: u64,
    /// The client's Source Connection ID in its first Initial: the
    /// Destination Connection ID of the server's replies.
    client_scid: Vec<u8>,
    /// The server's Source Connection ID a reply taught the flow, the
    /// Destination Connection ID of the client's later Initials.
    alias: Option<Vec<u8>>,
    state: FlowState,
}

enum FlowState {
    /// The ClientHello is not whole: the CRYPTO so far, and the datagrams
    /// that carried it, raw, in arrival order.
    Pending {
        crypto: CryptoStream,
        held: Vec<HeldDatagram>,
    },
    /// One call judges the whole ClientHello and sends what was held.
    Releasing,
    /// The ClientHello was admitted: later CRYPTO must agree with it.
    Admitted {
        hello: Vec<u8>,
        _room: Vec<HostNetPermit>,
    },
    /// Refused: later Initials are refused the same way.
    Refused(EgressDatagramNameRefusal),
}

/// A datagram held for its flow, and the floor room it holds.
struct HeldDatagram {
    bytes: Vec<u8>,
    room: HostNetPermit,
}

/// What a datagram's Initials do to their flow.
pub(super) enum Step<'a> {
    /// The flow's ClientHello was admitted, and the datagram's CRYPTO, if
    /// any, agrees with it.
    Agreed,
    /// The datagram is held until the ClientHello is whole.
    Held,
    /// The ClientHello is whole: this call judges it.
    Whole(Release<'a>),
    /// The flow refused it.
    Refused(EgressDatagramNameRefusal),
    /// Another call's release of the flow did not settle in time.
    Unsettled,
}

impl FlowTable {
    /// An empty table whose flows live `lifetime`.
    pub(in crate::code_sandbox::egress) fn new(lifetime: Duration) -> Self {
        Self {
            maps: Mutex::new(FlowMaps::default()),
            settled: Condvar::new(),
            lifetime,
        }
    }

    /// The key of the flow an Initial to `target` in `version` with `dcid`
    /// belongs to, found by its own key or through an alias, and the
    /// largest packet number of that flow's Initials the gate opened.
    pub(super) fn connection(
        &self,
        target: SocketAddr,
        version: Version,
        dcid: &[u8],
    ) -> Option<(FlowKey, u64)> {
        let mut maps = self.maps.lock().ok()?;
        maps.sweep();
        let key = (target, version, dcid.to_vec());
        let key = if maps.flows.contains_key(&key) {
            key
        } else {
            maps.aliases.get(&key)?.clone()
        };
        let largest = maps.flows.get(&key)?.largest;
        Some((key, largest))
    }

    /// Makes `server_scid` the alias of the one admitted flow at `target` in
    /// `version` whose client's Source Connection ID is `client_scid`. No
    /// such flow, or more than one, learns nothing.
    pub(super) fn learn_alias(
        &self,
        target: SocketAddr,
        version: Version,
        client_scid: &[u8],
        server_scid: &[u8],
    ) {
        let Ok(mut maps) = self.maps.lock() else {
            return;
        };
        maps.sweep();
        let mut admitted = maps.flows.iter().filter(|(key, flow)| {
            key.0 == target
                && key.1 == version
                && flow.client_scid == client_scid
                && matches!(flow.state, FlowState::Admitted { .. })
        });
        let (Some((key, _)), None) = (admitted.next(), admitted.next()) else {
            return;
        };
        let key = key.clone();
        maps.alias(&key, server_scid);
    }

    /// Adds what `opened` carries to its flow, which it starts when there is
    /// none, and holds `datagram` while the flow's ClientHello is not
    /// whole. Bytes are held on `floor`.
    pub(super) fn ingest(
        self: &Arc<Self>,
        opened: Opened,
        datagram: &[u8],
        floor: &dyn HostNetFloor,
    ) -> Step<'_> {
        let Opened {
            key,
            client_scid,
            number,
            frames,
        } = opened;
        let target = key.0;
        let unverifiable = |why| EgressDatagramNameRefusal::Unverifiable { target, why };
        let mut maps = match self.settled_maps(&key) {
            Ok(maps) => maps,
            Err(Unavailable::Unsettled) => return Step::Unsettled,
            Err(Unavailable::Poisoned) => {
                return Step::Refused(unverifiable("the gate's flow table is poisoned"));
            }
        };
        if !self.sweep_on_deadlines(&mut maps) {
            return Step::Refused(unverifiable(
                "the gate cannot end its QUIC flows on their deadlines",
            ));
        }
        let flow = maps.flows.entry(key.clone()).or_insert_with(|| Flow {
            expires: after(self.lifetime),
            largest: number,
            client_scid,
            alias: None,
            state: FlowState::Pending {
                crypto: CryptoStream::default(),
                held: Vec::new(),
            },
        });
        flow.largest = flow.largest.max(number);
        let whole = match &mut flow.state {
            FlowState::Releasing => return Step::Unsettled,
            FlowState::Refused(refusal) => return Step::Refused(refusal.clone()),
            FlowState::Admitted { hello, .. } => {
                let agreed = frames.and_then(|frames| {
                    frames
                        .iter()
                        .try_for_each(|(offset, data)| reassembly::agrees(hello, *offset, data))
                });
                return match agreed {
                    Ok(()) => Step::Agreed,
                    Err(why) => Step::Refused(unverifiable(why)),
                };
            }
            FlowState::Pending { crypto, held } => {
                frames.and_then(|frames| pend(crypto, held, &frames, datagram, floor))
            }
        };
        match whole {
            Ok(false) => Step::Held,
            Ok(true) => {
                let FlowState::Pending { crypto, held } =
                    std::mem::replace(&mut flow.state, FlowState::Releasing)
                else {
                    return Step::Unsettled;
                };
                drop(maps);
                Step::Whole(Release::new(self, key, crypto, held))
            }
            Err(why) => {
                let refusal = unverifiable(why);
                flow.state = FlowState::Refused(refusal.clone());
                flow.expires = after(self.lifetime);
                Step::Refused(refusal)
            }
        }
    }

    /// Starts the thread that ends this table's flows on their deadlines,
    /// unless one runs: true once one runs. It is started under the table
    /// lock, so the flow its caller adds next is there when it first looks.
    fn sweep_on_deadlines(self: &Arc<Self>, maps: &mut FlowMaps) -> bool {
        if maps.sweeping {
            return true;
        }
        let table = Arc::downgrade(self);
        let started = std::thread::Builder::new()
            .name("egress-quic-flows".to_owned())
            .spawn(move || end_flows_on_deadlines(&table));
        match started {
            Ok(_) => maps.sweeping = true,
            Err(error) => {
                tracing::warn!(%error, "the QUIC flow deadline sweeper did not start");
            }
        }
        maps.sweeping
    }

    /// The maps, swept of ended flows, once `key`'s flow is not being
    /// released: waits up to the flow lifetime for another call's release.
    fn settled_maps(&self, key: &FlowKey) -> Result<MutexGuard<'_, FlowMaps>, Unavailable> {
        let deadline = after(self.lifetime);
        let mut maps = self.maps.lock().map_err(|_| Unavailable::Poisoned)?;
        loop {
            maps.sweep();
            let releasing = maps
                .flows
                .get(key)
                .is_some_and(|flow| matches!(flow.state, FlowState::Releasing));
            if !releasing {
                return Ok(maps);
            }
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                return Err(Unavailable::Unsettled);
            }
            maps = self
                .settled
                .wait_timeout(maps, wait)
                .map_err(|_| Unavailable::Poisoned)?
                .0;
        }
    }
}

impl FlowMaps {
    /// Drops the ended flows that no call is releasing, and the aliases of
    /// flows that are gone.
    fn sweep(&mut self) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| flow.expires > now || matches!(flow.state, FlowState::Releasing));
        let flows = &self.flows;
        self.aliases.retain(|_, key| flows.contains_key(&*key));
    }

    /// Makes `server_scid` the one alias of the flow `key`. Its old alias
    /// goes, and a flow that held this alias before loses it.
    fn alias(&mut self, key: &FlowKey, server_scid: &[u8]) {
        let (target, version) = (key.0, key.1);
        let Some(flow) = self.flows.get_mut(key) else {
            return;
        };
        if let Some(old) = flow.alias.replace(server_scid.to_vec()) {
            self.aliases.remove(&(target, version, old));
        }
        if let Some(previous) = self
            .aliases
            .insert((target, version, server_scid.to_vec()), key.clone())
            && previous != *key
            && let Some(other) = self.flows.get_mut(&previous)
        {
            other.alias = None;
        }
    }
}

/// Ends `table`'s flows on their deadlines until it holds none or is gone.
/// It sleeps until the earliest deadline holding no lock and no strong
/// reference, so a dropped proxy ends it at its next wake.
fn end_flows_on_deadlines(table: &Weak<FlowTable>) {
    loop {
        let Some(strong) = table.upgrade() else {
            return;
        };
        let wait = {
            let Ok(mut maps) = strong.maps.lock() else {
                return;
            };
            maps.sweep();
            if maps.flows.is_empty() {
                maps.sweeping = false;
                return;
            }
            // A flow some call is releasing has no deadline of its own until
            // its release settles: look again after one lifetime.
            maps.flows
                .values()
                .filter(|flow| !matches!(flow.state, FlowState::Releasing))
                .map(|flow| flow.expires.saturating_duration_since(Instant::now()))
                .min()
                .unwrap_or(strong.lifetime)
        };
        drop(strong);
        std::thread::sleep(wait);
    }
}

/// Why the table is not to be had for a flow.
enum Unavailable {
    /// A thread panicked while it held the table.
    Poisoned,
    /// Another call's release of the flow did not settle within the flow
    /// lifetime.
    Unsettled,
}

/// Adds `frames` to a pending flow's `crypto`, and answers whether its
/// ClientHello is whole now. A datagram that leaves it partial is held in
/// `held`, on `floor`.
fn pend(
    crypto: &mut CryptoStream,
    held: &mut Vec<HeldDatagram>,
    frames: &[(u64, Vec<u8>)],
    datagram: &[u8],
    floor: &dyn HostNetFloor,
) -> Result<bool, &'static str> {
    for (offset, data) in frames {
        crypto.insert(*offset, data, floor)?;
    }
    if crypto.whole()? {
        return Ok(true);
    }
    let size = u64::try_from(datagram.len()).map_err(|_| BEYOND_FLOOR)?;
    let room = floor.acquire_bytes(size).map_err(|_| BEYOND_FLOOR)?;
    held.push(HeldDatagram {
        bytes: datagram.to_vec(),
        room,
    });
    Ok(false)
}

/// `lifetime` from now; an instant the clock cannot reach ends now.
fn after(lifetime: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(lifetime).unwrap_or(now)
}

/// A flow whose ClientHello is whole, held by the one call that judges it
/// and sends what the flow held. Dropping it settles the flow: refused if
/// [`Release::refuse`] said so, else admitted. It wakes the calls that
/// wait for the flow, and drops the held datagrams and their room.
pub(in crate::code_sandbox::egress) struct Release<'a> {
    table: &'a FlowTable,
    key: FlowKey,
    hello: Vec<u8>,
    hello_room: Vec<HostNetPermit>,
    held: Vec<Vec<u8>>,
    _held_room: Vec<HostNetPermit>,
    /// Boxed, so a release stays small beside the outcomes that carry it.
    refusal: Option<Box<EgressDatagramNameRefusal>>,
}

impl<'a> Release<'a> {
    fn new(
        table: &'a FlowTable,
        key: FlowKey,
        crypto: CryptoStream,
        held: Vec<HeldDatagram>,
    ) -> Self {
        let (hello, hello_room) = crypto.into_hello();
        let (held, held_room) = held
            .into_iter()
            .map(|datagram| (datagram.bytes, datagram.room))
            .unzip();
        Self {
            table,
            key,
            hello,
            hello_room,
            held,
            _held_room: held_room,
            refusal: None,
        }
    }
}

impl Release<'_> {
    /// The whole ClientHello handshake message.
    pub(super) fn hello(&self) -> &[u8] {
        &self.hello
    }

    /// The datagrams the flow held, raw, in arrival order.
    pub(in crate::code_sandbox::egress) fn held(&self) -> &[Vec<u8>] {
        &self.held
    }

    /// Settles the flow refused for `refusal`; nothing it held is sent.
    pub(super) fn refuse(mut self, refusal: EgressDatagramNameRefusal) {
        self.refusal = Some(Box::new(refusal));
    }
}

impl Drop for Release<'_> {
    fn drop(&mut self) {
        let state = match self.refusal.take() {
            Some(refusal) => FlowState::Refused(*refusal),
            None => FlowState::Admitted {
                hello: std::mem::take(&mut self.hello),
                _room: std::mem::take(&mut self.hello_room),
            },
        };
        if let Ok(mut maps) = self.table.maps.lock()
            && let Some(flow) = maps.flows.get_mut(&self.key)
        {
            flow.state = state;
            flow.expires = after(self.table.lifetime);
        }
        self.table.settled.notify_all();
    }
}
