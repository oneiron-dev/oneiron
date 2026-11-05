//! The QUIC flows of one proxy, by target, version and the Destination
//! Connection ID their keys derive from (FIX 8991).
//!
//! A flow is pending until its ClientHello is whole. Then the one call that
//! made it whole judges it and sends the datagrams it held, while calls for
//! the same flow wait. An admitted flow keeps its ClientHello and a refused
//! flow keeps a tombstone, each for the egress config's datagram timeout.
//! A pending flow ends that long after its first datagram, and what it
//! held is dropped, never sent. The table lock covers no DNS lookup, no
//! policy check and no remote receive.

use super::EgressDatagramNameRefusal;
use super::initial::Version;
use super::reassembly::{self, BEYOND_FLOOR, CryptoStream};
use oneiron_container::{HostNetFloor, HostNetPermit};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// One QUIC connection as its opening Initial names it: the target, the
/// version and the Destination Connection ID.
pub(super) type FlowKey = (SocketAddr, Version, Vec<u8>);

/// The CRYPTO frames of one datagram's Initials, as offset and bytes, or
/// why they cannot be read.
pub(super) type Frames = Result<Vec<(u64, Vec<u8>)>, &'static str>;

/// The QUIC flows of one proxy.
pub(in crate::code_sandbox::egress) struct FlowTable {
    flows: Mutex<HashMap<FlowKey, Flow>>,
    /// Woken when a flow's release settles.
    settled: Condvar,
    /// How long a flow lives after it starts or settles: the egress
    /// config's datagram timeout.
    lifetime: Duration,
}

struct Flow {
    /// When the flow and what it holds are dropped.
    expires: Instant,
    /// The largest packet number of its Initials the gate opened.
    largest: u64,
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
    /// Refused: later CRYPTO is refused the same way.
    Refused(EgressDatagramNameRefusal),
}

/// A datagram held for its flow, and the floor room it holds.
struct HeldDatagram {
    bytes: Vec<u8>,
    room: HostNetPermit,
}

/// What a datagram's CRYPTO does to its flow.
pub(super) enum Step<'a> {
    /// The flow's ClientHello was admitted, and the CRYPTO agrees with it.
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
            flows: Mutex::new(HashMap::new()),
            settled: Condvar::new(),
            lifetime,
        }
    }

    /// The largest packet number of `key`'s Initials the gate opened.
    pub(super) fn largest(&self, key: &FlowKey) -> Option<u64> {
        self.flows.lock().ok()?.get(key).map(|flow| flow.largest)
    }

    /// Adds `frames`, which `datagram`'s Initials up to packet `number`
    /// carry for `key`, to its flow, and holds `datagram` while the flow's
    /// ClientHello is not whole. Bytes are held on `floor`.
    pub(super) fn ingest(
        &self,
        key: FlowKey,
        number: u64,
        frames: Frames,
        datagram: &[u8],
        floor: &dyn HostNetFloor,
    ) -> Step<'_> {
        let target = key.0;
        let unverifiable = |why| EgressDatagramNameRefusal::Unverifiable { target, why };
        let mut flows = match self.settled_table(&key) {
            Ok(flows) => flows,
            Err(Unavailable::Unsettled) => return Step::Unsettled,
            Err(Unavailable::Poisoned) => {
                return Step::Refused(unverifiable("the gate's flow table is poisoned"));
            }
        };
        let flow = flows.entry(key.clone()).or_insert_with(|| Flow {
            expires: after(self.lifetime),
            largest: number,
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
                drop(flows);
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

    /// The table, swept of ended flows, once `key`'s flow is not being
    /// released: waits up to the flow lifetime for another call's release.
    fn settled_table(
        &self,
        key: &FlowKey,
    ) -> Result<MutexGuard<'_, HashMap<FlowKey, Flow>>, Unavailable> {
        let deadline = after(self.lifetime);
        let mut flows = self.flows.lock().map_err(|_| Unavailable::Poisoned)?;
        loop {
            let now = Instant::now();
            flows
                .retain(|_, flow| flow.expires > now || matches!(flow.state, FlowState::Releasing));
            let releasing = flows
                .get(key)
                .is_some_and(|flow| matches!(flow.state, FlowState::Releasing));
            if !releasing {
                return Ok(flows);
            }
            let wait = deadline.saturating_duration_since(now);
            if wait.is_zero() {
                return Err(Unavailable::Unsettled);
            }
            flows = self
                .settled
                .wait_timeout(flows, wait)
                .map_err(|_| Unavailable::Poisoned)?
                .0;
        }
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
        if let Ok(mut flows) = self.table.flows.lock()
            && let Some(flow) = flows.get_mut(&self.key)
        {
            flow.state = state;
            flow.expires = after(self.table.lifetime);
        }
        self.table.settled.notify_all();
    }
}
