//! Lifted half of `oneiron::code_sandbox::egress::quic::flows` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::quic::flows::*;
#[allow(unused_imports)]
use crate::ext::*;
use super::EgressDatagramNameRefusal;
use super::initial::Version;
use super::reassembly::CryptoStream;
use std::net::SocketAddr;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;

/// Methods of [`FlowTable`] that moved out of `oneiron` with `code_sandbox::egress::quic::flows` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressQuicFlowsFlowTableExt {
    /// An empty table whose flows live `lifetime`.
    fn new(lifetime: Duration) -> Self;
    /// The key of the flow an Initial to `target` in `version` with `dcid`
    /// belongs to, found by its own key or through an alias, and the
    /// largest packet number of that flow's Initials the gate opened.
    fn connection(
        &self,
        target: SocketAddr,
        version: Version,
        dcid: &[u8],
    ) -> Option<(FlowKey, u64)>;
}

impl CodeSandboxEgressQuicFlowsFlowTableExt for FlowTable {
    /// An empty table whose flows live `lifetime`.
    fn new(lifetime: Duration) -> Self {
            Self {
                maps: Mutex::new(FlowMaps::default()),
                settled: Condvar::new(),
                lifetime,
            }
        }

    /// The key of the flow an Initial to `target` in `version` with `dcid`
    /// belongs to, found by its own key or through an alias, and the
    /// largest packet number of that flow's Initials the gate opened.
    fn connection(
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
}

/// Methods of [`Release`] that moved out of `oneiron` with `code_sandbox::egress::quic::flows` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressQuicFlowsReleaseExt<'a> {
    fn new(
        table: &'a FlowTable,
        key: FlowKey,
        crypto: CryptoStream,
        held: Vec<HeldDatagram>,
    ) -> Self;
    /// The datagrams the flow held, raw, in arrival order.
    fn held(&self) -> &[Vec<u8>];
    /// Settles the flow refused for `refusal`; nothing it held is sent.
    fn refuse(self, refusal: EgressDatagramNameRefusal);
}

impl<'a> CodeSandboxEgressQuicFlowsReleaseExt<'a> for Release<'a> {
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

    /// The datagrams the flow held, raw, in arrival order.
    fn held(&self) -> &[Vec<u8>] {
            &self.held
        }

    /// Settles the flow refused for `refusal`; nothing it held is sent.
    fn refuse(mut self, refusal: EgressDatagramNameRefusal) {
            self.refusal = Some(Box::new(refusal));
        }
}

