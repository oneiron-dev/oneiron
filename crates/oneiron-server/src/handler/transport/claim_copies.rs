//! Native optional-copy variants at the existing guarded socket send.

use axum::extract::ws::Message as WsMessage;
use futures_util::{SinkExt, Stream};

use super::GuardedTransport;

pub(super) enum ClaimCopyRelease {
    Promotion(oneiron::sync::window::PreparedPromotionClaimCopies),
    Window(oneiron::sync::window::WindowClaimCopyRelease),
}

impl ClaimCopyRelease {
    pub(super) fn is_current(
        &self,
        vault: &oneiron::Vault,
        peer: oneiron::authority::PeerMachine,
    ) -> bool {
        match self {
            Self::Promotion(copies) => copies.is_current(vault, peer),
            Self::Window(copies) => copies.is_current(vault, peer),
        }
    }
}

impl<S, E> GuardedTransport<S>
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
{
    pub(in crate::handler) async fn send_rpc_promotion(
        &mut self,
        data: Vec<u8>,
        promotion: super::super::direct::PromotionFrame,
        vault: &oneiron::Vault,
        peer: oneiron::authority::PeerMachine,
    ) -> bool {
        let optional = promotion.for_required(&data).map(|(candidate, copies)| {
            (candidate, ClaimCopyRelease::Promotion(copies), vault, peer)
        });
        self.send_binary_inner(data, optional).await
    }

    pub(in crate::handler) async fn send_window_claim_frame(
        &mut self,
        data: Vec<u8>,
        candidate: Vec<u8>,
        copies: oneiron::sync::window::WindowClaimCopyRelease,
        vault: &oneiron::Vault,
        peer: oneiron::authority::PeerMachine,
    ) -> bool {
        self.send_binary_inner(
            data,
            Some((candidate, ClaimCopyRelease::Window(copies), vault, peer)),
        )
        .await
    }
}
