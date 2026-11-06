//! Optional derived copies bound to one promotion's original envelope.

use crate::Vault;
use crate::authority::PeerMachine;
use crate::embed::home_vectors::{HomeClaimDelivery, PreparedHomeClaimSend};
use crate::sync::transport::{WindowPadKind, decode_window_pad_envelope};

/// Native source and recipient evidence kept until this promotion's socket send.
/// The encoded copies alone are data, not a release certificate.
pub struct PreparedPromotionClaimCopies {
    window: String,
    payload: Vec<u8>,
    sends: Vec<PreparedHomeClaimSend>,
    bytes: Vec<u8>,
}

impl PreparedPromotionClaimCopies {
    /// Prepares optional copies without changing the promotion envelope or result.
    /// Any miss leaves the ordinary promotion intact.
    pub fn prepare(
        vault: &Vault,
        peer: PeerMachine,
        window: &str,
        envelope: &[u8],
    ) -> Option<Self> {
        let envelope = decode_window_pad_envelope(envelope).ok()?;
        if envelope.kind != WindowPadKind::Promotion {
            return None;
        }
        let delivery = HomeClaimDelivery {
            window,
            payload: &envelope.payload,
        };
        let sends = vault
            .prepare_carried_home_claim_sends(peer, &delivery, None)
            .ok()?;
        if sends.is_empty() {
            return None;
        }
        let mut copies = Vec::with_capacity(sends.len());
        for send in &sends {
            copies.push(send.copy_for(vault, peer, &delivery).ok()??);
        }
        let bytes = rmp_serde::to_vec(&copies).ok()?;
        Some(Self {
            window: window.to_owned(),
            payload: envelope.payload,
            sends,
            bytes,
        })
    }

    /// Preparation bytes only; the final socket must still call `is_current`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Rechecks every selected source, release row and native key for the actual
    /// socket's vault and proved peer. Call after its last wait, before start_send.
    pub fn is_current(&self, vault: &Vault, peer: PeerMachine) -> bool {
        let delivery = HomeClaimDelivery {
            window: &self.window,
            payload: &self.payload,
        };
        self.sends
            .iter()
            .all(|send| matches!(send.copy_for(vault, peer, &delivery), Ok(Some(_))))
    }
}
