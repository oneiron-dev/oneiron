//! The one action that asks a former peer to erase what it holds from this
//! vault (ARCH-0043 #leaving-a-company: "Each side gets a list of what it
//! holds from the other, by attribution, and one action to send erase
//! requests. Nothing is erased by force in either direction."; L7-09).
//!
//! It is the courtesy ask (OF-273) over each pact with the peer that this
//! vault ended, sent in one call: signed with the host's key at the pact's
//! terminal epoch, queued, retried while the peer is away, and recorded
//! with its delivery status. Each ask names no world, which asks about all
//! the pact delivered: an ended pact keeps no scope to choose worlds from,
//! and the peer's own delivery history maps the ask to its copies, a copied
//! inquiry answer among them. The peer files each ask for its owner, and
//! nothing is erased on receipt.

use super::{CooperativeDeletionNotice, QueuedAsk};
use crate::authority::{AuthorityVaultId, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::deletion::CooperativeDeletionRequest;
use crate::error::RecordError;
use crate::{Result, Vault};
use oneiron_authority::authority::FederationPactStatus;

/// The key context of a leave ask's nonce.
const LEAVE_ASK_NONCE_CONTEXT: &str = "oneiron leave erase request nonce v1";

/// The nonce of the leave ask over `pact_id` up to `epoch_cutoff`: one per
/// ended pact, so a repeated action finds its first ask instead of queuing
/// a second. The queue refuses any other ask under it.
pub(super) fn leave_ask_nonce(pact_id: &[u8; 32], epoch_cutoff: u64) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key(LEAVE_ASK_NONCE_CONTEXT);
    hasher.update(pact_id);
    hasher.update(&epoch_cutoff.to_le_bytes());
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    nonce
}

/// Whether `body` is the ask the leave action signs over its pact ended at
/// `terminal_epoch`: one page naming no world, cut off at that epoch.
pub(super) fn is_leave_ask(body: &CooperativeDeletionRequest, terminal_epoch: u64) -> bool {
    body.worlds.is_empty() && body.pages == 1 && body.epoch_cutoff == terminal_epoch
}

impl Vault {
    /// Asks `peer_vault_id` to erase what it holds from this vault, as
    /// `owner`, in one action: for each pact with that peer that this
    /// vault's fold shows Disconnected or Dissolved, one courtesy ask about
    /// all the pact delivered up to its terminal epoch, signed by `issuer`
    /// and queued for `destination` (the peer's courtesy route). An ask this
    /// action already queued is answered as it stands, not queued again,
    /// also when two calls run at once: the writer that would queue it looks.
    /// The answers come in pact order.
    ///
    /// # Errors
    ///
    /// No pact with that peer has ended here
    /// ([`RecordError::CooperativeDeletionRequiresTerminalPact`]): the
    /// member ends its inquiry edge first; the owner's proof no longer
    /// holds; signing and storage errors.
    pub fn send_leave_erase_requests(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        peer_vault_id: &AuthorityVaultId,
        destination: &str,
        now: u64,
    ) -> Result<Vec<CooperativeDeletionNotice>> {
        self.recheck_owner(owner)?;
        let fold = self.authority_fold()?;
        let ended: Vec<([u8; 32], u64)> = fold
            .federation_pacts
            .iter()
            .filter(|(_, pact)| {
                pact.peer_vault_id == *peer_vault_id
                    && matches!(
                        pact.status,
                        FederationPactStatus::Disconnected | FederationPactStatus::Dissolved
                    )
            })
            .map(|(pact_id, pact)| (*pact_id, pact.terminal_epoch.unwrap_or(pact.pact_epoch)))
            .collect();
        if ended.is_empty() {
            return Err(RecordError::CooperativeDeletionRequiresTerminalPact.into());
        }
        let mut notices = Vec::with_capacity(ended.len());
        for (pact_id, epoch_cutoff) in ended {
            let nonce = leave_ask_nonce(&pact_id, epoch_cutoff);
            for signed in issuer.sign_cooperative_deletion_request(
                self,
                &pact_id,
                Vec::new(),
                epoch_cutoff,
                nonce,
            )? {
                notices.push(self.queue_cooperative_deletion_request(
                    owner,
                    &signed,
                    destination,
                    now,
                    QueuedAsk::Answer,
                )?);
            }
        }
        Ok(notices)
    }
}
