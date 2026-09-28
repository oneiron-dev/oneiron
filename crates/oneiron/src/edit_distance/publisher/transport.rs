//! Publisher comm transport: counterparty, send states, and the send door.

use super::dial::publisher_enabled;
use super::signature_store::SIGNATURE;
use super::{PublisherError, PublisherResult};
use crate::Vault;
use crate::comm::{record_comm_send_receipt, resolve_or_create_comm_party};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// The comm party key the publisher counterparty resolves under.
pub const PUBLISHER_PARTY_KEY: &str = "publisher";

/// The comm channel class publisher sends ride.
pub const PUBLISHER_CHANNEL_CLASS: &str = "publisher";

/// Send-state token for a publisher issue signature, keyed by signature id.
const SEND_STATE: SideTable<EntityId, SignatureSendState, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ISSUE_SIGNATURE_SEND);

/// Resolves — creating on first use — the PERSON entity the publisher channel
/// hangs off.
///
/// # Errors
///
/// Whatever `comm.rs`'s party door raises.
pub fn publisher_party(vault: &Vault) -> PublisherResult<EntityId> {
    Ok(resolve_or_create_comm_party(vault, PUBLISHER_PARTY_KEY)?)
}

/// Where a stored signature stands with respect to the outbound hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureSendState {
    /// Computed and stored; never offered to the send door.
    #[default]
    Pending,
    /// Offered while the dial was off — stored, deliberately not sent.
    Withheld,
    /// Handed to `comm.rs`'s send-receipt door.
    Sent,
}

impl SignatureSendState {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Withheld, Self::Sent];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Withheld => "withheld",
            Self::Sent => "sent",
        }
    }

    /// Parses a pinned token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

impl RawValue for SignatureSendState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.as_str().as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(Self::parse)
            .ok_or_else(|| CodecError::Value(Error::CorruptedIndex("issue signature send state")))
    }
}

/// What one [`send_signatures_if_enabled`] batch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendOutcome {
    /// Signatures handed to the comm send door.
    pub sent: usize,
    /// Signatures held locally because the dial is off.
    pub withheld: usize,
    /// The counterparty this batch rode, resolved once for the whole batch.
    /// `None` when the dial was off — a withheld batch mints no party.
    pub party: Option<EntityId>,
}

/// Reads a signature's send state; [`SignatureSendState::Pending`] until the
/// send door has ruled on it.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a token this engine never
/// wrote.
pub fn signature_send_state(vault: &Vault, id: EntityId) -> PublisherResult<SignatureSendState> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(SEND_STATE
        .get(&vault.store, &rtxn, &id)?
        .unwrap_or(SignatureSendState::Pending))
}

fn put_send_state(vault: &Vault, id: EntityId, state: SignatureSendState) -> Result<()> {
    vault.with_write_txn(|wtxn| SEND_STATE.put(&vault.store, wtxn, &id, &state))
}

fn require_signature(vault: &Vault, id: EntityId) -> PublisherResult<()> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    if !SIGNATURE.contains(&vault.store, &rtxn, &id)? {
        return Err(PublisherError::SignatureNotFound);
    }
    Ok(())
}

/// Offers a batch of stored signatures to the publisher channel, honoring the
/// dial.
///
/// Dial ON: the counterparty is resolved once, then each signature rides
/// `comm.rs`'s send-receipt door. Dial OFF: nothing is sent and nothing is
/// resolved; each signature is durably marked
/// [`SignatureSendState::Withheld`], which is what makes a skip auditable
/// afterwards.
///
/// The projector is NOT run here — `comm.rs` owns when its pass runs, and
/// coupling a send door to a projector pass is exactly the kind of internal
/// this lane is not allowed to reach into.
///
/// # Errors
///
/// [`PublisherError::SignatureNotFound`] when an id has no stored record,
/// plus storage and comm errors.
pub fn send_signatures_if_enabled(
    vault: &Vault,
    sigs: &[EntityId],
) -> PublisherResult<SendOutcome> {
    // An empty batch resolves nothing: minting the counterparty for a send that
    // carries no signatures would leave a PERSON row behind for a caller that
    // asked for no work.
    if sigs.is_empty() {
        return Ok(SendOutcome::default());
    }
    for id in sigs {
        require_signature(vault, *id)?;
    }
    if !publisher_enabled(vault)? {
        for id in sigs {
            put_send_state(vault, *id, SignatureSendState::Withheld)?;
        }
        return Ok(SendOutcome {
            sent: 0,
            withheld: sigs.len(),
            party: None,
        });
    }
    let party = publisher_party(vault)?;
    let now = vault.store.clock.now_recorded_at();
    for id in sigs {
        record_comm_send_receipt(vault, PUBLISHER_PARTY_KEY, PUBLISHER_CHANNEL_CLASS, now)?;
        put_send_state(vault, *id, SignatureSendState::Sent)?;
    }
    Ok(SendOutcome {
        sent: sigs.len(),
        withheld: 0,
        party: Some(party),
    })
}
