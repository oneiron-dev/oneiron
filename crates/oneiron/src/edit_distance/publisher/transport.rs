//! Publisher comm transport: send states and the send door. The channel's
//! counterparty is each signature artifact's publisher ACTOR, which the
//! delivery path resolves (`delivery_outcome.rs`, FIX 7829).

use super::dial::publisher_enabled;
use super::signature_store::SIGNATURE;
use super::{PublisherError, PublisherResult};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// The comm channel class publisher sends ride.
pub const PUBLISHER_CHANNEL_CLASS: &str = "publisher";

/// Send state of a publisher issue signature, keyed by signature id.
pub(super) const SEND_STATE: SideTable<EntityId, SendStateRow, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ISSUE_SIGNATURE_SEND);

/// Separates a send-state token from its logical send on disk.
const SEND_REF_SEPARATOR: u8 = 0;

/// Where a stored signature stands with respect to the outbound hop. Only the
/// ordinary outbound path's answer moves a signature past `Pending` while the
/// dial is on (FIX 9811).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureSendState {
    /// Computed and stored; no outbound send has answered for it yet.
    #[default]
    Pending,
    /// Offered while the dial was off — stored, deliberately not sent.
    Withheld,
    /// Its send may have landed; the outbound ledger reconciles it, and a
    /// later delivery still confirms it.
    Uncertain,
    /// Its last send did not leave; the next send may still deliver it.
    NotDelivered,
    /// The channel acknowledged its send (`delivered_to_channel`, never
    /// "seen"), and the comm send receipt was recorded with it.
    Sent,
}

impl SignatureSendState {
    /// Every arm.
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Withheld,
        Self::Uncertain,
        Self::NotDelivered,
        Self::Sent,
    ];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Withheld => "withheld",
            Self::Uncertain => "uncertain",
            Self::NotDelivered => "not_delivered",
            Self::Sent => "sent",
        }
    }

    /// Parses a pinned token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

/// One signature's stored send state, and the logical send that answered it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SendStateRow {
    pub(super) state: SignatureSendState,
    /// The outbound path's logical send, on a state that path wrote.
    pub(super) send_ref: Option<String>,
}

impl RawValue for SendStateRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = self.state.as_str().as_bytes().to_vec();
        if let Some(send_ref) = &self.send_ref {
            bytes.push(SEND_REF_SEPARATOR);
            bytes.extend_from_slice(send_ref.as_bytes());
        }
        Ok(bytes)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || CodecError::Value(Error::CorruptedIndex("issue signature send state"));
        let mut parts = bytes.splitn(2, |byte| *byte == SEND_REF_SEPARATOR);
        let state = parts
            .next()
            .and_then(|token| std::str::from_utf8(token).ok())
            .and_then(SignatureSendState::parse)
            .ok_or_else(corrupt)?;
        let send_ref = match parts.next() {
            Some(raw) => Some(std::str::from_utf8(raw).map_err(|_| corrupt())?.to_owned()),
            None => None,
        };
        Ok(Self { state, send_ref })
    }
}

/// What one [`send_signatures_if_enabled`] batch did. A handed-off signature
/// is never counted as sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendOutcome {
    /// Signatures left [`SignatureSendState::Pending`] for the ordinary
    /// delivery path; none of them is confirmed yet.
    pub handed_off: usize,
    /// Signatures the outbound path already confirmed:
    /// [`SignatureSendState::Sent`].
    pub sent: usize,
    /// Signatures held locally because the dial is off.
    pub withheld: usize,
}

/// Reads a signature's send state; [`SignatureSendState::Pending`] until the
/// dial or the outbound path has ruled on it.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a token this engine never
/// wrote.
pub fn signature_send_state(vault: &Vault, id: EntityId) -> PublisherResult<SignatureSendState> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(SEND_STATE
        .get(&vault.store, &rtxn, &id)?
        .unwrap_or_default()
        .state)
}

fn put_send_state(vault: &Vault, id: EntityId, state: SignatureSendState) -> Result<()> {
    let row = SendStateRow {
        state,
        send_ref: None,
    };
    vault.with_write_txn_grouped(|wtxn| SEND_STATE.put(&vault.store, wtxn, &id, &row))
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
/// Dial ON: each signature is handed to the ordinary delivery path
/// (`feedback/report/delivery.rs`), which dispatches it under one logical send
/// to its artifact's publisher ACTOR and writes that send's outcome back
/// (`delivery_outcome.rs`); an artifact with no publisher actor has no
/// outward channel, and its signature stays here unsent. Nothing is
/// confirmed here: a handed-off signature stays [`SignatureSendState::Pending`]
/// (a withheld one returns to it) and is counted as handed off, never as sent
/// (FIX 9811). Dial OFF: nothing is sent; each pending signature is durably
/// marked [`SignatureSendState::Withheld`], which is what makes a skip
/// auditable afterwards. Either way a state the outbound path wrote stands,
/// and a confirmed signature counts as sent.
///
/// The projector is NOT run here — `comm.rs` owns when its pass runs, and
/// coupling a send door to a projector pass is exactly the kind of internal
/// this lane is not allowed to reach into.
///
/// # Errors
///
/// [`PublisherError::SignatureNotFound`] when an id has no stored record,
/// plus storage errors.
pub fn send_signatures_if_enabled(
    vault: &Vault,
    sigs: &[EntityId],
) -> PublisherResult<SendOutcome> {
    for id in sigs {
        require_signature(vault, *id)?;
    }
    let enabled = publisher_enabled(vault)?;
    let mut outcome = SendOutcome::default();
    for id in sigs {
        let state = signature_send_state(vault, *id)?;
        if state == SignatureSendState::Sent {
            outcome.sent += 1;
        } else if enabled {
            if state == SignatureSendState::Withheld {
                put_send_state(vault, *id, SignatureSendState::Pending)?;
            }
            outcome.handed_off += 1;
        } else {
            if state == SignatureSendState::Pending {
                put_send_state(vault, *id, SignatureSendState::Withheld)?;
            }
            outcome.withheld += 1;
        }
    }
    Ok(outcome)
}
