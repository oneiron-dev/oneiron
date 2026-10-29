//! Publisher comm transport: send states and the send door. The channel's
//! counterparty is each signature artifact's publisher ACTOR, which the
//! delivery path resolves (`delivery_outcome.rs`, FIX 7829).

use super::dial::publisher_enabled_in_txn;
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
    /// No delivery lane carries it, so it has no outward publisher channel:
    /// it is never sent and never refused, and stays readable here. A
    /// signature no lane stored reads this.
    #[default]
    Local,
    /// A delivery lane carries it; no outbound send has answered for it yet.
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
    pub const ALL: [Self; 6] = [
        Self::Local,
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
            Self::Local => "local",
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

/// One signature's stored send state, and the delivery lane's logical send
/// that carries it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SendStateRow {
    pub(super) state: SignatureSendState,
    /// The lane's logical send, the key its outcome is written back under.
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
    /// Signatures left to their delivery lane, the ordinary delivery path;
    /// none of them is confirmed yet.
    pub handed_off: usize,
    /// Signatures the outbound path already confirmed:
    /// [`SignatureSendState::Sent`].
    pub sent: usize,
    /// Signatures held locally because the dial is off.
    pub withheld: usize,
    /// Signatures no delivery lane carries: [`SignatureSendState::Local`].
    pub local: usize,
}

/// Reads a signature's send state: [`SignatureSendState::Local`] when no
/// delivery lane stored it, [`SignatureSendState::Pending`] while its lane's
/// send is unanswered.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a token this engine never
/// wrote.
pub fn signature_send_state(vault: &Vault, id: EntityId) -> PublisherResult<SignatureSendState> {
    Ok(send_state_row(vault, id)?.unwrap_or_default().state)
}

fn send_state_row(vault: &Vault, id: EntityId) -> PublisherResult<Option<SendStateRow>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(SEND_STATE.get(&vault.store, &rtxn, &id)?)
}

/// The state a hold moves a row to, or `None` when the row stands. Only a
/// lane signature's unanswered states move: `Pending` is `Withheld` while the
/// switches hold it, and returns to `Pending` once released. `Local` and
/// every state the outbound path wrote (`Uncertain`, `NotDelivered`, `Sent`)
/// stand.
const fn held_state(state: SignatureSendState, withheld: bool) -> Option<SignatureSendState> {
    match (state, withheld) {
        (SignatureSendState::Pending, true) => Some(SignatureSendState::Withheld),
        (SignatureSendState::Withheld, false) => Some(SignatureSendState::Pending),
        _ => None,
    }
}

/// Writes a delivery lane's hold onto its signature, in the lane's write: a
/// lane the switches hold (`withheld`) leaves its pending signature
/// [`SignatureSendState::Withheld`], and a lane they release returns it to
/// [`SignatureSendState::Pending`]. A state the outbound path wrote stands.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn record_signature_hold_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    signature: EntityId,
    withheld: bool,
) -> Result<()> {
    let row = SEND_STATE
        .get(&vault.store, &*wtxn, &signature)?
        .unwrap_or_default();
    if let Some(state) = held_state(row.state, withheld) {
        SEND_STATE.put(
            &vault.store,
            wtxn,
            &signature,
            &SendStateRow { state, ..row },
        )?;
    }
    Ok(())
}

/// Offers a batch of stored signatures to the publisher channel, honoring the
/// dial.
///
/// Dial ON: each signature a delivery lane carries is left to that lane, the
/// ordinary delivery path (`feedback/report/delivery.rs`), which dispatches it
/// under one logical send and writes that send's outcome back
/// (`delivery_outcome.rs`). Nothing is confirmed here: a handed-off signature
/// stays [`SignatureSendState::Pending`] (a withheld one returns to it) and is
/// counted as handed off, never as sent (FIX 9811). Dial OFF: nothing is sent;
/// each pending signature is durably marked [`SignatureSendState::Withheld`],
/// which is what makes a skip auditable afterwards. Either way a signature no
/// lane carries stays [`SignatureSendState::Local`], a state the outbound path
/// wrote stands, and a confirmed signature counts as sent. Each row is read,
/// decided, counted and written under one writer, so a state the outbound
/// path commits meanwhile is never overwritten.
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
    vault.try_with_write_txn_grouped(|wtxn| {
        for id in sigs {
            if !SIGNATURE.contains(&vault.store, &*wtxn, id)? {
                return Err(PublisherError::SignatureNotFound);
            }
        }
        let enabled = publisher_enabled_in_txn(vault, &*wtxn)?;
        let mut outcome = SendOutcome::default();
        for id in sigs {
            let row = SEND_STATE
                .get(&vault.store, &*wtxn, id)?
                .unwrap_or_default();
            match row.state {
                SignatureSendState::Sent => outcome.sent += 1,
                SignatureSendState::Local => outcome.local += 1,
                _ if enabled => outcome.handed_off += 1,
                _ => outcome.withheld += 1,
            }
            if let Some(state) = held_state(row.state, !enabled) {
                SEND_STATE.put(&vault.store, wtxn, id, &SendStateRow { state, ..row })?;
            }
        }
        Ok(outcome)
    })
}
