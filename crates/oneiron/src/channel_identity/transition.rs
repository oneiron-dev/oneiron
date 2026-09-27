//! ChannelIdentity transition admission, custody re-proof, and uniqueness scan.

use crate::batch::EntityMetadataHeader;
use crate::ports::EntityStoreRead;

use crate::entity_id::EntityId;

use crate::error::{Error, Result};

use crate::store::Store;

use super::binding::ChannelIdentityBinding;
use super::custody::{DelegatedGrant, verify_delegated_custody_in_txn};

use super::lifecycle::{ChannelIdentityState, ChannelIdentityStep, IdentityEdge};

use super::record::ChannelIdentity;
use crate::error::RecordError;

/// What an adapter hands the delegated door: NAMES, never evidence.
///
/// There is deliberately no proof field and no way to add one. A
/// `DelegatedCustodyProof` borrows the transaction that read the custody
/// record, so a proof that reached a caller-owned struct would be a proof that
/// outlived its evidence. The door mints its own inside the write transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedProvisionRequest {
    /// Channel key; normalized by the door.
    pub channel: String,
    /// The member-held mailbox; normalized by the door.
    pub address_or_handle: String,
    /// Which agent (or vault) the mailbox routes to. Chosen by a LOCAL actor.
    pub binding: ChannelIdentityBinding,
    /// The custody record NAME plus the read scopes it covers.
    pub grant: DelegatedGrant,
}

/// WHICH WRITE this is.
///
/// A door that takes a BODY — one incoming row, with no view of what stood at
/// `id` before it — has to guess the rest, and the guesses are exactly where a
/// re-keyed row looks like a fresh one and a crafted ACTIVE delegated body
/// looks like a lawfully stepped one. These two shapes are the only ways a
/// stored CHANNEL_IDENTITY row changes, and each is produced by a road that
/// ALREADY HOLDS the facts it needs: the creating door knows the id was empty,
/// the stepping door read the prior row in its own transaction.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IdentityTransition<'a> {
    /// No CHANNEL_IDENTITY row stood at this id: the key is being claimed.
    Birth { next: &'a ChannelIdentity },
    /// A stored row moves. `prior` is what this transaction read at `id`.
    Step {
        prior: &'a ChannelIdentity,
        next: &'a ChannelIdentity,
    },
}

impl IdentityTransition<'_> {
    const fn next(&self) -> &ChannelIdentity {
        match self {
            Self::Birth { next } | Self::Step { next, .. } => next,
        }
    }
}

/// Admits a ChannelIdentity TRANSITION arriving at the store.
///
/// Every typed CID writer converges here, before its bytes are handed to the
/// batch funnel, and three laws are stated once rather than re-derived per
/// writer.
///
/// **B — a delegated row is BORN `Requested`.** Custody is a local fact,
/// consent is a local fact, and the BINDING is chosen by the local actor that
/// consented; `Active` claims all three already happened. A body that arrives
/// ACTIVE at a birth asserts them without any of them having occurred — no
/// provision decision, no bind edge, no fulfillment, no receipt. Every later
/// delegated state is reachable only as a checked step from a row that exists.
/// Self-held births in stepped states stay admitted: a self-held row asserts no
/// external fact, and `own_app_home` births ACTIVE on purpose.
///
/// **K — a stored row's assignment key is immutable across a step.** The key is
/// the mailbox the row was provisioned for; moving it would leave the key it
/// used to hold naming a row that is no longer there while another key gains a
/// second occupant.
///
/// **U — one occupant per key.** Uniqueness compares [`AssignmentKey`], not the
/// stored spellings, and it asks [`ChannelIdentity::occupies_assignment_key`]
/// rather than "does a row exist": a self-held row holds its address forever
/// (never-recycle), while a retired DELEGATED row holds nothing, because the
/// mailbox was never ours to hold back.
///
/// **C — custody is re-proved in THIS transaction for a live delegated row.**
/// The proof a constructor consumed was minted in the read transaction that
/// preceded the write, so a grant revoked in between would otherwise stand up a
/// row that claims a mailbox this device can no longer read. The wall is kept
/// exactly for the states that assert a live grant
/// ([`Custody::asserts_delegated_custody`](super::custody::Custody::asserts_delegated_custody));
/// the retirement lane is
/// deliberately exempt, because retirement after a member revokes is precisely
/// when custody can no longer be proved and must stay possible.
///
/// # Errors
///
/// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody) for a delegated birth outside
/// `Requested` or a step that moves the key; [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound) /
/// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive) / [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied) when a
/// live delegated row cannot re-prove custody for its own mailbox; and
/// [`RecordError::ChannelIdentityAlreadyExists`](crate::error::RecordError::ChannelIdentityAlreadyExists) when the write would put a second
/// occupant on a key.
pub(crate) fn admit_channel_identity_transition_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    transition: IdentityTransition<'_>,
) -> Result<()> {
    let next = transition.next();
    next.validate()?;
    if let Some(facet_ref) = next.binding().facet_ref() {
        let facet_type = store
            .port_entity_record(txn, &facet_ref)?
            .map(|row| row.encode())
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type));
        if facet_type != Some(crate::registry::ENTITY_TYPE_FACET) {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "channel identity binding facet_ref must name a FACET",
            )));
        }
    }
    match transition {
        IdentityTransition::Birth { next } => {
            if next.is_delegated() && next.state() != ChannelIdentityState::Requested {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "a delegated_grant identity is born Requested; every later state is a \
                     checked lifecycle step from a row that already exists",
                )));
            }
        }
        IdentityTransition::Step { prior, next } => {
            if prior.assignment_key() != next.assignment_key() {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "a stored channel identity's assignment key is immutable",
                )));
            }
        }
    }
    if super::assignment::conflicts(store, txn, id, next)? {
        return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
    }
    reprove_delegated_custody_in_txn(store, txn, next)
}

/// Lowers one lifecycle ACT to the next row, proving custody IN this
/// transaction when the act asserts a live delegated grant.
///
/// This is where the delegated machine's two proof-carrying edges get their
/// proof, and why they are unreachable without one: the proof borrows `txn`, so
/// the only way to build a `Bind` or `Fulfill` delegated edge is inside the
/// transaction that read the custody record — which is the transaction that
/// writes the row. A caller cannot verify, wait, and then step.
///
/// Retirement (`Release`, `Close`) deliberately mints no proof. A member who
/// revokes their grant is exactly the case where custody can no longer be
/// proved, and the row must still be closable.
///
/// # Errors
///
/// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
/// when the act is not on this row's machine (a delegated `Rotate` or
/// `Quarantine`) or not on its current state's table;
/// [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound) /
/// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive) /
/// [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied)
/// when a live delegated act cannot re-prove custody for its own mailbox.
pub(crate) fn step_channel_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    current: &ChannelIdentity,
    step: ChannelIdentityStep,
    at: u64,
) -> Result<ChannelIdentity> {
    let Some(grant) = current.grant() else {
        return current.step(step, at);
    };
    let proof = if step.asserts_live_custody() {
        Some(verify_delegated_custody_in_txn(
            store,
            txn,
            current.channel(),
            current.address_or_handle(),
            grant,
        )?)
    } else {
        None
    };
    current.step_edge(IdentityEdge::delegated(step, proof)?, at)
}

/// Law C, for the row a birth or a step is about to store.
fn reprove_delegated_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &ChannelIdentity,
) -> Result<()> {
    let Some(grant) = identity.grant() else {
        return Ok(());
    };
    if identity.custody().asserts_delegated_custody() {
        verify_delegated_custody_in_txn(
            store,
            txn,
            identity.channel(),
            identity.address_or_handle(),
            grant,
        )?;
    }
    Ok(())
}
