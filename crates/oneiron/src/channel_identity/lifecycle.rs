//! ChannelIdentity lifecycle: the wire projection, the two machines, and their
//! proof-carrying edge tables.
//!
//! CID-1 multiplexed TWO machines onto one flat [`ChannelIdentityState`]: an
//! account the product minted (which it may rotate and hold out of recycling)
//! and a member-held mailbox under a scoped-read grant (which it may neither
//! re-mint nor hold back). Which states were legal, which payload fields had to
//! be present, and which edges were admitted then had to be re-derived from the
//! pair `(shape, state)` at every door.
//!
//! Here each machine is its own type, each state carries exactly the payload
//! that state means, and an edge is the only way to move: `Rotating` and
//! `Quarantine` have no spelling on the delegated machine, and a delegated
//! `Bind`/`Fulfill` edge cannot be built without a transaction-bound custody
//! proof. [`ChannelIdentityState`] stays as the WIRE and claim projection, so
//! the pinned body key set, receipts and `channel_identity.state` predicates
//! are byte-for-byte unchanged.

use super::binding::ChannelIdentityFulfillment;
use super::codec::invalid_identity;
use super::custody::DelegatedCustodyProof;
use crate::error::{Error, RecordError, Result};

/// ChannelIdentity lifecycle state as it appears on the wire (OF-347 R3/R5).
///
/// A PROJECTION of [`SelfHeldLifecycle`] / [`DelegatedLifecycle`], never the
/// state itself: it is what the codec writes, what `channel_identity.state`
/// claims carry, and what lifecycle receipts name. It has no edge table —
/// admission belongs to the machine that owns the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityState {
    Requested,
    PendingFulfillment,
    Active,
    Rotating,
    Released,
    Quarantine,
    Tombstone,
}

impl ChannelIdentityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PendingFulfillment => "pending_fulfillment",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Released => "released",
            Self::Quarantine => "quarantine",
            Self::Tombstone => "tombstone",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "pending_fulfillment" => Some(Self::PendingFulfillment),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "released" => Some(Self::Released),
            "quarantine" => Some(Self::Quarantine),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// The lifecycle of an account the PRODUCT holds.
///
/// Each state carries what that state means: a pending row names the
/// fulfillment lane it is waiting on, and a quarantined row names the window it
/// is held out of recycling for. "Pending without a lane" and "quarantine
/// without a window" have no inhabitant, so no validator re-derives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelfHeldLifecycle {
    Requested,
    PendingFulfillment(ChannelIdentityFulfillment),
    Active,
    Rotating,
    Released,
    /// Held out of recycling until `until`.
    ///
    /// The floor `until` must clear is the manifest's resolved
    /// `channel_identity.quarantine` wait row, checked by this machine's step
    /// against the number its door resolved. The decoder checks only that the
    /// window does not end before the stamp it dates from: it holds no manifest
    /// snapshot, and a replicated body carries no evidence about this vault's
    /// policy.
    Quarantine {
        until: u64,
    },
    Tombstone,
}

/// The lifecycle of a member-held mailbox under a scoped-read grant.
///
/// `Rotating` and `Quarantine` are ABSENT, and their absence is the
/// enforcement rather than a predicate somewhere else: rotating would be
/// re-minting an account the product never owned, and quarantining would be a
/// never-recycle hold on someone else's mailbox. Retirement is
/// `Active -> Released -> Tombstone`, and both stops free the assignment key,
/// because closing the row out must never be the act that locks a member out of
/// re-consenting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DelegatedLifecycle {
    Requested,
    PendingFulfillment(ChannelIdentityFulfillment),
    Active,
    Released,
    Tombstone,
}

/// One lifecycle ACT a caller asks for, before it is known which machine the
/// row runs.
///
/// This is the verb layer's entire vocabulary, and the payload rides IN the act
/// that decides it — the lane a bind waits on, the window a release is held
/// back for — so "go to PENDING but say nothing about the lane" and "go to
/// ACTIVE while naming a quarantine window" have no spelling to be refused.
///
/// The self-held machine has an edge for every act. The delegated machine has
/// four, and the two it lacks are refused where the step is lowered: rotating
/// would re-mint an account the product never owned, and quarantining would be
/// a never-recycle hold on someone else's mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityStep {
    /// Enter async fulfillment on `mode`.
    Bind(ChannelIdentityFulfillment),
    /// The provider (or ops, or review) completed: go live.
    Fulfill,
    /// Re-mint the account behind a live row. Self-held only.
    Rotate,
    /// Stop sending; the address is not recycled yet.
    Release,
    /// Take the never-recycle hold on a released address. Self-held only.
    Quarantine { until: u64 },
    /// Close the row out for good.
    Close,
}

impl ChannelIdentityStep {
    /// Whether this act asserts that a delegated grant is STILL LIVE, and so
    /// must carry a proof minted in the transaction that writes the row.
    ///
    /// Binding and going live say "this device may read the member's mailbox".
    /// Retirement says the opposite, and requiring custody there would make a
    /// revoked grant unclosable — so `Release` and `Close` deliberately do not.
    #[must_use]
    pub(super) const fn asserts_live_custody(self) -> bool {
        matches!(self, Self::Bind(_) | Self::Fulfill)
    }

    /// The self-held edge this act names. Total: every act is on that table.
    pub(super) const fn self_held_edge(self) -> SelfHeldEdge {
        match self {
            Self::Bind(mode) => SelfHeldEdge::Bind(mode),
            Self::Fulfill => SelfHeldEdge::Fulfill,
            Self::Rotate => SelfHeldEdge::Rotate,
            Self::Release => SelfHeldEdge::Release,
            Self::Quarantine { until } => SelfHeldEdge::Quarantine { until },
            Self::Close => SelfHeldEdge::Close,
        }
    }
}

/// A step on the SELF-HELD machine.
///
/// The edge names the act, and carries what the act decides: which lane the
/// bind waits on, and how long the release holds the address back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub(super) enum SelfHeldEdge {
    /// Enter async fulfillment on `mode`.
    Bind(ChannelIdentityFulfillment),
    /// The provider (or ops, or review) completed: go live.
    Fulfill,
    /// Re-mint the account behind a live row.
    Rotate,
    /// Stop sending; the address is not recycled yet.
    Release,
    /// Take the never-recycle hold on a released address.
    Quarantine { until: u64 },
    /// Close the row out for good.
    Close,
}

/// A step on the DELEGATED machine.
///
/// The two edges that assert a LIVE grant carry the proof that it is live, so
/// "a delegated row went live without custody having been verified in the
/// writing transaction" is a borrow-checked impossibility rather than a rule a
/// caller has to remember. There is no `Rotate` and no `Quarantine`: neither
/// act is the product's to perform on a mailbox it never minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DelegatedEdge<'txn> {
    /// Enter async fulfillment on `mode`, custody proved in this txn.
    Bind(ChannelIdentityFulfillment, DelegatedCustodyProof<'txn>),
    /// Go live, custody proved in this txn.
    Fulfill(DelegatedCustodyProof<'txn>),
    /// Withdraw the row. Custody is deliberately NOT required: retirement after
    /// a member revokes is precisely when it can no longer be proved.
    Release,
    /// Close the row out; the mailbox stays the member's, free to re-consent.
    Close,
}

/// One step on whichever machine a row runs.
///
/// The verb layer lowers an intent to this ONE value and hands it to
/// [`Custody::step`](super::custody::Custody::step); the mismatched pairing is
/// the only thing left to refuse, in one place, and `Rotate`/`Quarantine` on a
/// delegated row cannot be built at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IdentityEdge<'txn> {
    SelfHeld(SelfHeldEdge),
    Delegated(DelegatedEdge<'txn>),
}

impl<'txn> IdentityEdge<'txn> {
    /// The delegated edge this act names, or a refusal.
    ///
    /// `Rotate` and `Quarantine` are the two acts the delegated machine has no
    /// edge for, and this is the ONE place that refusal is stated: re-minting
    /// and holding back an account belong to whoever owns it, and the product
    /// does not own a member's mailbox. `Bind` and `Fulfill` assert a live
    /// grant, so they take the transaction-bound proof the caller minted; a
    /// caller with no proof cannot reach them.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// for `Rotate` or `Quarantine`.
    pub(super) fn delegated(
        step: ChannelIdentityStep,
        proof: Option<DelegatedCustodyProof<'txn>>,
    ) -> Result<Self> {
        let unowned = || {
            Error::Record(RecordError::InvalidChannelIdentityBody(
                "a delegated_grant identity is never rotated or quarantined: the product \
                 neither mints nor holds back the member's mailbox",
            ))
        };
        let missing_proof = || {
            Error::Record(RecordError::InvalidChannelIdentityBody(
                "a delegated_grant identity goes live only on verified custody for its own \
                 mailbox",
            ))
        };
        let edge = match step {
            ChannelIdentityStep::Bind(mode) => {
                DelegatedEdge::Bind(mode, proof.ok_or_else(missing_proof)?)
            }
            ChannelIdentityStep::Fulfill => {
                DelegatedEdge::Fulfill(proof.ok_or_else(missing_proof)?)
            }
            ChannelIdentityStep::Release => DelegatedEdge::Release,
            ChannelIdentityStep::Close => DelegatedEdge::Close,
            ChannelIdentityStep::Rotate | ChannelIdentityStep::Quarantine { .. } => {
                return Err(unowned());
            }
        };
        Ok(Self::Delegated(edge))
    }
}

impl SelfHeldLifecycle {
    /// The wire projection of this state.
    #[must_use]
    pub const fn state(self) -> ChannelIdentityState {
        match self {
            Self::Requested => ChannelIdentityState::Requested,
            Self::PendingFulfillment(_) => ChannelIdentityState::PendingFulfillment,
            Self::Active => ChannelIdentityState::Active,
            Self::Rotating => ChannelIdentityState::Rotating,
            Self::Released => ChannelIdentityState::Released,
            Self::Quarantine { .. } => ChannelIdentityState::Quarantine,
            Self::Tombstone => ChannelIdentityState::Tombstone,
        }
    }

    /// The fulfillment lane this row waits on, when it waits on one.
    #[must_use]
    pub const fn pending_fulfillment(self) -> Option<ChannelIdentityFulfillment> {
        match self {
            Self::PendingFulfillment(mode) => Some(mode),
            _ => None,
        }
    }

    /// The never-recycle window, when this row is holding one.
    #[must_use]
    pub const fn quarantine_until(self) -> Option<u64> {
        match self {
            Self::Quarantine { until } => Some(until),
            _ => None,
        }
    }

    /// Applies one edge at `at`, with `min_quarantine_secs` as the resolved
    /// hold floor for this vault.
    ///
    /// The floor is a PARAMETER because it is policy: the door resolves the
    /// manifest's `channel_identity.quarantine` wait row in the transaction
    /// that writes the row, and hands the number here. The state table is still
    /// code; how long the hold runs is not.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// when the edge is not on this state's table, or when a quarantine window
    /// is shorter than the resolved floor; [`Error::ArithmeticOverflow`] when
    /// that floor cannot be computed.
    pub(super) fn step(
        self,
        edge: SelfHeldEdge,
        at: u64,
        min_quarantine_secs: u64,
    ) -> Result<Self> {
        match (self, edge) {
            (Self::Requested, SelfHeldEdge::Bind(mode)) => Ok(Self::PendingFulfillment(mode)),
            (Self::PendingFulfillment(_) | Self::Rotating, SelfHeldEdge::Fulfill) => {
                Ok(Self::Active)
            }
            (Self::Active, SelfHeldEdge::Rotate) => Ok(Self::Rotating),
            (Self::Active | Self::Rotating, SelfHeldEdge::Release) => Ok(Self::Released),
            (Self::Released, SelfHeldEdge::Quarantine { until }) => {
                let floor =
                    at.checked_add(min_quarantine_secs)
                        .ok_or(Error::ArithmeticOverflow(
                            "channel identity quarantine window",
                        ))?;
                if until < floor {
                    return Err(invalid_identity());
                }
                Ok(Self::Quarantine { until })
            }
            (Self::Quarantine { .. }, SelfHeldEdge::Close) => Ok(Self::Tombstone),
            _ => Err(invalid_identity()),
        }
    }
}

impl DelegatedLifecycle {
    /// The wire projection of this state.
    #[must_use]
    pub const fn state(self) -> ChannelIdentityState {
        match self {
            Self::Requested => ChannelIdentityState::Requested,
            Self::PendingFulfillment(_) => ChannelIdentityState::PendingFulfillment,
            Self::Active => ChannelIdentityState::Active,
            Self::Released => ChannelIdentityState::Released,
            Self::Tombstone => ChannelIdentityState::Tombstone,
        }
    }

    /// The fulfillment lane this row waits on, when it waits on one.
    #[must_use]
    pub const fn pending_fulfillment(self) -> Option<ChannelIdentityFulfillment> {
        match self {
            Self::PendingFulfillment(mode) => Some(mode),
            _ => None,
        }
    }

    /// Whether a row in this state claims a LIVE grant over the member's
    /// mailbox.
    ///
    /// True for every state that says we can still read it, false once the row
    /// is retiring — which is exactly when custody may no longer be provable,
    /// and must not be required to be.
    #[must_use]
    pub const fn asserts_custody(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::PendingFulfillment(_) | Self::Active
        )
    }

    /// Applies one edge. The edge carries its own custody proof where a live
    /// grant is being asserted, so nothing is re-derived here.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// when the edge is not on this state's table.
    pub(super) fn step(self, edge: DelegatedEdge<'_>) -> Result<Self> {
        match (self, edge) {
            (Self::Requested, DelegatedEdge::Bind(mode, _)) => Ok(Self::PendingFulfillment(mode)),
            (Self::PendingFulfillment(_), DelegatedEdge::Fulfill(_)) => Ok(Self::Active),
            (Self::Active, DelegatedEdge::Release) => Ok(Self::Released),
            (Self::Released, DelegatedEdge::Close) => Ok(Self::Tombstone),
            _ => Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "edge is not on the delegated lifecycle table",
            ))),
        }
    }
}
