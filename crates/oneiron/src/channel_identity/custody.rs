//! Custody: WHO holds the account behind a channel identity, the delegated
//! grant handle, the txn-bound proof, and the one verification door.
//!
//! [`Custody`] is the sum type the whole module turns on. A row is either an
//! account the product minted — self-held, with a shape and the self-held
//! lifecycle — or a member's mailbox under a scoped-read grant, with that grant
//! and the delegated lifecycle. The pairing is the representation, so "a
//! delegated row without a grant", "a self-held row carrying one", and "a
//! delegated row in Rotating or Quarantine" have no inhabitant to validate
//! against.
//!
//! A `delegated_grant` row is a claim that this device may read a mailbox the
//! product never minted and does not own. What makes that claim true is a live
//! SECRET_CUSTODY record with a `connector:<provider>` read binding that NAMES
//! THIS MAILBOX as its subject. So the custody record names its subject through
//! a `subject:<channel>:<address>` scope, the proof carries the address, and
//! `covers` is a three-way match: a caller holding a proof for one member's
//! record cannot stand up a row over another member's mailbox.

use std::marker::PhantomData;

use crate::error::{Error, Result};
use crate::secret_custody::{
    SECRET_SCOPE_READ, SecretBinding, SecretCustodyStatus, read_secret_custody_admission_in_txn,
    resolve_secret_ref_in_txn,
};
use crate::store::Store;

use super::address::{AssignmentAddress, ChannelKey};
use super::auth_mode::ChannelAuthMode;
use super::binding::ChannelIdentityFulfillment;
use super::codec::invalid_identity;
use super::keys::SUBJECT_CLASS_SELF_HELD;
use super::lifecycle::{ChannelIdentityState, DelegatedLifecycle, IdentityEdge, SelfHeldLifecycle};
use super::shape::{ChannelIdentityShape, SelfHeldShape};
use crate::error::{RecordError, SecretError};
use crate::gate::class_policy::ActPosture;

const MAX_DELEGATED_GRANT_REF_BYTES: usize = 256;
const MAX_DELEGATED_GRANT_SCOPES: usize = 8;

/// Read-only OAuth scope classes a `delegated_grant` row may carry.
///
/// There is deliberately no send, reply, delete, or modify variant. Scoped-read
/// is not a policy setting that a caller could widen: the absence of the variant
/// is what makes a delegated row structurally incapable of naming a write scope,
/// including through a decoded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DelegatedGrantScope {
    /// Read message bodies in the granted mailbox.
    MailRead,
    /// Read message headers/metadata only.
    MailMetadata,
}

impl DelegatedGrantScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailRead => "mail.read",
            Self::MailMetadata => "mail.metadata",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mail.read" => Some(Self::MailRead),
            "mail.metadata" => Some(Self::MailMetadata),
            _ => None,
        }
    }
}

/// The custody handle a `delegated_grant` row carries.
///
/// This is a custody record NAME plus the read scopes the grant covers. The
/// OAuth access/refresh token bytes live in the custody record and are reachable
/// only through the SECRET-02 door under an effector binding; they never land on
/// this struct, on the encoded body, or on any claim derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedGrant {
    /// Custody record name (`Vault::resolve_secret_ref` key), never a token.
    pub custody_record_ref: String,
    /// Read scopes the grant covers; non-empty, deduplicated.
    pub scopes: Vec<DelegatedGrantScope>,
}

impl DelegatedGrant {
    /// Builds a delegated grant handle from a custody record name and scopes.
    #[must_use]
    pub fn new(custody_record_ref: impl Into<String>, scopes: Vec<DelegatedGrantScope>) -> Self {
        Self {
            custody_record_ref: custody_record_ref.into(),
            scopes,
        }
    }

    /// Whether the scopes this grant covers include OUTBOUND SEND.
    ///
    /// Always false today, and matched exhaustively on purpose:
    /// [`DelegatedGrantScope`] declares read classes only, so adding a send
    /// class is a compile error here until someone decides what it answers.
    /// That is what keeps a manifest row from turning a read-only OAuth grant
    /// into send authority — the policy row says whether the ACT class may run,
    /// and this says whether the grant we actually hold carries it.
    #[must_use]
    pub(crate) fn covers_outbound_send(&self) -> bool {
        self.scopes.iter().any(|scope| match scope {
            DelegatedGrantScope::MailRead | DelegatedGrantScope::MailMetadata => false,
        })
    }

    /// Validates the grant handle's own bounds.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody) for a blank or over-long custody
    /// record name, an empty or over-long scope set, or a repeated scope.
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.custody_record_ref.trim();
        if trimmed.is_empty() || self.custody_record_ref.len() > MAX_DELEGATED_GRANT_REF_BYTES {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated_grant_ref must be a non-empty custody record name of at most 256 bytes",
            )));
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_DELEGATED_GRANT_SCOPES {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated grant must declare 1..=8 read scopes",
            )));
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if self.scopes[..index].contains(scope) {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "delegated grant scopes must not repeat",
                )));
            }
        }
        Ok(())
    }
}

/// WHO holds the account behind a channel identity — and therefore which
/// lifecycle the row runs on.
///
/// This is the module's central representation. A self-held row carries the
/// shape of an account the product minted plus the self-held machine; a
/// delegated row carries the grant over a member's mailbox plus the delegated
/// machine. Because the two travel together, the pairs CID-1 had to re-derive
/// on every encode, decode and door — a delegated row with no grant, a self-held
/// row carrying one, a delegated row in `Rotating` or `Quarantine`, a pending
/// row with no fulfillment lane, a quarantined row with no window — are not
/// refused. They cannot be spelled.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Custody {
    /// An address or handle the product minted, owns, and may recycle.
    SelfHeld {
        shape: SelfHeldShape,
        lifecycle: SelfHeldLifecycle,
    },
    /// A member-held mailbox read under a scoped OAuth grant.
    Delegated {
        grant: DelegatedGrant,
        lifecycle: DelegatedLifecycle,
    },
}

/// What a row can do for a message arriving NOW.
///
/// One projection replaces the three duplicated `(shape, state)` matches CID-1
/// carried at the inbound router, the lifecycle verb and the export layer. The
/// router's observable answers are unchanged: a retiring row still delivers with
/// outbound closed, a tombstone still refuses, and a row that has not been
/// fulfilled is not yet routable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InboundDisposition {
    /// Deliver normally.
    Deliver,
    /// Deliver, but the row is retiring: outbound is closed.
    DeliverRetiring,
    /// The row exists but has not gone live yet.
    NotYetRoutable,
    /// The row is closed out; refuse.
    Closed,
}

impl Custody {
    /// A self-held row at the start of its machine.
    #[must_use]
    pub const fn requested_self_held(shape: SelfHeldShape) -> Self {
        Self::SelfHeld {
            shape,
            lifecycle: SelfHeldLifecycle::Requested,
        }
    }

    /// A delegated row at the start of its machine.
    ///
    /// `pub(super)`: what makes a delegated row TRUE is a verified custody
    /// proof, and only [`ChannelIdentity::requested_delegated`](super::record::ChannelIdentity::requested_delegated)
    /// holds one.
    #[must_use]
    pub(super) const fn requested_delegated(grant: DelegatedGrant) -> Self {
        Self::Delegated {
            grant,
            lifecycle: DelegatedLifecycle::Requested,
        }
    }

    /// The wire shape this custody projects to.
    #[must_use]
    pub const fn shape(&self) -> ChannelIdentityShape {
        match self {
            Self::SelfHeld { shape, .. } => shape.shape(),
            Self::Delegated { .. } => ChannelIdentityShape::DelegatedGrant,
        }
    }

    /// The wire lifecycle state this custody projects to.
    #[must_use]
    pub const fn state(&self) -> ChannelIdentityState {
        match self {
            Self::SelfHeld { lifecycle, .. } => lifecycle.state(),
            Self::Delegated { lifecycle, .. } => lifecycle.state(),
        }
    }

    /// The fulfillment lane this row waits on, when it waits on one.
    #[must_use]
    pub const fn pending_fulfillment(&self) -> Option<ChannelIdentityFulfillment> {
        match self {
            Self::SelfHeld { lifecycle, .. } => lifecycle.pending_fulfillment(),
            Self::Delegated { lifecycle, .. } => lifecycle.pending_fulfillment(),
        }
    }

    /// The never-recycle window, when this row holds one. Only a self-held row
    /// ever does: the delegated machine has no `Quarantine` to be in.
    #[must_use]
    pub const fn quarantine_until(&self) -> Option<u64> {
        match self {
            Self::SelfHeld { lifecycle, .. } => lifecycle.quarantine_until(),
            Self::Delegated { .. } => None,
        }
    }

    /// The grant a delegated row reads under.
    #[must_use]
    pub const fn grant(&self) -> Option<&DelegatedGrant> {
        match self {
            Self::SelfHeld { .. } => None,
            Self::Delegated { grant, .. } => Some(grant),
        }
    }

    /// Whether this row is a member-held mailbox under a scoped-read grant.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated { .. })
    }

    /// The credential mechanism this custody REQUIRES.
    ///
    /// A delegated row is a member's OAuth grant by construction; a self-held
    /// row's mechanism is the adapter's business, so only the delegated arm
    /// pins one.
    #[must_use]
    pub(super) const fn required_auth_mode(&self) -> Option<ChannelAuthMode> {
        match self {
            Self::SelfHeld { .. } => None,
            Self::Delegated { .. } => Some(ChannelAuthMode::OAuth),
        }
    }

    /// Whether this row still OCCUPIES its assignment key.
    ///
    /// A self-held row occupies it forever: never-recycle is the whole point of
    /// releasing an address WE minted, so a quarantined or tombstoned row is
    /// still holding it back. A delegated row is the opposite case — the mailbox
    /// was never ours, so once the row is retiring we hold no claim on it at
    /// all, and lawful re-consent stays open after the close.
    #[must_use]
    pub const fn occupies_assignment_key(&self) -> bool {
        match self {
            Self::SelfHeld { .. } => true,
            Self::Delegated { lifecycle, .. } => !matches!(
                lifecycle,
                DelegatedLifecycle::Released | DelegatedLifecycle::Tombstone
            ),
        }
    }

    /// The `act_policy` subject class this row resolves under.
    #[must_use]
    pub(crate) const fn outbound_subject_class(&self) -> &'static str {
        match self {
            Self::SelfHeld { .. } => SUBJECT_CLASS_SELF_HELD,
            Self::Delegated { .. } => ChannelIdentityShape::DelegatedGrant.as_str(),
        }
    }

    /// Whether this row's SUBSTRATE carries the capability an outbound send
    /// needs, with the act class already permitted by policy.
    ///
    /// This is the half that stays in code, and it is a capability question,
    /// never a class one. A self-held row holds an account the product minted,
    /// so the capability is its live state. A delegated row holds a grant, and
    /// [`DelegatedGrant::covers_outbound_send`] asks that grant — which answers
    /// no for every scope class that exists, because
    /// [`DelegatedGrantScope`] has no send variant to name. Raising the
    /// manifest row does not change that answer; it changes which refusal the
    /// caller reports.
    #[must_use]
    pub(crate) fn holds_outbound_capability(&self) -> bool {
        match self {
            Self::SelfHeld { lifecycle, .. } => {
                matches!(lifecycle, SelfHeldLifecycle::Active)
            }
            Self::Delegated { grant, lifecycle } => {
                matches!(lifecycle, DelegatedLifecycle::Active) && grant.covers_outbound_send()
            }
        }
    }

    /// Whether this row may carry an OUTBOUND effect under `posture`.
    #[must_use]
    pub(crate) fn may_send_under(&self, posture: ActPosture) -> bool {
        match posture {
            ActPosture::Deny => false,
            ActPosture::RequireCapability => self.holds_outbound_capability(),
        }
    }

    /// Whether this row may carry an OUTBOUND effect under the RESTRICTIVE
    /// default posture.
    ///
    /// The posture this answers under is the one the default manifest ships
    /// (`deny` for a delegated row, `require_capability` for a self-held one),
    /// so it is also the fail-closed answer for a caller that holds no resolved
    /// manifest. A caller that resolves policy asks `may_send_under` with the
    /// posture it resolved; a caller that only needs selection hygiene keeps
    /// asking this.
    #[must_use]
    pub fn may_send(&self) -> bool {
        self.may_send_under(match self {
            Self::SelfHeld { .. } => ActPosture::RequireCapability,
            Self::Delegated { .. } => ActPosture::Deny,
        })
    }

    /// What this row can do for a message arriving now.
    #[must_use]
    pub const fn inbound(&self) -> InboundDisposition {
        match self {
            Self::SelfHeld { lifecycle, .. } => match lifecycle {
                SelfHeldLifecycle::Active | SelfHeldLifecycle::Rotating => {
                    InboundDisposition::Deliver
                }
                SelfHeldLifecycle::Released | SelfHeldLifecycle::Quarantine { .. } => {
                    InboundDisposition::DeliverRetiring
                }
                SelfHeldLifecycle::Tombstone => InboundDisposition::Closed,
                SelfHeldLifecycle::Requested | SelfHeldLifecycle::PendingFulfillment(_) => {
                    InboundDisposition::NotYetRoutable
                }
            },
            Self::Delegated { lifecycle, .. } => match lifecycle {
                DelegatedLifecycle::Active => InboundDisposition::Deliver,
                DelegatedLifecycle::Released => InboundDisposition::DeliverRetiring,
                DelegatedLifecycle::Tombstone => InboundDisposition::Closed,
                DelegatedLifecycle::Requested | DelegatedLifecycle::PendingFulfillment(_) => {
                    InboundDisposition::NotYetRoutable
                }
            },
        }
    }

    /// Rebuilds custody from a decoded body's wire fields.
    ///
    /// THE decode-side door, and the one place every cross-field refusal a
    /// stored or replicated body can still fail now lives. A body is
    /// `(shape, state, pending_fulfillment, quarantine_until, grant?)` — five
    /// independent wire fields — and exactly one combination of them names each
    /// variant. Everything CID-1 checked in `validate()` and
    /// `validate_custody()` is therefore checked HERE, once, on the only road
    /// that can present an inconsistent combination at all:
    ///
    /// * a `delegated_grant` shape with no grant keys, or a self-held shape
    ///   carrying them (the schema version already splits the key sets, so this
    ///   is the belt to that braces);
    /// * a delegated body claiming `Rotating` or `Quarantine` — states that
    ///   assert the product mints and holds back the member's mailbox;
    /// * `pending_fulfillment` present outside PENDING, or absent inside it;
    /// * `quarantine_until` present outside QUARANTINE, absent inside it, or
    ///   naming a window that ends before the stamp it dates from. HOW LONG the
    ///   hold must run is manifest policy the door resolves, not a decode-side
    ///   number (see [`WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE`](super::keys::WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE)).
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// for any of the above; [`Error::ArithmeticOverflow`] when the quarantine
    /// floor cannot be computed.
    pub(super) fn from_wire(
        shape: ChannelIdentityShape,
        state: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        quarantine_until: Option<u64>,
        grant: Option<DelegatedGrant>,
        state_changed_at: u64,
    ) -> Result<Self> {
        match (SelfHeldShape::from_shape(shape), grant) {
            (Some(shape), None) => Ok(Self::SelfHeld {
                shape,
                lifecycle: self_held_lifecycle_from_wire(
                    state,
                    pending_fulfillment,
                    quarantine_until,
                    state_changed_at,
                )?,
            }),
            (None, Some(grant)) => {
                if quarantine_until.is_some() {
                    return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                        "a delegated_grant identity is never rotated or quarantined: the \
                         product neither mints nor holds back the member's mailbox",
                    )));
                }
                Ok(Self::Delegated {
                    grant,
                    lifecycle: delegated_lifecycle_from_wire(state, pending_fulfillment)?,
                })
            }
            (Some(_), Some(_)) => Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "only a delegated_grant identity may carry a delegated grant ref",
            ))),
            (None, None) => Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated_grant identity requires a delegated grant ref",
            ))),
        }
    }

    /// Whether a delegated row in this state claims a LIVE grant, and so must
    /// re-prove custody in the transaction that stores it.
    #[must_use]
    pub(super) const fn asserts_delegated_custody(&self) -> bool {
        match self {
            Self::SelfHeld { .. } => false,
            Self::Delegated { lifecycle, .. } => lifecycle.asserts_custody(),
        }
    }

    /// Applies one edge, on whichever machine this custody runs, with
    /// `min_quarantine_secs` as the resolved hold floor.
    ///
    /// A mismatch is refused HERE rather than by a predicate at the caller: a
    /// self-held edge handed to a delegated row (and the reverse) is one arm,
    /// and the edges the delegated machine does not have — `Rotate`,
    /// `Quarantine` — cannot even be built as a
    /// [`DelegatedEdge`](super::lifecycle::DelegatedEdge).
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// when the edge belongs to the other machine, or is not on this state's
    /// table.
    pub(super) fn step(
        &self,
        edge: IdentityEdge<'_>,
        at: u64,
        min_quarantine_secs: u64,
    ) -> Result<Self> {
        match (self, edge) {
            (Self::SelfHeld { shape, lifecycle }, IdentityEdge::SelfHeld(edge)) => {
                Ok(Self::SelfHeld {
                    shape: *shape,
                    lifecycle: lifecycle.step(edge, at, min_quarantine_secs)?,
                })
            }
            (Self::Delegated { grant, lifecycle }, IdentityEdge::Delegated(edge)) => {
                Ok(Self::Delegated {
                    grant: grant.clone(),
                    lifecycle: lifecycle.step(edge)?,
                })
            }
            (Self::SelfHeld { .. }, IdentityEdge::Delegated(_)) => {
                Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "a delegated edge cannot step a self-held identity",
                )))
            }
            (Self::Delegated { .. }, IdentityEdge::SelfHeld(_)) => {
                Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "a self-held edge cannot step a delegated identity",
                )))
            }
        }
    }
}

/// The self-held state a body's `(state, pending_fulfillment, quarantine_until)`
/// triple names, or a refusal.
fn self_held_lifecycle_from_wire(
    state: ChannelIdentityState,
    pending_fulfillment: Option<ChannelIdentityFulfillment>,
    quarantine_until: Option<u64>,
    state_changed_at: u64,
) -> Result<SelfHeldLifecycle> {
    let lifecycle = match state {
        ChannelIdentityState::Requested => SelfHeldLifecycle::Requested,
        ChannelIdentityState::PendingFulfillment => {
            SelfHeldLifecycle::PendingFulfillment(pending_fulfillment.ok_or_else(invalid_identity)?)
        }
        ChannelIdentityState::Active => SelfHeldLifecycle::Active,
        ChannelIdentityState::Rotating => SelfHeldLifecycle::Rotating,
        ChannelIdentityState::Released => SelfHeldLifecycle::Released,
        // Coherence, not duration: a window that ends before the state change
        // it dates from means two things at once, and no policy can make it
        // mean one. HOW LONG the hold must run is the manifest's
        // `channel_identity.quarantine` wait row, resolved at the door that
        // holds the snapshot — decode has no snapshot to resolve against, and a
        // replicated body carries no evidence about the local vault's policy.
        ChannelIdentityState::Quarantine => {
            let until = quarantine_until.ok_or_else(invalid_identity)?;
            if until < state_changed_at {
                return Err(invalid_identity());
            }
            SelfHeldLifecycle::Quarantine { until }
        }
        ChannelIdentityState::Tombstone => SelfHeldLifecycle::Tombstone,
    };
    check_wire_payload(&lifecycle, pending_fulfillment, quarantine_until)?;
    Ok(lifecycle)
}

/// A payload field the named state does not carry is a body that means two
/// things at once. Refuse rather than drop it: the row would then re-encode to
/// different bytes than it was read from.
fn check_wire_payload(
    lifecycle: &SelfHeldLifecycle,
    pending_fulfillment: Option<ChannelIdentityFulfillment>,
    quarantine_until: Option<u64>,
) -> Result<()> {
    if lifecycle.pending_fulfillment() != pending_fulfillment
        || lifecycle.quarantine_until() != quarantine_until
    {
        return Err(invalid_identity());
    }
    Ok(())
}

/// The delegated state a body's `(state, pending_fulfillment)` pair names.
///
/// `Rotating` and `Quarantine` have no delegated variant to land in, so a body
/// claiming one is refused here — the same refusal CID-1's `validate_custody`
/// made, now as an absent arm rather than a predicate.
fn delegated_lifecycle_from_wire(
    state: ChannelIdentityState,
    pending_fulfillment: Option<ChannelIdentityFulfillment>,
) -> Result<DelegatedLifecycle> {
    let lifecycle = match state {
        ChannelIdentityState::Requested => DelegatedLifecycle::Requested,
        ChannelIdentityState::PendingFulfillment => DelegatedLifecycle::PendingFulfillment(
            pending_fulfillment.ok_or_else(invalid_identity)?,
        ),
        ChannelIdentityState::Active => DelegatedLifecycle::Active,
        ChannelIdentityState::Released => DelegatedLifecycle::Released,
        ChannelIdentityState::Tombstone => DelegatedLifecycle::Tombstone,
        ChannelIdentityState::Rotating | ChannelIdentityState::Quarantine => {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "a delegated_grant identity is never rotated or quarantined: the product \
                 neither mints nor holds back the member's mailbox",
            )));
        }
    };
    if lifecycle.pending_fulfillment() != pending_fulfillment {
        return Err(invalid_identity());
    }
    Ok(lifecycle)
}

/// The effector whose read binding is what "custody" MEANS for a delegated
/// row on a given channel.
///
/// One entry today: a delegated `email` row is a member-held Gmail/Workspace
/// mailbox, and the only thing that makes the row true is a live
/// `connector:gmail` read binding on the named custody record. A channel with
/// no entry admits no delegated row at all, so an unknown channel fails closed
/// rather than defaulting to "any binding will do".
const DELEGATED_CUSTODY_EFFECTORS: [(&str, &str); 1] = [("email", "connector:gmail")];

/// The effector binding a delegated `channel` row's custody record must carry.
///
/// `None` means the channel admits no delegated rows. The lookup takes the
/// channel through [`ChannelKey::normalize`] for the same reason
/// [`delegated_custody_subject_scope`] does: a table keyed on lowercase nouns
/// answers a raw spelling honestly or not at all.
#[must_use]
pub fn delegated_custody_effector(channel: &str) -> Option<&'static str> {
    let channel = ChannelKey::normalize(channel);
    DELEGATED_CUSTODY_EFFECTORS
        .iter()
        .find_map(|(candidate, effector)| (*candidate == channel.as_str()).then_some(*effector))
}

/// The scope string a custody record must declare to name `(channel, address)`
/// as its SUBJECT.
///
/// Scope-string form, not a codec change: `SecretBinding.scopes` is already a
/// free-form `Vec<String>` whose documented job is naming what a binding is
/// FOR, so the subject rides there with no on-disk migration.
///
/// The host registers it at OAuth completion — it has the account email from
/// the token exchange, which the engine does not and must not.
///
/// BOTH halves of the subject are normalized here, and the channel half is what
/// ONE-1825 closes. Every writer that consumes this scope —
/// `verify_delegated_custody_in_txn`, reached through
/// [`Vault::provision_delegated_identity`](crate::Vault::provision_delegated_identity)
/// and [`Vault::verify_delegated_custody`](crate::Vault::verify_delegated_custody) —
/// runs the request channel through [`ChannelKey::normalize`] FIRST and then
/// looks for `subject:email:…`. A helper that interpolated the caller's raw
/// spelling would put the registration side and the admission side of the same
/// tie out of step on any channel spelling that normalizes:
/// [`delegated_custody_scopes`]`("Email", addr)` would emit `subject:Email:…`,
/// the engine would look for `subject:email:…`, and a binding a host registered
/// in good faith would be refused forever for a mailbox the engine otherwise
/// accepts. Normalizing once, here, is what keeps the two halves from drifting;
/// already-normalized inputs are byte-for-byte unaffected.
#[must_use]
pub fn delegated_custody_subject_scope(channel: &str, address: &str) -> String {
    let channel = ChannelKey::normalize(channel);
    format!(
        "subject:{}:{}",
        channel.as_str(),
        AssignmentAddress::normalize(channel.as_str(), address).as_str()
    )
}

/// The read + subject scope pair a delegated custody binding must declare.
///
/// The registration-side twin of `verify_delegated_custody_in_txn`, so a host
/// registering a grant and the engine admitting it cannot drift. `"Email"`,
/// `"EMAIL"` and `" email "` all register the one scope the engine looks for.
#[must_use]
pub fn delegated_custody_scopes(channel: &str, address: &str) -> Vec<String> {
    vec![
        SECRET_SCOPE_READ.to_owned(),
        delegated_custody_subject_scope(channel, address),
    ]
}

/// Typed proof that a delegated grant's custody record was read out of the
/// vault and found active, with the channel's required read binding present AND
/// that binding naming this exact mailbox as its subject.
///
/// There is no public constructor and no public field: the ONLY way to hold one
/// is `verify_delegated_custody_in_txn`, which reads the custody record. That
/// is the difference between a caller ASSERTING custody and custody having been
/// VERIFIED.
///
/// The `'txn` lifetime is load-bearing, not decoration. The proof borrows the
/// transaction that read the record, so it cannot outlive it: "a point-in-time
/// proof reused after the grant was revoked" stops being a discipline the
/// callers have to remember and becomes a BORROW ERROR.
///
/// The proof carries names, never bytes: it is minted from the value-less
/// admission projection, so no OAuth token material reaches it or anything
/// derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelegatedCustodyProof<'txn> {
    channel: String,
    address: String,
    custody_record_ref: String,
    _txn: PhantomData<&'txn ()>,
}

impl DelegatedCustodyProof<'_> {
    /// Whether this proof covers exactly `(channel, address, grant)`.
    ///
    /// The ADDRESS arm is the one that matters: a two-way `(channel, record)`
    /// match is what would let a proof for one member's record stand up a row
    /// over another member's mailbox.
    #[must_use]
    pub(super) fn covers(&self, channel: &str, address: &str, grant: &DelegatedGrant) -> bool {
        self.channel == channel
            && self.address == address
            && self.custody_record_ref == grant.custody_record_ref
    }
}

/// Verifies the custody record behind a delegated grant inside an existing txn.
///
/// Fails closed when the channel admits no delegated rows, when the named
/// record is missing, when it is not `Active`, when the binding the token door
/// would select for the channel's effector does not declare the read scope, or
/// when that binding does not name `address` as its subject.
///
/// The record's value bytes are never MATERIALIZED, not merely never printed:
/// the read is [`read_secret_custody_admission_in_txn`], whose projection has
/// no value field at all. Decoding the full `SecretCustodyRecord` here would
/// heap-copy the member's OAuth token into a verification path that has no
/// business holding it; the one sanctioned value read stays the SECRET-02 door.
///
/// # Errors
///
/// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody), [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound),
/// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive), or [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied).
pub(super) fn verify_delegated_custody_in_txn<'txn>(
    store: &Store,
    txn: &'txn heed::RoTxn<'_>,
    channel: &str,
    address: &str,
    grant: &DelegatedGrant,
) -> Result<DelegatedCustodyProof<'txn>> {
    grant.validate()?;
    let effector = delegated_custody_effector(channel).ok_or(Error::Record(
        RecordError::InvalidChannelIdentityBody(
            "channel admits no delegated_grant custody effector",
        ),
    ))?;
    let missing = || {
        Error::Secret(SecretError::SecretRefNotFound {
            name: grant.custody_record_ref.clone(),
        })
    };
    let id =
        resolve_secret_ref_in_txn(store, txn, &grant.custody_record_ref)?.ok_or_else(missing)?;
    let admission = read_secret_custody_admission_in_txn(store, txn, &id)?.ok_or_else(missing)?;
    if admission.status != SecretCustodyStatus::Active {
        return Err(Error::Secret(SecretError::SecretCustodyNotActive {
            name: admission.name,
        }));
    }
    // The SELECTION rule has to be the token door's, not a looser one. The
    // door resolves `binding_for` — the FIRST binding naming the effector —
    // and then asks that one binding for `read`. An `any()` scan answers a
    // different question: it would mint a proof for a record whose first
    // `connector:gmail` binding grants nothing and whose second grants read,
    // and the door this proof exists to stand for would then refuse to service
    // the row at poll time. A proof that outruns its door is not a proof.
    //
    // The subject rides on that same one binding, for the same reason: the
    // door services a MAILBOX, and a binding that grants read of some other
    // member's mail is not custody of this one.
    let subject = delegated_custody_subject_scope(channel, address);
    let denied = || {
        Error::Secret(SecretError::SecretBindingDenied {
            effector: effector.to_owned(),
            secret_ref: admission.name.clone(),
        })
    };
    let binding = admission.binding_for(effector).ok_or_else(denied)?;
    if !binding.grants_read() || !binding_names_subject(binding, &subject) {
        return Err(denied());
    }
    Ok(DelegatedCustodyProof {
        channel: channel.to_owned(),
        address: address.to_owned(),
        custody_record_ref: grant.custody_record_ref.clone(),
        _txn: PhantomData,
    })
}

/// Whether the binding declares this exact subject scope.
///
/// An empty scope list is not a wildcard, and neither is a missing subject:
/// both mean the record never named a mailbox, which is precisely the
/// mailbox-unbound custody this check exists to refuse. Fail closed.
fn binding_names_subject(binding: &SecretBinding, subject: &str) -> bool {
    binding.scopes.iter().any(|scope| scope == subject)
}
