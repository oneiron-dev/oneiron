//! Vault-resident ChannelIdentity record: private fields, one custody value,
//! accessors, and the one stepping door.

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

use crate::entity_id::EntityId;

use crate::error::{Error, Result};

use super::address::{AssignmentAddress, AssignmentKey, ChannelKey};

use super::binding::{ChannelIdentityBinding, ChannelIdentityFulfillment};

use super::codec::{
    encode_binding_target, encode_optional_entity_ref, invalid_identity, validate_non_empty_bounded,
};

use super::custody::{Custody, DelegatedCustodyProof, DelegatedGrant, InboundDisposition};

use super::keys::{
    CHANNEL_IDENTITY_CLAIM_PREDICATES, DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
    MAX_ADDRESS_OR_HANDLE_BYTES, MAX_CHANNEL_BYTES, PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF, PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET, PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF, PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL, PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_SHAPE, PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
};

use super::auth_mode::ChannelAuthMode;
use super::keys::PREDICATE_CHANNEL_IDENTITY_AUTH_MODE;
use super::lifecycle::{
    ChannelIdentityState, ChannelIdentityStep, IdentityEdge, SelfHeldLifecycle,
};

use super::shape::{ChannelIdentityShape, SelfHeldShape};
use crate::error::RecordError;

/// Vault-resident ChannelIdentity record.
///
/// Every field is PRIVATE, and that is the point of R1. CID-1's public product
/// struct let any caller write `identity.state = Active` on a requested row, or
/// assemble a body whose `shape`, `state`, `pending_fulfillment`,
/// `quarantine_until` and `delegated_grant` disagreed — so a 40-line
/// `validate()` had to re-derive the coupling between them on every encode and
/// decode. Here [`Custody`] carries the coupling, the constructors below are the
/// only ways in, [`Self::step`] is the only way a stored row moves, and
/// `validate` is two bounds checks on the two strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentity {
    /// Authentication mechanism only; credentials stay in host custody.
    auth_mode: ChannelAuthMode,
    channel: String,
    address_or_handle: String,
    binding: ChannelIdentityBinding,
    /// WHO holds the account, and therefore which lifecycle this row runs on.
    custody: Custody,
    /// Audit only; never a precedence key.
    state_changed_at: u64,
    reputation_ref: Option<EntityId>,
    manifest_ref: Option<EntityId>,
}

/// Validated codec input after the wire key set selected a custody variant.
pub(super) struct StoredIdentityParts {
    pub(super) auth_mode: ChannelAuthMode,
    pub(super) channel: String,
    pub(super) address_or_handle: String,
    pub(super) binding: ChannelIdentityBinding,
    pub(super) custody: Custody,
    pub(super) state_changed_at: u64,
    pub(super) reputation_ref: Option<EntityId>,
    pub(super) manifest_ref: Option<EntityId>,
}

impl ChannelIdentity {
    /// Constructs a requested SELF-HELD identity row before provider
    /// fulfillment starts.
    ///
    /// The channel and address are normalized HERE, once, so two spellings of
    /// one mailbox cannot become two assignment keys with two occupants.
    ///
    /// The shape parameter is [`SelfHeldShape`], not the wire
    /// [`ChannelIdentityShape`], and that is the whole of ONE-1825's third
    /// root. A door that took the wire enum would have to answer for
    /// `DelegatedGrant`, and every available answer is wrong: mapping it onto a
    /// self-held shape hands a caller who asked for a read-only member-held
    /// mailbox a PRODUCT-OWNED, send-capable row instead (see [`Self::may_send`]
    /// — every self-held shape may send once Active, a delegated row never
    /// does), and silence makes that escalation invisible. Refusing at runtime
    /// is not available either: this signature is infallible and `#[must_use]`,
    /// and a `panic!` is not a product-code refusal.
    ///
    /// So the misuse is made UNSPELLABLE instead. `SelfHeldShape` has no
    /// `DelegatedGrant` variant, so there is no argument left that would need
    /// degrading. `Self::requested_delegated` — behind
    /// [`Vault::provision_delegated_identity`](crate::Vault::provision_delegated_identity), which mints a real custody
    /// proof — is the only delegated door.
    #[must_use]
    pub fn requested(
        channel: impl AsRef<str>,
        address_or_handle: impl AsRef<str>,
        shape: SelfHeldShape,
        binding: ChannelIdentityBinding,
        requested_at: u64,
    ) -> Self {
        let channel = channel.as_ref();
        Self {
            address_or_handle: AssignmentAddress::normalize(channel, address_or_handle.as_ref())
                .as_str()
                .to_owned(),
            channel: ChannelKey::normalize(channel).as_str().to_owned(),
            binding,
            custody: Custody::requested_self_held(shape),
            state_changed_at: requested_at,
            reputation_ref: None,
            manifest_ref: None,
            auth_mode: ChannelAuthMode::ApiKey,
        }
    }

    /// Constructs a requested `delegated_grant` row over a member-held mailbox.
    ///
    /// `grant` names an already-granted custody record; this constructor does
    /// not mint, rotate, or read it. It also does not TAKE the caller's word
    /// that the grant exists: `custody` is a [`DelegatedCustodyProof`], which
    /// only the engine's verification door can mint, and it must cover this
    /// exact `(channel, address, custody record)` TRIPLE. A caller holding a
    /// proof for another member's mailbox is refused here rather than at one
    /// adapter.
    ///
    /// The row is born `Requested`, always — and now by CONSTRUCTION, not by a
    /// field assignment a later caller could overwrite: the only other producer
    /// of a [`DelegatedLifecycle`](super::lifecycle::DelegatedLifecycle) is
    /// `step`, so "a retired delegated row that was never stored" has no
    /// spelling. Custody is a local fact, consent is a local fact, and the
    /// BINDING is chosen by the local actor that consented; `Active` asserts all
    /// three already happened.
    ///
    /// `pub(super)`: the proof borrows a transaction, so the only sound public
    /// spelling is an engine door that mints and consumes it in one txn —
    /// [`Vault::provision_delegated_identity`](crate::Vault::provision_delegated_identity).
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody) when the proof does not cover the
    /// triple, or when the row fails the record's bounds checks.
    pub(super) fn requested_delegated(
        channel: impl AsRef<str>,
        address_or_handle: impl AsRef<str>,
        binding: ChannelIdentityBinding,
        grant: DelegatedGrant,
        custody: &DelegatedCustodyProof<'_>,
        requested_at: u64,
    ) -> Result<Self> {
        let channel_key = ChannelKey::normalize(channel.as_ref());
        let address = AssignmentAddress::normalize(channel.as_ref(), address_or_handle.as_ref());
        if !custody.covers(channel_key.as_str(), address.as_str(), &grant) {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated_grant identity requires a verified custody proof for its own \
                 (channel, mailbox, grant)",
            )));
        }
        let identity = Self {
            channel: channel_key.as_str().to_owned(),
            address_or_handle: address.as_str().to_owned(),
            binding,
            custody: Custody::requested_delegated(grant),
            state_changed_at: requested_at,
            reputation_ref: None,
            manifest_ref: None,
            auth_mode: ChannelAuthMode::OAuth,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Constructs the pre-provisioned own-app home-channel identity for an agent.
    #[must_use]
    pub fn own_app_home(agent_ref: EntityId, created_at: u64) -> Self {
        Self {
            channel: "own_app".to_owned(),
            address_or_handle: format!("own_app:{}", agent_ref.to_hex()),
            binding: ChannelIdentityBinding::agent(agent_ref),
            custody: Custody::SelfHeld {
                shape: SelfHeldShape::DedicatedHandle,
                lifecycle: SelfHeldLifecycle::Active,
            },
            state_changed_at: created_at,
            reputation_ref: None,
            manifest_ref: None,
            auth_mode: ChannelAuthMode::Local,
        }
    }

    /// Rebuilds a row from stored parts. The CODEC's door, and nothing else's.
    ///
    /// The decoder has already chosen the [`Custody`] variant from the pinned
    /// key set its schema version selects, so this takes the finished value
    /// rather than loose fields: a body whose shape and custody keys disagree
    /// fails at the key-set check, not here.
    pub(super) fn from_stored_parts(parts: StoredIdentityParts) -> Result<Self> {
        let identity = Self {
            auth_mode: parts.auth_mode,
            channel: parts.channel,
            address_or_handle: parts.address_or_handle,
            binding: parts.binding,
            custody: parts.custody,
            state_changed_at: parts.state_changed_at,
            reputation_ref: parts.reputation_ref,
            manifest_ref: parts.manifest_ref,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// The channel key, normalized at construction.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The assignment address or handle, normalized at construction.
    #[must_use]
    pub fn address_or_handle(&self) -> &str {
        &self.address_or_handle
    }

    /// Which actor or vault this identity routes to.
    #[must_use]
    pub const fn binding(&self) -> ChannelIdentityBinding {
        self.binding
    }

    /// WHO holds the account behind this row.
    #[must_use]
    pub const fn custody(&self) -> &Custody {
        &self.custody
    }

    /// The wire addressability shape.
    #[must_use]
    pub const fn shape(&self) -> ChannelIdentityShape {
        self.custody.shape()
    }

    /// The wire lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ChannelIdentityState {
        self.custody.state()
    }

    /// The async fulfillment lane this row waits on, when it waits on one.
    #[must_use]
    pub const fn pending_fulfillment(&self) -> Option<ChannelIdentityFulfillment> {
        self.custody.pending_fulfillment()
    }

    /// The never-recycle window this row holds, when it holds one.
    #[must_use]
    pub const fn quarantine_until(&self) -> Option<u64> {
        self.custody.quarantine_until()
    }

    /// The delegated grant this row reads under, when it is delegated.
    #[must_use]
    pub const fn grant(&self) -> Option<&DelegatedGrant> {
        self.custody.grant()
    }

    /// Authentication mechanism; never credential material.
    #[must_use]
    pub const fn auth_mode(&self) -> ChannelAuthMode {
        self.auth_mode
    }

    /// When this row last moved. Audit only, never a precedence key.
    #[must_use]
    pub const fn state_changed_at(&self) -> u64 {
        self.state_changed_at
    }

    /// The channel actor this identity's reputation rides on.
    #[must_use]
    pub const fn reputation_ref(&self) -> Option<EntityId> {
        self.reputation_ref
    }

    /// The channel manifest this identity was provisioned against.
    #[must_use]
    pub const fn manifest_ref(&self) -> Option<EntityId> {
        self.manifest_ref
    }

    /// Rebinds this row to the channel actor that owns it.
    ///
    /// `register_channel_actor` mints the actor and the identity in one
    /// transaction, so the actor ref does not exist when the caller builds the
    /// row. This is a WRITER's door, not a field: the binding target and the
    /// reputation ref move together, and the facet mask worn on the channel is
    /// carried over rather than dropped.
    pub(super) fn bind_to_channel_actor(&mut self, actor_ref: EntityId) {
        self.binding = ChannelIdentityBinding::Actor {
            actor_ref,
            facet_ref: self.binding.facet_ref(),
        };
        self.reputation_ref = Some(actor_ref);
    }

    /// Returns the uniqueness key used for never-recycle enforcement.
    ///
    /// DERIVED, not stored. Returning the stored pair verbatim meant a row
    /// decoded from disk — replay, rebuild, any body an older or third-party
    /// writer produced — was compared under whatever spelling was on disk,
    /// while another road normalized. Computing the key from the stored bytes
    /// makes every road agree by construction.
    ///
    /// The ROW is never rewritten: `self.channel` and `self.address_or_handle`
    /// keep the exact bytes the decoder read, so the codec's
    /// `encode(decode(bytes)) == bytes` pin is untouched. Only the KEY is
    /// canonical.
    #[must_use]
    pub fn assignment_key(&self) -> AssignmentKey {
        AssignmentKey::of(&self.channel, &self.address_or_handle)
    }

    /// Whether this row is a member-held mailbox under a scoped-read grant.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.custody.is_delegated()
    }

    /// Whether this row still OCCUPIES its assignment key.
    #[must_use]
    pub const fn occupies_assignment_key(&self) -> bool {
        self.custody.occupies_assignment_key()
    }

    /// Capability-only preflight. A send still requires vault-resident
    /// `act_policy` and gate authorization at the effect door (see
    /// [`Custody::may_send`]).
    #[must_use]
    pub fn may_send(&self) -> bool {
        self.custody.may_send()
    }

    /// Whether this row may carry an OUTBOUND effect under `posture`, as the
    /// caller resolved it from the manifest's `act_policy` table.
    #[must_use]
    pub(crate) fn may_send_under(&self, posture: crate::gate::class_policy::ActPosture) -> bool {
        self.custody.may_send_under(posture)
    }

    /// The `act_policy` subject class this row resolves under.
    #[must_use]
    pub(crate) const fn outbound_subject_class(&self) -> &'static str {
        self.custody.outbound_subject_class()
    }

    /// Whether this row's substrate carries the capability an outbound send
    /// needs, with the act class already permitted (see
    /// [`Custody::holds_outbound_capability`]).
    #[must_use]
    pub(crate) fn holds_outbound_capability(&self) -> bool {
        self.custody.holds_outbound_capability()
    }

    /// What this row can do for a message arriving now.
    #[must_use]
    pub const fn inbound(&self) -> InboundDisposition {
        self.custody.inbound()
    }

    /// Validates what remains after custody and lifecycle are represented as values.
    pub fn validate(&self) -> Result<()> {
        if let Some(required) = self.custody.required_auth_mode()
            && self.auth_mode != required
        {
            return Err(RecordError::InvalidChannelIdentityBody(
                "delegated identity requires OAuth",
            )
            .into());
        }
        validate_non_empty_bounded(
            &self.channel,
            MAX_CHANNEL_BYTES,
            "channel must be non-empty and at most 64 bytes",
        )?;
        validate_non_empty_bounded(
            &self.address_or_handle,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "address_or_handle must be non-empty and at most 512 bytes",
        )?;
        self.binding.validate()?;
        if let Some(grant) = self.custody.grant() {
            grant.validate()?;
        }
        Ok(())
    }

    /// Returns a copy with one lifecycle ACT applied. SELF-HELD rows only.
    ///
    /// A delegated row is refused HERE rather than stepped, and the refusal is
    /// the point: `Bind` and `Fulfill` on a member's mailbox assert that the
    /// grant is still live, and the only place that can be PROVED is the
    /// transaction that writes the row. So a delegated row steps through
    /// [`Vault::step_channel_identity`](crate::Vault::step_channel_identity),
    /// which mints the proof and consumes it in one txn; there is no
    /// caller-owned spelling that skips it.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// when this row is delegated, when the act is not on its state's table, or
    /// when the stamp moves backwards.
    pub fn step(&self, step: ChannelIdentityStep, state_changed_at: u64) -> Result<Self> {
        self.step_with_wait(
            step,
            state_changed_at,
            DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
        )
    }

    /// [`Self::step`] with the vault's RESOLVED quarantine floor.
    ///
    /// A door that holds a manifest snapshot resolves
    /// [`WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE`](super::keys::WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE)
    /// and calls this; [`Self::step`] is the same act under the floor the
    /// default manifest ships, which is the fail-closed answer for a caller
    /// that has no snapshot to resolve against.
    ///
    /// # Errors
    ///
    /// As [`Self::step`], with the window checked against
    /// `min_quarantine_secs`.
    pub fn step_with_wait(
        &self,
        step: ChannelIdentityStep,
        state_changed_at: u64,
        min_quarantine_secs: u64,
    ) -> Result<Self> {
        if self.custody.is_delegated() {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "a delegated_grant identity steps only through the vault door, which proves \
                 custody in the writing transaction",
            )));
        }
        self.step_edge(
            IdentityEdge::SelfHeld(step.self_held_edge()),
            state_changed_at,
            min_quarantine_secs,
        )
    }

    /// Returns a copy with one lifecycle EDGE applied.
    ///
    /// The edge is the whole admission: [`Custody::step`] owns both tables, and
    /// a delegated edge that asserts a live grant carries the transaction-bound
    /// proof of it. What is left here is the one fact an edge cannot carry —
    /// time does not run backwards.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](crate::error::RecordError::InvalidChannelIdentityBody)
    /// when the edge is not on this row's table or the stamp moves backwards.
    pub(super) fn step_edge(
        &self,
        edge: IdentityEdge<'_>,
        state_changed_at: u64,
        min_quarantine_secs: u64,
    ) -> Result<Self> {
        if state_changed_at < self.state_changed_at {
            return Err(invalid_identity());
        }
        let next = Self {
            custody: self
                .custody
                .step(edge, state_changed_at, min_quarantine_secs)?,
            state_changed_at,
            ..self.clone()
        };
        next.validate()?;
        Ok(next)
    }

    /// Builds typed `channel_identity.*` claim bodies for this record.
    #[must_use]
    pub fn claim_bodies(&self, identity_id: EntityId) -> Vec<ClaimBody> {
        CHANNEL_IDENTITY_CLAIM_PREDICATES
            .iter()
            .map(|predicate| {
                ClaimBody::new(
                    *predicate,
                    ClaimSubject::Entity(identity_id),
                    self.claim_value(predicate)
                        .expect("predicate drawn from channel identity family"),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
            })
            .collect()
    }

    fn claim_value(&self, predicate: &str) -> Option<Value> {
        match predicate {
            PREDICATE_CHANNEL_IDENTITY_AUTH_MODE => Some(Value::from(self.auth_mode.as_str())),
            PREDICATE_CHANNEL_IDENTITY_CHANNEL => Some(Value::from(self.channel.as_str())),
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => {
                Some(Value::from(self.address_or_handle.as_str()))
            }
            PREDICATE_CHANNEL_IDENTITY_SHAPE => Some(Value::from(self.shape().as_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => Some(Value::from(self.binding.scope_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => Some(encode_binding_target(self.binding)),
            PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF => {
                Some(encode_optional_entity_ref(self.binding.facet_ref()))
            }
            PREDICATE_CHANNEL_IDENTITY_STATE => Some(Value::from(self.state().as_str())),
            PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => Some(
                self.pending_fulfillment()
                    .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
            ),
            PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => Some(Value::from(self.state_changed_at)),
            PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
                Some(self.quarantine_until().map_or(Value::Nil, Value::from))
            }
            PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF => {
                Some(encode_optional_entity_ref(self.reputation_ref))
            }
            PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF => {
                Some(encode_optional_entity_ref(self.manifest_ref))
            }
            _ => None,
        }
    }
}
