//! Vault-resident ChannelIdentity record with validators, transitions, and claims.

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

use crate::entity_id::EntityId;

use crate::error::{Error, Result};

use super::address::{AssignmentAddress, AssignmentKey, ChannelKey};

use super::binding::{ChannelIdentityBinding, ChannelIdentityFulfillment};

use super::codec::{
    encode_binding_target, encode_optional_entity_ref, invalid_identity, validate_non_empty_bounded,
};

use super::custody::{DelegatedCustodyProof, DelegatedGrant};

use super::keys::{
    CHANNEL_IDENTITY_CLAIM_PREDICATES, CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
    MAX_ADDRESS_OR_HANDLE_BYTES, MAX_CHANNEL_BYTES, PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF, PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET, PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF, PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL, PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_SHAPE, PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
};

use super::lifecycle::ChannelIdentityState;

use super::shape::{ChannelIdentityShape, SelfHeldShape};

/// Vault-resident ChannelIdentity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentity {
    pub channel: String,
    pub address_or_handle: String,
    pub shape: ChannelIdentityShape,
    pub binding: ChannelIdentityBinding,
    pub state: ChannelIdentityState,
    pub pending_fulfillment: Option<ChannelIdentityFulfillment>,
    pub state_changed_at: u64,
    pub quarantine_until: Option<u64>,
    pub reputation_ref: Option<EntityId>,
    pub manifest_ref: Option<EntityId>,
    /// Present exactly when `shape` is [`ChannelIdentityShape::DelegatedGrant`].
    ///
    /// The one-to-one tie is enforced by [`ChannelIdentity::validate`], so a
    /// delegated row without custody, or a self-held row carrying custody,
    /// cannot be built, encoded, or decoded.
    pub grant: Option<DelegatedGrant>,
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
    /// [`Vault::provision_delegated_identity`], which mints a real custody
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
            shape: shape.shape(),
            binding,
            state: ChannelIdentityState::Requested,
            pending_fulfillment: None,
            state_changed_at: requested_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: None,
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
    /// The row is born `Requested`, always. Custody is a local fact, consent is
    /// a local fact, and the BINDING is chosen by the local actor that
    /// consented; `Active` asserts all three already happened. Every later
    /// delegated state is therefore reachable only as a checked step from a row
    /// that already exists.
    ///
    /// `pub(crate)`: the proof borrows a transaction, so the only sound public
    /// spelling is an engine door that mints and consumes it in one txn —
    /// [`Vault::provision_delegated_identity`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidChannelIdentityBody`] when the proof does not cover the
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
            return Err(Error::InvalidChannelIdentityBody(
                "delegated_grant identity requires a verified custody proof for its own \
                 (channel, mailbox, grant)",
            ));
        }
        let identity = Self {
            channel: channel_key.as_str().to_owned(),
            address_or_handle: address.as_str().to_owned(),
            shape: ChannelIdentityShape::DelegatedGrant,
            binding,
            state: ChannelIdentityState::Requested,
            pending_fulfillment: None,
            state_changed_at: requested_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: Some(grant),
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
            shape: ChannelIdentityShape::DedicatedHandle,
            binding: ChannelIdentityBinding::agent(agent_ref),
            state: ChannelIdentityState::Active,
            pending_fulfillment: None,
            state_changed_at: created_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: None,
        }
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
        !self.shape.is_self_held()
    }

    /// Whether this row still OCCUPIES its assignment key.
    ///
    /// A self-held row occupies it forever: never-recycle is the whole point of
    /// releasing an address WE minted, so a quarantined or tombstoned row is
    /// still holding it back. A delegated row is the opposite case — the
    /// mailbox was never ours, so once the row is retiring we hold no claim on
    /// it at all, and lawful re-consent stays open after the close.
    #[must_use]
    pub const fn occupies_assignment_key(&self) -> bool {
        if self.is_delegated() {
            !matches!(
                self.state,
                ChannelIdentityState::Released | ChannelIdentityState::Tombstone
            )
        } else {
            true
        }
    }

    /// Whether this row may carry an OUTBOUND effect.
    ///
    /// Self-held and `Active`, and nothing else. A delegated row is a
    /// scoped-READ grant over a mailbox the product does not own; there is no
    /// state it can reach in which sending as the member is a thing we were
    /// given permission to do.
    #[must_use]
    pub const fn may_send(&self) -> bool {
        !self.is_delegated() && matches!(self.state, ChannelIdentityState::Active)
    }

    /// Validates CID-1 record invariants.
    pub fn validate(&self) -> Result<()> {
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
        self.validate_custody()?;
        match self.state {
            ChannelIdentityState::PendingFulfillment => {
                if self.pending_fulfillment.is_none() {
                    return Err(invalid_identity());
                }
                if self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
            ChannelIdentityState::Quarantine => {
                if self.pending_fulfillment.is_some() {
                    return Err(invalid_identity());
                }
                let quarantine_until = self.quarantine_until.ok_or_else(invalid_identity)?;
                let min_until = self
                    .state_changed_at
                    .checked_add(CHANNEL_IDENTITY_MIN_QUARANTINE_SECS)
                    .ok_or(Error::ArithmeticOverflow(
                        "channel identity quarantine window",
                    ))?;
                if quarantine_until < min_until {
                    return Err(invalid_identity());
                }
            }
            _ => {
                if self.pending_fulfillment.is_some() || self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
        }
        Ok(())
    }

    /// The shape/grant tie, and the two states a delegated row has no business
    /// being in.
    ///
    /// `ROTATING` would be re-minting an account the product never owned;
    /// `QUARANTINE` would be a never-recycle hold on someone else's mailbox.
    /// Both are absent from [`ChannelIdentityState::can_transition_to_delegated`]
    /// so no lawful step reaches them, and refused here so no assembled or
    /// decoded body can claim one either.
    fn validate_custody(&self) -> Result<()> {
        match (self.shape.is_self_held(), &self.grant) {
            (true, None) => Ok(()),
            (false, Some(grant)) => {
                grant.validate()?;
                if matches!(
                    self.state,
                    ChannelIdentityState::Rotating | ChannelIdentityState::Quarantine
                ) {
                    return Err(Error::InvalidChannelIdentityBody(
                        "a delegated_grant identity is never rotated or quarantined: the \
                         product neither mints nor holds back the member's mailbox",
                    ));
                }
                Ok(())
            }
            (true, Some(_)) => Err(Error::InvalidChannelIdentityBody(
                "only a delegated_grant identity may carry a delegated grant ref",
            )),
            (false, None) => Err(Error::InvalidChannelIdentityBody(
                "delegated_grant identity requires a delegated grant ref",
            )),
        }
    }

    /// Returns a copy with a checked lifecycle transition applied.
    pub fn transition(
        &self,
        next: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<Self> {
        let admitted = if self.is_delegated() {
            self.state.can_transition_to_delegated(next)
        } else {
            self.state.can_transition_to(next)
        };
        if !admitted {
            return Err(invalid_identity());
        }
        if state_changed_at < self.state_changed_at {
            return Err(invalid_identity());
        }
        let next_identity = Self {
            state: next,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
            ..self.clone()
        };
        next_identity.validate()?;
        Ok(next_identity)
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
            PREDICATE_CHANNEL_IDENTITY_CHANNEL => Some(Value::from(self.channel.as_str())),
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => {
                Some(Value::from(self.address_or_handle.as_str()))
            }
            PREDICATE_CHANNEL_IDENTITY_SHAPE => Some(Value::from(self.shape.as_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => Some(Value::from(self.binding.scope_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => Some(encode_binding_target(self.binding)),
            PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF => {
                Some(encode_optional_entity_ref(self.binding.facet_ref()))
            }
            PREDICATE_CHANNEL_IDENTITY_STATE => Some(Value::from(self.state.as_str())),
            PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => Some(
                self.pending_fulfillment
                    .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
            ),
            PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => Some(Value::from(self.state_changed_at)),
            PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
                Some(self.quarantine_until.map_or(Value::Nil, Value::from))
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
