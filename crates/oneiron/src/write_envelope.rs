//! Write-path stamping: `WriteActor`/`WriteProvenance`/`WriteEnvelope`/`ClaimCandidate` + evidence stamping.

use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::claim::ClaimBody;
use crate::claim::ClaimLifecycleStatus;
use crate::claim::ClaimSource;
use crate::claim::ClaimSubject;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// Actor metadata required by [`WriteEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteActor {
    entity_ref: EntityId,
    actor_class: EdgeActorClass,
}

impl WriteActor {
    /// Creates a write actor from an entity id plus its caller-asserted class.
    #[must_use]
    pub const fn new(entity_ref: EntityId, actor_class: EdgeActorClass) -> Self {
        Self {
            entity_ref,
            actor_class,
        }
    }

    /// Actor entity reference stamped into candidate writes.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        self.entity_ref
    }

    /// Actor class stamped into candidate writes and supplied to the Gate evaluator.
    #[must_use]
    pub const fn actor_class(self) -> EdgeActorClass {
        self.actor_class
    }
}

/// Opaque provenance payload carried by a [`WriteEnvelope`].
#[derive(Debug, Clone, PartialEq)]
pub struct WriteProvenance {
    value: Value,
}

impl WriteProvenance {
    /// Creates a provenance payload, rejecting an absent (`nil`) value.
    pub fn new(value: Value) -> crate::error::Result<Self> {
        if matches!(value, Value::Nil) {
            return Err(crate::error::Error::InvalidClaimBody(
                "write envelope missing provenance",
            ));
        }

        Ok(Self { value })
    }

    /// Returns the opaque provenance value.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Required metadata for writing a [`ClaimCandidate`].
#[derive(Debug, Clone, PartialEq)]
pub struct WriteEnvelope {
    actor: WriteActor,
    source: ClaimSource,
    provenance: WriteProvenance,
    approval: ClaimApprovalStatus,
    session_tag: Option<String>,
}

impl WriteEnvelope {
    /// Creates an envelope from already-validated typed fields.
    #[must_use]
    pub fn new(
        actor: WriteActor,
        source: ClaimSource,
        provenance: WriteProvenance,
        approval: ClaimApprovalStatus,
    ) -> Self {
        Self {
            actor,
            source,
            provenance,
            approval,
            session_tag: None,
        }
    }

    /// Creates an envelope from caller-bound optional fields.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when any required envelope
    /// axis is absent.
    pub fn try_new(
        actor: Option<WriteActor>,
        source: Option<ClaimSource>,
        provenance: Option<WriteProvenance>,
        approval: Option<ClaimApprovalStatus>,
    ) -> crate::error::Result<Self> {
        let actor = actor.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing actor",
        ))?;
        let source = source.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing source",
        ))?;
        let provenance = provenance.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing provenance",
        ))?;
        let approval = approval.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing approval",
        ))?;

        Ok(Self::new(actor, source, provenance, approval))
    }

    /// Actor stamped into candidate writes.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Provenance source stamped into candidate writes.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        self.source
    }

    /// Opaque provenance payload stamped into candidate writes.
    #[must_use]
    pub fn provenance(&self) -> &WriteProvenance {
        &self.provenance
    }

    /// Explicit approval state stamped into candidate writes.
    #[must_use]
    pub const fn approval(&self) -> ClaimApprovalStatus {
        self.approval
    }

    /// Tags every emitted claim with the agent session that produced it.
    ///
    /// The tag is validated by the claim write door and becomes the durable
    /// data-native session-bundle association on proposed claims.
    #[must_use]
    pub fn with_session_tag(mut self, session_tag: impl Into<String>) -> Self {
        self.session_tag = Some(session_tag.into());
        self
    }
}

/// Caller-emitted claim data before write-path envelope stamping.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimCandidate {
    predicate: String,
    subject: ClaimSubject,
    value: Value,
    confidence: f32,
    salience: Option<f32>,
    evidence: Option<Value>,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
    world: Option<EntityId>,
    scope: Option<Value>,
    stale: bool,
}

impl ClaimCandidate {
    /// Creates candidate claim data. Metadata axes are supplied by
    /// [`WriteEnvelope`] at write time.
    #[must_use]
    pub fn new(
        predicate: impl Into<String>,
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
    ) -> Self {
        Self {
            predicate: predicate.into(),
            subject,
            value,
            confidence,
            salience: None,
            evidence: None,
            valid_from: None,
            valid_to: None,
            world: None,
            scope: None,
            stale: false,
        }
    }

    /// Adds candidate-local salience.
    #[must_use]
    pub fn with_salience(mut self, salience: f32) -> Self {
        self.salience = Some(salience);
        self
    }

    /// Adds candidate-local evidence; the envelope keeps its own provenance stamp.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Value) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Adds an optional validity window.
    #[must_use]
    pub fn with_validity(mut self, valid_from: Option<u64>, valid_to: Option<u64>) -> Self {
        self.valid_from = valid_from;
        self.valid_to = valid_to;
        self
    }

    /// Adds an optional world scope.
    #[must_use]
    pub fn with_world(mut self, world: EntityId) -> Self {
        self.world = Some(world);
        self
    }

    /// Adds an optional opaque scope value.
    #[must_use]
    pub fn with_scope(mut self, scope: Value) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Marks the candidate as stale derived data.
    #[must_use]
    pub fn with_stale(mut self, stale: bool) -> Self {
        self.stale = stale;
        self
    }

    pub(crate) const fn subject(&self) -> ClaimSubject {
        self.subject
    }

    /// The candidate's optional world scope, as an entity ref.
    ///
    /// ONE-1728 (K4): the batch decode point enumerates every overlay-id-bearing
    /// ref on a `BatchOp::ClaimCandidate`, and the world scope is one of them.
    /// The field is otherwise consumed only inside `into_claim_body`.
    pub(crate) const fn world(&self) -> Option<EntityId> {
        self.world
    }

    pub(crate) fn value_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    pub(crate) fn into_claim_body(self, envelope: &WriteEnvelope) -> ClaimBody {
        let mut body = ClaimBody::new(
            self.predicate,
            self.subject,
            self.value,
            self.confidence,
            envelope.approval(),
            ClaimLifecycleStatus::Active,
        );
        body.salience = self.salience;
        body.evidence = Some(write_envelope_evidence(envelope, self.evidence));
        body.valid_from = self.valid_from;
        body.valid_to = self.valid_to;
        body.source = Some(envelope.source());
        body.world = self.world;
        body.scope = self.scope;
        body.session_tag = envelope.session_tag.clone();
        body.stale = self.stale;
        body
    }
}

pub(crate) const WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY: &str = "actor_entity_ref";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY: &str = "actor_class";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY: &str = "provenance";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY: &str = "candidate_evidence";

pub(crate) fn write_envelope_evidence(
    envelope: &WriteEnvelope,
    candidate_evidence: Option<Value>,
) -> Value {
    let actor = envelope.actor();
    let mut entries = vec![
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(actor.entity_ref().as_bytes().to_vec()),
        ),
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY),
            Value::from(actor.actor_class() as u8),
        ),
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
            envelope.provenance().value().clone(),
        ),
    ];

    if let Some(candidate_evidence) = candidate_evidence {
        entries.push((
            Value::from(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
            candidate_evidence,
        ));
    }

    Value::Map(entries)
}
