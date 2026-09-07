//! Write-path stamping: `WriteActor`/`WriteProvenance`/`WriteEnvelope`/`ClaimCandidate` + evidence stamping.

use std::collections::BTreeSet;

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

/// The set of source classes a write's own history actually drew on.
///
/// The envelope's `source` is a DECLARATION: one label the writer stamps. The
/// lineage is what happened — every source class in the effect history behind
/// this write. A code-mode run that observed an external effect and then wrote
/// a claim declares `Generated` truthfully about the declaration and falsely
/// about the run; the lineage carries `ToolOutput` alongside it, and the
/// auto-permit decision consults both.
///
/// It is a SET, not a trail: order and per-hop identity are deliberately not
/// modelled here, so the type cannot drift into a provenance chain (that lives
/// in candidate evidence). Membership is additive and never removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLineage {
    sources: BTreeSet<ClaimSource>,
}

impl SourceLineage {
    /// The trivial lineage: exactly the one declared source class.
    ///
    /// Every 4-arity [`WriteEnvelope`] construction lands here, so a write
    /// whose history is its own declaration behaves exactly as it did before
    /// lineage existed.
    #[must_use]
    pub fn of(source: ClaimSource) -> Self {
        Self {
            sources: BTreeSet::from([source]),
        }
    }

    /// Adds one more observed source class. Additive: an already-present
    /// class is a no-op, and nothing is ever removed.
    #[must_use]
    pub fn with(mut self, source: ClaimSource) -> Self {
        self.sources.insert(source);
        self
    }

    /// Whether this class is part of the write's history.
    #[must_use]
    pub fn contains(&self, source: ClaimSource) -> bool {
        self.sources.contains(&source)
    }

    /// Whether ANY member requires an explicit auto permit. This classifies
    /// the history; it does not authorize it. Authorization must check each
    /// restricted member's own permit. No member can vouch for another.
    #[must_use]
    pub fn requires_explicit_auto_permit(&self) -> bool {
        self.sources
            .iter()
            .any(|source| source.requires_explicit_auto_permit())
    }

    /// The member classes, in the set's canonical (`Ord`) order.
    pub fn iter(&self) -> impl Iterator<Item = ClaimSource> + '_ {
        self.sources.iter().copied()
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
    /// ONE-1314. Stamped HOST-INTERNALLY only: no public constructor, guest
    /// payload, or API argument reaches this field, and the 4-arity
    /// constructors below can only produce the trivial value.
    lineage: SourceLineage,
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
            lineage: SourceLineage::of(source),
        }
    }

    /// Creates an envelope whose history is WIDER than its declared source.
    ///
    /// The ONE non-trivial-lineage constructor, reserved for host dispatchers
    /// that own a run's effect history (the code-run dispatcher, the Dreamer
    /// promotion writer). It is `pub(crate)` on purpose: no public, guest, or
    /// API path may supply a lineage value, so a caller cannot narrow its own
    /// history to ride the auto lane.
    pub(crate) fn with_lineage(
        actor: WriteActor,
        source: ClaimSource,
        provenance: WriteProvenance,
        approval: ClaimApprovalStatus,
        lineage: SourceLineage,
    ) -> Self {
        Self {
            actor,
            source,
            provenance,
            approval,
            session_tag: None,
            lineage,
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

    /// The source classes this write's history actually drew on.
    #[must_use]
    pub const fn lineage(&self) -> &SourceLineage {
        &self.lineage
    }

    /// Whether the gate must expose the declared source and sensitivity even
    /// for a non-Auto write. This is an input-shape question, not authorization:
    /// the gate must still check the actual restricted lineage members.
    /// A trivial lineage answers exactly what the declared label answered.
    #[must_use]
    pub(crate) fn effective_requires_explicit_auto_permit(&self) -> bool {
        self.source.requires_explicit_auto_permit() || self.lineage.requires_explicit_auto_permit()
    }

    /// Whether the lineage says nothing the declared source did not already
    /// say. Trivial lineage stamps NO evidence entry, so every write that
    /// existed before this axis keeps byte-identical evidence.
    fn lineage_is_trivial(&self) -> bool {
        self.lineage == SourceLineage::of(self.source)
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

    /// The predicate this candidate would write. Read by the batch doors so
    /// they can refuse a predicate family whose supersession chain a typed
    /// door owns, before the candidate reaches a write.
    pub(crate) fn predicate(&self) -> &str {
        &self.predicate
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
/// ONE-1314: the engine-owned record of what the write's history drew on.
/// Present ONLY when the lineage says more than the declared source already
/// did, so trivial-lineage writes keep the evidence map they always had.
pub(crate) const WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY: &str = "lineage";

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

    // Engine-owned and strictly additive: a writer cannot suppress it (the
    // lineage is not caller-supplied) and cannot mint it (a trivial lineage
    // stamps nothing at all, which is every pre-ONE-1314 write).
    if !envelope.lineage_is_trivial() {
        entries.push((
            Value::from(WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY),
            Value::Array(
                envelope
                    .lineage()
                    .iter()
                    .map(|source| Value::from(source.as_str()))
                    .collect(),
            ),
        ));
    }

    if let Some(candidate_evidence) = candidate_evidence {
        entries.push((
            Value::from(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
            candidate_evidence,
        ));
    }

    Value::Map(entries)
}

#[cfg(test)]
mod tests;
