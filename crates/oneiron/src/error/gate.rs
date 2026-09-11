//! Gate-domain errors: consent grants and bounds, disclosure scope and
//! clamps, and the Gate write refusal with its typed denial taxonomy.
//!
//! Reached from the root as `Error::Gate(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use std::fmt;

use crate::entity_id::EntityId;

use super::ErrorKind;

/// Stable Gate rejection outcome for typed caller handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateDenialOutcome {
    Pending,
    Deny,
}

impl GateDenialOutcome {
    /// Stable string used in audit logs and existing [`GateError::GateWriteRejected`] fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Deny => "deny",
        }
    }

    /// Parses the stable string form used by [`GateError::GateWriteRejected`].
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for GateDenialOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable Gate rejection reason for typed caller handling and audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateDenialReason {
    DenyMissingActorClass,
    DenyMissingActorProvenance,
    DenyMissingPolicyManifestVersion,
    DenyPolicyFailClosed,
    PendingActorCeiling,
    PendingSourceTrust,
    PendingCriticalityFloor,
    PendingPolicyManifestAuthority,
    PendingExternalEffectAuthority,
    /// GATE-12: the Dreamer's claim value was empty-after-trim or opened with
    /// narration instead of a value.
    DenyDreamerPrecommitDegenerateOutput,
    /// GATE-12: predicate, confidence, subject or value shape was outside the
    /// claim contract.
    DenyDreamerPrecommitMalformed,
    /// GATE-12: a non-runtime-record Dreamer claim cited no evidence ref that
    /// resolves. Validity, not authority — so it denies and never becomes an
    /// owner-review row.
    DenyDreamerPrecommitNoEvidence,
    /// ONE-1686 (RT-04): the witnessed MESSAGE envelope was malformed — an
    /// unknown author bucket, an out-of-shape message type or order, an
    /// incoherent author/visibility pair, out-of-bounds or axis-shadowing
    /// metadata, or staged bytes that were not the canonical encoding of the
    /// authorized axes.
    DenyWitnessMessageMalformedEnvelope,
    /// ONE-1686 (RT-04): the acting actor may not author this envelope. Only
    /// the unattributed `system` bucket needs authority beyond a bound actor,
    /// and only an explicit owner-authored actor-bound `auto` ceiling row
    /// matching the writing actor carries it.
    DenyWitnessMessageAuthorNotAuthorized,
}

impl GateDenialReason {
    /// Stable `gate.*` code used in audit logs and existing [`GateError::GateWriteRejected`] fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DenyMissingActorClass => "gate.deny.missing_actor_class",
            Self::DenyMissingActorProvenance => "gate.deny.missing_actor_provenance",
            Self::DenyMissingPolicyManifestVersion => "gate.deny.missing_policy_manifest_version",
            Self::DenyPolicyFailClosed => "gate.deny.policy_fail_closed",
            Self::PendingActorCeiling => "gate.pending.actor_ceiling",
            Self::PendingSourceTrust => "gate.pending.source_trust",
            Self::PendingCriticalityFloor => "gate.pending.criticality_floor",
            Self::PendingPolicyManifestAuthority => "gate.pending.policy_manifest_authority",
            Self::PendingExternalEffectAuthority => "gate.pending.external_effect_authority",
            Self::DenyDreamerPrecommitDegenerateOutput => {
                "gate.deny.dreamer_precommit.degenerate_output"
            }
            Self::DenyDreamerPrecommitMalformed => "gate.deny.dreamer_precommit.malformed",
            Self::DenyDreamerPrecommitNoEvidence => "gate.deny.dreamer_precommit.no_evidence",
            Self::DenyWitnessMessageMalformedEnvelope => {
                "gate.deny.witness_message.malformed_envelope"
            }
            Self::DenyWitnessMessageAuthorNotAuthorized => {
                "gate.deny.witness_message.author_not_authorized"
            }
        }
    }

    /// Parses a stable `gate.*` reason code.
    #[must_use]
    pub fn from_code(value: &str) -> Option<Self> {
        match value {
            "gate.deny.missing_actor_class" => Some(Self::DenyMissingActorClass),
            "gate.deny.missing_actor_provenance" => Some(Self::DenyMissingActorProvenance),
            "gate.deny.missing_policy_manifest_version" => {
                Some(Self::DenyMissingPolicyManifestVersion)
            }
            "gate.deny.policy_fail_closed" => Some(Self::DenyPolicyFailClosed),
            "gate.pending.actor_ceiling" => Some(Self::PendingActorCeiling),
            "gate.pending.source_trust" => Some(Self::PendingSourceTrust),
            "gate.pending.criticality_floor" => Some(Self::PendingCriticalityFloor),
            "gate.pending.policy_manifest_authority" => Some(Self::PendingPolicyManifestAuthority),
            "gate.pending.external_effect_authority" => Some(Self::PendingExternalEffectAuthority),
            "gate.deny.dreamer_precommit.degenerate_output" => {
                Some(Self::DenyDreamerPrecommitDegenerateOutput)
            }
            "gate.deny.dreamer_precommit.malformed" => Some(Self::DenyDreamerPrecommitMalformed),
            "gate.deny.dreamer_precommit.no_evidence" => Some(Self::DenyDreamerPrecommitNoEvidence),
            "gate.deny.witness_message.malformed_envelope" => {
                Some(Self::DenyWitnessMessageMalformedEnvelope)
            }
            "gate.deny.witness_message.author_not_authorized" => {
                Some(Self::DenyWitnessMessageAuthorNotAuthorized)
            }
            _ => None,
        }
    }

    /// Outcome associated with this rejection reason.
    #[must_use]
    pub fn outcome(self) -> GateDenialOutcome {
        match self {
            Self::DenyMissingActorClass
            | Self::DenyMissingActorProvenance
            | Self::DenyMissingPolicyManifestVersion
            | Self::DenyPolicyFailClosed
            | Self::DenyDreamerPrecommitDegenerateOutput
            | Self::DenyDreamerPrecommitMalformed
            | Self::DenyDreamerPrecommitNoEvidence
            | Self::DenyWitnessMessageMalformedEnvelope
            | Self::DenyWitnessMessageAuthorNotAuthorized => GateDenialOutcome::Deny,
            Self::PendingActorCeiling
            | Self::PendingSourceTrust
            | Self::PendingCriticalityFloor
            | Self::PendingPolicyManifestAuthority
            | Self::PendingExternalEffectAuthority => GateDenialOutcome::Pending,
        }
    }
}

impl fmt::Display for GateDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed view over [`GateError::GateWriteRejected`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDenial {
    outcome: GateDenialOutcome,
    reason_codes: Vec<GateDenialReason>,
}

impl GateDenial {
    /// Gate rejection outcome.
    #[must_use]
    pub fn outcome(&self) -> GateDenialOutcome {
        self.outcome
    }

    /// Stable Gate rejection reasons.
    #[must_use]
    pub fn reason_codes(&self) -> &[GateDenialReason] {
        &self.reason_codes
    }
}

/// Gate-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GateError {
    /// A persona snapshot export presented consent bound to a different
    /// compile stamp than the compile being exported (OF-325: consent is
    /// content-addressed to the previewed compile; a recompile invalidates
    /// prior consent). Nothing was written.
    #[error(
        "persona snapshot export consent is stale: consent bound to {consent_stamp}, compile stamp is {compile_stamp}"
    )]
    PersonaSnapshotConsentStale {
        consent_stamp: String,
        compile_stamp: String,
    },
    /// A DisclosureScope body failed pinned structural validation. Nothing
    /// was written.
    #[error("invalid disclosure scope: {0}")]
    InvalidDisclosureScope(&'static str),
    /// A non-admitted entity survived into an assembled context pack. The
    /// pack build FAILS rather than leaks (OF-365 fail-closed sweep).
    #[error("disclosure clamp violation: {0}")]
    DisclosureClampViolation(&'static str),
    /// A DEC-0006 consent bound failed normalization: an empty/oversized ref,
    /// an empty envelope, or — the load-bearing case — a triple that crosses
    /// the disclosure and action domains (invariant 4). Nothing was written.
    #[error("invalid consent bound: {0}")]
    InvalidConsentBound(&'static str),
    /// A persisted standing consent-grant row failed pinned structural
    /// validation. Nothing was written.
    #[error("invalid consent grant row: {0}")]
    InvalidConsentGrantRow(&'static str),
    /// The engine-owned write facts required to classify a composed effect
    /// were malformed or absent, so no reversibility verdict can be produced.
    /// The caller takes the invariant-8 domain fail-safe.
    #[error("invalid consent effect facts: {0}")]
    InvalidConsentEffectFacts(&'static str),
    /// A consent minting door was reached without an authenticated owner.
    /// Standing grants are created ONLY by the authenticated owner — never
    /// inferred from a preference, a claim, a transcript line, or a guard
    /// hunch (DEC-0006 invariant 2). Nothing was written.
    #[error("consent owner not authenticated: {0}")]
    ConsentOwnerNotAuthenticated(&'static str),
    /// A GenUI consent action reached evaluation without a store-authenticated
    /// owner handle bound to both the card principal and the claimed actor.
    /// Caller-deserialized actor text and voice booleans are never authority.
    #[error("consent actor is not authenticated: {0}")]
    ConsentUnauthenticatedActor(&'static str),
    /// A standing-grant mint named a catastrophe-floor class. The closed floor
    /// is non-rememberable at ANY trust level (DEC-0006 invariant 7): the
    /// owner may approve the op in the moment, but never make it automatic.
    /// Nothing was written.
    #[error("catastrophe floor is non-rememberable: {0}")]
    ConsentCatastropheNotRememberable(&'static str),
    /// A consent registry operation named a grant row that does not exist.
    #[error("consent grant not found")]
    ConsentGrantNotFound,
    /// A standing grant was used after revocation. Revocation is immediate.
    #[error("consent grant is revoked")]
    ConsentGrantRevoked,
    /// An approve-once digest was replayed: either the owner tried to mint a
    /// second approve-once over it, or the evaluator matched a receipt whose
    /// effect already ran. Approve-once authorizes this op, NOW, exactly once
    /// (DEC-0006 invariant 2). Nothing was written.
    #[error("approve-once digest already spent: {0}")]
    ConsentApproveOnceSpent(&'static str),
    /// The source-trust ceiling does not explicitly permit this provenance
    /// source to write an auto-approved Claim. Route the write through the
    /// proposed/inbox review path instead of silently auto-approving it.
    #[error(
        "claim source {claim_source} is not trusted for auto approval; route as proposed/inbox review"
    )]
    SourceNotTrustedForAuto { claim_source: &'static str },
    /// A typed family door asked the gate for `Auto`, did not get it, and has
    /// no consent flow to fall back on — so the refusal is final rather than a
    /// write parked for review.
    ///
    /// Distinct from [`GateError::GateWriteRejected`] because it answers a
    /// different question. That one says the gate refused and the caller may
    /// have somewhere else to go (submit as proposed, adjust the actor or
    /// scope). This one says there is nowhere else: the family's write MEANS
    /// "this is now the head", which has no coherent parked state, so a vault
    /// admitting only reviewed writes cannot use this door at all. It is still
    /// a POLICY denial and classifies with the gate family, never as a
    /// malformed request — the request shape was fine.
    #[error("{family} needs an auto grant: this family has no consent flow")]
    FamilyRequiresAutoGrant {
        /// The predicate family, in the voice its other refusals use.
        family: &'static str,
    },
    /// The Gate evaluator rejected a local write before persistence. The
    /// outcome is `pending` or `deny`, and `reason_codes` are stable
    /// `gate.*` strings suitable for caller routing and audit breadcrumbs.
    /// [`Error::gate_denial`](crate::error::Error::gate_denial) exposes the same fields as typed taxonomy values.
    #[error("gate write rejected: outcome={outcome}, reasons={reason_codes:?}")]
    GateWriteRejected {
        outcome: &'static str,
        reason_codes: Vec<&'static str>,
    },
    /// A pending consent approval attempted to approve bytes or a policy
    /// read-frontier different from the original pending Gate decision.
    #[error("gate consent approval is stale for claim {}", claim_id.to_hex())]
    GateConsentStale { claim_id: EntityId },
}

impl GateError {
    /// Returns the typed Gate denial taxonomy for [`GateError::GateWriteRejected`].
    #[must_use]
    pub(crate) fn gate_denial(&self) -> Option<GateDenial> {
        let Self::GateWriteRejected {
            outcome,
            reason_codes,
        } = self
        else {
            return None;
        };

        let outcome = GateDenialOutcome::parse(outcome)?;
        let mut typed_reasons = Vec::with_capacity(reason_codes.len());
        for reason_code in reason_codes {
            let reason = GateDenialReason::from_code(reason_code)?;
            if reason.outcome() != outcome {
                return None;
            }
            typed_reasons.push(reason);
        }

        Some(GateDenial {
            outcome,
            reason_codes: typed_reasons,
        })
    }

    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidDisclosureScope(_) => ErrorKind::InvalidDisclosureScope,
            Self::InvalidConsentBound(_) => ErrorKind::InvalidConsentBound,
            Self::InvalidConsentGrantRow(_) => ErrorKind::InvalidConsentGrantRow,
            Self::InvalidConsentEffectFacts(_) => ErrorKind::InvalidConsentEffectFacts,
            Self::ConsentOwnerNotAuthenticated(_) => ErrorKind::ConsentOwnerNotAuthenticated,
            Self::ConsentUnauthenticatedActor(_) => ErrorKind::ConsentUnauthenticatedActor,
            Self::ConsentCatastropheNotRememberable(_) => {
                ErrorKind::ConsentCatastropheNotRememberable
            }
            Self::ConsentGrantNotFound => ErrorKind::ConsentGrantNotFound,
            Self::ConsentGrantRevoked => ErrorKind::ConsentGrantRevoked,
            Self::ConsentApproveOnceSpent(_) => ErrorKind::ConsentApproveOnceSpent,
            Self::DisclosureClampViolation(_) => ErrorKind::DisclosureClampViolation,
            Self::PersonaSnapshotConsentStale { .. } => ErrorKind::PersonaSnapshotConsentStale,
            Self::SourceNotTrustedForAuto { .. } => ErrorKind::SourceNotTrustedForAuto,
            Self::GateWriteRejected { .. } => ErrorKind::GateWriteRejected,
            Self::GateConsentStale { .. } => ErrorKind::GateConsentStale,
            Self::FamilyRequiresAutoGrant { .. } => ErrorKind::FamilyRequiresAutoGrant,
        }
    }
}
