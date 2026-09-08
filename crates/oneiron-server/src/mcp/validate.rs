//! Validation of MCP tool arguments, per-verb allow-lists, and metadata checks.

use super::args::{
    McpActorMetadata, McpAskRoute, McpAskToolArgs, McpBookOperation, McpBookToolArgs,
    McpCalendarOperation, McpCalendarRange, McpCalendarSelector, McpCalendarToolArgs,
    McpConsentMetadata, McpEditEdgeSubject, McpEditSubject, McpEditToolArgs, McpEditVerb,
    McpNavToolArgs, McpOccurredRange, McpReadTarget, McpReadToolArgs, McpRoutedAskToolArgs,
    McpToolScope,
};
use super::tool_catalog::{McpToolLabel, McpToolName, McpToolValidationError};
use super::validators::{
    validate_absent, validate_confidence, validate_context_pack, validate_context_pack_field,
    validate_entity_ref, validate_nonblank, validate_optional_context_pack,
    validate_optional_entity_ref, validate_optional_nonblank, validate_required_entity_ref,
    validate_schema_version, validate_short_ref,
};
use oneiron::EdgeKind;
use oneiron::booking::agent_api::BookingBookInput;

pub(super) trait ValidateMcpArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError>;
}

impl ValidateMcpArgs for McpNavToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_optional_nonblank(tool, "query", self.query.as_deref())?;
        validate_optional_nonblank(tool, "cursor", self.cursor.as_deref())?;
        if self.limit == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "limit",
                "must be greater than zero",
            ));
        }
        validate_optional_context_pack(tool, self.context_pack.as_ref())
    }
}

impl ValidateMcpArgs for McpReadToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        self.target.validate(tool)
    }
}

impl ValidateMcpArgs for McpCalendarToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        match &self.operation {
            McpCalendarOperation::Read { event_ref } => {
                validate_entity_ref(tool, "operation.event_ref", event_ref)
            }
            McpCalendarOperation::Search {
                calendars,
                range,
                text,
                limit,
            } => {
                validate_calendar_selectors(tool, calendars)?;
                if let Some(range) = range {
                    validate_calendar_range(tool, *range)?;
                }
                validate_optional_nonblank(tool, "operation.text", text.as_deref())?;
                if *limit == Some(0) {
                    return Err(McpToolValidationError::field(
                        tool,
                        "operation.limit",
                        "must be greater than zero",
                    ));
                }
                Ok(())
            }
            McpCalendarOperation::Freebusy { calendars, range } => {
                validate_calendar_selectors(tool, calendars)?;
                validate_calendar_range(tool, *range)
            }
            McpCalendarOperation::Invite {
                uid,
                ics_blob_ref,
                recipient,
                ..
            } => {
                validate_nonblank(tool, "operation.uid", uid)?;
                validate_nonblank(tool, "operation.ics_blob_ref", ics_blob_ref)?;
                validate_nonblank(tool, "operation.recipient", recipient)
            }
        }
    }
}

impl ValidateMcpArgs for McpBookToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "page_token", &self.page_token)?;
        // Deeper shape, caps, admission, and every booking semantic belong to
        // the shared executor. This validator only proves the envelope is the
        // envelope: a second copy of the booking rules here would be exactly
        // the drift the one-executor design exists to prevent.
        match &self.operation {
            McpBookOperation::Availability { input } => {
                validate_nonblank(tool, "operation.input.session_ref", &input.session_ref)?;
                validate_nonblank(tool, "operation.input.visitor_tz", &input.visitor_tz)?;
                validate_nonblank(tool, "operation.input.event_type", &input.event_type.0)
            }
            McpBookOperation::Book { input } => match input {
                BookingBookInput::Hold(hold) => {
                    validate_nonblank(tool, "operation.input.session_ref", &hold.session_ref)?;
                    validate_nonblank(tool, "operation.input.visitor_tz", &hold.visitor_tz)?;
                    validate_nonblank(tool, "operation.input.event_type", &hold.event_type.0)?;
                    validate_nonblank(
                        tool,
                        "operation.input.idempotency_key",
                        &hold.idempotency_key,
                    )
                }
                BookingBookInput::Confirm(confirm) => {
                    validate_nonblank(tool, "operation.input.hold_token", &confirm.hold_token)?;
                    validate_nonblank(tool, "operation.input.booker_email", &confirm.booker_email)?;
                    validate_nonblank(tool, "operation.input.session_ref", &confirm.session_ref)?;
                    validate_nonblank(
                        tool,
                        "operation.input.idempotency_key",
                        &confirm.idempotency_key,
                    )
                }
            },
            McpBookOperation::Reschedule { input } => {
                validate_nonblank(
                    tool,
                    "operation.input.reschedule_token",
                    &input.reschedule_token,
                )?;
                validate_nonblank(tool, "operation.input.visitor_tz", &input.visitor_tz)?;
                validate_nonblank(
                    tool,
                    "operation.input.idempotency_key",
                    &input.idempotency_key,
                )
            }
            McpBookOperation::Cancel { input } => {
                validate_nonblank(tool, "operation.input.cancel_token", &input.cancel_token)?;
                validate_nonblank(
                    tool,
                    "operation.input.idempotency_key",
                    &input.idempotency_key,
                )
            }
        }
    }
}

fn validate_calendar_selectors(
    tool: McpToolName,
    calendars: &[McpCalendarSelector],
) -> Result<(), McpToolValidationError> {
    for selector in calendars {
        validate_optional_nonblank(
            tool,
            "operation.calendars.system",
            selector.system.as_deref(),
        )?;
    }
    Ok(())
}

fn validate_calendar_range(
    tool: McpToolName,
    range: McpCalendarRange,
) -> Result<(), McpToolValidationError> {
    if range.start > range.end {
        return Err(McpToolValidationError::field(
            tool,
            "operation.range",
            "start must not exceed end",
        ));
    }
    Ok(())
}

impl ValidateMcpArgs for McpEditToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "idempotency_key", &self.idempotency_key)?;

        match self.verb {
            McpEditVerb::ProposeClaim => self.validate_propose_claim(tool),
            McpEditVerb::AttestEdgeProvenance => self.validate_attest_edge_provenance(tool),
            McpEditVerb::SupersedeClaim => self.validate_supersede_claim(tool),
            McpEditVerb::RetractClaim => self.validate_retract_claim(tool),
            McpEditVerb::ProposeEntity => self.validate_propose_entity(tool),
            McpEditVerb::PostTask => self.validate_post_task(tool),
            McpEditVerb::ReportTask => self.validate_report_task(tool),
            McpEditVerb::ChannelSend => self.validate_channel_send(tool),
        }
    }
}

impl McpEditToolArgs {
    /// The claim ref this verb NAMES as its lifecycle target, if it names one
    /// (ONE-1936). The mapping is explicit per verb rather than "whichever id
    /// field happens to be set", because the guard's whole value is that the
    /// caller's chosen target is the thing checked:
    ///
    /// * `supersede_claim` → `old_claim_id` (the claim being replaced);
    /// * `retract_claim` → `claim_id` (the claim being withdrawn);
    /// * `attest_edge_provenance` → `old_claim_id`, present only for a
    ///   REPLACEMENT-style attestation. A first attestation for an edge has no
    ///   prior wrapper and therefore no lifecycle target.
    ///
    /// Every other verb proposes something new and has no target at all.
    #[must_use]
    pub fn lifecycle_target_ref(&self) -> Option<&str> {
        match self.verb {
            McpEditVerb::SupersedeClaim | McpEditVerb::AttestEdgeProvenance => {
                self.old_claim_id.as_deref()
            }
            McpEditVerb::RetractClaim => self.claim_id.as_deref(),
            McpEditVerb::ProposeClaim
            | McpEditVerb::ProposeEntity
            | McpEditVerb::PostTask
            | McpEditVerb::ReportTask
            | McpEditVerb::ChannelSend => None,
        }
    }

    fn validate_propose_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
                "subject",
                "predicate",
                "value",
                "confidence",
                "evidence",
                "valid_from",
                "valid_to",
                "salience",
                "world",
                "scope",
            ],
        )?;
        self.validate_required_subject(tool, "subject")?
            .validate(tool)?;
        self.validate_required_predicate(tool)?;
        self.validate_required_value(tool, "value")?;
        self.validate_required_confidence(tool)?;
        validate_optional_entity_ref(tool, "world", self.world.as_deref())?;
        self.validate_optional_salience(tool)
    }

    fn validate_attest_edge_provenance(
        &self,
        tool: McpToolName,
    ) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
                "subject",
                "confidence",
                "old_claim_id",
                "supersession_status",
                "source_revision_ref",
                "body_snapshot_ref",
                "reasoning_effort",
            ],
        )?;
        self.validate_required_subject(tool, "subject")?
            .validate_edge_only(tool, "subject")?;
        self.validate_required_confidence(tool)?;
        // Replacement-style attestation names the wrapper it replaces; a FIRST
        // attestation for an edge has no prior and omits it (ONE-1936).
        validate_optional_entity_ref(tool, "old_claim_id", self.old_claim_id.as_deref())?;
        validate_optional_nonblank(
            tool,
            "supersession_status",
            self.supersession_status.as_deref(),
        )?;
        validate_optional_nonblank(
            tool,
            "source_revision_ref",
            self.source_revision_ref.as_deref(),
        )?;
        validate_optional_nonblank(tool, "body_snapshot_ref", self.body_snapshot_ref.as_deref())?;
        validate_optional_nonblank(tool, "reasoning_effort", self.reasoning_effort.as_deref())
    }

    fn validate_supersede_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &[
                "old_claim_id",
                "predicate",
                "value",
                "confidence",
                "evidence",
                "valid_from",
                "valid_to",
                "salience",
                "reason",
            ],
        )?;
        validate_required_entity_ref(tool, "old_claim_id", self.old_claim_id.as_deref())?;
        self.validate_required_predicate(tool)?;
        self.validate_required_value(tool, "value")?;
        self.validate_required_confidence(tool)?;
        validate_optional_nonblank(tool, "reason", self.reason.as_deref())?;
        self.validate_optional_salience(tool)
    }

    fn validate_retract_claim(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["claim_id", "reason", "explanation"])?;
        validate_required_entity_ref(tool, "claim_id", self.claim_id.as_deref())?;
        validate_nonblank(
            tool,
            "reason",
            self.reason
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "reason", "is required"))?,
        )?;
        validate_optional_nonblank(tool, "explanation", self.explanation.as_deref())
    }

    fn validate_propose_entity(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(
            tool,
            &["entity_type", "occurred", "data", "initial_claims"],
        )?;
        self.entity_type
            .ok_or_else(|| McpToolValidationError::field(tool, "entity_type", "is required"))?;
        self.occurred
            .as_ref()
            .ok_or_else(|| McpToolValidationError::field(tool, "occurred", "is required"))?
            .validate(tool)?;
        self.validate_required_value(tool, "data")?;
        if self
            .initial_claims
            .as_ref()
            .is_some_and(|initial_claims| initial_claims.len() > 16)
        {
            return Err(McpToolValidationError::field(
                tool,
                "initial_claims",
                "must contain at most 16 claims",
            ));
        }
        Ok(())
    }

    fn validate_post_task(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["brief"])?;
        self.validate_required_value(tool, "brief")
    }

    fn validate_report_task(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["job_id", "outcome", "summary", "result_claims"])?;
        validate_nonblank(
            tool,
            "job_id",
            self.attempt_id
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "job_id", "is required"))?,
        )?;
        validate_nonblank(
            tool,
            "outcome",
            self.outcome
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "outcome", "is required"))?,
        )?;
        validate_nonblank(
            tool,
            "summary",
            self.summary
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "summary", "is required"))?,
        )?;
        if self
            .result_claims
            .as_ref()
            .is_some_and(|result_claims| result_claims.len() > 8)
        {
            return Err(McpToolValidationError::field(
                tool,
                "result_claims",
                "must contain at most 8 claims",
            ));
        }
        Ok(())
    }

    fn validate_channel_send(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        self.validate_only_edit_fields(tool, &["channel", "payload"])?;
        validate_nonblank(
            tool,
            "channel",
            self.channel
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "channel", "is required"))?,
        )?;
        self.validate_required_value(tool, "payload")
    }

    fn validate_only_edit_fields(
        &self,
        tool: McpToolName,
        allowed: &[&'static str],
    ) -> Result<(), McpToolValidationError> {
        for (field, present) in self.present_edit_fields() {
            if present && !allowed.contains(&field) {
                validate_absent(tool, field, true)?;
            }
        }
        Ok(())
    }

    fn present_edit_fields(&self) -> [(&'static str, bool); 29] {
        [
            ("subject", self.subject.is_some()),
            ("predicate", self.predicate.is_some()),
            ("value", self.value.is_some()),
            ("confidence", self.confidence.is_some()),
            ("evidence", self.evidence.is_some()),
            ("valid_from", self.valid_from.is_some()),
            ("valid_to", self.valid_to.is_some()),
            ("salience", self.salience.is_some()),
            ("world", self.world.is_some()),
            ("scope", self.scope.is_some()),
            ("old_claim_id", self.old_claim_id.is_some()),
            ("claim_id", self.claim_id.is_some()),
            ("reason", self.reason.is_some()),
            ("explanation", self.explanation.is_some()),
            ("entity_type", self.entity_type.is_some()),
            ("occurred", self.occurred.is_some()),
            ("data", self.data.is_some()),
            ("initial_claims", self.initial_claims.is_some()),
            ("brief", self.brief.is_some()),
            ("job_id", self.attempt_id.is_some()),
            ("outcome", self.outcome.is_some()),
            ("summary", self.summary.is_some()),
            ("result_claims", self.result_claims.is_some()),
            ("channel", self.channel.is_some()),
            ("payload", self.payload.is_some()),
            ("supersession_status", self.supersession_status.is_some()),
            ("source_revision_ref", self.source_revision_ref.is_some()),
            ("body_snapshot_ref", self.body_snapshot_ref.is_some()),
            ("reasoning_effort", self.reasoning_effort.is_some()),
        ]
    }

    fn validate_required_subject(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<&McpEditSubject, McpToolValidationError> {
        self.subject
            .as_ref()
            .ok_or_else(|| McpToolValidationError::field(tool, field, "is required"))
    }

    fn validate_required_predicate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(
            tool,
            "predicate",
            self.predicate
                .as_deref()
                .ok_or_else(|| McpToolValidationError::field(tool, "predicate", "is required"))?,
        )
    }

    fn validate_required_value(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<(), McpToolValidationError> {
        match field {
            "value" if self.value.is_some() => Ok(()),
            "data" if self.data.is_some() => Ok(()),
            "brief" if self.brief.is_some() => Ok(()),
            "payload" if self.payload.is_some() => Ok(()),
            _ => Err(McpToolValidationError::field(tool, field, "is required")),
        }
    }

    fn validate_required_confidence(
        &self,
        tool: McpToolName,
    ) -> Result<(), McpToolValidationError> {
        let confidence = self
            .confidence
            .ok_or_else(|| McpToolValidationError::field(tool, "confidence", "is required"))?;
        validate_confidence(tool, "confidence", confidence)
    }

    fn validate_optional_salience(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match self.salience {
            Some(salience) if salience.is_finite() => Ok(()),
            Some(_) => Err(McpToolValidationError::field(
                tool,
                "salience",
                "must be finite",
            )),
            None => Ok(()),
        }
    }
}

impl McpEditSubject {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match (self.entity.as_deref(), self.edge.as_ref()) {
            (Some(entity), None) => validate_entity_ref(tool, "subject.entity", entity),
            (None, Some(edge)) => edge.validate(tool, "subject.edge", false),
            _ => Err(McpToolValidationError::field(
                tool,
                "subject",
                "must include exactly one of entity or edge",
            )),
        }
    }

    fn validate_edge_only(
        &self,
        tool: McpToolName,
        field: &'static str,
    ) -> Result<(), McpToolValidationError> {
        match (&self.entity, &self.edge) {
            (None, Some(edge)) => edge.validate(tool, "subject.edge", true),
            _ => Err(McpToolValidationError::field(
                tool,
                field,
                "must include an edge subject",
            )),
        }
    }
}

impl McpEditEdgeSubject {
    fn validate(
        &self,
        tool: McpToolName,
        field: &'static str,
        provenance_only: bool,
    ) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "subject.edge.source", &self.source)?;
        validate_entity_ref(tool, "subject.edge.target", &self.target)?;
        if EdgeKind::try_from_u8(self.kind).is_none()
            || self.kind > 19
            || (provenance_only && self.kind < 9)
        {
            let message = if provenance_only {
                "must be a registered provenance edge kind in 9..=19"
            } else {
                "must be a registered edge kind in 0..=19"
            };
            return Err(McpToolValidationError::field(tool, field, message));
        }
        Ok(())
    }
}

impl McpOccurredRange {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        if self.start > self.end {
            return Err(McpToolValidationError::field(
                tool,
                "occurred.start",
                "must be less than or equal to occurred.end",
            ));
        }
        Ok(())
    }
}

impl ValidateMcpArgs for McpAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)
    }
}

impl ValidateMcpArgs for McpRoutedAskToolArgs {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_schema_version(tool, &self.schema_version)?;
        self.actor.validate(tool)?;
        validate_context_pack(tool, &self.context_pack)?;
        self.consent.validate(tool)?;
        validate_nonblank(tool, "query", &self.query)?;
        self.route.validate(tool)
    }
}

impl McpReadTarget {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        match (
            self.entity_ref.as_deref(),
            self.short_ref.as_deref(),
            self.context_pack.as_ref(),
        ) {
            (Some(entity_ref), None, None) => {
                validate_entity_ref(tool, "target.entity_ref", entity_ref)
            }
            (None, Some(short_ref), None) => {
                validate_short_ref(tool, "target.short_ref", short_ref)
            }
            (None, None, Some(context_pack)) => {
                validate_context_pack_field(tool, "target.context_pack", context_pack)
            }
            _ => Err(McpToolValidationError::field(
                tool,
                "target",
                "must include exactly one of entity_ref, short_ref, or context_pack",
            )),
        }
    }
}

impl McpAskRoute {
    fn validate(&self, tool: McpToolName) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "route.model_tier", &self.model_tier)?;
        validate_optional_nonblank(tool, "route.model_id", self.model_id.as_deref())?;
        validate_optional_nonblank(tool, "route.substrate_ref", self.substrate_ref.as_deref())?;
        if self.max_latency_ms == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "route.max_latency_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl McpActorMetadata {
    pub(super) fn validate(&self, tool: impl McpToolLabel) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "actor.actor_ref", &self.actor_ref)?;
        validate_entity_ref(tool, "actor.gate_actor_ref", &self.gate_actor_ref)?;
        if self.actor_class != self.gate_actor_class {
            return Err(McpToolValidationError::field(
                tool,
                "actor.gate_actor_class",
                "must match actor_class for foreign MCP clients",
            ));
        }
        self.scope.validate(tool)
    }
}

impl McpToolScope {
    fn validate(&self, tool: impl McpToolLabel) -> Result<(), McpToolValidationError> {
        validate_optional_entity_ref(tool, "actor.scope.world_ref", self.world_ref.as_deref())?;
        validate_optional_entity_ref(tool, "actor.scope.facet_ref", self.facet_ref.as_deref())
    }
}

impl McpConsentMetadata {
    pub(super) fn validate(&self, tool: impl McpToolLabel) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "consent.policy_ref", &self.policy_ref)?;
        validate_nonblank(tool, "consent.purpose", &self.purpose)?;
        validate_optional_nonblank(tool, "consent.approval_ref", self.approval_ref.as_deref())?;
        validate_optional_nonblank(
            tool,
            "consent.consent_receipt_ref",
            self.consent_receipt_ref.as_deref(),
        )
    }
}
