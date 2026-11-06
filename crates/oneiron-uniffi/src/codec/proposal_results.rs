//! Owned lifts for proposal and connector results (FIX 12936).
//!
//! Proposal outcomes consume their nested `proposed` leaf first through the
//! existing `PendingProposalView` lift, then converts its finite siblings
//! through the shared record shape. Caller-named JSON leaves (`unit`,
//! `requested_schema`) move owned into `WireJson::lift`; no `lift_record`
//! here runs over a graph containing a `serde_json::Value`.

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<oneiron::blob_artifact::DeckProposeOutcome> for crate::DeckProposeOutcome {
    fn lift(value: oneiron::blob_artifact::DeckProposeOutcome) -> Result<Self, OneironError> {
        let oneiron::blob_artifact::DeckProposeOutcome { proposed, rejected } = value;
        // Consume the nested proposal (and its deep summary tree) first.
        let proposed = proposed.map(crate::PendingProposalView::lift).transpose()?;
        Ok(Self {
            proposed,
            rejected: lift_record("vault.artifacts.propose_deck:rejected", &rejected)?,
        })
    }
}

impl Lift<oneiron::office_body::DeckExportView> for crate::DeckExportView {
    fn lift(value: oneiron::office_body::DeckExportView) -> Result<Self, OneironError> {
        let oneiron::office_body::DeckExportView {
            frontier,
            profile,
            projector,
            authoritative,
            noop,
            changed_parts,
            effects,
            record,
            proposed,
            reconciliation,
        } = value;
        // Consume the nested proposal (and its deep summary tree) first.
        let proposed = proposed.map(crate::PendingProposalView::lift).transpose()?;
        Ok(Self {
            frontier,
            profile,
            projector,
            authoritative,
            noop,
            changed_parts,
            effects,
            record: lift_record("vault.artifacts.body.deck.export:record", &record)?,
            proposed,
            reconciliation: lift_record(
                "vault.artifacts.body.deck.export:reconciliation",
                &reconciliation,
            )?,
        })
    }
}

impl Lift<oneiron::edit_roundtrip::UnitAbstention> for crate::UnitAbstention {
    fn lift(value: oneiron::edit_roundtrip::UnitAbstention) -> Result<Self, OneironError> {
        let oneiron::edit_roundtrip::UnitAbstention {
            unit,
            decision,
            judged_live,
        } = value;
        // Consume the caller-named unit JSON first, before any sibling lift.
        let unit = WireJson::lift(unit)?;
        Ok(Self {
            unit,
            decision: lift_record("artifact ask abstention decision", &decision)?,
            judged_live: judged_live.map(|pin| crate::LivePin {
                frontier: pin.frontier,
                commits: pin.commits,
            }),
        })
    }
}

impl Lift<oneiron::blob_artifact::unit_refusal::UnitRefusal> for crate::UnitRefusal {
    fn lift(
        value: oneiron::blob_artifact::unit_refusal::UnitRefusal,
    ) -> Result<Self, OneironError> {
        let oneiron::blob_artifact::unit_refusal::UnitRefusal {
            unit,
            reason,
            judged_live,
        } = value;
        // Consume the caller-named unit JSON first, before any sibling lift.
        let unit = WireJson::lift(unit)?;
        Ok(Self {
            unit,
            reason,
            judged_live: judged_live.map(|pin| crate::LivePin {
                frontier: pin.frontier,
                commits: pin.commits,
            }),
        })
    }
}

impl Lift<oneiron::blob_artifact::ArtifactAskOutcome> for crate::ArtifactAskOutcome {
    fn lift(value: oneiron::blob_artifact::ArtifactAskOutcome) -> Result<Self, OneironError> {
        let oneiron::blob_artifact::ArtifactAskOutcome {
            proposed,
            abstained,
            refused,
        } = value;
        // Consume the nested proposal (and its deep summary tree) first.
        let proposed = proposed.map(crate::PendingProposalView::lift).transpose()?;
        let abstained = abstained
            .into_iter()
            .map(crate::UnitAbstention::lift)
            .collect::<Result<Vec<_>, _>>()?;
        let refused = refused
            .into_iter()
            .map(crate::UnitRefusal::lift)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            proposed,
            abstained,
            refused,
        })
    }
}

impl Lift<oneiron::blob_artifact::SlideReviewOutcome> for crate::SlideReviewOutcome {
    fn lift(value: oneiron::blob_artifact::SlideReviewOutcome) -> Result<Self, OneironError> {
        let oneiron::blob_artifact::SlideReviewOutcome {
            proposed,
            judgments,
            comments,
            abstained,
            refused,
        } = value;
        // Consume the nested proposal (and its deep summary tree) first.
        let proposed = proposed.map(crate::PendingProposalView::lift).transpose()?;
        Ok(Self {
            proposed,
            judgments: lift_record("vault.artifacts.review_slides:judgments", &judgments)?,
            comments: lift_record("vault.artifacts.review_slides:comments", &comments)?,
            abstained: lift_record("vault.artifacts.review_slides:abstained", &abstained)?,
            refused: lift_record("vault.artifacts.review_slides:refused", &refused)?,
        })
    }
}

impl Lift<oneiron::verbs::NarrowedQuestion> for crate::NarrowedQuestion {
    fn lift(value: oneiron::verbs::NarrowedQuestion) -> Result<Self, OneironError> {
        let oneiron::verbs::NarrowedQuestion {
            key,
            message,
            requested_schema,
            on_device,
        } = value;
        // Native `Some(Value::Null)` serializes as JSON null, which the
        // generated `Option<WireJson>` reads as absent; keep that shape.
        // Null itself carries no recursive children.
        let requested_schema = match requested_schema {
            None | Some(serde_json::Value::Null) => None,
            Some(schema) => Some(WireJson::lift(schema)?),
        };
        Ok(Self {
            key,
            message,
            requested_schema,
            on_device: if on_device { Some(true) } else { None },
        })
    }
}

impl Lift<oneiron::verbs::NarrowedQuestions> for crate::NarrowedQuestions {
    fn lift(value: oneiron::verbs::NarrowedQuestions) -> Result<Self, OneironError> {
        let oneiron::verbs::NarrowedQuestions {
            outcome,
            questions_narrowed,
            handle,
            call_ref,
            source,
            foreign,
            questions,
            live_until_ms,
            reasons,
        } = value;
        let questions = questions
            .into_iter()
            .map(crate::NarrowedQuestion::lift)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            outcome,
            questions_narrowed,
            handle,
            call_ref,
            source,
            foreign,
            questions,
            live_until_ms,
            reasons: if reasons.is_empty() {
                None
            } else {
                Some(reasons)
            },
        })
    }
}

impl Lift<oneiron::task_verb::sdk::ActAnswer<oneiron::blob_artifact::SlideReviewOutcome>>
    for crate::ActAnswerSlideReviewOutcome
{
    fn lift(
        value: oneiron::task_verb::sdk::ActAnswer<oneiron::blob_artifact::SlideReviewOutcome>,
    ) -> Result<Self, OneironError> {
        match value {
            oneiron::task_verb::sdk::ActAnswer::DetailsOnDevice(details) => {
                Ok(Self::DetailsOnDevice(crate::DetailsOnDevice {
                    details_on_device: details.details_on_device,
                }))
            }
            oneiron::task_verb::sdk::ActAnswer::QuestionsNarrowed(questions) => Ok(
                Self::QuestionsNarrowed(crate::NarrowedQuestions::lift(questions)?),
            ),
            oneiron::task_verb::sdk::ActAnswer::Done(outcome) => {
                Ok(Self::Done(crate::SlideReviewOutcome::lift(outcome)?))
            }
        }
    }
}

impl Lift<oneiron::task_verb::sdk::ActAnswer<oneiron::blob_artifact::ArtifactAskOutcome>>
    for crate::ActAnswerArtifactAskOutcome
{
    fn lift(
        value: oneiron::task_verb::sdk::ActAnswer<oneiron::blob_artifact::ArtifactAskOutcome>,
    ) -> Result<Self, OneironError> {
        match value {
            oneiron::task_verb::sdk::ActAnswer::DetailsOnDevice(details) => {
                Ok(Self::DetailsOnDevice(crate::DetailsOnDevice {
                    details_on_device: details.details_on_device,
                }))
            }
            oneiron::task_verb::sdk::ActAnswer::QuestionsNarrowed(questions) => Ok(
                Self::QuestionsNarrowed(crate::NarrowedQuestions::lift(questions)?),
            ),
            oneiron::task_verb::sdk::ActAnswer::Done(outcome) => {
                Ok(Self::Done(crate::ArtifactAskOutcome::lift(outcome)?))
            }
        }
    }
}

impl Lift<oneiron::code_run::ConnectorToolResult> for crate::ConnectorToolResult {
    fn lift(value: oneiron::code_run::ConnectorToolResult) -> Result<Self, OneironError> {
        let oneiron::code_run::ConnectorToolResult {
            source,
            foreign,
            content,
            structured_content,
            is_error,
            rpc_error,
        } = value;
        let content = WireJson::lift(content);
        let structured_content = match structured_content {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => WireJson::lift(value).map(Some),
        };
        let rpc_error = match rpc_error {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => WireJson::lift(value).map(Some),
        };
        Ok(Self {
            source,
            foreign,
            content: content?,
            structured_content: structured_content?,
            is_error,
            rpc_error: rpc_error?,
        })
    }
}

impl Lift<oneiron::outbound_consent::ConnectorQuestion> for crate::ConnectorQuestion {
    fn lift(value: oneiron::outbound_consent::ConnectorQuestion) -> Result<Self, OneironError> {
        let oneiron::outbound_consent::ConnectorQuestion {
            key,
            message,
            requested_schema,
        } = value;
        Ok(Self {
            key,
            message,
            requested_schema: WireJson::lift(requested_schema)?,
        })
    }
}

impl Lift<oneiron::code_run::ConnectorCallReply> for crate::ConnectorCallReply {
    fn lift(value: oneiron::code_run::ConnectorCallReply) -> Result<Self, OneironError> {
        match value {
            oneiron::code_run::ConnectorCallReply::Delivered {
                result,
                reasons,
                budget_steering,
            } => Ok(Self::Delivered {
                result: result.map(crate::ConnectorToolResult::lift).transpose()?,
                reasons: if reasons.is_empty() {
                    None
                } else {
                    Some(reasons)
                },
                budget_steering: if budget_steering.is_empty() {
                    None
                } else {
                    Some(budget_steering)
                },
            }),
            oneiron::code_run::ConnectorCallReply::Held {
                call_ref,
                decision_ref,
                reasons,
                approval_digest,
            } => Ok(Self::Held {
                call_ref,
                decision_ref,
                reasons,
                approval_digest,
            }),
            oneiron::code_run::ConnectorCallReply::Refused {
                decision_ref,
                reasons,
            } => Ok(Self::Refused {
                decision_ref,
                reasons,
            }),
            oneiron::code_run::ConnectorCallReply::PendingDelivery { call_ref, reasons } => {
                Ok(Self::PendingDelivery { call_ref, reasons })
            }
            oneiron::code_run::ConnectorCallReply::AwaitingInput {
                handle,
                call_ref,
                source,
                foreign,
                questions,
                live_until_ms,
                reasons,
            } => Ok(Self::AwaitingInput {
                handle,
                call_ref,
                source,
                foreign,
                questions: questions
                    .into_iter()
                    .map(crate::ConnectorQuestion::lift)
                    .collect::<Result<Vec<_>, _>>()?,
                live_until_ms,
                reasons: if reasons.is_empty() {
                    None
                } else {
                    Some(reasons)
                },
            }),
        }
    }
}

impl Lift<oneiron::task_verb::sdk::ConnectorSchemaReply> for crate::ConnectorSchemaReply {
    fn lift(value: oneiron::task_verb::sdk::ConnectorSchemaReply) -> Result<Self, OneironError> {
        let oneiron::task_verb::sdk::ConnectorSchemaReply {
            source,
            foreign,
            input_schema,
            destructive,
            reasons,
        } = value;
        let input_schema = match input_schema {
            None | Some(serde_json::Value::Null) => None,
            Some(schema) => Some(WireJson::lift(schema)?),
        };
        Ok(Self {
            source,
            foreign,
            input_schema,
            destructive,
            reasons: if reasons.is_empty() {
                None
            } else {
                Some(reasons)
            },
        })
    }
}

impl Lift<oneiron::task_verb::sdk::ConnectorCallStatus> for crate::ConnectorCallStatus {
    fn lift(value: oneiron::task_verb::sdk::ConnectorCallStatus) -> Result<Self, OneironError> {
        match value {
            oneiron::task_verb::sdk::ConnectorCallStatus::Pending {
                call_ref,
                name,
                tool,
                held_at_ms,
                reasons,
                approval_digest,
            } => Ok(Self::Pending {
                call_ref,
                name,
                tool,
                held_at_ms,
                reasons: if reasons.is_empty() {
                    None
                } else {
                    Some(reasons)
                },
                approval_digest,
            }),
            oneiron::task_verb::sdk::ConnectorCallStatus::Settled {
                call_ref,
                name,
                tool,
                reply,
            } => Ok(Self::Settled {
                call_ref,
                name,
                tool,
                reply: crate::ConnectorCallReply::lift(reply)?,
            }),
            oneiron::task_verb::sdk::ConnectorCallStatus::AwaitingInput {
                call_ref,
                name,
                tool,
                generation,
                asked,
                uncertain,
                reply,
            } => {
                let reply = crate::ConnectorCallReply::lift(reply)?;
                Ok(Self::AwaitingInput {
                    call_ref,
                    name,
                    tool,
                    generation,
                    asked: super::count("connector.call_status:asked", asked)?,
                    uncertain: if uncertain { Some(true) } else { None },
                    reply,
                })
            }
        }
    }
}
