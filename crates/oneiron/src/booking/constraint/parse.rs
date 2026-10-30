//! The one constraint parse: a booking request's free text through the
//! decision model into a `ConstraintObject`, or an off-topic refusal.
//! Entry: `parse_constraint_with_backend`. Defines its own items; the seam types stay in `constraint`.

use super::*;

/// Parse bounded free text into a disposition: the off-topic question through
/// the host's ladder, then, for an on-topic turn, one zero-temperature,
/// JSON-schema, tool-free extraction call.
///
/// The caller has already admitted the parse pass: both calls go out on its
/// lease, and this function does not touch session state.
pub async fn parse_constraint_with_backend(
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    request: &ConstraintParseRequest,
    config: &ConstraintParseConfig,
) -> Result<ConstraintParseDisposition, BookingError> {
    config.validate()?;
    let free_text = request.free_text.trim();
    if free_text.is_empty() {
        return Err(BookingError::InvalidConstraint(
            "constraint free text must not be empty".to_owned(),
        ));
    }
    if free_text.len() > config.max_input_bytes {
        return Err(BookingError::InvalidConstraint(format!(
            "constraint free text exceeds the configured bound of {} bytes",
            config.max_input_bytes
        )));
    }
    validate_visitor_tz(&request.detected_visitor_tz)?;

    if off_topic(backend, lease, request, config, free_text).await? {
        return Ok(ConstraintParseDisposition::OffTopic);
    }

    let response = backend
        .generate(
            constraint_parse_llm_request(request, config, free_text)?,
            lease,
        )
        .await
        .map_err(|error| BookingError::ConstraintParse(error.to_string()))?;

    let extraction: ConstraintExtraction = serde_json::from_str(&response_text(&response.message))
        .map_err(|error| {
            BookingError::ConstraintParse(format!("parser payload is not a constraint: {error}"))
        })?;
    // A timezone override is the only free-form string the parser may emit.
    // Validating it as an identifier is what stops the original sentence from
    // riding into the solve request.
    if let Some(tz) = &extraction.visitor_tz_override {
        validate_visitor_tz(tz)?;
    }
    Ok(ConstraintParseDisposition::Constraint {
        object: extraction.object.canonicalize()?,
        visitor_tz_override: extraction.visitor_tz_override,
    })
}

/// What an on-topic turn's extraction returns.
#[derive(Deserialize)]
struct ConstraintExtraction {
    object: ConstraintObject,
    visitor_tz_override: Option<String>,
}

/// Whether the turn is off topic, through the host's ladder: the parse tier's
/// read on the caller's lease is the first rung, under the parser's own system
/// voice, and the turn is the call's state. A read that does not decide fails
/// the parse.
async fn off_topic(
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    request: &ConstraintParseRequest,
    config: &ConstraintParseConfig,
    free_text: &str,
) -> Result<bool, BookingError> {
    let decisions = &config.decisions;
    let unread = |reason: String| BookingError::ConstraintParse(reason);
    let question = BOOKING_OFF_TOPIC
        .question(
            &[&CONSTRAINT_SCHEMA_VERSION.to_be_bytes()],
            OFF_TOPIC_QUESTION.to_owned(),
            AnswerContract::Noul,
        )
        .map_err(|error| unread(error.to_string()))?;
    let mut shell = constraint_parse_llm_request(request, config, free_text)?;
    shell.messages = vec![system_message(constraint_system_prompt())];
    let seal = |request: LlmRequest| -> crate::Result<LlmRequest> { Ok(request) };
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: decisions.dial.first,
            model: shell.model.to_string(),
            version: shell.model.to_string(),
        },
        backend,
        step: GeneratedStep::Raw { lease },
        request: shell,
        seal: &seal,
    };
    let state = json!({
        "schema_version": CONSTRAINT_SCHEMA_VERSION,
        "visitor_tz": request.detected_visitor_tz,
        "now_utc": request.now_utc,
        "text": free_text,
    });
    let decided = decisions
        .ladder
        .ladder()
        .run_pack_generated(
            &rung,
            &[&question],
            decisions.principal,
            &[],
            &state,
            decisions.dial,
            &decisions.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), decisions.budget),
        )
        .await
        .map_err(|error| unread(error.to_string()))?;
    match decided {
        GeneratedDecisions::Decided { decisions, .. } => {
            match decisions.first().map(|decision| &decision.answer) {
                Some(DecisionAnswer::Noul(yes)) => Ok(*yes),
                _ => Err(unread("off-topic read did not decide".to_owned())),
            }
        }
        GeneratedDecisions::Unread(GeneratedMiss::Backend(error)) => Err(unread(error.to_string())),
        GeneratedDecisions::Unread(GeneratedMiss::Budget(_)) | GeneratedDecisions::Trapped => {
            Err(unread("off-topic read did not run".to_owned()))
        }
    }
}

fn response_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn constraint_parse_llm_request(
    request: &ConstraintParseRequest,
    config: &ConstraintParseConfig,
    free_text: &str,
) -> Result<LlmRequest, BookingError> {
    // `params` is copied verbatim into the provider request body, so only
    // provider-supported generation parameters belong here.
    // `config.max_input_bytes` is local admission state: it is enforced before
    // this request is built and never sent.
    let mut params = BTreeMap::new();
    params.insert("temperature".to_owned(), json!(0));
    params.insert("max_output_tokens".to_owned(), json!(MAX_OUTPUT_TOKENS));

    Ok(LlmRequest {
        model: config.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::Other {
                name: CONSTRAINT_PARSE_CALL_PURPOSE.to_owned(),
            },
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: CONSTRAINT_PARSE_FALLBACK.to_owned(),
                    config: None,
                },
            },
            tier: config.tier.clone(),
            response_format: ResponseFormat::Json {
                schema: constraint_response_schema(),
            },
            locality: config.locality,
            host_keyless: false,
        },
        messages: vec![
            system_message(format!(
                "{}\nConvert the scheduling preference into the JSON schema and return nothing else.",
                constraint_system_prompt()
            )),
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: constraint_user_section(request, free_text),
                }],
            },
        ],
        // The capability boundary: the model parses scheduling constraints and
        // nothing else. No tools, ever.
        tools: Vec::new(),
        params,
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

fn system_message(text: String) -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text { text }],
    }
}

/// Machine-facing instruction for the parser, which the off-topic read shares.
/// This never reaches a visitor — all visible copy is host-supplied
/// configuration.
fn constraint_system_prompt() -> String {
    [
        "You are the Oneiron booking constraint parser, a system voice independent of any persona.",
        "Never copy the input text, an explanation, or any other field into the output.",
        "You do not choose times, hold, confirm, or cancel anything.",
    ]
    .join("\n")
}

fn constraint_user_section(request: &ConstraintParseRequest, free_text: &str) -> String {
    format!(
        "schema_version={CONSTRAINT_SCHEMA_VERSION}\nvisitor_tz={}\nnow_utc={}\ntext={free_text}",
        request.detected_visitor_tz, request.now_utc
    )
}

fn constraint_response_schema() -> JsonValue {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["object"],
        "properties": {
            "visitor_tz_override": { "type": ["string", "null"], "maxLength": MAX_VISITOR_TZ_BYTES },
            "object": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version", "utc_window", "allow_flex_pool"],
                "properties": {
                    "schema_version": { "const": CONSTRAINT_SCHEMA_VERSION },
                    "weekdays": {
                        "type": "array",
                        "maxItems": 7,
                        "items": {
                            "enum": [
                                "monday", "tuesday", "wednesday", "thursday",
                                "friday", "saturday", "sunday",
                            ]
                        }
                    },
                    "local_time_windows": {
                        "type": "array",
                        "maxItems": MAX_LOCAL_TIME_WINDOWS,
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["start_minute", "end_minute"],
                            "properties": {
                                "start_minute": { "type": "integer", "minimum": 0, "maximum": MINUTES_PER_DAY },
                                "end_minute": { "type": "integer", "minimum": 0, "maximum": MINUTES_PER_DAY },
                            }
                        }
                    },
                    "utc_window": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "required": ["start", "end"],
                        "properties": {
                            "start": { "type": "integer", "minimum": 0 },
                            "end": { "type": "integer", "minimum": 0 },
                        }
                    },
                    "allow_flex_pool": { "type": "boolean" },
                }
            }
        }
    })
}
