//! The host's seats for a derived text's safe copy (FIX 7608 S3F, CALL
//! DERIVED-TEXT-COPY): a caption or transcript a model once wrote from repo
//! bytes a mark now covers is written again from those sources' masked
//! copies, and only then indexed. The seats are the probe author's (the
//! chat seat for a text, the captioner or Local-vision seat for an image,
//! the media transcribe seat then the chat seat for audio), admitted and
//! paid as a probe call is; but the call asks for that output, a caption,
//! never a probe, and never sees the old caption.

use oneiron::embed::RepoDerivedIndexTextAuthor;

use super::*;

/// The purpose a derived text's call is budgeted and audited under.
const DERIVED_TEXT_PURPOSE: &str = "repo_index.derived_text";
/// What the seat is asked.
const DERIVED_TEXT_INSTRUCTION: &str = "You write captions for a search index. Given one stored \
    item, describe what it holds in one or two plain sentences. Write the description alone.";
/// Safe copies one backfill pass derives.
const DERIVED_TEXT_BATCH: usize = 4;

/// The host's author of derived texts' safe copies, on the probe author's
/// seats.
struct ServerDerivedTextAuthor<'a> {
    server: &'a SyncServer,
    runtime: &'a tokio::runtime::Handle,
    author: String,
    locality: EmbedderLocality,
}

impl RepoDerivedIndexTextAuthor for ServerDerivedTextAuthor<'_> {
    fn author_id(&self) -> &str {
        &self.author
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    /// Every source is described by the seat of its kind; a copy is the
    /// sources' descriptions together, or none when any seat is missing or
    /// hears nothing.
    fn derive_text(&self, sources: &[MediaEmbeddingInput<'_>]) -> oneiron::Result<Option<String>> {
        let mut parts = Vec::with_capacity(sources.len());
        for source in sources {
            let Some(seat) = self.server.probe_author(source.kind, self.runtime) else {
                return Ok(None);
            };
            let Some(text) = seat.derive_caption(source)? else {
                return Ok(None);
            };
            parts.push(text);
        }
        Ok(Some(parts.join("\n")).filter(|text| !text.trim().is_empty()))
    }
}

impl ServerProbeAuthor<'_> {
    /// `document`'s description from this seat: an image's caption, a
    /// text's or a transcript's summary; `None` when it hears no words.
    fn derive_caption(
        &self,
        document: &MediaEmbeddingInput<'_>,
    ) -> oneiron::Result<Option<String>> {
        let part = match document.kind {
            InputKind::Text => ContentPart::Text {
                text: String::from_utf8_lossy(document.bytes)
                    .chars()
                    .take(PROBE_SOURCE_MAX_CHARS)
                    .collect(),
            },
            InputKind::Image => ContentPart::Image {
                media_type: document.media_type.to_owned(),
                image: ImageContent::Base64 {
                    data: base64::engine::general_purpose::STANDARD.encode(document.bytes),
                },
            },
            InputKind::Audio => match self.transcribe(document)? {
                Some(transcript) => ContentPart::Text {
                    text: transcript.chars().take(PROBE_SOURCE_MAX_CHARS).collect(),
                },
                None => return Ok(None),
            },
        };
        let purpose = CallPurpose::Other {
            name: DERIVED_TEXT_PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(DERIVED_TEXT_PURPOSE.to_owned()),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: self.locality,
                host_keyless: false,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: DERIVED_TEXT_INSTRUCTION.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![part],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let vault = &self.server.vault;
        let call = self
            .server
            .ai
            .admit_role(vault, self.role, request)
            .map_err(|refusal| {
                Error::InvalidConfig(format!("derived text call refused: {refusal}"))
            })?;
        let run_id = format!("repo-index-derived:{}", document.entity_id.to_hex());
        let units = self.server.ai.chat_settings().turn_budget_units;
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            vault.dreamer_authority()?,
        )?;
        let run = self
            .server
            .ai
            .undeclared_run(run_id, guard)
            .sourced(Some(vec![document.entity_id]));
        let response = self
            .runtime
            .block_on(call.ladder.generate(&run, call.request, None))
            .map_err(|error| Error::InvalidConfig(format!("derived text call failed: {error}")))?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        Ok(Some(text.trim().to_owned()).filter(|text| !text.is_empty()))
    }
}

impl SyncServer {
    /// Derives a few pending safe copies of texts a model wrote from marked
    /// repo bytes, every backfill pass, open space move or not. Blocking;
    /// the model runs outside every vault transaction.
    pub(in crate::server) fn rederive_repo_index_texts(&self, runtime: &tokio::runtime::Handle) {
        let seats: Vec<ServerProbeAuthor<'_>> =
            [InputKind::Text, InputKind::Image, InputKind::Audio]
                .into_iter()
                .filter_map(|kind| self.probe_author(kind, runtime))
                .collect();
        let Some(first) = seats.first() else {
            return;
        };
        let locality = if seats
            .iter()
            .any(|seat| seat.locality() == EmbedderLocality::ThirdParty)
        {
            EmbedderLocality::ThirdParty
        } else {
            first.locality()
        };
        let egress = seats.iter().find_map(ServerProbeAuthor::media_egress);
        let author = ServerDerivedTextAuthor {
            server: self,
            runtime,
            author: author_label(&first.model),
            locality,
        };
        match self.vault.rederive_repo_index_text_copies(
            &author,
            DERIVED_TEXT_BATCH,
            egress.as_ref().map(|gate| gate as &dyn EgressPredicate),
        ) {
            Ok(report) if report.derived > 0 => {
                tracing::info!(derived = report.derived, "repo index safe copies derived");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "repo index safe copies stay pending"),
        }
    }
}
