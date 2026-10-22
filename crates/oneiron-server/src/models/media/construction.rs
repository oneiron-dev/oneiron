//! Media runtime construction and transport adapters.
//! Entry: MediaRuntime::build.
//! Types and private provider helpers stay in the parent; this module owns the listed impls.

use super::{
    Arc, BTreeMap, BTreeSet, BrokerSite, BudgetExhaustionPolicy, BudgetGuard, BudgetLease,
    FatalLlmError, HostAccount, KeyDoor, LlmBackend, LlmError, LlmGenerateFuture, LlmRequest,
    LlmResult, LlmStreamResult, LoggedReceipts, MEDIA_RUN, MediaHttp, MediaRow, MediaRuntime,
    MediaSeat, MediaSend, ModelHostBudgets, ModelsConfig, Mutex, NoChat, OfferCooldowns, OfferLadder,
    OpenAiMediaBody, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse, OpenAiMediaMethod,
    OpenAiMediaTransport, OpenAiMediaTransportFuture, RunReceiptSink, RungStatus, SeatScope,
    SeatState, SeatStatus, SingleRouteBackend, SingleSend, Wire, ladder_locality, media_backends,
    media_rung, media_seat_model, soniox, transport, voice_cloners,
};

impl SingleSend for NoChat {}

impl LlmBackend for NoChat {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async { Err(LlmError::from(FatalLlmError::InvalidRequest)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for NoChat {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl OpenAiMediaTransport for MediaHttp {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a> {
        Box::pin(async move {
            let send = match (request.method, request.body) {
                (OpenAiMediaMethod::Get, OpenAiMediaBody::Empty) => MediaSend::Get,
                (OpenAiMediaMethod::Delete, OpenAiMediaBody::Empty) => MediaSend::Delete,
                (OpenAiMediaMethod::Post, OpenAiMediaBody::Json(body)) => MediaSend::Json(body),
                (OpenAiMediaMethod::Post, OpenAiMediaBody::Multipart { fields, files }) => {
                    let mut form = reqwest::multipart::Form::new();
                    for (name, value) in fields {
                        form = form.text(name, value);
                    }
                    for file in files {
                        let part = reqwest::multipart::Part::bytes(file.bytes)
                            .file_name(file.filename)
                            .mime_str(&file.media_type)
                            .map_err(|_| FatalLlmError::InvalidRequest)?;
                        form = form.part(file.name, part);
                    }
                    MediaSend::Multipart(form)
                }
                _ => return Err(FatalLlmError::InvalidRequest.into()),
            };
            let reply = self
                .http
                .send_media(&request.path, send)
                .await
                .map_err(transport)?;
            Ok::<_, LlmError>(OpenAiMediaHttpResponse {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        })
    }
}

impl MediaRuntime {
    pub(in crate::models) fn empty() -> Self {
        Self {
            seats: BTreeMap::new(),
            meter: None,
            receipts: Arc::new(LoggedReceipts),
            host: None,
            jobs: Mutex::default(),
            store: None,
            job_rungs: BTreeMap::new(),
            rests: None,
            reference_targets: BTreeSet::new(),
            cloners: BTreeMap::new(),
            live_asr: BTreeMap::new(),
        }
    }

    /// Builds each `[models.media]` seat. A rung whose provider cannot
    /// start drops out of its ladder, and the reason shows in `status`. A
    /// `key_secret` provider's calls go through the credential broker at
    /// `site`, its key read at `keys`. Every rung's and clone wire's replies
    /// hold their bytes on `budgets`, the vault's (FIX 9321).
    pub(in crate::models) fn build(
        config: &ModelsConfig,
        rests: &Arc<OfferCooldowns>,
        status: &mut Vec<SeatStatus>,
        site: Option<&Result<BrokerSite, String>>,
        keys: Option<&Arc<dyn KeyDoor>>,
        budgets: &ModelHostBudgets,
    ) -> Self {
        let mut runtime = Self::empty();
        if config.media.seats.is_empty() {
            return runtime;
        }
        runtime.meter = Some(BudgetGuard::new(
            MEDIA_RUN,
            config.media.budget_units,
            BudgetExhaustionPolicy::Suspend,
        ));
        runtime.rests = Some(Arc::clone(rests));
        runtime.reference_targets = config
            .providers
            .iter()
            .filter(|(_, provider)| provider.kind.renders_from_refs())
            .map(|(name, _)| name.clone())
            .collect();
        runtime.cloners = voice_cloners(config, budgets);
        runtime.live_asr = soniox::live_rungs(config);
        let backends = media_backends(config, site, keys);
        for (operation, seat) in &config.media.seats {
            let mut rungs = Vec::new();
            let mut rung_status = Vec::new();
            let mut rows = Vec::new();
            for (position, model) in seat.rungs.iter().enumerate() {
                let provider = &config.providers[&model.provider];
                let mut entry = RungStatus::new(model, provider);
                match backends.get(&model.provider).and_then(|backend| {
                    media_rung(provider, backend, model, position, *operation, &seat.caps, budgets)
                }) {
                    Some(rung) => {
                        rows.push((rung.model.clone(), model.clone(), provider.locality));
                        rungs.push(rung);
                    }
                    None => entry.available = false,
                }
                rung_status.push(entry);
            }
            if operation.is_job() {
                for rung in &rungs {
                    runtime.job_rungs.insert(rung.model.clone(), rung.clone());
                }
            }
            let state = if rungs.is_empty() {
                SeatState::Unavailable
            } else {
                SeatState::Ready
            };
            let seat_model = media_seat_model(*operation, &rungs);
            status.push(SeatStatus {
                role: format!("media.{}", operation.as_str()),
                seat_model: seat_model.as_ref().map(ToString::to_string),
                state,
                rungs: rung_status,
            });
            let Some(seat_model) = seat_model.filter(|_| !rungs.is_empty()) else {
                continue;
            };
            // A tier bound to a rung that did not start serves no voice.
            let tiers = seat
                .tiers
                .iter()
                .filter_map(|(tier, model)| {
                    let (id, _, _) = rows.iter().find(|(_, bound, _)| bound == model)?;
                    Some((tier.clone(), id.clone()))
                })
                .collect();
            let locality = ladder_locality(&rungs, config);
            let scope = SeatScope {
                wire: Wire::Media(*operation),
                stays_on_device: false,
                configured: seat.rungs.len(),
            };
            let alone = rungs
                .iter()
                .map(|rung| {
                    let ladder = OfferLadder::pinned(rung.clone(), Arc::clone(rests)).scoped(scope);
                    (rung.model.clone(), Arc::new(ladder))
                })
                .collect();
            let rows = rows
                .into_iter()
                .map(|(id, model, locality)| MediaRow {
                    operation: *operation,
                    model: id.to_string(),
                    seat_model: seat_model.to_string(),
                    provider: model.provider,
                    wire_model: model.model,
                    locality,
                    inputs: seat.caps.inputs.clone(),
                    outputs: seat.caps.outputs.clone(),
                    native_rates: seat.caps.native_rates.clone(),
                    max_references: seat.caps.max_references,
                    peer: None,
                })
                .collect();
            runtime.seats.insert(
                *operation,
                MediaSeat {
                    model: seat_model.clone(),
                    locality,
                    ladder: Arc::new(
                        OfferLadder::seat(seat_model, rungs, Arc::clone(rests)).scoped(scope),
                    ),
                    rungs: alone,
                    rows,
                    tiers,
                },
            );
        }
        runtime
    }

    pub(in crate::models) fn set_host_account(&mut self, host: Arc<HostAccount>) {
        self.host = Some(host);
    }

    pub(in crate::models) fn set_receipts(&mut self, receipts: Arc<dyn RunReceiptSink>) {
        self.receipts = receipts;
    }
}
