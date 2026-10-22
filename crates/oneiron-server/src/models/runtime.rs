//! Model runtime construction and accessors.
//! Entry: ModelRuntime::build.
//! ModelRuntime and private provider helpers stay in the parent; this module owns the complete impl.

use super::*;

impl ModelRuntime {
    /// No `[models]`: no seat, no router.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            seats: BTreeMap::new(),
            router: None,
            raw_router: Arc::new(ModelRouter::default()),
            status: ModelsStatus::unconfigured(),
            receipts: Arc::new(LoggedReceipts),
            host: None,
            decision_read: None,
            stays_on_device: BTreeSet::new(),
            media: MediaRuntime::empty(),
            rests: OfferCooldowns::unkept(),
            token_ratios: None,
            training: Default::default(),
        }
    }

    /// Writes the receipts of every run this runtime admits to `receipts`
    /// instead of the log.
    #[must_use]
    pub fn with_receipts(mut self, receipts: Arc<dyn RunReceiptSink>) -> Self {
        self.media.set_receipts(Arc::clone(&receipts));
        self.receipts = receipts;
        self
    }

    /// The live vault allocation used by every run this runtime serves.
    #[must_use]
    pub fn with_host_account(mut self, host: Arc<HostAccount>) -> Self {
        self.media.set_host_account(Arc::clone(&host));
        self.host = Some(host);
        self
    }

    pub(crate) fn host_account(&self) -> Option<Arc<HostAccount>> {
        self.host.clone()
    }

    /// A run that declares nothing, on a meter its host built (see
    /// [`undeclared_run`]), with this runtime's receipts.
    #[must_use]
    pub fn undeclared_run(&self, run: impl Into<String>, meter: BudgetGuard) -> RunAdmission {
        undeclared_run(run, meter, self.host.clone(), Arc::clone(&self.receipts))
    }

    /// [`Self::undeclared_run`] for a call a room's root spend scope pays
    /// for (OF-531): each permit binds `payer`, which the host resolved
    /// before the run began. `None` is the vault owner's run.
    #[must_use]
    pub fn funded_run(
        &self,
        run: impl Into<String>,
        meter: BudgetGuard,
        payer: Option<PayerPerson>,
    ) -> RunAdmission {
        raw::funded_run(
            run,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
            payer,
        )
    }

    /// [`Self::undeclared_run`] for a free-time item's calls (FIX 4453): the
    /// run carries `attribution`, which the engine stamped before it began,
    /// beside this runtime's receipts and host account. No room pays for it.
    #[must_use]
    pub fn attributed_run(
        &self,
        run: impl Into<String>,
        meter: BudgetGuard,
        attribution: RunAttribution,
    ) -> RunAdmission {
        let line = BudgetLine {
            limit_units: meter.read().limit_units,
            reserve_units: meter.reserve_units(),
            unit: LeaseUnit::tokens(),
        };
        RunAdmission::with_attribution(
            run,
            RunDeclaration::undeclared(line),
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
            None,
            attribution,
        )
    }

    /// A declared run (ARCH-0053 `#run-declaration`) on its own line, over
    /// this runtime's models: its teachers, connectors and budget, as the host
    /// that starts it states them. `host` is the account whose allocation
    /// pays host-paid offers; `None` uses this runtime's live host account.
    /// Its paid keys must sit at T0 unless the owner
    /// allowed an offer at T1; a `key_env` key is at T1.
    #[must_use]
    pub fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: RunDeclaration,
        host: Option<Arc<HostAccount>>,
    ) -> DeclaredRun {
        DeclaredRun::new(
            RunAdmission::new(
                run,
                declaration,
                host.or_else(|| self.host.clone()),
                Arc::clone(&self.receipts),
            ),
            self.router.clone(),
        )
    }

    #[must_use]
    pub fn build(config: Option<&ModelsConfig>) -> Self {
        Self::build_with_keys(config, None)
    }

    /// [`build`](Self::build), with the custody door a `key_secret`
    /// provider's calls read their key at, through a broker made for the
    /// providers alone. Without one, or outside a runtime, such a provider is
    /// unavailable.
    #[must_use]
    pub fn build_with_keys(config: Option<&ModelsConfig>, keys: Option<Arc<dyn KeyDoor>>) -> Self {
        let broker = config
            .zip(keys)
            .and_then(|(config, keys)| BrokerContext::for_providers(keys, config));
        Self::build_hosted(config, broker.as_ref(), OfferCooldowns::unkept())
    }

    /// [`build`](Self::build), with the vault's one credential-broker
    /// context every `key_secret` provider, chat or media, sends through
    /// (without one, such a provider is unavailable), and where an offer a
    /// provider refused for a quota or a limit rests until its reset.
    #[must_use]
    pub(crate) fn build_hosted(
        config: Option<&ModelsConfig>,
        broker: Option<&BrokerContext>,
        rests: Arc<OfferCooldowns>,
    ) -> Self {
        let Some(config) = config else {
            // A discovered model's rest outlives a restart here too.
            return Self {
                rests,
                ..Self::unconfigured()
            };
        };
        // V2-R3: the next vault lock's bound and the status read this.
        worker_host::snapshot_policy(&config.snapshots);
        let mut status = ModelsStatus {
            // The process's supervisors for `[models.workers]` (FIX 8315).
            workers: worker_host::configure(&config.workers, &config.providers),
            ..ModelsStatus::default()
        };
        let mut built = BTreeMap::new();
        // Every `key_secret` provider, chat or media, sends through the
        // context's one broker and reads its key at the context's door.
        let site = broker.map(BrokerContext::site);
        let keys = broker.map(BrokerContext::keys);
        // One cache of house llama.cpp launch manifests, for the chat routes
        // and the decision read alike (FIX 7895).
        let identities = Arc::new(llama_identity::LlamaIdentityResolver::default());
        for (name, provider) in &config.providers {
            match build_provider(name, provider, config, site, keys, &identities) {
                Ok(Some(backend)) => {
                    let broker = backend.broker_isolation();
                    built.insert(name.clone(), backend);
                    status
                        .providers
                        .push(ProviderStatus::ready(name, provider, broker));
                }
                Ok(None) => status
                    .providers
                    .push(ProviderStatus::without_consumer(name, provider)),
                Err(error) => {
                    tracing::warn!(provider = %name, %error, "model provider unavailable");
                    status
                        .providers
                        .push(ProviderStatus::unavailable(name, provider, &error));
                }
            }
        }
        // The reranker's rungs speak `/v1/rerank`, not chat: each provider
        // that serves one gets a rerank client beside its chat backend.
        let mut rerankers = BTreeMap::new();
        for (name, provider) in &config.providers {
            let models = reranker_models(config, name);
            if models.is_empty() || !provider.kind.reranks() {
                continue;
            }
            match build_reranker(provider, &models) {
                Ok(backend) => {
                    rerankers.insert(name.clone(), backend);
                }
                Err(error) => {
                    tracing::warn!(provider = %name, %error, "reranker provider unavailable");
                }
            }
        }
        let mut router = ModelRouter::default();
        let mut fallbacks = Vec::new();
        for (rerank, backends) in [(false, &built), (true, &rerankers)] {
            for (name, backend) in backends {
                let provider = &config.providers[name];
                let models = if rerank {
                    reranker_models(config, name)
                } else {
                    referenced_models(config, name)
                };
                for model in models {
                    if let Some(rung) = rung(name, provider, backend, &model, 0, None, rerank)
                        // A model that also serves a chat role keeps its raw
                        // chat route; the reranker reaches it through its seat.
                        && !(rerank && router.served(&rung.model).is_some())
                    {
                        let wire = if rerank { Wire::Rerank } else { Wire::Chat };
                        let ladder = Arc::new(OfferLadder::bare(rung, Arc::clone(&rests)).scoped(
                            SeatScope {
                                wire,
                                ..SeatScope::default()
                            },
                        ));
                        if !rerank {
                            fallbacks.push(FallbackRung {
                                provider: name.clone(),
                                model: ladder.model().clone(),
                                ladder: Arc::downgrade(&ladder),
                            });
                            router.chat_model(
                                ladder.model().clone(),
                                model_family(&model, provider).map(str::to_owned),
                            );
                            if let Ok(entry) = catalog_entry(&model, provider) {
                                router.chat_entry(LlmCatalogEntry {
                                    model: ladder.model().clone(),
                                    ..entry
                                });
                            }
                        }
                        router.insert(ladder.model().clone(), provider.locality, ladder);
                    }
                }
            }
        }
        let mut seats = BTreeMap::new();
        for (role, ladder) in &config.roles {
            let mut rungs = Vec::new();
            let mut rung_status = Vec::new();
            // A seat whose work never leaves the device has no rung off it,
            // first or as a fallback.
            let stays = config.stays_on_device.contains(role);
            for (position, rung) in ladder.iter().enumerate() {
                let provider = &config.providers[&rung.model.provider];
                let mut entry = RungStatus::new(&rung.model, provider);
                let rerank = *role == ModelRole::Reranker;
                let backends = if rerank { &rerankers } else { &built };
                let served = backends
                    .get(&rung.model.provider)
                    .filter(|_| provider.kind.generates())
                    .filter(|_| config.role_permits(*role, provider.locality))
                    .and_then(|backend| {
                        crate::models::rung(
                            &rung.model.provider,
                            provider,
                            backend,
                            &rung.model,
                            position,
                            rung.prompt.clone(),
                            rerank,
                        )
                    });
                match served {
                    Some(served) => rungs.push(served),
                    None => entry.available = false,
                }
                rung_status.push(entry);
            }
            let state = if rungs.is_empty() {
                SeatState::Unavailable
            } else {
                SeatState::Ready
            };
            let scope = SeatScope {
                wire: if *role == ModelRole::Reranker {
                    Wire::Rerank
                } else {
                    Wire::Chat
                },
                stays_on_device: stays,
                configured: ladder.len(),
            };
            if let Some(seat) = seat_for(
                *role,
                ladder_locality(&rungs, config),
                rungs,
                Arc::clone(&rests),
                scope,
            ) {
                router.insert(seat.model.clone(), seat.locality, Arc::clone(&seat.ladder));
                status.seats.push(SeatStatus::new(
                    *role,
                    Some(&seat.model),
                    state,
                    rung_status,
                ));
                seats.insert(*role, seat);
            } else {
                status
                    .seats
                    .push(SeatStatus::new(*role, None, state, rung_status));
            }
        }
        let media = MediaRuntime::build(config, &rests, &mut status.seats, site, keys);
        // Each chat model the router serves, and each media seat's rung, is
        // one a parked offer's calls may fall back to once the owner names
        // it (`use_fallback`).
        fallbacks.extend(media.fallback_rungs());
        rests.offer_fallbacks(fallbacks);
        status.configured = true;
        // A read blocks on the runtime its reader was built on; a build with
        // none has no reader.
        let decision_read = tokio::runtime::Handle::try_current()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| decision_read::bind(config, runtime, &identities))
            .unwrap_or_else(|error| {
                if config.decision_read.is_some() {
                    tracing::warn!(%error, "decision read unavailable");
                }
                None
            });
        router.name_aliases(&config.aliases);
        // Counts run on the runtime the host was built on, like a read.
        let token_ratios = tokio::runtime::Handle::try_current()
            .ok()
            .map(|runtime| Arc::new(TokenRatios::new(config, runtime)));
        let router = Arc::new(router);
        Self {
            seats,
            router: (!router.is_empty()).then(|| Arc::clone(&router)),
            raw_router: router,
            status,
            receipts: Arc::new(LoggedReceipts),
            host: None,
            decision_read,
            stays_on_device: config.stays_on_device.clone(),
            media,
            rests,
            token_ratios,
            training: config.training.clone(),
        }
    }

    /// The host's catalog token counters; `None` without `[models]` or a
    /// runtime to run their requests on.
    #[must_use]
    pub fn token_ratios(&self) -> Option<Arc<TokenRatios>> {
        self.token_ratios.clone()
    }

    /// The house model's decision read, when `[models.decision_read]` binds
    /// one.
    #[must_use]
    pub fn decision_read(&self) -> Option<&DecisionReadDoor> {
        self.decision_read.as_ref()
    }

    /// The `ai.*` media seats: image, video, speech, transcription and
    /// embedding.
    #[must_use]
    pub fn media(&self) -> &MediaRuntime {
        &self.media
    }

    /// Hears each stable recovery of an offer whose provider was down
    /// (OF-305), for the memory work its outage stopped.
    #[must_use]
    pub fn recoveries(&self) -> tokio::sync::watch::Receiver<u64> {
        self.rests.recoveries()
    }

    /// The owner's open quota questions (OF-305): each offer parked on a
    /// spent usage window or spent credit, and the choices it offers.
    #[must_use]
    pub fn quota_questions(&self) -> Vec<QuotaQuestion> {
        self.rests.questions()
    }

    /// The owner's answer to quota question `id`; a top-up or pay-as-you-go
    /// puts its offer back in rotation now, and `use_fallback` sends its
    /// calls to `fallback`, one of the question's fallbacks, while it is
    /// parked. `false` when no such question is open, it offers no such
    /// choice, or it offers no such fallback.
    pub fn answer_quota(
        &self,
        id: &str,
        choice: QuotaChoice,
        fallback: Option<&str>,
    ) -> oneiron::Result<bool> {
        self.rests.answer(id, choice, fallback)
    }

    /// The seat for `role`, when at least one of its rungs can serve.
    #[must_use]
    pub fn seat(&self, role: ModelRole) -> Option<&Seat> {
        self.seats.get(&role)
    }

    /// Every configured model and seat by id, for raw calls that name their
    /// model. `None` when nothing is configured.
    #[must_use]
    pub fn router(&self) -> Option<Arc<ModelRouter>> {
        self.router.clone()
    }

    /// The router the raw routes call: the configured models, and the ones
    /// the owner's other nodes offer. With no configured model it holds only
    /// those, so a device with no `[models]` still serves them (FIX 3229).
    #[must_use]
    pub(crate) fn raw_router(&self) -> Arc<ModelRouter> {
        Arc::clone(&self.raw_router)
    }

    /// Serves on this runtime's raw router, beside the configured models,
    /// the ones the owner's other nodes offer over `mesh` (FIX 3229), as the
    /// vault's discovery rows hold them now and after each refresh.
    #[cfg(feature = "mesh")]
    pub(crate) fn mesh_routes(
        &self,
        vault: &Arc<oneiron::Vault>,
        mesh: Arc<dyn oneiron_mesh_transport::MeshTransport>,
    ) -> MeshRoutes {
        MeshRoutes::new(self.raw_router(), Arc::clone(&self.rests), vault, mesh)
    }

    #[must_use]
    pub fn status(&self) -> &ModelsStatus {
        &self.status
    }

    /// [`Self::status`] with each built rung's live health, and each seat's
    /// state worked out from it (OF-305). A seat whose offers' providers are
    /// down shows Down, and one with an offer on probation shows Recovering.
    /// A limit hold shows on its rung, apart from the outage state. Read-only:
    /// it takes no probation slot, probes nothing and rebuilds nothing.
    #[must_use]
    pub fn live_status(&self) -> ModelsStatus {
        let mut status = self.status.clone();
        for seat in &mut status.seats {
            let ladder = self
                .seats
                .iter()
                .find(|(role, _)| role_key(**role) == seat.role)
                .map(|(_, built)| &built.ladder)
                .or_else(|| self.media.seat_ladder(&seat.role));
            if let Some(ladder) = ladder {
                seat.live(ladder.health());
            }
        }
        // Each model the mesh discovered, whatever its health (FIX 3229).
        status.discovered = self
            .raw_router
            .discovered_routes()
            .into_iter()
            .filter_map(|(model, peer, ladder)| {
                let (_, health) = ladder.health().into_iter().next()?;
                Some(DiscoveredStatus {
                    model: model.to_string(),
                    peer,
                    health,
                })
            })
            .collect();
        worker_host::refresh(&mut status.workers);
        // V2-R3: sealed snapshot parking, counts and outcomes only.
        status.snapshots = worker_host::snapshot_status();
        status
    }
}
