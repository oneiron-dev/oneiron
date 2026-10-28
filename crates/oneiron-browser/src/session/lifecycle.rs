use super::*;

impl BrowserSession {
    /// The engine selects and proves a backend before attaching the browser.
    /// A lower driver crate must never silently select a weaker backend.
    /// The session's live-handle registry is charged to the host's memory
    /// floor through `retention` (C013). A session given the host's
    /// `starter` serves `switch_engine`. A session given the host's
    /// `requests` handler has it perform every request of its pages in
    /// place of `relay`, from before any page loads (FIX 7122); one given
    /// none takes `relay` as always.
    pub fn attach(
        config: &BrowserGuest,
        transport: SessionTransport,
        relay: Arc<dyn EgressRelay>,
        retention: Box<dyn HandleRetention>,
        starter: Option<Box<dyn BrowserGuestStarter>>,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<Self, BrowserError> {
        let started = StartedGuest {
            transport,
            relay,
            retention,
        };
        let snapshots = starter
            .as_ref()
            .map(|starter| OriginSnapshots::collector(starter.state_charge()));
        let sink = snapshots.as_ref().map(OriginSnapshots::sink);
        let custody = Custody::new(requests);
        let secrets = Secrets::default();
        let (engine, wait_cap) = (config.engine, config.wait_cap);
        let attached = EngineGuest::attach(
            engine,
            started,
            wait_cap,
            sink,
            custody.clone(),
            secrets.clone(),
        );
        let EngineGuest {
            driver,
            lease,
            manifest,
        } = attached?;
        if let Some(starter) = &starter {
            driver.book_inbound(starter.state_charge());
        }
        Ok(Self {
            driver,
            guest: lease,
            manifest,
            policy: config.policy.clone(),
            trail: Vec::new(),
            receipt_seq: 0,
            acted: None,
            stop_pending: None,
            press_refused: None,
            presses: PressBook::new(config.policy.clone()),
            unread: None,
            decider: None,
            field_writer: None,
            typed: None,
            library: None,
            receipt_sink: None,
            takeover: Takeover::Agent,
            returned: None,
            starter,
            history: OriginHistory::default(),
            snapshots,
            custody,
            fresh: None,
            secrets,
            demos: demonstration::Demonstrations::default(),
        })
    }

    /// Gives the session the host's secret custody (FIX 8028): the secrets
    /// its reads find from now on become handles bound to its run, and a
    /// type or expect may name them.
    pub fn set_secret_custody(&mut self, custody: Arc<dyn SecretCustody>) {
        self.secrets.install(custody);
    }

    /// Gives the session the host's replay library.
    pub fn set_library(&mut self, library: Box<dyn WorkflowLibrary>) {
        self.library = Some(library);
    }

    /// Runs `act` over the session with its library, decider and field
    /// writer lent out, so a library verb drives the session's own gated
    /// verbs.
    pub(super) fn with_library<T>(
        &mut self,
        act: impl FnOnce(
            &mut Self,
            &mut dyn WorkflowLibrary,
            &mut dyn RoutineDecider,
            &dyn FieldWriter,
        ) -> Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let mut library = self.library.take().ok_or_else(no_library)?;
        let mut decider = self.decider.take();
        let writer = self.field_writer.take();
        let lent: &dyn FieldWriter = match writer.as_deref() {
            Some(writer) => writer,
            None => &NoWriter,
        };
        let result = match decider.as_deref_mut() {
            Some(decider) => act(self, library.as_mut(), decider, lent),
            None => act(self, library.as_mut(), &mut NoDecider, lent),
        };
        self.library = Some(library);
        self.decider = decider;
        self.field_writer = writer;
        result
    }

    /// Gives the session's batches the host's routine decider.
    pub fn set_decider(&mut self, decider: Box<dyn RoutineDecider>) {
        self.decider = Some(decider);
    }

    /// Gives the session's Fill steps the host's field writer (CUA E6).
    pub fn set_field_writer(&mut self, writer: Box<dyn FieldWriter>) {
        self.field_writer = Some(writer);
    }

    /// Gives the session the host's keeper of receipt screenshots.
    pub fn set_receipt_sink(&mut self, sink: Box<dyn ReceiptEvidenceSink>) {
        self.receipt_sink = Some(sink);
    }

    /// A browser may only be started through the engine's tier selector.
    pub fn start(_config: &BrowserGuest) -> Result<Self, BrowserError> {
        Err(BrowserError::Unavailable(
            "engine-selected sandbox and egress proxy required".into(),
        ))
    }

    /// What the guest's container proved, for the run's receipt.
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    /// The engine the session attached, which runs its every verb.
    #[must_use]
    pub const fn engine(&self) -> BrowserEngine {
        self.driver.engine()
    }

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.driver.image(image)
    }

    /// Every effect this session receipted, in order.
    pub fn receipts(&self) -> impl Iterator<Item = &EffectReceipt> {
        self.trail.iter().filter_map(Event::receipt)
    }

    /// The press policy as it stands, batch counts spent down.
    #[must_use]
    pub fn policy(&self) -> &SendPolicy {
        &self.policy
    }

    #[must_use]
    pub fn abandoned(&self) -> bool {
        self.guest.abandoned()
    }

    /// Who has the browser now.
    #[must_use]
    pub fn takeover(&self) -> &Takeover {
        &self.takeover
    }

    /// Person `by` takes the browser, asked or not. The caller holds the
    /// session, so the agent's call in flight has ended; its next one
    /// refuses until `by` hands the browser back. Taking it again is a no-op.
    /// The take of an ask that opted in starts the person's span (CUA E9b).
    pub fn take_over(&mut self, by: &str) -> Result<&Takeover, BrowserError> {
        self.guest_up()?;
        let asked = match &self.takeover {
            Takeover::Agent => None,
            Takeover::Waiting { reason, .. } => Some(reason.clone()),
            Takeover::Held { by: holder, .. } if holder == by => return Ok(&self.takeover),
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
        };
        // The agent's demonstration ends before a person's input begins.
        self.recording_close(DemonstrationStopCause::HandedOver);
        self.takeover = Takeover::Held {
            by: by.to_owned(),
            asked,
            taken_at_ms: now_ms(),
            inputs: 0,
        };
        self.takeover_start_policy();
        Ok(&self.takeover)
    }

    /// The browser's tabs for the person's view, the one in front marked:
    /// a tab or popup opened since is followed, and while a person holds
    /// the browser it comes to the front, as a browser shows a popup.
    pub fn tabs(&mut self) -> Result<Vec<BrowserTab>, BrowserError> {
        self.guest_up()?;
        let held = matches!(self.takeover, Takeover::Held { .. });
        if held {
            // The person's acts are matched before a popup comes to the
            // front (CUA E9b).
            self.recording_drain();
        }
        self.driver.tabs(held)
    }

    /// The front tab's viewport as a PNG for the person, or `tab`'s, which
    /// comes to the front: unmasked, never held in the session's images and
    /// never a receipt. Only the person who holds the browser brings
    /// another tab to the front.
    pub fn person_screen(&mut self, tab: Option<&str>) -> Result<Vec<u8>, BrowserError> {
        self.tabs()?;
        self.bring_up(tab)?;
        self.driver.person_screen()
    }

    /// The person's view in one look: the tabs, then the front tab's
    /// viewport, as [`Self::tabs`] and [`Self::person_screen`] give them.
    pub fn person_view(&mut self) -> Result<(Vec<BrowserTab>, Vec<u8>), BrowserError> {
        let tabs = self.tabs()?;
        Ok((tabs, self.driver.person_screen()?))
    }

    /// One input from `by`, who must hold the browser, at the viewport's
    /// pixels of the front tab, or of `tab`, which comes to the front first,
    /// or a page to go to; it counts toward the takeover's record. A tab
    /// opened since the person's last look stays behind: the input goes to
    /// the tab they saw. No press gates it: the person's own input is their
    /// press.
    pub fn person_input(
        &mut self,
        by: &str,
        tab: Option<&str>,
        input: BrowserPersonInput,
    ) -> Result<u64, BrowserError> {
        self.guest_up()?;
        match &self.takeover {
            Takeover::Held { by: holder, .. } if holder == by => {}
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
            Takeover::Agent | Takeover::Waiting { .. } => {
                return Err(BrowserError::Input(
                    "take the browser over first".to_owned(),
                ));
            }
        }
        if let BrowserPersonInput::Navigate { url } = &input
            && !web_page(url)
        {
            return Err(BrowserError::Url(url.clone()));
        }
        self.driver.tabs(false)?;
        self.bring_up(tab)?;
        self.driver.checkpoint(StoragePhase::PreInput);
        // A destination refusal of the person's own navigation answers
        // their input, never the agent's next act (FIX 7409).
        let sent = self.driver.person_input(input);
        // What the input made the page send is matched now, sent or
        // refused (CUA E9b).
        self.recording_drain();
        self.crossed(sent)?;
        let Takeover::Held { inputs, .. } = &mut self.takeover else {
            return Err(BrowserError::GuestLost);
        };
        *inputs += 1;
        let inputs = *inputs;
        self.undelivered()?;
        Ok(inputs)
    }

    /// `by` hands the browser back, from holding it or from the agent's ask
    /// it never took: the agent's next read is a whole observation of the
    /// page the person left, and its next answer carries this record once.
    /// A span the ask opted in ends here, drafted with its reason and
    /// `postcondition` (CUA E9b): `by` gets it, and the agent's next answer
    /// the same, once.
    pub fn hand_back(
        &mut self,
        by: &str,
        postcondition: Vec<ExpectInput>,
    ) -> Result<(TakeoverRecord, Option<DemonstrationOutput>), BrowserError> {
        let returned_at_ms = now_ms();
        let mut record = match &self.takeover {
            Takeover::Held {
                by: holder,
                asked,
                taken_at_ms,
                inputs,
            } if holder == by => TakeoverRecord {
                by: by.to_owned(),
                asked: asked.clone(),
                taken_at_ms: *taken_at_ms,
                returned_at_ms,
                inputs: *inputs,
                refusal: None,
            },
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
            Takeover::Waiting { reason, .. } => TakeoverRecord {
                by: by.to_owned(),
                asked: Some(reason.clone()),
                taken_at_ms: returned_at_ms,
                returned_at_ms,
                inputs: 0,
                refusal: None,
            },
            Takeover::Agent => {
                return Err(BrowserError::Input("the agent has the browser".to_owned()));
            }
        };
        // A refusal of the person's requests still pending is theirs: the
        // record carries it, and no act of the agent's answers it (FIX 7409).
        if matches!(self.takeover, Takeover::Held { .. }) {
            record.refusal = self.custody.take();
        }
        // The person's span is drafted while what the session read of their
        // pages stands (CUA E9b).
        let demonstration =
            self.takeover_end_policy(DemonstrationStopCause::HandedBack, postcondition);
        self.takeover = Takeover::Agent;
        self.driver.forget_observations();
        // The agent reads the tab the person left in front; a front tab that
        // closed gives way here. A guest that no longer answers refuses the
        // agent's next call itself. The takeover's record covers where the
        // person left it: no tab they opened, and no move from before,
        // counts as the agent's.
        let _ = self.driver.tabs(false);
        self.driver.checkpoint(StoragePhase::HandBack);
        self.driver.know_tabs();
        self.returned = Some(record.clone());
        Ok((record, demonstration))
    }

    /// Brings `tab` to the front for the person who holds the browser; the
    /// tab already in front needs no hold.
    fn bring_up(&mut self, tab: Option<&str>) -> Result<(), BrowserError> {
        let Some(tab) = tab else {
            return Ok(());
        };
        if !matches!(self.takeover, Takeover::Held { .. }) {
            let front = self.driver.tabs(false)?.into_iter().find(|t| t.front);
            if front.is_some_and(|front| front.tab == tab) {
                return Ok(());
            }
            return Err(BrowserError::Input(
                "take the browser over to bring another tab to the front".to_owned(),
            ));
        }
        // The person's acts are matched while their tab is in front (CUA
        // E9b).
        self.recording_drain();
        self.driver.bring_to_front(tab)
    }

    /// The takeover that ended since the agent's last answer, once.
    pub fn take_returned(&mut self) -> Option<TakeoverRecord> {
        self.returned.take()
    }

    /// The agent's move to another tab since its last answer, once: a tab
    /// its act opened came to the front, or the tab it drove closed. The
    /// host's door names it on that answer as `switched`.
    pub fn take_switched(&mut self) -> Option<TabSwitch> {
        self.driver.take_switched()
    }

    /// Ends a takeover still asked or held as the browser goes away, with
    /// what it held so far; `None` while the agent has the browser. A
    /// person's span ends first, drafted with what it kept (CUA E9b).
    pub fn abandon_takeover(&mut self) -> Option<AbandonedTakeover> {
        self.takeover_abandoned();
        match std::mem::replace(&mut self.takeover, Takeover::Agent) {
            Takeover::Agent => None,
            state => Some(AbandonedTakeover {
                state,
                ended_at_ms: now_ms(),
            }),
        }
    }

    /// An agent verb's first check: the agent has the browser. While it
    /// waits on its ask or a person holds it, the verb refuses.
    pub(super) fn agent_has(&self) -> Result<(), BrowserError> {
        match self.takeover {
            Takeover::Agent => Ok(()),
            Takeover::Waiting { .. } => Err(BrowserError::BrowserTakenOver("asked".to_owned())),
            Takeover::Held { .. } => Err(BrowserError::BrowserTakenOver("held".to_owned())),
        }
    }

    /// The guest still answers; a demonstration recording ends with the
    /// cause of one that does not, with what it kept.
    pub(super) fn guest_up(&mut self) -> Result<(), BrowserError> {
        if self.guest.abandoned() {
            self.recording_close(DemonstrationStopCause::Abandoned);
            return Err(BrowserError::Abandoned);
        }
        if self.guest.is_running() {
            Ok(())
        } else {
            self.recording_close(DemonstrationStopCause::GuestLost);
            Err(BrowserError::GuestLost)
        }
    }

    /// An agent verb's entry: the agent has the browser and the guest runs.
    /// Its verbs follow the tabs first: a tab opened since its last call
    /// (a popup a script opened late) comes to the front, and a front tab
    /// that closed gives way to its opener. A look at the tabs that fails
    /// leaves the front where it was, for the verb's own answer; a tab a
    /// Lightpanda guest cannot follow is the verb's refusal.
    pub(super) fn live(&mut self) -> Result<&mut CdpDriver, BrowserError> {
        self.stop_pending = None;
        self.agent_has()?;
        self.guest_up()?;
        if let (_, Some(refused)) = self.driver.follow_or_refusal() {
            return Err(refused);
        }
        self.recording_drain();
        Ok(&mut self.driver)
    }

    /// Pages a batch's last observation, as an answer pages it, and its
    /// failed step's, with a cursor of its own (FIX 8044).
    pub(super) fn page_batch(&mut self, batch: &mut BatchOutput) {
        if let Some(observation) = batch.observation.take() {
            let page = self.driver.paged(observation);
            batch.observation = Some(page.observation);
            batch.next = page.next;
        }
        if let Some(failed) = batch.failed_receipt.as_mut()
            && let Some(observation) = failed.observation.take()
        {
            let page = self.driver.paged(observation);
            failed.observation = Some(page.observation);
            failed.next = page.next;
        }
    }

    /// The press an effect of `class` on `row` runs under, the grants read
    /// again where the host reads them live (FIX 4613); a batch press it
    /// takes is paid on the session (FIX 4615).
    pub(super) fn press_for(&mut self, class: &str, row: &Row) -> Result<PressMode, BrowserError> {
        let pressed = press_for(self.press_policy(), class, row);
        match pressed {
            Ok(PressMode::PerBatch) => self.press_paid(class),
            // A refused press ends a draft as the press would (CUA E7).
            Err(_) => self.press_refused = Some(class.to_owned()),
            Ok(_) => {}
        }
        pressed
    }

    /// Types `input`, its receipt naming where the text came from
    /// (`provenance`, CUA E6): a `type` names `supplied`, a Fill its own.
    pub(super) fn type_as(
        &mut self,
        input: TypeInput,
        mut provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let entry = entry(input.text.as_deref(), input.secret.as_deref())?;
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        let base = Base::of(input.base);
        // The operand as typed, a secret's taken into custody (CUA E7).
        let operand = self.operand(&target.row, entry, source.origin.as_deref());
        let locator = target.row.locator.clone();
        let action = typed_action(locator, operand, input.clear, provenance.fill.take());
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        self.typed = Some(provenance);
        let effect = Effect {
            verb: "type",
            target: Some(&target.row),
            class: None,
            press: PressMode::None,
            started,
        };
        let typed = self.driver.type_target(&target, entry, input.clear, &base);
        let mut observation = self.sent(&effect, typed)?;
        self.receipt(&effect, &mut observation);
        self.undelivered()?;
        Ok(observation)
    }

    /// Stamps `observation` with the receipt of `effect`, which made it.
    /// The receipt's screenshot is best-effort: an effect that already
    /// happened is receipted even when its evidence could not be captured.
    pub(super) fn receipt(&mut self, effect: &Effect<'_>, observation: &mut Observation) {
        let left = Left {
            url: observation.url.clone(),
            title: observation.title.clone(),
            rebound: observation.rebound.clone(),
            fact: observation.fact.clone(),
            unread: None,
        };
        observation.receipt = Some(self.land(effect, left));
    }

    /// An effect verb's driver answer (FIX 8010): an input the driver sent
    /// stands even when settling or reading the page after it failed. Its
    /// receipt lands then, before the failure answers, naming the page as
    /// it reads now (else where the act began) and the failure's code; the
    /// input is never sent again. A failure before the send lands none.
    pub(super) fn sent(
        &mut self,
        effect: &Effect<'_>,
        answer: Result<Observation, BrowserError>,
    ) -> Result<Observation, BrowserError> {
        let sent = self.driver.take_sent();
        let error = match self.crossed(answer) {
            Ok(observation) => return Ok(observation),
            Err(error) => error,
        };
        if sent {
            let began = self
                .acted
                .as_ref()
                .and_then(|acted| acted.source.shown.clone());
            let shown = self.driver.page_shown().ok().map(|(_, shown)| shown);
            let (url, title) = shown.or(began).unwrap_or_default();
            let left = Left {
                url,
                title,
                rebound: None,
                fact: None,
                unread: Some(error.code().to_owned()),
            };
            self.unread = Some(self.land(effect, left));
        } else {
            self.acted = None;
            self.typed = None;
        }
        Err(error)
    }

    /// Lands `effect`'s receipt, as the page it `left` names, in the
    /// session's history and the host's evidence.
    fn land(&mut self, effect: &Effect<'_>, left: Left) -> EffectReceipt {
        self.receipt_seq += 1;
        // What the verb kept for a replay, and where it began (CUA E7).
        let (action, source) = self
            .acted
            .take()
            .map_or((None, None), |acted| (acted.action, Some(acted.source)));
        let (source_url, source_origin, source_title, tab) =
            source.map_or((None, None, None, None), |source| {
                let title = source.shown.map(|(_, title)| title);
                (source.url, source.origin, title, Some(source.tab))
            });
        // Never compared: each receipt's screenshot is a capture of its own.
        let (screenshot, capture_id) = self
            .driver
            .screenshot(ScreenshotInput {
                trigger: ScreenshotTrigger::EffectReceipt,
                since_capture: None,
            })
            .ok()
            .map(|shot| (shot.image, shot.capture_id))
            .unzip();
        let target = effect.target;
        let mut receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: effect.verb.to_owned(),
            url: left.url,
            title: left.title,
            target: target.map(|row| row.target.clone()),
            target_name: target.map(|row| row.name.clone()),
            target_locator: target.map(|row| row.locator.clone()),
            rebound: left.rebound,
            effect_class: effect.class.map(str::to_owned),
            press: effect.press.as_str().to_owned(),
            screenshot,
            capture_id,
            screenshot_evidence: None,
            engine: Some(self.driver.engine()),
            fact: left.fact,
            engine_switch: None,
            text_source: None,
            text_ref: None,
            action,
            source_url,
            source_origin,
            source_title,
            tab,
            result_tab: Some(self.driver.front_target().to_owned()),
            result_unread: left.unread,
            // Stamped before the host keeps the screenshot.
            duration_ms: elapsed_ms(effect.started),
        };
        // A type's text provenance, before the host keeps the receipt.
        if let Some(typed) = self.typed.take() {
            typed.stamp(&mut receipt);
        }
        // The pixels are kept before the receipt is stored, while the
        // session still holds them.
        if let Some(mut sink) = self.receipt_sink.take() {
            if let Some(png) = receipt
                .screenshot
                .as_deref()
                .and_then(|image| self.image(image))
            {
                receipt.screenshot_evidence = Some(sink.keep(&receipt, png));
            }
            self.receipt_sink = Some(sink);
        }
        self.keep(receipt.clone());
        self.landed();
        receipt
    }
}
