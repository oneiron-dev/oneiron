use super::*;

/// One verb's observation as its answer pages it: `act`'s observation, as
/// `driver` pages it.
pub fn paged<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    act: impl FnOnce(&mut D) -> Result<Observation, BrowserError>,
) -> Result<ObservationPage, BrowserError> {
    let observation = act(&mut *driver)?;
    Ok(driver.paged(observation))
}

/// The verbs a browser serves. The CDP driver implements it for a Chromium
/// guest, and the desktop driver for a Linux desktop guest through
/// cua-driver; each refuses the other's own verbs.
pub trait BrowserDriver: Send {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError>;
    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError>;

    /// A whole read of the page that no answer gives the caller (a routine
    /// step's look, a batch's progress read): kept apart from the
    /// observations a caller's base names, so it never ages one out (FIX
    /// 8510). A driver that keeps no such apart reads as `observe` does.
    fn observe_hidden(&mut self) -> Result<Observation, BrowserError> {
        self.observe(ObserveInput {
            full: true,
            ..ObserveInput::default()
        })
    }
    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError>;
    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError>;
    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError>;
    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError>;
    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError>;
    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError>;
    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError>;
    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError>;
    fn view(&mut self, input: ViewInput) -> Result<ImageOutput, BrowserError>;
    fn crop(&mut self, input: CropInput) -> Result<ImageOutput, BrowserError>;
    fn zoom(&mut self, input: ZoomInput) -> Result<ImageOutput, BrowserError>;
    /// The PNG bytes of a held image, while the driver holds them.
    fn image_bytes(&self, image: &str) -> Option<Vec<u8>>;

    /// What the driver knows of a live handle it minted: its locator and
    /// last scope. A driver with no live handles knows none.
    fn handle_info(&self, _handle: &str) -> Option<HandleInfo> {
        None
    }

    /// The kind of secret a run-bound handle (`scN`, or as a row shows it)
    /// holds, when a read of this session took it (FIX 8028). A driver that
    /// holds no secrets knows none.
    fn secret_kind(&self, _handle: &str) -> Option<SecretKind> {
        None
    }

    /// `observation` as its first page. A driver that pages keeps the rest
    /// for `observe_page` to read on; one that does not answers it whole.
    fn paged(&mut self, observation: Observation) -> ObservationPage {
        ObservationPage::whole(observation)
    }

    /// One page of an observation: the page as `observe` reads it, or, with
    /// `cursor`, the next page of one an earlier answer paged.
    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        if input.cursor.is_some() {
            return Err(BrowserError::Input(
                "this driver pages no observation; observe without a cursor".to_owned(),
            ));
        }
        let observation = self.observe(input)?;
        Ok(self.paged(observation))
    }

    /// The replay library's programs for a site. A driver with no library
    /// refuses the library verbs.
    fn library_find(
        &mut self,
        _input: LibraryFindInput,
    ) -> Result<LibraryFindOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Offers a solved run's program to the library: it joins only once the
    /// solved page and a no-model replay both meet its postcondition.
    fn library_propose(&mut self, _input: ProposeInput) -> Result<ProposeOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Runs a library program live; a missed postcondition goes back to the
    /// planner.
    fn library_run(&mut self, _input: LibraryRunInput) -> Result<LibraryRunOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Takes a program out of the library, for every run after.
    fn library_retire(
        &mut self,
        _input: LibraryRetireInput,
    ) -> Result<LibraryRetireOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// The programs retires took out of the library for a site.
    fn library_retired(
        &mut self,
        _input: LibraryRetiredInput,
    ) -> Result<LibraryRetiredOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Drafts a proposal from the driver's own history of effects and
    /// stops for its open page (CUA E7), with no model and no library: a
    /// driver with no such history serves none, and never answers an empty
    /// draft.
    fn library_draft(&mut self, _input: DraftInput) -> Result<DraftOutput, BrowserError> {
        Err(BrowserError::Unsupported("library_draft".to_owned()))
    }

    /// Notes in the driver's history that a step stopped (CUA E7), with the
    /// receipt of an effect it made first, so a draft never takes it for a
    /// step that worked. A driver that keeps no history notes nothing.
    fn note_stop(&mut self, _stop: StepStop) {}

    /// The receipt of the input the last effect verb sent before it failed
    /// (FIX 8010): its settle or its read after failed, and the effect
    /// stands. Taken once; a driver that receipts no such input has none.
    fn sent_receipt(&mut self) -> Option<EffectReceipt> {
        None
    }

    /// The operand the driver's newest receipt typed into `target`, a live
    /// handle or a locator, as it kept it for a replay (CUA E7; FIX 8344,
    /// 8345): a secret by its handle and kind, else its text. None where no
    /// receipt typed there, or the driver keeps no history.
    fn typed_operand(&self, _target: &str) -> Option<TypeOperand> {
        None
    }

    /// The viewport's scroll offset now, in CSS pixels, where the driver
    /// reads one (FIX 8508); none elsewhere.
    fn viewport_offset(&self) -> Option<(f64, f64)> {
        None
    }

    /// What the driver's last read of its window showed of its rows'
    /// places, as one hash, where it tells (`desktop_scroll_proof_policy`,
    /// FIX 10430): two reads that differ show rows that moved, as a scroll
    /// that moved the view does. None elsewhere, which proves no move.
    fn view_fingerprint(&self) -> Option<[u8; 32]> {
        None
    }

    /// Withdraws the newest no-progress stop the driver's history noted
    /// (FIX 8507): the run's final checks met after all. A driver that
    /// keeps no history withdraws nothing.
    fn withdraw_no_progress(&mut self) {}

    /// Starts recording a demonstration of the attached browser (CUA E9a):
    /// only a browser session on a Chromium guest records one; any other
    /// driver records none, and never answers an empty recording.
    fn demonstration_start(
        &mut self,
        _input: DemonstrationStartInput,
    ) -> Result<DemonstrationStarted, BrowserError> {
        Err(BrowserError::Unsupported("demonstration.start".to_owned()))
    }

    /// Stops a demonstration, or takes one that ended, with its steps,
    /// gaps and draft, once (CUA E9a).
    fn demonstration_stop(
        &mut self,
        _input: DemonstrationStopInput,
    ) -> Result<DemonstrationOutput, BrowserError> {
        Err(BrowserError::Unsupported("demonstration.stop".to_owned()))
    }

    /// A desktop key press.
    fn press_key(&mut self, _input: KeyInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("key".to_owned()))
    }

    /// A desktop key combination.
    fn hotkey(&mut self, _input: HotkeyInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("hotkey".to_owned()))
    }

    /// A desktop scroll.
    fn scroll(&mut self, _input: ScrollInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("scroll".to_owned()))
    }

    /// The desktop's windows.
    fn windows(&mut self, _input: WindowsInput) -> Result<WindowsOutput, BrowserError> {
        Err(BrowserError::Unsupported("windows".to_owned()))
    }

    /// Moves a desktop session onto another window.
    fn window(&mut self, _input: WindowInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("window".to_owned()))
    }

    /// Asks a person to take a desktop or browser session over.
    fn handover(&mut self, _input: HandoverInput) -> Result<HandoverOutput, BrowserError> {
        Err(BrowserError::Unsupported("handover".to_owned()))
    }

    /// Moves a run's browser to another engine, its page carried (FIX
    /// 6680). Only a session its host can start guests for serves it.
    fn switch_engine(
        &mut self,
        _input: SwitchEngineInput,
    ) -> Result<SwitchEngineOutput, BrowserError> {
        Err(BrowserError::Unsupported("switch_engine".to_owned()))
    }

    /// Types a Fill step's resolved text as `type_text` types text, its
    /// receipt naming where the text came from (`provenance`, CUA E6). A
    /// driver whose receipts are stamped before they are kept overrides it;
    /// this one stamps the answer's.
    fn fill_text(
        &mut self,
        input: TypeInput,
        provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        let mut observation = self.type_text(input)?;
        if let Some(receipt) = &mut observation.receipt {
            provenance.stamp(receipt);
        }
        Ok(observation)
    }

    /// Runs one batched program for a subgoal; a routine step has no
    /// decider here, so it goes up, and a Fill has no writer.
    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        self.batch_with(input, &mut NoDecider, &NoWriter)
    }

    /// Runs one batched program for a subgoal, step by step through this
    /// driver's own verbs, so a host wrapper's door still gates each effect,
    /// and its routine steps through `decider` under the subgoal's one clock,
    /// a Fill's generation through `writer`. The batch stops at the first
    /// refused, timed-out, unmet or sent-up step, never for its count: it
    /// holds one or more steps. It goes up too once [`NO_PROGRESS_STEPS`]
    /// steps in a row acted and left the page as it was (CUA E3): after the
    /// last of them ran, never before. A Fill whose template or options do
    /// not hold stops it before any step runs (CUA E6).
    fn batch_with(
        &mut self,
        input: BatchInput,
        decider: &mut dyn RoutineDecider,
        writer: &dyn FieldWriter,
    ) -> Result<BatchOutput, BrowserError> {
        let started = std::time::Instant::now();
        if input.steps.is_empty() {
            return Err(BrowserError::Input(
                "a batch holds one or more steps".to_owned(),
            ));
        }
        let base = input.base;
        let mut output = BatchOutput {
            status: SubgoalStatus::Done,
            completed: 0,
            failed_step: None,
            error: None,
            stop_cause: None,
            failed_receipt: None,
            elapsed_ms: 0,
            observation: None,
            receipts: Vec::new(),
            decisions: Vec::new(),
            until_ms: input.until_ms,
            next: None,
            rebindings: Vec::new(),
        };
        // Every Fill's template and options, checked before any step, so a
        // bad one stops the batch at no decision's or model's cost (CUA E6
        // `fill_precheck`, CALLS row).
        let unfit = input
            .steps
            .iter()
            .enumerate()
            .find_map(|(index, step)| match step {
                BatchStep::Fill { field, .. } => field.prepare().err().map(|stop| (index, stop)),
                _ => None,
            });
        if let Some((index, stop)) = unfit {
            stop::noted(self, input.steps[index].name(), &stop);
            return Ok(stop::stopped(self, output, index, stop, base, started));
        }
        let mut routine = Routine {
            decider,
            until_ms: input.until_ms,
            no_model: input.no_model,
            misses: 0,
            decisions: Vec::new(),
            base: base.clone(),
            rebindings: Vec::new(),
        };
        // Starts with the batch: a run of unchanged steps is the batch's own.
        let mut monitor = Progress::new();
        for (index, step) in input.steps.into_iter().enumerate() {
            let counts = step.counts_for_progress();
            let name = step.name();
            // The caller's clock is the batch's one clock (FIX 8043): past
            // its `until_ms`, the batch hands up before the step.
            if let Some(stop) = stop::clock_out(routine.until_ms) {
                stop::noted(self, name, &stop);
                return Ok(stop::stopped(self, output, index, stop, base, started));
            }
            monitor.before(self, counts);
            // The targets this step matched by their locators.
            let mut rebindings = Vec::new();
            let outcome: Result<Option<Observation>, Stop> = match step {
                BatchStep::Open { url } => self
                    .open(OpenInput { url })
                    .map(Some)
                    .map_err(Stop::opening),
                BatchStep::Click { target } => self
                    .click(ClickInput {
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Type {
                    target,
                    text,
                    secret,
                    clear,
                } => self
                    .type_text(TypeInput {
                        target,
                        text,
                        secret,
                        clear,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Select { target, option } => self
                    .select(SelectInput {
                        target,
                        option,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::WaitFor {
                    targets,
                    role,
                    name,
                    timeout_ms,
                } => self
                    .wait_for(WaitForInput {
                        targets,
                        role,
                        name,
                        timeout_ms,
                        cursor: None,
                    })
                    .map_err(Stop::from)
                    .and_then(|mut waited| {
                        rebindings.append(&mut waited.rebindings);
                        if waited.timed_out {
                            let scope = ClockScope::Wait;
                            let error = BrowserError::Timeout("a batch wait_for step".to_owned());
                            Err(Stop::new(BatchStopCause::Clock { scope }, error))
                        } else {
                            Ok(None)
                        }
                    }),
                BatchStep::Expect {
                    target,
                    role,
                    name,
                    value,
                    secret,
                    absent,
                } => {
                    let check = ExpectInput {
                        target,
                        role,
                        name,
                        value,
                        secret,
                        absent,
                    };
                    self.expect(check.clone())
                        .map_err(Stop::from)
                        .and_then(|expected| {
                            rebindings.extend(expected.rebindings.iter().cloned());
                            Stop::checked(check, expected).map(|()| None)
                        })
                }
                BatchStep::Screenshot { trigger } => self
                    .screenshot(ScreenshotInput {
                        trigger,
                        since_capture: None,
                    })
                    .map(|_| None)
                    .map_err(Stop::from),
                BatchStep::Key {
                    key,
                    modifiers,
                    target,
                } => self
                    .press_key(KeyInput {
                        key,
                        modifiers,
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Hotkey { keys } => self
                    .hotkey(HotkeyInput {
                        keys,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Scroll {
                    direction,
                    amount,
                    target,
                } => self
                    .scroll(ScrollInput {
                        direction,
                        amount,
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Decide(step) => routine.step(self, step).map(Some),
                BatchStep::Fill { target, field } => {
                    field::fill(self, &mut routine, writer, target, field).map(Some)
                }
            };
            output.decisions.append(&mut routine.decisions);
            output.until_ms = routine.until_ms;
            rebindings.append(&mut routine.rebindings);
            if let Ok(Some(observation)) = &outcome {
                rebindings.extend(observation.rebound.clone());
            }
            output
                .rebindings
                .extend(rebindings.into_iter().map(|rebound| StepRebound {
                    step: index,
                    rebound,
                }));
            match outcome {
                Ok(observation) => {
                    output.completed += 1;
                    // The step's effect is kept; the page read after it,
                    // its own whole answer where it is one (FIX 8509), may
                    // show it the last of a run that changed nothing.
                    let unchanged = monitor.after(self, counts, observation.as_ref());
                    let mut acted = None;
                    if let Some(observation) = observation {
                        if let Some(receipt) = &observation.receipt {
                            acted = Some(receipt.seq);
                            output.receipts.push(receipt.clone());
                        }
                        output.observation = Some(observation);
                    }
                    if let Some(page) = unchanged {
                        self.note_stop(progress::no_progress(name, acted));
                        return Ok(progress::handed_up(output, index, page, started));
                    }
                }
                Err(mut stop) => {
                    // An input the step sent stands with its receipt (FIX
                    // 8010), as a Fill's does.
                    if stop.receipt.is_none() {
                        stop.receipt = self.sent_receipt();
                    }
                    stop::noted(self, name, &stop);
                    return Ok(stop::stopped(self, output, index, stop, base, started));
                }
            }
        }
        output.elapsed_ms = elapsed_ms(started);
        Ok(output)
    }
}
