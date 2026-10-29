//! A code-mode run's browser and desktop guests: started, driven and planned for one run.
//! `RunGuests` (its `admits` and `call`) and `start_run_guest` are its call surface.
//! The code_mode_verbs root defines `RunGuests`, `RunBrowser` and `RunDesktop`.

use super::*;
use oneiron_browser::PressGrants;

/// Starts one run's guest from a pinned image through the engine's tier
/// selector, behind the run's egress proxy, on `command`, and receipts its
/// manifest. The proxy takes `fixture` through its checked builder.
pub(super) fn start_run_guest(
    vault: &Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    runtime: &Path,
    image: &str,
    limits: GuestLimits,
    fixture: RunGuestFixture<'_>,
    command: &[std::ffi::OsString],
) -> Result<(SessionTransport, Arc<dyn EgressRelay>), GuestStartFailure> {
    use oneiron::code_sandbox::{SandboxGuestTier, microvm::select_backend_for_session};
    use oneiron_container::{GuestSeccomp, GuestSpec, ImageRef};
    use oneiron_vault_contract::BrowserUnavailableReason as Phase;
    let unavailable = |phase, e: String| GuestStartFailure {
        phase,
        error: BrowserError::Unavailable(e),
    };
    let backend =
        select_backend_for_session(SandboxGuestTier::Untrusted, runtime.to_path_buf(), image)
            .map_err(|e| unavailable(Phase::SandboxUnavailable, e.to_string()))?;
    let spec = GuestSpec {
        image: ImageRef::pinned(image)
            .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?,
        user: (10001, 10001),
        limits,
        seccomp: GuestSeccomp::EngineFence,
        read_only_mounts: fixture
            .directory
            .iter()
            .map(|p| ((*p).clone(), PathBuf::from("/srv/fixture")))
            .collect(),
    };
    let relay: Arc<dyn EgressRelay> = Arc::new(
        oneiron::code_sandbox::egress::OpenEgressProxy::new(
            Arc::clone(vault),
            run_id,
            oneiron::code_sandbox::egress::EgressConfig::from_env()
                .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?,
        )
        .with_fixture(fixture.directory.cloned())
        .with_fixture_forward(fixture.forward)
        .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?,
    );
    let transport = backend
        .start_session(&spec, command, Arc::clone(&relay))
        .map_err(|e| unavailable(Phase::GuestStartFailed, e.to_string()))?;
    vault
        .append_sandbox_manifest_receipt(run_id, &transport.manifest)
        .map_err(|e| unavailable(Phase::SessionReceiptFailed, e.to_string()))?;
    Ok((transport, relay))
}

/// One verb call on a run's guest session: an abandoned sandbox lands its
/// receipt and refuses, and an answer carries the session's manifest.
pub(super) fn drive_run_guest<S: RunGuestSession>(
    vault: &oneiron::Vault,
    run_id: oneiron::EntityId,
    driver: &mut S,
    verb: AgentVerb,
    input: Value,
) -> Result<Value, BrowserError> {
    let result = oneiron::task_verb::sdk::invoke_browser(driver, verb.as_str(), input);
    if driver.abandoned() {
        vault
            .append_sandbox_abandon_receipt(run_id, driver.manifest())
            .map_err(|e| BrowserError::Unavailable(e.to_string()))?;
        // A demonstration's stop gives what it kept of the abandoned
        // browser without acting on it (CUA E9a).
        let kept = matches!(verb, AgentVerb::SelfBrowserDemonstrationStop) && result.is_ok();
        if !kept {
            return Err(BrowserError::Abandoned);
        }
    }
    let mut output = result?;
    if let Some(output) = output.as_object_mut() {
        output.insert(
            "session_manifest".into(),
            serde_json::to_value(driver.manifest())
                .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
        );
    }
    Ok(output)
}

/// The press policy the vault's standing action grants set for one run's
/// browser: a grant naming a browser effect class covers it (no press),
/// and a budgeted grant covers that many sends as one reviewed batch.
/// No grant leaves the floor: a press per send.
pub(super) fn browser_send_policy(server: &SyncServer) -> SendPolicy {
    grants_policy(&server.vault)
}

/// The press policy `vault`'s standing action grants set now, as
/// [`browser_send_policy`] reads it; the floor where they cannot be read.
fn grants_policy(vault: &oneiron::Vault) -> SendPolicy {
    let mut policy = SendPolicy::default();
    let Ok(grants) = vault.active_standing_consent_grants() else {
        return policy;
    };
    for grant in &grants {
        let StandingConsentGrant::Action(_) = grant else {
            continue;
        };
        let bound = grant.bound();
        let BoundClass::Action(class) = bound.class() else {
            continue;
        };
        let class = class.as_str();
        if !EFFECT_CLASSES.contains(&class) || SendPolicy::person_only(class) {
            continue;
        }
        let budget = match bound.envelope() {
            BoundEnvelope::Action(envelope) => envelope.budget(),
            BoundEnvelope::Disclosure(_) => None,
        };
        match budget {
            Some(count) => {
                policy.modes.insert(class.to_owned(), PressMode::PerBatch);
                policy
                    .batch
                    .insert(class.to_owned(), u32::try_from(count).unwrap_or(u32::MAX));
            }
            None => {
                policy.modes.insert(class.to_owned(), PressMode::None);
            }
        }
    }
    policy
}

/// A batch's or library run's answer with its row hooks' decisions among
/// its own (FIX 8042): a library run's `model_free` then reads them too, so
/// a hook that asked a model leaves it false.
pub(crate) fn count_hook_decisions(verb: &str, output: &mut Value, hooks: Vec<Value>) {
    if hooks.is_empty() {
        return;
    }
    // A batch with no decisions of its own answers none: the hooks' start
    // its list.
    let batch = match verb {
        "self.browser.batch" => output.as_object_mut(),
        "self.browser.library.run" => output.get_mut("batch").and_then(Value::as_object_mut),
        _ => None,
    };
    let Some(batch) = batch else {
        return;
    };
    let decisions = batch
        .entry("decisions")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(decisions) = decisions else {
        return;
    };
    decisions.extend(hooks);
    let read = oneiron_browser::model_free(decisions);
    if verb == "self.browser.library.run"
        && let Some(run) = output.as_object_mut()
    {
        let (free, unproven) = match read {
            Ok(free) => (free, None),
            Err(index) => (false, Some(index)),
        };
        run.insert("model_free".to_owned(), Value::Bool(free));
        match unproven {
            Some(index) => run.insert("model_free_unproven".to_owned(), Value::from(index)),
            None => run.remove("model_free_unproven"),
        };
    }
}

/// A receipt as the host's log shows it (FIX 9267): its act projected to
/// its verb and locator, never the literal a type typed, the option a
/// select picked, or a Fill's texts. The answer keeps the receipt whole.
fn logged_receipt(receipt: &Value) -> Value {
    let mut logged = receipt.clone();
    if let Some(action) = logged.get_mut("action").and_then(Value::as_object_mut) {
        action.retain(|key, _| matches!(key.as_str(), "action" | "locator"));
    }
    logged
}

/// The vault's grants, read again at each classified browser send (FIX
/// 4613): a grant revoked during the run covers no later send.
struct VaultPressGrants(Arc<oneiron::Vault>);

impl PressGrants for VaultPressGrants {
    fn current(&self) -> SendPolicy {
        grants_policy(&self.0)
    }
}

impl FreshGuest for RunFreshGuest {
    fn start(
        &mut self,
        engine: BrowserEngine,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<BrowserSession, BrowserError> {
        let guest = BrowserGuest {
            engine,
            ..self.guest.clone()
        };
        let mut session = browser_guest::start_run_browser(
            &self.vault,
            self.run_id,
            &guest,
            &self.handles,
            &self.readiness,
            requests,
        )?;
        let writer = ReceiptWriter::new(
            &self.decider.server,
            self.decider.asker.clone(),
            &self.decider.origin,
            self.invocation,
            self.run_id,
        );
        session.set_decider(Box::new(self.decider.clone()));
        session.set_receipt_sink(Box::new(writer));
        session.set_secret_custody(Arc::clone(&self.secrets));
        session.set_site_skill_loader(Arc::clone(&self.site_skills));
        Ok(session)
    }

    fn state_charge(&self) -> Box<dyn HandleRetention> {
        self.handles.charge()
    }

    /// A fresh guest abandoned under its replay lands its sandbox's abandon
    /// receipt, as the run's own guest's does (FIX 7879). The replay's own
    /// answer stands either way.
    fn abandoned(&mut self, manifest: &oneiron_container::SessionManifest) {
        let _ = self
            .vault
            .append_sandbox_abandon_receipt(self.run_id, manifest);
    }
}

impl RunBrowser {
    /// The browser the host gives run `run_id`, under the press policy the
    /// vault's standing grants set, when it has a `[browser]` guest.
    pub(super) fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Option<Self> {
        let mut guest = server.browser_guest()?.clone();
        guest.policy = browser_send_policy(server);
        let session = server.browser_seats.bind(run_id, &server.vault);
        Some(Self {
            guest,
            session,
            seats: Arc::clone(&server.browser_seats),
            vault: Arc::clone(&server.vault),
            run_id,
            policy_set: AtomicBool::new(false),
            handles: crate::server::HandleLine::of(server),
            readiness: server.browser_readiness().clone(),
        })
    }

    /// The run's browser planner state (CUA E5), bound beside this
    /// browser's seat, when the host's code mode routes the run's steps.
    pub(super) fn planner(&self, server: &SyncServer) -> Option<Arc<BrowserPlannerRun>> {
        let runs = server
            .code_execution_host()?
            .engine_native()?
            .provider()
            .browser_planner()?;
        Some(runs.bind(self.run_id, &self.session))
    }

    /// The fresh guest this run's proposals replay on, for one call of
    /// `decider`'s caller (`invocation`), holding the run's `secrets` and
    /// `site_skills`.
    pub(super) fn fresh_guest(
        &self,
        decider: LadderDecider,
        invocation: Option<InvocationId>,
        secrets: Arc<dyn SecretCustody>,
        site_skills: Arc<dyn SiteSkillLoader>,
    ) -> RunFreshGuest {
        RunFreshGuest {
            vault: Arc::clone(&self.vault),
            run_id: self.run_id,
            guest: self.guest.clone(),
            handles: self.handles.clone(),
            readiness: self.readiness.clone(),
            decider,
            invocation,
            secrets,
            site_skills,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one host service the call's session takes"
    )]
    pub(super) fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
        library: VaultLibrary,
        writer: ReceiptWriter,
        fresh: RunFreshGuest,
        fields: RunFieldWriter,
        capture: Option<&BrowserCapture<'_, '_>>,
    ) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            // The session keeps the starter its engine switches take. No
            // host request handler: its pages take the run's relay.
            let started = browser_guest::start_run_browser(
                &self.vault,
                self.run_id,
                &self.guest,
                &self.handles,
                &self.readiness,
                None,
            )?;
            *session = Some(started);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        if !self.policy_set.swap(true, Ordering::AcqRel) {
            driver.set_policy(self.guest.policy.clone());
        }
        // Each classified send reads the grants again (FIX 4613); the sends
        // a budget paid stay on the session every door shares (FIX 4615).
        driver.set_press_grants(Box::new(VaultPressGrants(Arc::clone(&self.vault))));
        driver.set_decider(Box::new(decider));
        // A Fill's writer (CUA E6): role-bound calls on the caller's run.
        driver.set_field_writer(Box::new(fields));
        driver.set_library(Box::new(library));
        driver.set_receipt_sink(Box::new(writer));
        // The run's secret custody, for this call's caller: the fresh guest
        // holds the same one.
        driver.set_secret_custody(Arc::clone(&fresh.secrets));
        // The run's site skills (CUA E10), the fresh guest's too.
        driver.set_site_skill_loader(Arc::clone(&fresh.site_skills));
        driver.set_fresh_guest(Box::new(fresh));
        // While a person is asked or holds the browser, the session refuses
        // the verb `browser_taken_over`; the first answer after they hand it
        // back carries the takeover's record as `takeover`. An answer after
        // the agent's verbs moved to another tab (one its act opened, or the
        // one a closed tab gave way to) names the move as `switched`. Every
        // answer names the engine that ran it (FIX 6680).
        let asked = capture.map(|capture| (capture, driver.history_mark(), input.clone()));
        let mut output = drive_run_guest(&self.vault, self.run_id, driver, verb, input)?;
        // CUA E8a: what the call solved is kept while its seat is held,
        // before the run's planner hears how it ended.
        if let Some((capture, mark, input)) = asked {
            capture.after_call(driver, verb, &input, &output, mark);
        }
        self.seats.asked(self.run_id, driver.takeover());
        if let Some(object) = output.as_object_mut() {
            object.insert("engine".into(), Value::from(driver.engine().as_str()));
            if let Some(record) = driver.take_returned() {
                object.insert(
                    "takeover".into(),
                    serde_json::to_value(record)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
            if let Some(switch) = driver.take_switched() {
                object.insert(
                    "switched".into(),
                    serde_json::to_value(switch)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
            // A demonstration that ended without its stop (a handover, an
            // engine switch, a lost guest), once (CUA E9a).
            if let Some(ended) = driver.take_demonstration() {
                object.insert(
                    "demonstration".into(),
                    serde_json::to_value(ended)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
        }
        Ok(output)
    }
}

impl RunDesktop {
    /// The desktop the host gives run `run_id`, as [`RunBrowser::new`] gives
    /// its browser, when it has a `[desktop]` guest.
    pub(super) fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Option<Self> {
        let mut guest = server.desktop_guest()?.clone();
        guest.policy = browser_send_policy(server);
        let session = server.desktop_seats.bind(run_id, &server.vault);
        Some(Self {
            guest,
            session,
            seats: Arc::clone(&server.desktop_seats),
            vault: Arc::clone(&server.vault),
            run_id,
            policy_set: AtomicBool::new(false),
        })
    }

    /// A desktop verb. While a person is asked or holds the desktop, the
    /// session refuses it `desktop_taken_over`; the first answer after they
    /// hand it back carries the takeover's record as `takeover`. An answer
    /// after the window the agent's verbs read was gone, and the session
    /// gave way to the window in front, names the move as `switched`. A
    /// handover raises the owners' inbox Ask. The secrets the desktop finds
    /// are held through `secrets`, the run's custody for this call.
    pub(super) fn call(
        &self,
        verb: AgentVerb,
        input: Value,
        decider: LadderDecider,
        writer: ReceiptWriter,
        secrets: Arc<dyn SecretCustody>,
        fields: RunFieldWriter,
    ) -> Result<Value, BrowserError> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_none() {
            // The desktop's own apps reach the network through the same
            // engine proxy, at the guest's fenced sockets.
            let (transport, _relay) = start_run_guest(
                &self.vault,
                self.run_id,
                &self.guest.runtime,
                &self.guest.image,
                self.guest.limits,
                RunGuestFixture::default(),
                &["/usr/local/bin/oneiron-desktop-guest".into()],
            )?;
            *session = Some(DesktopSession::attach(&self.guest, transport)?);
        }
        let driver = session.as_mut().ok_or(BrowserError::GuestLost)?;
        if !self.policy_set.swap(true, Ordering::AcqRel) {
            driver.set_policy(self.guest.policy.clone());
        }
        driver.set_decider(Box::new(decider));
        // A Fill's writer (FIX 8899): role-bound calls on the caller's run.
        driver.set_field_writer(Box::new(fields));
        driver.set_receipt_sink(Box::new(writer));
        driver.set_secret_custody(secrets);
        let mut output = drive_run_guest(&self.vault, self.run_id, driver, verb, input)?;
        self.seats.asked(self.run_id, driver.takeover());
        if let Some(object) = output.as_object_mut() {
            if let Some(record) = driver.take_returned() {
                object.insert(
                    "takeover".into(),
                    serde_json::to_value(record)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
            if let Some(switch) = driver.take_switched() {
                object.insert(
                    "switched".into(),
                    serde_json::to_value(switch)
                        .map_err(|e| BrowserError::Unavailable(e.to_string()))?,
                );
            }
        }
        Ok(output)
    }
}

impl RunGuests {
    /// The guests the host gives run `run_id`.
    pub(crate) fn new(server: &SyncServer, run_id: oneiron::EntityId) -> Self {
        let browser = RunBrowser::new(server, run_id);
        Self {
            planner: browser.as_ref().and_then(|guest| guest.planner(server)),
            browser,
            desktop: RunDesktop::new(server, run_id),
            refused: browser_guest::KeptRefusal::default(),
            payer: None,
            admission: None,
            admission_lease: None,
        }
    }

    /// Binds only this attached run's browser for a public host call.
    pub(crate) fn browser(server: &SyncServer, run_id: oneiron::EntityId) -> Self {
        let browser = RunBrowser::new(server, run_id);
        Self {
            planner: browser.as_ref().and_then(|guest| guest.planner(server)),
            browser,
            desktop: None,
            refused: browser_guest::KeptRefusal::default(),
            payer: None,
            admission: None,
            admission_lease: None,
        }
    }

    /// The same, billing `payer`, the attached live run's (FIX 8902), for a
    /// call whose door bound no line: its Fill writer bills that payer.
    #[must_use]
    pub(crate) fn with_payer(
        mut self,
        payer: Option<oneiron::llm::run_admission::PayerPerson>,
    ) -> Self {
        self.payer = payer;
        self
    }

    /// The words the run's newest browser call was refused with, for
    /// `browser_unsupported` alone (FIX 6887).
    pub(crate) fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.refused.words()
    }

    /// A code-mode call fires the row's hooks once around the shared guest door.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one axis of the caller's door"
    )]
    pub(crate) fn call(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        asker: VerdictAsker,
        by: oneiron::EntityId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        self.refused.keep(None);
        if let Err(refusal) = self.admits(call.verb, server) {
            return Ok(Err(refusal));
        }
        // The row's hooks' own decisions count in the run's evidence (FIX
        // 8042): they run on this thread, and are recorded, never capped.
        let (pre, mut decided) = crate::hook_verdict::collect_hook_decisions(|| {
            oneiron::task_verb::verb_hook_boundary::browser_row_pre(
                memory,
                call.verb.as_str(),
                call.input.clone(),
            )
        });
        let hooks = match pre {
            Ok(hooks) => hooks,
            Err(error) => return refused(super::mcp_facade_error(error)),
        };
        let admitted = SelfAgentVerbCall {
            verb: call.verb,
            input: hooks.args.clone(),
        };
        self.begin_press_call();
        let answer =
            match self.call_admitted(server, runtime, &admitted, origin, memory, asker, by)? {
                Ok(answer) => answer,
                Err(refused) => {
                    let refused = self.bound_refusal(call.verb, origin, memory, refused);
                    self.refused.keep(Some(&refused));
                    return Ok(Err(AgentVerbRefusal { code: refused.code }));
                }
            };
        let held = self.take_held_press();
        let (post, mut after) = crate::hook_verdict::collect_hook_decisions(|| {
            oneiron::task_verb::verb_hook_boundary::row_post(&server.vault, hooks, answer.output)
        });
        decided.append(&mut after);
        match post {
            Ok(mut output) => {
                count_hook_decisions(call.verb.as_str(), &mut output, decided);
                self.hold_stopped_batch(call.verb, origin, memory, held, &output);
                Ok(Ok(AgentVerbAnswer {
                    output,
                    rows: answer.rows,
                }))
            }
            Err(error) => refused(super::mcp_facade_error(error)),
        }
    }

    /// The facade and MCP host doors already crossed the row's hooks. They
    /// take this same guest admission and driver without firing hooks twice.
    /// A refusal carries its code, and for `browser_unsupported` the
    /// engine's words naming the verb that serves it (FIX 6862).
    #[expect(
        clippy::too_many_arguments,
        reason = "the admitted caller and run are separate axes"
    )]
    pub(crate) fn call_admitted(
        &self,
        server: &Arc<SyncServer>,
        runtime: &tokio::runtime::Handle,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        asker: VerdictAsker,
        by: oneiron::EntityId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusalWords>> {
        if let Err(refusal) = self.admits(call.verb, server) {
            return Ok(Err(browser_guest::code_words(refusal.code)));
        }
        let verb = call.verb.as_str();
        let desktop = verb.starts_with("self.desktop.");
        let run_id = if desktop {
            self.desktop.as_ref().map(|guest| guest.run_id)
        } else {
            self.browser.as_ref().map(|guest| guest.run_id)
        }
        .ok_or(oneiron::Error::InvariantViolation(
            "admitted guest has no run",
        ))?;
        let writer = ReceiptWriter::new(server, asker.clone(), origin, memory.invocation(), run_id);
        // The run's secrets, held for this call's caller on the seat it
        // calls (FIX 8028).
        let seat = if desktop {
            RunSecretSeat::Desktop
        } else {
            RunSecretSeat::Browser
        };
        let secrets: Arc<dyn SecretCustody> =
            Arc::new(RunSecretCustody::new(&server.vault, &asker, run_id, seat));
        let decider = LadderDecider {
            server: Arc::clone(server),
            asker,
            runtime: runtime.clone(),
            origin: origin.clone(),
            run_id,
        };
        let called = match (&self.desktop, &self.browser) {
            (Some(run), _) if desktop => {
                // A desktop Fill's writer, as a browser's (FIX 8899).
                let fields =
                    RunFieldWriter::new(server, runtime, &decider.asker, self.payer.clone());
                let input = call.input.clone();
                run.call(call.verb, input, decider, writer, secrets, fields)
            }
            (_, Some(run)) if !desktop => {
                // The library this call files in names the caller's solved
                // group (CUA E8a).
                let scope = memory
                    .solved_run_scope()
                    .inspect_err(|error| {
                        tracing::warn!(%error, "browser caller's solved-run scope did not encode");
                    })
                    .ok();
                let library = VaultLibrary {
                    server: Arc::clone(server),
                    by,
                    scope,
                    admission: self.admission,
                };
                // Its site skills load under the run's skill-load lease (CUA E10).
                let lease = self.admission_lease.as_ref();
                let sites = Arc::new(RunSiteSkills::new(server, run_id, lease));
                let fresh = run.fresh_guest(decider.clone(), memory.invocation(), secrets, sites);
                let fields =
                    RunFieldWriter::new(server, runtime, &decider.asker, self.payer.clone());
                let input = call.input.clone();
                let capture = BrowserCapture {
                    vault: &server.vault,
                    memory,
                    origin,
                    run_id,
                };
                // An admission job's replay is no source run (CUA E8b).
                let capture = self.admission.is_none().then_some(&capture);
                run.call(
                    call.verb, input, decider, library, writer, fresh, fields, capture,
                )
            }
            _ => Err(BrowserError::Unbound),
        };
        let output = match called {
            Ok(output) => output,
            Err(error) => return Ok(Err(browser_guest::refusal_words(&error))),
        };
        // An effect's answer carries its receipt, naming the page it acted
        // on. The log shows each receipt's act by its verb and locator only,
        // never a typed literal or a picked option (FIX 9267).
        if let Some(receipt) = output.get("receipt") {
            let receipt = logged_receipt(receipt);
            tracing::info!(verb, ?receipt, "browser effect receipt");
        }
        if let Some(receipts) = output.get("receipts").and_then(Value::as_array) {
            let receipts: Vec<Value> = receipts.iter().map(logged_receipt).collect();
            tracing::info!(verb, ?receipts, "browser batch receipts");
        }
        // CUA E5: how a batch or library run ended reaches the run's browser
        // planner here, at execution, before its answer goes back.
        if let Some(planner) = &self.planner {
            let mut library = VaultLibrary {
                server: Arc::clone(server),
                by,
                scope: None,
                admission: None,
            };
            planner.observe(call.verb, &call.input, &output, |workflow| {
                let filed = library.program(workflow).ok().flatten()?;
                Some(filed.program.subgoal)
            });
        }
        Ok(Ok(AgentVerbAnswer {
            output,
            rows: Some(Vec::new()),
        }))
    }

    pub(super) fn admits(
        &self,
        verb: AgentVerb,
        server: &SyncServer,
    ) -> Result<(), AgentVerbRefusal> {
        // The browser runs as its connector pack: no installed pack, no browser.
        if server
            .vault
            .require_builtin_channel_pack("browser")
            .is_err()
        {
            return Err(AgentVerbRefusal {
                code: "browser_pack_not_installed".to_owned(),
            });
        }
        // A desktop row drives the run's desktop; every other row its browser.
        let desktop = verb.as_str().starts_with("self.desktop.");
        // The browser guest runs only once its setup connection is checked.
        if !desktop
            && server
                .vault
                .require_pack_connection_verified("oneiron.browser", "browser-guest")
                .is_err()
        {
            return Err(AgentVerbRefusal {
                code: "browser_connection_unchecked".to_owned(),
            });
        }
        let run_id = if desktop {
            self.desktop.as_ref().map(|desktop| desktop.run_id)
        } else {
            self.browser.as_ref().map(|browser| browser.run_id)
        };
        if run_id.is_none() {
            return Err(AgentVerbRefusal {
                code: BrowserError::Unbound.code().to_owned(),
            });
        }
        Ok(())
    }

    /// The screenshot this run's browser or desktop holds under the
    /// `blake3:` ref an `ai.verdict` input names, when one holds it.
    pub(crate) fn held_image(&self, input: &Value) -> Option<HeldImage> {
        let handle = input
            .get("image")
            .and_then(Value::as_str)
            .filter(|handle| handle.starts_with(HELD_PREFIX))?;
        if let Some(browser) = self.browser.as_ref() {
            let session = browser
                .session
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(png) = session.as_ref().and_then(|s| s.image(handle)) {
                return Some(HeldImage::new(browser.run_id, handle, png.to_vec()));
            }
        }
        let desktop = self.desktop.as_ref()?;
        let session = desktop
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let png = session.as_ref()?.image(handle)?.to_vec();
        Some(HeldImage::new(desktop.run_id, handle, png))
    }

    pub(crate) fn manifests(&self) -> Vec<Value> {
        let browser = self
            .browser
            .as_ref()
            .and_then(|b| b.session.lock().ok())
            .and_then(|session| {
                session
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s.manifest()).ok())
            });
        let desktop = self
            .desktop
            .as_ref()
            .and_then(|d| d.session.lock().ok())
            .and_then(|session| {
                session
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s.manifest()).ok())
            });
        browser.into_iter().chain(desktop).collect()
    }
}
