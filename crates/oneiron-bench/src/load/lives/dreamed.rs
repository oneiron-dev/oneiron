//! The `oneiron-dreamed` arm (ASK L9-36-ONEIRON-INGEST = C): the Oneiron
//! store with its Dreamer on, every role a consolidation pass calls routed to
//! one model (`--dreamed <base-url>,<model>`), as `load dream` routes them.
//! Each life is witnessed in a sitting of its own. The bench opens the sitting
//! (`POST /v1/ai/session`), waits until the server has applied the open (a
//! TURN witnessed before that joins no sitting), witnesses the life's turns
//! (each bumps its sitting's activity) and ends the sitting, whose close
//! queues the Meso round over that life's conversations. After the last life
//! the bench waits for the round to start, then until the Dreamer stays still
//! (`load dream`'s `await_still`), and only then asks the plain arm's
//! questions, so the two arms' rows sit side by side. A sitting that does not
//! open, a hint the server refuses, a round that does not start or a Dreamer
//! not still within `--dream-max-seconds` makes the arm `not_ready` before it
//! asks: its rows would not measure a consolidated store.
//!
//! Spawned, the model key (`--model-key-file`, when given) goes to the
//! server's environment only, and the owner's stopped-vault grant routes the
//! Dreamer's purposes (`oneiron-server dreamer grant`). In-process, the bench
//! makes the same grant on the vault it rooted and starts the Dreamer in this
//! process (`AiHost::start`). That engine reads a provider key only from this
//! process's environment, which the bench never writes, so the in-process
//! Dreamer calls its model without a key: name a keyless one (a local model,
//! or a GPU host over an ssh tunnel). The in-process engine logs to no file,
//! so there the open wait reads the vault's open sessions, and the still wait
//! reads the Dreamer's status alone.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::authority::HostSlipIssuer;
use oneiron::{CallPurpose, ModelLocality};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::ModelsConfig;
use reqwest::blocking::Client;
use serde::Serialize;

use super::super::client::Agent;
use super::super::dream::cycle::{self, DreamerStatus, OPEN_WAIT, QUIET, StillWait};
use super::super::dream::server_log::{Scan, Tail};
use super::super::dream::{RUST_LOG, proof, setup};
use super::super::server::Vault;
use super::super::stats::Sample;
use super::answer::Endpoint;
use super::corpus::Life;
use super::oneiron::witness;
use super::{Mode, say};

/// The arm's name in the report.
pub(super) const NAME: &str = "oneiron-dreamed";

/// The Dreamer's purposes, as `oneiron-server dreamer grant
/// --extraction-route` routes them (`ai_host/policy.rs` `DREAMER_PURPOSES`).
const PURPOSES: [CallPurpose; 4] = [
    CallPurpose::Extraction,
    CallPurpose::Consolidation,
    CallPurpose::AutonomyForHuman,
    CallPurpose::AutonomyOwnTime,
];

/// `--dreamed`, `--dream-max-seconds` and the key file, as parsed.
pub(super) struct Planned {
    pub(super) endpoint: Endpoint,
    /// `--model-key-file`: the spawned server's model key, when given.
    pub(super) key_file: Option<PathBuf>,
    /// The longest wait for a still Dreamer after the last sitting ends.
    pub(super) max_wait: Duration,
}

/// The dreamed arm's model, checked before any store is opened.
pub(super) struct Dreaming {
    endpoint: Endpoint,
    /// The key the spawned server's provider reads; `None` in-process.
    key: Option<String>,
    reply_model: String,
    max_wait: Duration,
}

impl Planned {
    /// Reads the key and makes `load dream`'s preflight call the way the
    /// Dreamer will call the model: with the key when the server gets one.
    pub(super) fn start(self, mode: &Mode) -> Result<Dreaming, String> {
        let key = match (mode, &self.key_file) {
            (Mode::Spawned { .. }, Some(path)) => Some(setup::read_key(path)?),
            _ => None,
        };
        if matches!(mode, Mode::InProcess) {
            say("dreamed arm in-process: the Dreamer calls its model without a key");
        }
        say(&format!("dreamed preflight: {}", self.endpoint.model));
        let reply_model = setup::preflight(
            &self.endpoint.base_url,
            &self.endpoint.model,
            key.as_deref(),
        )
        .map(|answer| answer.reply_model)
        .map_err(|e| format!("--dreamed: {e}"))?;
        Ok(Dreaming {
            endpoint: self.endpoint,
            key,
            reply_model,
            max_wait: self.max_wait,
        })
    }
}

impl Dreaming {
    /// The `[models]` body the in-process Dreamer serves: keyless.
    pub(super) fn models_body(&self) -> String {
        setup::models_body(&self.endpoint.base_url, &self.endpoint.model, None, false)
    }

    /// The spawned server's Dreamer, before it starts: `[models]` written
    /// into the config `init` wrote and the owner's stopped-vault grant.
    /// Returns what the server's environment adds: its log level (the
    /// Dreamer's open lines are info) and the model key.
    pub(super) fn configure(
        &self,
        bin: &Path,
        vault: &Vault,
    ) -> Result<Vec<(String, String)>, String> {
        let keyed = self.key.is_some();
        setup::write_models(
            vault,
            &self.endpoint.base_url,
            &self.endpoint.model,
            None,
            keyed,
        )?;
        let granted = setup::grant(bin, vault, setup::route(keyed))?;
        say(&format!("dreamer grant: {granted}"));
        let mut env = vec![("RUST_LOG".to_owned(), RUST_LOG.to_owned())];
        if let Some(key) = &self.key {
            env.push((setup::MODEL_KEY_ENV.to_owned(), key.clone()));
        }
        Ok(env)
    }

    /// `--dreamed` in the report's plan.
    pub(super) fn echo(&self) -> serde_json::Value {
        serde_json::json!({
            "base_url": self.endpoint.base_url,
            "model": self.endpoint.model,
            "max_seconds": self.max_wait.as_secs(),
        })
    }
}

const fn rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}

/// In-process, what `oneiron-server dreamer grant --extraction-route
/// own_server` does on a stopped vault (`commands/dreamer.rs`), on the vault
/// the bench rooted with `issuer`: the engine's MACHINE writers (the Dreamer
/// among them) get their signers, the Dreamer its Steward grant, and the
/// Dreamer's purposes the own-server route, the extraction bound raised to
/// it. The Dreamer's weave rows ship in the seeded policy, so a fresh vault
/// needs no owner grant for them; a vault without them is refused. Then the
/// Dreamer starts on `models`, as a rooted server's start starts it.
pub(super) async fn start_in_process(
    vault: &Arc<oneiron::Vault>,
    issuer: &HostSlipIssuer,
    models: &ModelsConfig,
) -> Result<AiHost, String> {
    vault
        .provision_engine_machine_identities(issuer)
        .map_err(|e| format!("engine machine identities: {e}"))?;
    vault
        .provision_system_agent_grants()
        .map_err(|e| format!("system agent grants: {e}"))?;
    let reach = vault
        .dreamer_weave_reach()
        .map_err(|e| format!("dreamer reach: {e}"))?;
    if !reach.ready() {
        return Err(format!(
            "the vault's policy keeps the Dreamer out ({reach:?})"
        ));
    }
    let route = ModelLocality::OwnServer;
    let mut table = vault
        .purpose_default_table()
        .map_err(|e| format!("purpose defaults: {e}"))?;
    for purpose in &PURPOSES {
        if let Some(row) = table.purposes.get_mut(purpose) {
            row.locality = route;
        }
    }
    if rank(table.extraction_max_locality) < rank(route) {
        table.extraction_max_locality = route;
    }
    vault
        .set_purpose_default_table(&table)
        .map_err(|e| format!("purpose defaults: {e}"))?;
    Ok(AiHost::start(Arc::clone(vault), Some(models), true).await)
}

/// What shows a sitting open: the server log's open lines (spawned), or the
/// vault's open sessions (in-process, where the tail reads no file).
pub(super) struct Watch {
    tail: Tail,
    scan: Scan,
    vault: Option<Arc<oneiron::Vault>>,
    /// The sessions seen open so far (in-process).
    seen: BTreeSet<oneiron::EntityId>,
}

impl Watch {
    /// The spawned server's log at `path`.
    pub(super) fn log(path: PathBuf) -> Self {
        Self {
            tail: Tail::new(path),
            scan: Scan::default(),
            vault: None,
            seen: BTreeSet::new(),
        }
    }

    /// The in-process vault; its engine logs to no file.
    pub(super) fn vault(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            tail: Tail::new(PathBuf::new()),
            scan: Scan::default(),
            vault: Some(vault),
            seen: BTreeSet::new(),
        }
    }

    /// Notes what is open before an open hint; the log's open lines so far.
    fn mark(&mut self, origin: Instant) -> usize {
        self.scan.read(&mut self.tail, origin);
        if let Some(open) = self.vault.as_ref().and_then(|v| v.open_sessions().ok()) {
            self.seen.extend(open.iter().map(|session| session.session));
        }
        self.scan.opened()
    }

    /// Whether a sitting opened after `mark`, waited for up to `OPEN_WAIT`.
    fn await_open(&mut self, mark: usize, origin: Instant) -> bool {
        let started = Instant::now();
        loop {
            self.scan.read(&mut self.tail, origin);
            if self.scan.opened() > mark {
                return true;
            }
            if let Some(open) = self.vault.as_ref().and_then(|v| v.open_sessions().ok())
                && let Some(new) = open.iter().find(|s| !self.seen.contains(&s.session))
            {
                self.seen.insert(new.session);
                return true;
            }
            if started.elapsed() >= OPEN_WAIT {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// One life's sitting, opened before its first turn and ended after its last.
#[derive(Serialize)]
struct Sitting {
    life: String,
    /// From the open hint to the open seen, in ms.
    open_ms: f64,
    turns: usize,
}

/// The dreamed arm's model, as the report pins it.
#[derive(Serialize)]
struct Pinned {
    base_url: String,
    model: String,
    /// The `model` the preflight reply named.
    reply_model: String,
    /// Whether the server's provider had a key.
    keyed: bool,
}

/// What the dreamed arm did before it asked.
#[derive(Serialize)]
pub(super) struct Dream {
    model: Pinned,
    /// The Dreamer's status once it ran, before the first sitting.
    ready: DreamerStatus,
    sittings: Vec<Sitting>,
    /// The wait for a still Dreamer, after a round started.
    still: StillWait,
    claims_before: usize,
    claims_after: usize,
    /// Claims listed after the wait that were not before the first sitting.
    landed: usize,
    /// A list reached its row limit, so `landed` can miss rows.
    list_cut: bool,
    list_error: Option<String>,
}

/// The dreamed arm from its Dreamer's start to a still Dreamer.
pub(super) struct Round<'r> {
    dreaming: &'r Dreaming,
    agent: &'r Agent,
    http: &'r Client,
    base: &'r str,
    watch: Watch,
    origin: Instant,
    ready: DreamerStatus,
    listed_before: Result<(BTreeSet<String>, bool), String>,
    sittings: Vec<Sitting>,
    /// The Dreamer's status just before the last sitting's end.
    before_end: DreamerStatus,
}

impl<'r> Round<'r> {
    /// Waits until the Dreamer runs (`load dream`'s `dreamer_ready`), then
    /// lists the claims there are before the first sitting.
    pub(super) fn begin(
        dreaming: &'r Dreaming,
        agent: &'r Agent,
        http: &'r Client,
        base: &'r str,
        watch: Watch,
    ) -> Result<Self, String> {
        let ready = cycle::dreamer_ready(agent, http, base)?;
        say(&format!("dreamer {}; one sitting per life", ready.state));
        Ok(Self {
            dreaming,
            agent,
            http,
            base,
            watch,
            origin: Instant::now(),
            ready,
            listed_before: proof::listed(agent),
            sittings: Vec::new(),
            before_end: DreamerStatus::default(),
        })
    }

    /// Witnesses each life in a sitting of its own; every witness's sample.
    /// A refused hint, or an open not seen within `OPEN_WAIT`, ends the arm:
    /// that life's turns would join no sitting of their own.
    pub(super) fn witness(&mut self, lives: &[Life]) -> Result<Vec<Sample>, String> {
        let mut samples = Vec::new();
        for life in lives {
            let mark = self.watch.mark(self.origin);
            let asked = Instant::now();
            cycle::hint(self.agent, self.http, self.base, "open")
                .map_err(|error| format!("{}: the open hint failed: {error}", life.key))?;
            if !self.watch.await_open(mark, self.origin) {
                return Err(format!(
                    "{}: no sitting open seen within {} s of the open hint",
                    life.key,
                    OPEN_WAIT.as_secs()
                ));
            }
            let mut sitting = Sitting {
                life: life.key.clone(),
                open_ms: asked.elapsed().as_secs_f64() * 1000.0,
                turns: 0,
            };
            for turn in &life.turns {
                samples.push(witness(self.agent, turn));
                sitting.turns += 1;
            }
            self.before_end = cycle::status(self.agent, self.http, self.base).unwrap_or_default();
            cycle::hint(self.agent, self.http, self.base, "end")
                .map_err(|error| format!("{}: the end hint failed: {error}", life.key))?;
            self.sittings.push(sitting);
        }
        Ok(samples)
    }

    /// Whether an attempt starts (or runs) after the last sitting's end,
    /// polled for up to `OPEN_WAIT`: the close queues the round, and the
    /// Dreamer's driver takes it up off the request.
    fn await_round(&self, before: &DreamerStatus) -> bool {
        let started = Instant::now();
        while started.elapsed() < OPEN_WAIT {
            if let Ok(now) = cycle::status(self.agent, self.http, self.base)
                && (now.state == "working" || now.started > before.started)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    /// Waits for the round, then for a still Dreamer within the arm's bound,
    /// and counts the claims it landed. A round that does not start within
    /// `OPEN_WAIT`, or a Dreamer not still by the bound, ends the arm: its
    /// questions would not be asked of a consolidated store, and the
    /// Dreamer's work would run under their timings.
    pub(super) fn finish(mut self) -> Result<Dream, String> {
        if !self.await_round(&self.before_end) {
            return Err(format!(
                "no Dreamer round started within {} s of the last sitting's end",
                OPEN_WAIT.as_secs()
            ));
        }
        let deadline = Instant::now() + self.dreaming.max_wait;
        let still = cycle::await_still(
            self.agent,
            self.http,
            self.base,
            &mut self.watch.tail,
            &mut self.watch.scan,
            self.origin,
            deadline,
        );
        say(&format!(
            "dreamer still: {} after {:.1} s",
            still.reached,
            still.waited_ms / 1000.0
        ));
        if !still.reached {
            return Err(format!(
                "the Dreamer was not still for {} s within --dream-max-seconds {} (last state {})",
                QUIET.as_secs(),
                self.dreaming.max_wait.as_secs(),
                still
                    .status
                    .as_ref()
                    .map_or("unread", |status| status.state.as_str())
            ));
        }
        let (claims_before, claims_after, landed, list_cut, list_error) =
            match (&self.listed_before, &proof::listed(self.agent)) {
                (Ok((before, cut_before)), Ok((after, cut_after))) => (
                    before.len(),
                    after.len(),
                    after.difference(before).count(),
                    *cut_before || *cut_after,
                    None,
                ),
                (Err(error), _) | (_, Err(error)) => (0, 0, 0, false, Some(error.clone())),
            };
        Ok(Dream {
            model: Pinned {
                base_url: self.dreaming.endpoint.base_url.clone(),
                model: self.dreaming.endpoint.model.clone(),
                reply_model: self.dreaming.reply_model.clone(),
                keyed: self.dreaming.key.is_some(),
            },
            ready: self.ready,
            sittings: self.sittings,
            still,
            claims_before,
            claims_after,
            landed,
            list_cut,
            list_error,
        })
    }
}
