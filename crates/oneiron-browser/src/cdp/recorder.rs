//! The road a demonstration's page events take to the host (CUA E9): the
//! recorder's own binding, never the storage read's, in its own isolated
//! world, on each page and frame session the recording listens on.
//!
//! The reader only checks and queues: it checks the binding's exact name
//! and the session's owner, parses the event, and has the one classifier
//! check a text it carries again (FIX 8028) before it is queued: a value
//! the classifier calls secret is dropped there, never kept or hashed. It
//! never calls the browser, which would wait for a reply only the reader
//! itself routes. The driver drains the queue at each verb's edge and at
//! the stop.

use super::Pipe;
use crate::BrowserError;
use crate::SecretKind;
use crate::secret_fields::{FieldFacts, SECRET_MARK, classify};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Instant;

/// The isolated world the recorder's listeners run in.
pub(crate) const REC_WORLD: &str = "oneironRecorder";

/// What every recording's binding name starts with; a recording's own
/// token follows, so an old recording's listeners never reach a new one.
pub(crate) const REC_BINDING: &str = "oneironRec";

/// A throwaway world the stop disarms each live document's listeners from.
const REC_STOP_WORLD: &str = "oneironRecorderStop";

/// A recording's capture while it runs.
pub(crate) struct Live {
    /// The binding its listeners call, and the DOM event that disarms them.
    pub(crate) binding: String,
    pub(crate) disarm: String,
    /// The script every new document of a session it listens on runs.
    pub(crate) preload: String,
    /// Each session it listens on, by its session id.
    pub(crate) sessions: HashMap<String, Owner>,
    /// What the pages sent, in order, not yet drained.
    pub(crate) queue: Vec<Cue>,
}

/// A session the recorder listens on: the target it is, the tab (page
/// target) it belongs to, and its new-document script's identifier.
#[derive(Clone)]
pub(crate) struct Owner {
    pub(crate) target: String,
    pub(crate) tab: String,
    pub(crate) script: Option<String>,
}

/// One event a page's recorder sent. No `Debug`: a value it carries is
/// never logged.
#[derive(Deserialize)]
pub(crate) struct Cue {
    /// `doc`, `click`, `edit`, `commit`, `select`, `key`, `submit`, `drag`,
    /// `file`; the host adds `lost` and `uncovered`.
    pub(crate) k: String,
    /// The sending document's URL, and whether it is its tab's top one.
    #[serde(default)]
    pub(crate) u: String,
    #[serde(default)]
    pub(crate) top: bool,
    /// The sending document's own token, new with each document.
    #[serde(default)]
    pub(crate) doc: String,
    /// The field an edit or commit names, within its document.
    #[serde(default)]
    pub(crate) t: Option<String>,
    #[serde(default)]
    pub(crate) d: Option<Descriptor>,
    /// An edit's whole text after it, or the kind of secret withheld.
    #[serde(default)]
    pub(crate) v: Option<String>,
    #[serde(default)]
    pub(crate) s: Option<SecretKind>,
    /// A select's chosen option, by its label.
    #[serde(default)]
    pub(crate) o: Option<String>,
    #[serde(default)]
    pub(crate) key: Option<KeyCue>,
    /// The tab it came from, set by the host.
    #[serde(skip)]
    pub(crate) tab: String,
}

/// What the page showed of an act's target before the act: its role and
/// accessible name as the page computes them, its input type and
/// autocomplete tokens, its description, and its place among the targets of
/// its document with the same role and name (`[at, of]`).
#[derive(Deserialize)]
pub(crate) struct Descriptor {
    #[serde(default)]
    pub(crate) r: String,
    #[serde(default)]
    pub(crate) n: String,
    #[serde(default)]
    pub(crate) ty: Option<String>,
    #[serde(default)]
    pub(crate) ac: Option<String>,
    #[serde(default)]
    pub(crate) ds: String,
    #[serde(default)]
    pub(crate) i: Option<(usize, usize)>,
}

/// A key going down, as the page saw it.
#[derive(Deserialize)]
pub(crate) struct KeyCue {
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) mods: String,
    #[serde(default)]
    pub(crate) editable: bool,
    #[serde(default)]
    pub(crate) select: bool,
    #[serde(default)]
    pub(crate) activates: bool,
    #[serde(default)]
    pub(crate) form: bool,
}

impl Cue {
    /// A marker the host itself queues.
    pub(crate) fn marker(k: &str, tab: &str, u: &str) -> Self {
        Self {
            k: k.to_owned(),
            u: u.to_owned(),
            top: false,
            doc: String::new(),
            t: None,
            d: None,
            v: None,
            s: None,
            o: None,
            key: None,
            tab: tab.to_owned(),
        }
    }

    /// The host's own check (FIX 8028): an edit's text the one classifier
    /// calls a secret by its field or by its value is dropped and only its
    /// kind kept; a name or description that is a secret by its value
    /// reads as `[secret]`; a select's option that is one is dropped.
    fn scrub(&mut self) {
        if let Some(d) = self.d.as_mut() {
            for text in [&mut d.n, &mut d.ds] {
                if value_secret(text).is_some() {
                    SECRET_MARK.clone_into(text);
                }
            }
        }
        if self.o.as_deref().and_then(value_secret).is_some() {
            self.o = None;
            self.s = Some(SecretKind::Card);
        }
        let Some(value) = self.v.as_deref() else {
            return;
        };
        let kind = match self.d.as_ref() {
            Some(d) => classify(&FieldFacts {
                role: &d.r,
                protected: false,
                input_type: d.ty.as_deref(),
                autocomplete: d.ac.as_deref(),
                label: &d.n,
                description: &d.ds,
                value,
            }),
            None => value_secret(value),
        };
        if let Some(kind) = kind {
            self.v = None;
            self.s = Some(kind);
        }
    }
}

/// The kind of secret `text` is by its value alone.
fn value_secret(text: &str) -> Option<SecretKind> {
    classify(&FieldFacts {
        role: "",
        protected: false,
        input_type: None,
        autocomplete: None,
        label: "",
        description: "",
        value: text,
    })
}

/// A target the browser just attached, as its attach event names it: its
/// id and type, and the session it was attached under.
pub(crate) struct Attached {
    target: String,
    kind: String,
    url: String,
    parent: Option<String>,
}

impl Attached {
    pub(crate) fn of(event: &Value) -> Self {
        let info = |name: &str| {
            event
                .pointer(&format!("/params/targetInfo/{name}"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        Self {
            target: info("targetId"),
            kind: info("type"),
            url: info("url"),
            parent: event["sessionId"].as_str().map(str::to_owned),
        }
    }
}

impl Pipe {
    /// Queues one event a recording's page sent; anything else passes.
    /// Called on the reader: it parses, checks and queues only.
    pub(super) fn note_recording(&self, event: &Value) {
        if event["method"].as_str() != Some("Runtime.bindingCalled") {
            return;
        }
        let Some(name) = event.pointer("/params/name").and_then(Value::as_str) else {
            return;
        };
        if !name.starts_with(REC_BINDING) {
            return;
        }
        let Some(session) = event["sessionId"].as_str() else {
            return;
        };
        let payload = event.pointer("/params/payload").and_then(Value::as_str);
        let parsed = payload.and_then(|payload| serde_json::from_str::<Cue>(payload).ok());
        let Ok(mut live) = self.recorder.lock() else {
            return;
        };
        let Some(live) = live.as_mut().filter(|live| live.binding == name) else {
            return;
        };
        let Some(owner) = live.sessions.get(session) else {
            return;
        };
        let mut cue = parsed.unwrap_or_else(|| Cue::marker("lost", &owner.tab, ""));
        owner.tab.clone_into(&mut cue.tab);
        cue.scrub();
        live.queue.push(cue);
    }

    /// Whether a recording runs.
    pub(crate) fn recording(&self) -> bool {
        matches!(self.recorder.lock().as_deref(), Ok(Some(_)))
    }

    /// Starts a recording's capture: its events queue from now on.
    pub(crate) fn recording_on(&self, live: Live) {
        if let Ok(mut held) = self.recorder.lock() {
            *held = Some(live);
        }
    }

    /// Ends the capture: no event queues after, and the sessions it
    /// listened on and the events not yet drained are the caller's.
    pub(crate) fn recording_off(&self) -> Option<Live> {
        self.recorder.lock().ok()?.take()
    }

    /// The events queued since the last drain, in order.
    pub(crate) fn recording_take(&self) -> Vec<Cue> {
        let Ok(mut held) = self.recorder.lock() else {
            return Vec::new();
        };
        held.as_mut()
            .map_or_else(Vec::new, |live| std::mem::take(&mut live.queue))
    }

    /// The running recording's binding, disarm event and script, when one
    /// runs and `target` is not yet listened on.
    fn recording_needs(&self, target: &str) -> Option<(String, String)> {
        let held = self.recorder.lock().ok()?;
        let live = held.as_ref()?;
        let listened = live.sessions.values().any(|owner| owner.target == target);
        (!listened).then(|| (live.binding.clone(), live.preload.clone()))
    }

    /// Registers `session` as listened on, or queues the coverage it lost.
    fn recording_owned(&self, session: &str, owner: Result<Owner, (String, String)>) {
        let Ok(mut held) = self.recorder.lock() else {
            return;
        };
        let Some(live) = held.as_mut() else {
            return;
        };
        match owner {
            Ok(owner) => {
                live.sessions.insert(session.to_owned(), owner);
            }
            Err((tab, target)) => live.queue.push(Cue::marker("uncovered", &tab, &target)),
        }
    }

    /// The tab a session the recording listens on belongs to.
    fn recording_tab(&self, session: &str) -> Option<String> {
        let held = self.recorder.lock().ok()?;
        Some(held.as_ref()?.sessions.get(session)?.tab.clone())
    }

    /// Listens on `session`, tab `tab`'s page or one of its frames, for
    /// the running recording, once per target.
    pub(crate) fn record_on(&self, session: &str, target: &str, tab: &str, deadline: Instant) {
        let Some((binding, preload)) = self.recording_needs(target) else {
            return;
        };
        let owner = match install(self, session, &binding, &preload, deadline) {
            Ok(script) => Ok(Owner {
                target: target.to_owned(),
                tab: tab.to_owned(),
                script,
            }),
            Err(_) => Err((tab.to_owned(), target.to_owned())),
        };
        self.recording_owned(session, owner);
    }

    /// Listens on a page or frame the browser just attached, paused at its
    /// start, before it runs (the attach worker, off the reader). A frame
    /// whose page the recording does not listen on is named uncovered.
    pub(super) fn record_attached(&self, session: &str, attached: &Attached, deadline: Instant) {
        if !self.recording() {
            return;
        }
        match attached.kind.as_str() {
            "page" => self.record_on(session, &attached.target, &attached.target, deadline),
            "iframe" => {
                let tab = attached
                    .parent
                    .as_deref()
                    .and_then(|parent| self.recording_tab(parent));
                let lost = (String::new(), attached.url.clone());
                match tab {
                    Some(tab) => self.record_on(session, &attached.target, &tab, deadline),
                    None => self.recording_owned(session, Err(lost)),
                }
            }
            _ => {}
        }
    }
}

/// Installs a recording on `session`: its binding in the recorder's world
/// first, then the script each new document runs there, run at once in the
/// live ones; the script's identifier, for the stop to remove.
fn install(
    pipe: &Pipe,
    session: &str,
    binding: &str,
    preload: &str,
    deadline: Instant,
) -> Result<Option<String>, BrowserError> {
    pipe.call(Some(session), "Page.enable", json!({}), deadline)?;
    let named = json!({"name": binding, "executionContextName": REC_WORLD});
    pipe.call(Some(session), "Runtime.addBinding", named, deadline)?;
    let script = json!({"source": preload, "worldName": REC_WORLD, "runImmediately": true});
    let added = pipe.call(
        Some(session),
        "Page.addScriptToEvaluateOnNewDocument",
        script,
        deadline,
    )?;
    Ok(added["identifier"].as_str().map(str::to_owned))
}

/// Takes a recording off one session it listened on: each live document's
/// listeners are disarmed through a throwaway world of its frame (the
/// recorder's own world keeps no handle the host can reach), its
/// new-document script is removed, then its binding. Best effort: a session
/// already gone has nothing left to take off.
pub(crate) fn uninstall(pipe: &Pipe, session: &str, owner: &Owner, live: &Live, deadline: Instant) {
    let mut frames = Vec::new();
    if let Ok(tree) = pipe.call(Some(session), "Page.getFrameTree", json!({}), deadline) {
        frame_ids(&tree["frameTree"], &mut frames);
    }
    let disarm = format!(
        "document.dispatchEvent(new CustomEvent({}))",
        Value::from(live.disarm.as_str())
    );
    for frame in frames {
        let world = json!({"frameId": frame, "worldName": REC_STOP_WORLD});
        let Ok(made) = pipe.call(Some(session), "Page.createIsolatedWorld", world, deadline) else {
            continue;
        };
        let run = json!({"expression": disarm, "contextId": made["executionContextId"]});
        let _ = pipe.call(Some(session), "Runtime.evaluate", run, deadline);
    }
    if let Some(script) = &owner.script {
        let _ = pipe.call(
            Some(session),
            "Page.removeScriptToEvaluateOnNewDocument",
            json!({"identifier": script}),
            deadline,
        );
    }
    let _ = pipe.call(
        Some(session),
        "Runtime.removeBinding",
        json!({"name": live.binding}),
        deadline,
    );
}

/// Every frame id of a frame tree, its root first.
fn frame_ids(tree: &Value, out: &mut Vec<String>) {
    if let Some(id) = tree.pointer("/frame/id").and_then(Value::as_str) {
        out.push(id.to_owned());
    }
    for child in tree["childFrames"].as_array().into_iter().flatten() {
        frame_ids(child, out);
    }
}
