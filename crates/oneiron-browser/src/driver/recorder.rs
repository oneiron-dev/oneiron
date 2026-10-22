//! A demonstration's capture on a Chromium guest (CUA E9): the listeners a
//! recording puts in each page and frame of the run, and what the host
//! makes of the events they send.
//!
//! The listeners run in the recorder's own isolated world and send through
//! its own binding (`cdp::recorder`). They see clicks, edits, changes,
//! submits, keys and drags in the capture phase, before the act's default
//! runs, script-made events included (the model's select is one). Before
//! any value leaves the page, the page's twin of the one secret classifier
//! (`secret_fields::page_predicate`) withholds a secret field's text, and
//! a secret-looking card number in a name reads as `[secret]`.
//!
//! An act's target is described as the page computes it: its role and
//! accessible name, its input type and autocomplete tokens, and its place
//! among the targets of its document with the same role and name. The host
//! matches that against the outline the session already read of the page
//! (its last whole observation at that URL), and only on a miss against
//! the front tab's outline read now; a target neither shows once is a
//! named gap. A replay locator is always an outline row's own.

use super::{CALL, CdpDriver, Tab};
use crate::cdp::recorder::{Cue, Descriptor, Live, REC_BINDING, uninstall};
use crate::demonstration::{Edited, KeyFacts, LocatorGap, Mapped, RecordingGapKind, Saw, Seen};
use crate::driver::pages::session_token;
use crate::outline::{self, CONTROLS, Masks, clip};
use crate::secret_fields::page_predicate;
use crate::session::{effect_class, receipt_class};
use crate::{BrowserError, Row};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

/// The script each document of a recorded session runs in the recorder's
/// world. `__BINDING__`, `__DISARM__`, `__CONTROLS__` and `__SECRETS__` are
/// the recording's binding, the event that disarms it, the outline's
/// control roles and the secret classifier's page twin.
const PRELOAD: &str = r##"(() => {
  const w = window;
  const send = w["__BINDING__"];
  if (typeof send !== "function") return;
  const SECRETS = __SECRETS__;
  const CONTROLS = __CONTROLS__;
  const FROM_CONTENT = ["button", "link", "option", "menuitem", "menuitemcheckbox",
    "menuitemradio", "tab", "treeitem", "checkbox", "radio", "switch"];
  const ACTIVATES = ["button", "link", "checkbox", "radio", "switch", "menuitem",
    "menuitemcheckbox", "menuitemradio", "tab", "option", "treeitem"];
  const BOXES = {checkbox: "checkbox", radio: "radio", range: "slider", number: "spinbutton",
    search: "searchbox", button: "button", submit: "button", reset: "button", image: "button",
    file: "button"};
  const SELECTOR = "a[href],area[href],button,input,select,textarea,option,summary,[role],[contenteditable]";
  const doc = document;
  const top = w === w.top;
  const DOC = Math.random().toString(36).slice(2);
  const quit = new AbortController();
  const on = {capture: true, signal: quit.signal};
  doc.addEventListener("__DISARM__", () => quit.abort(), {once: true});
  const post = (cue) => {
    cue.u = location.href;
    cue.top = top;
    cue.doc = DOC;
    try { send(JSON.stringify(cue)); } catch (_) {}
  };
  const ids = new WeakMap();
  let next = 0;
  const idOf = (el) => {
    let id = ids.get(el);
    if (id === undefined) { next += 1; id = String(next); ids.set(el, id); }
    return id;
  };
  const tagOf = (el) => (el.tagName ? el.tagName.toLowerCase() : "");
  const typeOf = (el) => (tagOf(el) === "input" ? (el.type || "text").toLowerCase() : "");
  const clean = (t) => (t || "").replace(/\s+/g, " ").trim();
  const roleOf = (el) => {
    const explicit = clean(el.getAttribute && el.getAttribute("role")).split(" ")[0];
    if (explicit) return explicit;
    const tag = tagOf(el);
    if (tag === "a" || tag === "area") return el.hasAttribute("href") ? "link" : "";
    if (tag === "button" || tag === "summary") return "button";
    if (tag === "select") return el.multiple || el.size > 1 ? "listbox" : "combobox";
    if (tag === "textarea") return "textbox";
    if (tag === "option") return "option";
    if (tag === "input") {
      const t = typeOf(el);
      if (t === "hidden") return "";
      if (BOXES[t]) return BOXES[t];
      return el.hasAttribute("list") ? "combobox" : "textbox";
    }
    return el.isContentEditable ? "textbox" : "";
  };
  const up = (el) => {
    if (el.parentElement) return el.parentElement;
    const root = el.getRootNode && el.getRootNode();
    return root && root.host ? root.host : null;
  };
  const control = (start) => {
    for (let el = start; el && el.nodeType === 1; el = up(el)) {
      if (tagOf(el) === "label") return {label: el};
      const role = roleOf(el);
      if (CONTROLS.includes(role)) return {el: el, role: role};
    }
    return null;
  };
  const textOf = (el, refs) => refs.split(/\s+/).map((id) => {
    const ref = el.ownerDocument.getElementById(id);
    return ref ? ref.textContent : "";
  }).join(" ");
  const nameOf = (el, role) => {
    const by = el.getAttribute("aria-labelledby");
    if (by && clean(textOf(el, by))) return clean(textOf(el, by));
    if (clean(el.getAttribute("aria-label"))) return clean(el.getAttribute("aria-label"));
    const t = typeOf(el);
    if (t === "submit" || t === "reset" || t === "button") {
      return clean(el.value) || (t === "submit" ? "Submit" : t === "reset" ? "Reset" : "");
    }
    if (t === "image") return clean(el.alt) || clean(el.value) || "Submit";
    if (el.labels && el.labels.length) {
      const label = clean(Array.from(el.labels).map((l) => l.textContent).join(" "));
      if (label) return label;
    }
    if (FROM_CONTENT.includes(role)) {
      const text = clean(el.innerText || el.textContent);
      if (text) return text;
      const img = el.querySelector("img[alt]");
      if (img && clean(img.alt)) return clean(img.alt);
    }
    return clean(el.getAttribute("title")) || clean(el.getAttribute("placeholder"));
  };
  const named = (el, role) => SECRETS.text(nameOf(el, role));
  const twins = (el, role, name) => {
    let at = -1;
    let of = 0;
    for (const other of el.ownerDocument.querySelectorAll(SELECTOR)) {
      if (roleOf(other) !== role || other.getClientRects().length === 0) continue;
      if (named(other, role) !== name) continue;
      if (other === el) at = of;
      of += 1;
    }
    return at < 0 ? null : [at, of];
  };
  const describe = (el, role) => {
    const name = named(el, role);
    const by = el.getAttribute("aria-describedby");
    return {r: role, n: name, ty: typeOf(el) || null, ac: el.getAttribute("autocomplete"),
      ds: SECRETS.text(by ? clean(textOf(el, by)) : ""), i: twins(el, role, name)};
  };
  const isText = (c) => !!c && !!c.el && (c.role === "textbox" || c.role === "searchbox"
    || c.role === "spinbutton" || (c.role === "combobox" && tagOf(c.el) !== "select"));
  const origin = (e) => (e.composedPath && e.composedPath()[0]) || e.target;
  const runs = new Map();
  const secret = new Map();
  doc.addEventListener("beforeinput", (e) => {
    const c = control(origin(e));
    if (!isText(c)) return;
    const id = idOf(c.el);
    if (!runs.has(id)) runs.set(id, describe(c.el, c.role));
  }, on);
  doc.addEventListener("input", (e) => {
    const c = control(origin(e));
    if (!isText(c)) return;
    const id = idOf(c.el);
    const d = runs.get(id) || describe(c.el, c.role);
    runs.set(id, d);
    const value = c.el.isContentEditable ? c.el.innerText : c.el.value;
    const kind = secret.get(id) || SECRETS.kind({role: d.r, type: d.ty, autocomplete: d.ac,
      label: d.n, description: d.ds, value: value});
    if (kind) {
      secret.set(id, kind);
      post({k: "edit", t: id, d: d, s: kind});
    } else {
      post({k: "edit", t: id, d: d, v: value});
    }
  }, on);
  const commit = (c) => {
    if (!c || !c.el) return;
    const id = idOf(c.el);
    if (!runs.has(id)) return;
    runs.delete(id);
    secret.delete(id);
    post({k: "commit", t: id});
  };
  doc.addEventListener("focusout", (e) => commit(control(origin(e))), on);
  doc.addEventListener("change", (e) => {
    const c = control(origin(e));
    if (!c || !c.el) return;
    if (tagOf(c.el) === "select") {
      const chosen = c.el.selectedOptions && c.el.selectedOptions[0];
      const label = chosen ? clean(chosen.label || chosen.text) : "";
      const cue = {k: "select", d: describe(c.el, c.role)};
      if (SECRETS.kind({value: label})) cue.s = "card"; else cue.o = label;
      post(cue);
    } else if (typeOf(c.el) === "file") {
      post({k: "file"});
    } else if (isText(c)) {
      commit(c);
    }
  }, on);
  doc.addEventListener("click", (e) => {
    const start = origin(e);
    if (start === doc.body || start === doc.documentElement) return;
    const c = control(start);
    if (c && c.label) return;
    if (!c) { post({k: "click", d: null}); return; }
    if (typeOf(c.el) === "file") { post({k: "file"}); return; }
    if (isText(c) || tagOf(c.el) === "select") return;
    post({k: "click", d: describe(c.el, c.role)});
  }, on);
  doc.addEventListener("submit", (e) => {
    const by = e.submitter;
    post({k: "submit", d: by ? describe(by, roleOf(by)) : null});
  }, on);
  doc.addEventListener("keydown", (e) => {
    if (e.isComposing) return;
    const c = control(origin(e));
    const editable = isText(c);
    const plain = e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey;
    if (editable && plain) return;
    const mods = (e.ctrlKey ? "Control+" : "") + (e.altKey ? "Alt+" : "")
      + (e.metaKey ? "Meta+" : "") + (e.shiftKey ? "Shift+" : "");
    post({k: "key", key: {key: e.key.length === 1 && editable ? "char" : e.key, mods: mods,
      editable: editable, select: !!c && !!c.el && (tagOf(c.el) === "select" || c.role === "listbox"),
      activates: !!c && !!c.el && ACTIVATES.includes(c.role),
      form: !!c && !!c.el && !!c.el.form}});
  }, on);
  doc.addEventListener("dragstart", () => post({k: "drag"}), on);
  post({k: "doc"});
})()"##;

impl CdpDriver {
    /// Starts a recording's capture in every tab the driver follows, and in
    /// each page or frame the browser attaches from now on; the frames
    /// already out of process, which no session of the recorder reaches,
    /// by their URLs. Chromium only.
    pub(crate) fn record_start(&mut self) -> Result<Vec<String>, BrowserError> {
        self.chromium_only("a demonstration recording")?;
        let token = session_token();
        let binding = format!("{REC_BINDING}{token}");
        let disarm = format!("oneironRecDisarm{token}");
        let preload = PRELOAD
            .replace("__BINDING__", &binding)
            .replace("__DISARM__", &disarm)
            .replace("__CONTROLS__", &json!(CONTROLS).to_string())
            .replace("__SECRETS__", &page_predicate());
        self.pipe.recording_on(Live {
            binding,
            disarm,
            preload,
            sessions: HashMap::new(),
            queue: Vec::new(),
        });
        for Tab {
            target, session, ..
        } in &self.tabs
        {
            self.pipe
                .record_on(session, target, target, Instant::now() + CALL);
        }
        let listed = self
            .pipe
            .call(None, "Target.getTargets", json!({}), Instant::now() + CALL);
        Ok(listed
            .ok()
            .and_then(|listed| listed.get("targetInfos").cloned())
            .and_then(|infos| infos.as_array().cloned())
            .into_iter()
            .flatten()
            .filter(|info| info.get("type").and_then(Value::as_str) == Some("iframe"))
            .filter_map(|info| info.get("url").and_then(Value::as_str).map(str::to_owned))
            .collect())
    }

    /// The events the running recording's pages sent since the last drain.
    pub(crate) fn record_drain(&self) -> Vec<Cue> {
        self.pipe.recording_take()
    }

    /// Ends the capture and takes it off every session it listened on:
    /// the events not yet drained.
    pub(crate) fn record_stop(&self) -> Vec<Cue> {
        let Some(mut live) = self.pipe.recording_off() else {
            return Vec::new();
        };
        for (session, owner) in &live.sessions {
            uninstall(&self.pipe, session, owner, &live, Instant::now() + CALL);
        }
        std::mem::take(&mut live.queue)
    }

    /// Ends the capture of a guest that no longer answers, asking it
    /// nothing: the events it queued.
    pub(crate) fn record_off(&self) -> Vec<Cue> {
        self.pipe
            .recording_off()
            .map_or_else(Vec::new, |live| live.queue)
    }

    /// What a recording saw in `cues`, in order, each act's target matched
    /// to an outline row: against what the session read of its page first,
    /// then, where `read`, against the front tab's outline read once now.
    /// `pages` names each tab's top page as the recording last saw it.
    pub(crate) fn record_map(
        &self,
        cues: Vec<Cue>,
        pages: &BTreeMap<String, String>,
        read: bool,
    ) -> Vec<Seen> {
        // A tab's top document that loaded later in this batch ends the
        // documents of the cues before it.
        let mut loaded: HashMap<String, usize> = HashMap::new();
        for (at, cue) in cues.iter().enumerate() {
            if cue.k == "doc" && cue.top {
                loaded.insert(cue.tab.clone(), at);
            }
        }
        let mut now = None;
        let mut tops: HashMap<String, String> = pages
            .iter()
            .map(|(tab, url)| (tab.clone(), url.clone()))
            .collect();
        let mut seen = Vec::with_capacity(cues.len());
        for (at, cue) in cues.into_iter().enumerate() {
            if cue.top {
                tops.insert(cue.tab.clone(), cue.u.clone());
            }
            let page = tops.get(&cue.tab).cloned();
            let gone = loaded.get(&cue.tab).is_some_and(|last| *last > at);
            let mut target = |descriptor: Option<&Descriptor>| {
                let place = Place {
                    tab: &cue.tab,
                    url: page.as_deref(),
                    gone,
                    read,
                };
                self.demonstration_locator_policy(descriptor, &place, &mut now)
            };
            if let Some(saw) = saw_of(&cue, &mut target) {
                seen.push(Seen {
                    url: cue.top.then_some(cue.u),
                    tab: cue.tab,
                    saw,
                });
            }
        }
        seen
    }

    /// The outline row `descriptor` names on its page, as a replay locator
    /// (`demonstration_locator_policy`, CALLS row): the one row with its
    /// role and name, or its place among several, in what the session last
    /// read of that page; on a miss, in the front tab's outline read once
    /// now, while the act's document still stands; else a named gap.
    fn demonstration_locator_policy(
        &self,
        descriptor: Option<&Descriptor>,
        place: &Place<'_>,
        now: &mut Option<Result<(String, Vec<Row>), LocatorGap>>,
    ) -> Result<Mapped, LocatorGap> {
        let descriptor = descriptor.ok_or(LocatorGap::NoTarget)?;
        let held = place.url.and_then(|url| self.pages.held_rows(url));
        if let Some(Ok(row)) = held.map(|rows| pick(rows.iter(), descriptor)) {
            return Ok(mapped(row));
        }
        if place.gone || !place.read {
            return Err(LocatorGap::DocumentGone);
        }
        if place.tab != self.target {
            return Err(LocatorGap::NotInFront);
        }
        let outline = now.get_or_insert_with(|| self.outline_now());
        let (url, rows) = outline.as_ref().map_err(|gap| *gap)?;
        if place.url.is_some_and(|page| page != url.as_str()) {
            return Err(LocatorGap::DocumentGone);
        }
        pick(rows.iter(), descriptor).map(mapped)
    }

    /// The front tab's URL and outline rows as a read masks them, minting
    /// no handle.
    fn outline_now(&self) -> Result<(String, Vec<Row>), LocatorGap> {
        let read = || -> Result<(String, Vec<Row>), BrowserError> {
            let url = self.url()?;
            let ax = self.ax_nodes()?;
            let candidates = outline::lines(&ax, &Masks::default());
            let dom = self.read_dom(&candidates);
            let masks = self.secret_masks(&ax, &candidates, &dom);
            let lines = if masks.is_empty() {
                candidates
            } else {
                outline::lines(&ax, &masks)
            };
            Ok((url, lines.into_iter().map(|line| line.row).collect()))
        };
        read().map_err(|_| LocatorGap::NoOutline)
    }
}

/// Where a cue's act happened: its tab, its top page, whether its document
/// is gone, and whether the page may be read now.
struct Place<'a> {
    tab: &'a str,
    url: Option<&'a str>,
    gone: bool,
    read: bool,
}

/// The one row with the descriptor's role and name; among several, the one
/// at its place when the page counted as many.
fn pick<'a>(
    rows: impl Iterator<Item = &'a Row>,
    descriptor: &Descriptor,
) -> Result<&'a Row, LocatorGap> {
    let name = clip(&descriptor.n);
    let named: Vec<&Row> = rows
        .filter(|row| row.role == descriptor.r && row.name == name)
        .collect();
    match (named.as_slice(), descriptor.i) {
        ([], _) => Err(LocatorGap::NoMatch),
        ([row], _) => Ok(*row),
        (many, Some((at, of))) if of == many.len() => {
            many.get(at).copied().ok_or(LocatorGap::Ambiguous)
        }
        _ => Err(LocatorGap::Ambiguous),
    }
}

/// A matched row as a recorded target: its locator, its name, and the
/// class its press takes (`effect_class`, unknown with no name).
fn mapped(row: &Row) -> Mapped {
    let class = receipt_class(effect_class(&row.name), Some(row));
    Mapped {
        locator: row.locator.clone(),
        name: row.name.clone(),
        effect_class: class.map(str::to_owned),
    }
}

/// What one cue shows the recording; none for a frame's own document.
fn saw_of(
    cue: &Cue,
    target: &mut impl FnMut(Option<&Descriptor>) -> Result<Mapped, LocatorGap>,
) -> Option<Saw> {
    let field = || {
        format!(
            "{}/{}/{}",
            cue.tab,
            cue.doc,
            cue.t.as_deref().unwrap_or_default()
        )
    };
    Some(match cue.k.as_str() {
        "doc" if cue.top => Saw::Document,
        "click" => Saw::Click(target(cue.d.as_ref())),
        "edit" => {
            let value = match (cue.s, &cue.v) {
                (Some(kind), _) => Edited::Secret(kind),
                (None, Some(text)) => Edited::Text(text.clone()),
                (None, None) => return None,
            };
            Saw::Edit {
                key: field(),
                target: target(cue.d.as_ref()),
                value,
            }
        }
        "commit" => Saw::Commit { key: field() },
        "select" => match &cue.o {
            Some(option) => Saw::Select {
                target: target(cue.d.as_ref()),
                option: option.clone(),
            },
            None => Saw::Gesture("select:withheld".to_owned()),
        },
        "key" => {
            let key = cue.key.as_ref()?;
            Saw::Key(KeyFacts {
                key: key.key.clone(),
                mods: key.mods.clone(),
                editable: key.editable,
                select: key.select,
                activates: key.activates,
                form: key.form,
            })
        }
        "submit" => Saw::Submit(cue.d.as_ref().map(|d| target(Some(d)))),
        "drag" => Saw::Gesture("drag".to_owned()),
        "file" => Saw::Gesture("file".to_owned()),
        "lost" => Saw::Gap(RecordingGapKind::CaptureLost),
        "uncovered" => Saw::Gap(RecordingGapKind::Uncovered {
            target: cue.u.clone(),
        }),
        _ => return None,
    })
}

/// The final text, or the secret kind, the last edit in `cues` showed.
pub(crate) fn last_edit(cues: &[Cue]) -> Option<Edited> {
    cues.iter()
        .rev()
        .filter(|cue| cue.k == "edit")
        .find_map(|cue| match (cue.s, &cue.v) {
            (Some(kind), _) => Some(Edited::Secret(kind)),
            (None, Some(text)) => Some(Edited::Text(text.clone())),
            (None, None) => None,
        })
}
