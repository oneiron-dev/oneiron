// The recorder window. It renders state and sends four intents; every rule
// about what may happen lives in the Rust core, so this file can only ask.
//
// No build chain: plain ES on the global Tauri bridge.

const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const REFRESH_MS = 2000;

function renderCopy(text) {
  el("app-name").textContent = text.app_name;
  el("disclosure-title").textContent = text.disclosure_title;
  el("disclosure-body").textContent = text.disclosure_body;
  el("disclosure-affirm").textContent = text.disclosure_affirm;
  el("affirm-button").textContent = text.disclosure_affirm_action;
  el("segments-empty").textContent = text.segments_empty;
  el("start-button").textContent = text.start;
  el("stop-button").textContent = text.stop;
}

function clock(seconds) {
  return new Date(seconds * 1000).toLocaleTimeString();
}

function renderSegments(segments) {
  const list = el("segments");
  list.replaceChildren();
  el("segments-empty").hidden = segments.length > 0;
  for (const segment of segments) {
    const item = document.createElement("li");
    const when = document.createElement("div");
    when.textContent = `${clock(segment.started_at)} · ${Math.round(
      segment.duration_ms / 1000,
    )}s`;
    const meta = document.createElement("div");
    meta.className = "meta";
    // The segment says what it actually got; the window repeats it verbatim.
    meta.textContent = `${segment.channels === 2 ? "mic + system" : "mic"} · ${
      segment.aec_mode
    } · ${segment.device}`;
    item.append(when, meta);
    list.append(item);
  }
}

function render(view) {
  const affirmed = view.disclosure === "affirmed";
  el("disclosure").hidden = view.recording || affirmed;
  el("state").textContent = view.menu_bar;
  el("state").dataset.recording = String(view.recording);
  el("hint").textContent = view.hint;
  el("start-button").disabled = view.recording || !affirmed;
  el("stop-button").disabled = !view.recording;
  renderSegments(view.segments);
}

function showError(message) {
  const box = el("error");
  box.textContent = message;
  box.hidden = message === "";
}

async function send(command) {
  try {
    render(await invoke(command));
    showError("");
  } catch (err) {
    showError(String(err));
    try {
      render(await invoke("session_state"));
    } catch {
      // The core is gone; the last rendered state is all we can honestly show.
    }
  }
}

async function boot() {
  renderCopy(await invoke("recorder_copy"));
  el("affirm-button").addEventListener("click", () =>
    send("affirm_disclosure"),
  );
  el("start-button").addEventListener("click", () => send("start_recording"));
  el("stop-button").addEventListener("click", () => send("stop_recording"));
  await send("session_state");
  // Segments close on their own every minute; the list follows.
  setInterval(() => send("session_state"), REFRESH_MS);
}

boot();
