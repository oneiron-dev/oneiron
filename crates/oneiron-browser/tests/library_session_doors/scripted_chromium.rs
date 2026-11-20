//! The scripted Chromium peer: one fixture page behind NUL-framed CDP.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

/// The change check's page signals, read in one evaluation.
const PAGE_SIGNALS: &str = "(() => { const d = document; let s = d.oneironChange; if (!s) { s = {n: 0}; s.o = new MutationObserver(r => { s.n += r.length; }); s.o.observe(d, {subtree: true, childList: true, attributes: true, characterData: true}); Object.defineProperty(d, 'oneironChange', {value: s}); } s.n += s.o.takeRecords().length; return [location.href, scrollX, scrollY, s.n]; })()";

/// One CDP request the peer answered, in order.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) params: Value,
}

/// The fixture page and the peer's logs.
struct State {
    target_id: &'static str,
    session_id: &'static str,
    current_url: String,
    title: String,
    heading: String,
    password_field: bool,
    otp_field: Option<Option<String>>,
    refuse_page_enable: bool,
    page_exists: bool,
    log: Vec<Request>,
    unanswered: Vec<String>,
}

/// The peer's end of the CDP pipe and its shared page.
pub(crate) struct ScriptedChromium {
    state: Arc<Mutex<State>>,
    control: UnixStream,
}

impl ScriptedChromium {
    /// Starts the peer at `url` on a new socket pair.
    pub(crate) fn start(url: &str, refuse_page_enable: bool) -> (UnixStream, Self) {
        Self::start_peer(url, refuse_page_enable, "page-1", "session-1")
    }

    /// Starts the replay peer on a blank document, without watching Page events.
    pub(crate) fn start_replay() -> (UnixStream, Self) {
        Self::start_peer("about:blank", true, "page-2", "session-2")
    }

    /// Opens a pipe with independent state, identity and request logs.
    fn start_peer(
        url: &str,
        refuse_page_enable: bool,
        target_id: &'static str,
        session_id: &'static str,
    ) -> (UnixStream, Self) {
        let (host, guest) = UnixStream::pair().expect("the CDP socket pair binds");
        let control = guest.try_clone().expect("the peer control socket clones");
        let state = Arc::new(Mutex::new(State {
            target_id,
            session_id,
            current_url: url.to_owned(),
            title: "Ready".to_owned(),
            heading: "Ready".to_owned(),
            password_field: false,
            otp_field: None,
            refuse_page_enable,
            page_exists: false,
            log: Vec::new(),
            unanswered: Vec::new(),
        }));
        let peer = Arc::clone(&state);
        drop(std::thread::spawn(move || run_peer(guest, peer)));
        (host, Self { state, control })
    }

    /// Adds a blank password field to the fixture page.
    pub(crate) fn show_password_field(&self) {
        self.state.lock().expect("peer state locks").password_field = true;
    }

    /// Gives this peer independent labels for its page and heading.
    pub(crate) fn set_page_labels(&self, title: &str, heading: &str) {
        let mut state = self.state.lock().expect("peer state locks");
        state.title = title.to_owned();
        state.heading = heading.to_owned();
    }

    /// Shows a one-time-code field, blank unless the fixture gives it a value.
    pub(crate) fn show_otp_field(&self, value: Option<&str>) {
        self.state.lock().expect("peer state locks").otp_field = Some(value.map(str::to_owned));
    }

    /// The log length now, for a test's mark before its door call.
    pub(crate) fn mark(&self) -> usize {
        self.state.lock().expect("peer state locks").log.len()
    }

    /// Every request logged since `mark`, in order.
    pub(crate) fn requests_since(&self, mark: usize) -> Vec<Request> {
        self.state.lock().expect("peer state locks").log[mark..].to_vec()
    }

    /// Checks all methods since a mark for a path without poll-dependent sends.
    pub(crate) fn assert_methods(&self, mark: usize, methods: &[&str]) {
        assert_eq!(
            self.unanswered(),
            Vec::<String>::new(),
            "unanswered CDP calls"
        );
        let requests = self.requests_since(mark);
        let actual: Vec<_> = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(actual, methods, "CDP methods since the mark");
    }

    /// Every method the page had no answer for, in order.
    pub(crate) fn unanswered(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("peer state locks")
            .unanswered
            .clone()
    }
}

impl Drop for ScriptedChromium {
    fn drop(&mut self) {
        let _ = self.control.shutdown(std::net::Shutdown::Both);
    }
}

/// Answers NUL-framed CDP calls from the page state until the pipe ends.
fn run_peer(stream: UnixStream, state: Arc<Mutex<State>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("the peer reader clones"));
    let mut writer = stream;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        let (Some(id), Some(method)) = (
            message.get("id").cloned(),
            message.get("method").and_then(Value::as_str),
        ) else {
            continue;
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let session = message.get("sessionId").cloned();
        let reply = {
            let mut state = state.lock().expect("peer state locks");
            let answered = answer_request(&mut state, method, &params);
            state.log.push(Request {
                method: method.to_owned(),
                params,
            });
            match answered {
                Ok(result) => json!({"id": id, "result": result}),
                Err((code, text)) => json!({"id": id, "error": {"code": code, "message": text}}),
            }
        };
        let mut reply = reply;
        if let Some(session) = session {
            reply["sessionId"] = session;
        }
        let mut bytes = serde_json::to_vec(&reply).expect("the CDP reply encodes");
        bytes.push(0);
        if writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Answers one request from the page state.
fn answer_request(state: &mut State, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    let domain = method.split_once('.').map(|(domain, _)| domain);
    match domain {
        Some("Target") => target_answer(state, method),
        Some("Page") => page_answer(state, method, params),
        Some("DOM") => dom_answer(state, method, params),
        Some("Runtime") => runtime_answer(state, method, params),
        Some("Accessibility") => accessibility_answer(state, method),
        Some("Emulation") => emulation_answer(state, method),
        Some("Network") => network_answer(state, method),
        Some("Fetch") => fetch_answer(state, method),
        Some("Input") => input_answer(state, method, params),
        _ => unknown_answer(state, method),
    }
}

/// Answers Target calls.
fn target_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    match method {
        "Target.getTargets" => Ok(target_list(state)),
        "Target.createTarget" => {
            state.page_exists = true;
            Ok(json!({"targetId": state.target_id}))
        }
        "Target.attachToTarget" => Ok(json!({"sessionId": state.session_id})),
        "Target.getTargetInfo" => Ok(json!({"targetInfo": {
            "targetId": state.target_id,
            "type": "page",
            "url": &state.current_url,
            "title": &state.title,
        }})),
        "Target.setAutoAttach" => Ok(json!({})),
        _ => unknown_answer(state, method),
    }
}

/// Lists the fixture page once created, else no page.
fn target_list(state: &State) -> Value {
    if state.page_exists {
        json!({"targetInfos": [{
            "targetId": state.target_id,
            "type": "page",
            "url": &state.current_url,
            "title": &state.title,
        }]})
    } else {
        json!({"targetInfos": []})
    }
}

/// Answers Page calls.
fn page_answer(state: &mut State, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    match method {
        "Page.enable" => {
            if state.refuse_page_enable {
                Err((-32000, "fixture omits Page events".to_owned()))
            } else {
                Ok(json!({}))
            }
        }
        "Page.getFrameTree" => Ok(json!({"frameTree": {"frame": {
            "id": "main",
            "loaderId": "loader-1",
            "url": &state.current_url,
        }}})),
        "Page.navigate" => {
            let Some(url) = params.get("url").and_then(Value::as_str) else {
                return unknown_answer(state, method);
            };
            state.current_url = url.to_owned();
            Ok(json!({"frameId": "main", "loaderId": "loader-1"}))
        }
        "Page.createIsolatedWorld" => Ok(json!({"executionContextId": 1})),
        "Page.addScriptToEvaluateOnNewDocument" => Ok(json!({"identifier": "storage-exit"})),
        _ => unknown_answer(state, method),
    }
}

/// Answers DOM calls.
fn dom_answer(state: &mut State, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    match method {
        "DOM.enable" => return Ok(json!({})),
        "DOM.resolveNode" if password_node(state, params) => {
            return Ok(json!({"object": {"objectId": "password-node"}}));
        }
        "DOM.focus" if password_node(state, params) => return Ok(json!({})),
        "DOM.getDocument" => {}
        _ => return unknown_answer(state, method),
    }
    match params.get("depth").and_then(Value::as_i64) {
        Some(-1) => Ok(json!({"root": {
            "nodeId": 1,
            "backendNodeId": 1,
            "nodeType": 9,
            "nodeName": "#document",
            "baseURL": &state.current_url,
            "children": dom_children(state),
        }})),
        Some(0) => Ok(json!({"root": {
            "nodeId": 1,
            "backendNodeId": 1,
            "nodeType": 9,
            "nodeName": "#document",
            "baseURL": &state.current_url,
        }})),
        _ => unknown_answer(state, method),
    }
}

/// Whether a request names the fixture's password input.
fn password_node(state: &State, params: &Value) -> bool {
    state.password_field && params["backendNodeId"].as_u64() == Some(3)
}

/// The heading and any input in the full DOM read.
fn dom_children(state: &State) -> Vec<Value> {
    let mut children = vec![json!({
        "nodeId": 2,
        "backendNodeId": 2,
        "nodeType": 1,
        "nodeName": "H1",
        "localName": "h1",
        "attributes": [],
    })];
    if state.password_field {
        children.push(json!({
            "nodeId": 3,
            "backendNodeId": 3,
            "nodeType": 1,
            "nodeName": "INPUT",
            "localName": "input",
            "attributes": ["type", "password"],
        }));
    }
    if state.otp_field.is_some() {
        children.push(json!({
            "nodeId": 4,
            "backendNodeId": 4,
            "nodeType": 1,
            "nodeName": "INPUT",
            "localName": "input",
            "attributes": ["autocomplete", "one-time-code"],
        }));
    }
    children
}

/// Answers Runtime calls.
fn runtime_answer(state: &mut State, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    match method {
        "Runtime.addBinding" => return Ok(json!({})),
        "Runtime.callFunctionOn"
            if state.password_field
                && params["objectId"] == "password-node"
                && params["functionDeclaration"] == "function() { return this.isConnected; }" =>
        {
            return Ok(json!({"result": {"value": true}}));
        }
        "Runtime.evaluate" => {}
        _ => return unknown_answer(state, method),
    }
    let expression = params
        .get("expression")
        .and_then(Value::as_str)
        .unwrap_or("");
    if expression == "document.readyState" {
        Ok(json!({"result": {"value": "complete"}}))
    } else if expression == "[scrollX, scrollY]" {
        Err((-32000, "fixture omits viewport reads".to_owned()))
    } else if expression == PAGE_SIGNALS {
        Ok(json!({"result": {"value": [&state.current_url, 0, 0, 0]}}))
    } else if expression.starts_with("(() => { let d = false;")
        && (expression.contains("const s = window.localStorage;")
            || expression.contains("const s = window.sessionStorage;"))
        && let Some((scheme, rest)) = state.current_url.split_once("://")
    {
        let host = rest.split('/').next().expect("the fixture URL has a host");
        let origin = format!("{scheme}://{host}");
        Ok(json!({"result": {"value": [origin, 0, [], 0, false, 0]}}))
    } else {
        unknown_answer(state, method)
    }
}

/// Answers Accessibility calls.
fn accessibility_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    match method {
        "Accessibility.enable" => Ok(json!({})),
        "Accessibility.getFullAXTree" => Ok(json!({"nodes": accessibility_nodes(state)})),
        _ => unknown_answer(state, method),
    }
}

/// The fixture page's AX nodes, with its configured textboxes.
fn accessibility_nodes(state: &State) -> Vec<Value> {
    let mut child_ids = vec!["ax1"];
    if state.password_field {
        child_ids.push("ax2");
    }
    if state.otp_field.is_some() {
        child_ids.push("ax3");
    }
    let mut nodes = vec![
        json!({
            "nodeId": "ax0",
            "role": {"value": "RootWebArea"},
            "childIds": child_ids,
        }),
        json!({
            "nodeId": "ax1",
            "parentId": "ax0",
            "backendDOMNodeId": 2,
            "role": {"value": "heading"},
            "name": {"value": &state.heading},
        }),
    ];
    if state.password_field {
        nodes.push(json!({
            "nodeId": "ax2",
            "parentId": "ax0",
            "backendDOMNodeId": 3,
            "role": {"value": "textbox"},
            "name": {"value": "Password"},
        }));
    }
    if let Some(value) = &state.otp_field {
        let mut node = json!({
            "nodeId": "ax3",
            "parentId": "ax0",
            "backendDOMNodeId": 4,
            "role": {"value": "textbox"},
            "name": {"value": "Verification code"},
        });
        if let Some(value) = value {
            node["value"] = json!({"value": value});
        }
        nodes.push(node);
    }
    nodes
}

/// Answers Emulation calls.
fn emulation_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    match method {
        "Emulation.setDeviceMetricsOverride" => Ok(json!({})),
        _ => unknown_answer(state, method),
    }
}

/// Answers Network calls.
fn network_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    match method {
        "Network.enable" => Ok(json!({})),
        "Network.setBypassServiceWorker" => Ok(json!({})),
        "Network.getAllCookies" => Ok(json!({"cookies": []})),
        _ => unknown_answer(state, method),
    }
}

/// Answers Fetch calls.
fn fetch_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    match method {
        "Fetch.enable" => Ok(json!({})),
        _ => unknown_answer(state, method),
    }
}

/// Accepts the password Type's input without echoing its bytes in later reads.
fn input_answer(state: &mut State, method: &str, params: &Value) -> Result<Value, (i32, String)> {
    match method {
        "Input.insertText" if state.password_field && params["text"].is_string() => Ok(json!({})),
        _ => unknown_answer(state, method),
    }
}

/// Answers a call the page has no answer for with a naming protocol error.
fn unknown_answer(state: &mut State, method: &str) -> Result<Value, (i32, String)> {
    state.unanswered.push(method.to_owned());
    Err((-32601, format!("fixture has no answer for {method}")))
}
