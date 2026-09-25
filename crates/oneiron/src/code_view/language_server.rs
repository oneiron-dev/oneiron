//! One LSP process per view set. View restarts change registrations, not process ownership.
use super::{CodeViewSet, ViewReceipt, relative};
use crate::{
    EntityId,
    error::{Error, Result},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

pub trait LanguageServer: Send {
    fn request(&mut self, method: &str, params: Value) -> Result<Value>;
    fn notify(&mut self, method: &str, params: Value) -> Result<()>;
}
/// Bounded stdio JSON-RPC adapter. No shell, no inherited stdin, no raw secrets.
pub struct StdioLanguageServer {
    child: Child,
    input: ChildStdin,
    responses: mpsc::Receiver<std::io::Result<Value>>,
    next_id: u64,
    timeout: Duration,
}
impl StdioLanguageServer {
    pub fn start(program: &Path, args: &[String], root: &Path, timeout: Duration) -> Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or(Error::InvariantViolation("LSP stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or(Error::InvariantViolation("LSP stdout"))?;
        let (tx, responses) = mpsc::sync_channel(32);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let value = read_message(&mut reader);
                let failed = value.is_err();
                if tx.send(value).is_err() || failed {
                    break;
                }
            }
        });
        let mut server = Self {
            child,
            input,
            responses,
            next_id: 1,
            timeout,
        };
        server.request("initialize", json!({"processId":null,"rootUri":file_uri(root)?,"capabilities":{"workspace":{"workspaceFolders":true}}}))?;
        server.notify("initialized", json!({}))?;
        Ok(server)
    }
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }
    fn send(&mut self, body: Value) -> Result<()> {
        let bytes = serde_json::to_vec(&body).map_err(|_| Error::InvalidClaimBody("LSP encode"))?;
        write!(self.input, "Content-Length: {}\r\n\r\n", bytes.len())?;
        self.input.write_all(&bytes)?;
        self.input.flush()?;
        Ok(())
    }
}
impl LanguageServer for StdioLanguageServer {
    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("LSP request id"))?;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            let message = self
                .responses
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .map_err(|_| Error::InvalidClaimBody("LSP timeout or exited"))??;
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                if message.get("error").is_some() {
                    return Err(Error::InvalidClaimBody("LSP request failed"));
                }
                return message
                    .get("result")
                    .cloned()
                    .ok_or(Error::InvalidClaimBody("LSP result absent"));
            }
            // Server-initiated requests must receive a response; notifications
            // are not replies to the outstanding request.
            if let Some(server_id) = message.get("id") {
                self.send(json!({"jsonrpc":"2.0","id":server_id,"error":{"code":-32601,"message":"unsupported request"}}))?;
            }
        }
    }
    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        self.send(json!({"jsonrpc":"2.0","method":method,"params":params}))
    }
}
impl Drop for StdioLanguageServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn read_message(reader: &mut impl BufRead) -> std::io::Result<Value> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid LSP frame");
    let mut length = None;
    let mut total = 0;
    loop {
        let mut line = String::new();
        let n = reader.take(8193).read_line(&mut line)?;
        total += n;
        if n == 0 || total > 8192 {
            return Err(invalid());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            if length.is_some() {
                return Err(invalid());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| invalid())?);
        }
    }
    let length = length
        .filter(|n| *n <= 8 * 1024 * 1024)
        .ok_or_else(invalid)?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|_| invalid())
}
fn file_uri(path: &Path) -> Result<String> {
    reqwest::Url::from_file_path(path)
        .map(String::from)
        .map_err(|_| Error::InvalidClaimBody("LSP file URI"))
}
struct Registration {
    receipt: ViewReceipt,
    root: std::path::PathBuf,
}
struct ServerState<L> {
    server: L,
    views: BTreeMap<EntityId, Registration>,
}
pub struct SharedLanguageServer<L> {
    state: Mutex<ServerState<L>>,
}
impl<L: LanguageServer> SharedLanguageServer<L> {
    pub fn new(server: L) -> Self {
        Self {
            state: Mutex::new(ServerState {
                server,
                views: BTreeMap::new(),
            }),
        }
    }
    pub fn attach(&self, set: &CodeViewSet<'_>, view: EntityId) -> Result<()> {
        let receipt = set
            .receipt(view)?
            .ok_or(Error::InvalidClaimBody("unknown view"))?;
        let root = set.view_path(view)?;
        super::verify_view_inputs(&root, &receipt)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("LSP lock poisoned"))?;
        if state.views.contains_key(&view) {
            return Ok(());
        }
        state.server.notify(
            "workspace/didChangeWorkspaceFolders",
            json!({"event":{"added":[{"uri":file_uri(&root)?,"name":view.to_hex()}],"removed":[]}}),
        )?;
        for path in receipt.files.keys() {
            if let Ok(text) = std::fs::read_to_string(root.join(path)) {
                state.server.notify("textDocument/didOpen", json!({"textDocument":{"uri":file_uri(&root.join(path))?,"languageId": if path.ends_with(".rs") {"rust"} else {"plaintext"},"version":1,"text":text}}))?;
            }
        }
        state.views.insert(view, Registration { receipt, root });
        Ok(())
    }
    pub fn restart_view(&self, set: &CodeViewSet<'_>, view: EntityId) -> Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::InvariantViolation("LSP lock poisoned"))?;
            if let Some(registration) = state.views.remove(&view) {
                for path in registration.receipt.files.keys() {
                    state.server.notify(
                        "textDocument/didClose",
                        json!({"textDocument":{"uri":file_uri(&registration.root.join(path))?}}),
                    )?;
                }
                state.server.notify("workspace/didChangeWorkspaceFolders", json!({"event":{"added":[],"removed":[{"uri":file_uri(&registration.root)?,"name":view.to_hex()}]}}))?;
            }
        }
        self.attach(set, view)
    }
    pub fn completions(
        &self,
        view: EntityId,
        path: &str,
        line: u32,
        character: u32,
    ) -> Result<Value> {
        self.query(
            view,
            path,
            "textDocument/completion",
            Some(json!({"line":line,"character":character})),
        )
    }
    pub fn diagnostics(&self, view: EntityId, path: &str) -> Result<Value> {
        self.query(view, path, "textDocument/diagnostic", None)
    }
    fn query(
        &self,
        view: EntityId,
        path: &str,
        method: &str,
        position: Option<Value>,
    ) -> Result<Value> {
        relative(path)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("LSP lock poisoned"))?;
        let registration = state
            .views
            .get(&view)
            .ok_or(Error::InvalidClaimBody("view not attached"))?;
        if !registration.receipt.files.contains_key(path) {
            return Err(Error::InvalidClaimBody("file not visible in view"));
        }
        let mut params = json!({"textDocument":{"uri":file_uri(&registration.root.join(path))?}});
        if let Some(position) = position {
            params["position"] = position;
        }
        state.server.request(method, params)
    }
}
