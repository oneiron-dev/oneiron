//! The Chrome DevTools Protocol over Chromium's `--remote-debugging-pipe`:
//! JSON messages, each ended by a NUL byte, on one reader and one writer.
//! Replies are matched to calls by id; events are read and dropped, because
//! the driver polls instead of following them.

use crate::BrowserError;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The largest message the pipe reads. A 1,366 px PNG screenshot in base64
/// is a few MiB; a message past this closes the pipe.
const MAX_MESSAGE: u64 = 32 << 20;

type Reply = Result<Value, String>;
type Pending = Arc<Mutex<Option<HashMap<u64, Sender<Reply>>>>>;

pub(crate) struct Pipe {
    writer: Mutex<Box<dyn Write + Send>>,
    pending: Pending,
    next: AtomicU64,
}

impl Pipe {
    pub(crate) fn new(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
    ) -> Self {
        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        let routes = Arc::clone(&pending);
        std::thread::spawn(move || {
            read_replies(BufReader::new(reader), &routes);
            // The guest is gone: every waiting call sees its sender dropped.
            if let Ok(mut routes) = routes.lock() {
                routes.take();
            }
        });
        Self {
            writer: Mutex::new(Box::new(writer)),
            pending,
            next: AtomicU64::new(1),
        }
    }

    /// Sends one command and waits for its reply until `deadline`.
    pub(crate) fn call(
        &self,
        session: Option<&str>,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, BrowserError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        {
            let mut routes = self.pending.lock().map_err(|_| BrowserError::GuestLost)?;
            routes
                .as_mut()
                .ok_or(BrowserError::GuestLost)?
                .insert(id, tx);
        }
        let mut message = json!({"id": id, "method": method, "params": params});
        if let Some(session) = session {
            message["sessionId"] = Value::from(session);
        }
        let mut bytes =
            serde_json::to_vec(&message).map_err(|e| BrowserError::Protocol(e.to_string()))?;
        bytes.push(0);
        {
            let mut writer = self.writer.lock().map_err(|_| BrowserError::GuestLost)?;
            writer
                .write_all(&bytes)
                .and_then(|()| writer.flush())
                .map_err(|_| BrowserError::GuestLost)?;
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(message)) => Err(BrowserError::Protocol(format!("{method}: {message}"))),
            Err(RecvTimeoutError::Disconnected) => Err(BrowserError::GuestLost),
            Err(RecvTimeoutError::Timeout) => {
                if let Ok(mut routes) = self.pending.lock()
                    && let Some(routes) = routes.as_mut()
                {
                    routes.remove(&id);
                }
                Err(BrowserError::Timeout(method.to_owned()))
            }
        }
    }
}

fn read_replies(mut reader: impl BufRead, routes: &Pending) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_MESSAGE).read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) if buf.last() != Some(&0) => return,
            Ok(_) => {}
        }
        buf.pop();
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        let Some(id) = message.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let reply = match message.get("error") {
            Some(error) => Err(error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_owned()),
            None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
        };
        let Ok(mut routes) = routes.lock() else {
            return;
        };
        if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
            let _ = tx.send(reply);
        }
    }
}
