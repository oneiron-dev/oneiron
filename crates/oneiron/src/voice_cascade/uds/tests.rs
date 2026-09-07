//! Source-authored socket tests. Deterministic enrichment is test-only, not TINY.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown as SocketShutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::Vault;
use crate::error::{Error, Result};
use crate::voice_cascade::{PartialEnricher, PartialEnrichment};

mod bridge_tests;
#[cfg(target_os = "linux")]
mod socket_tests;

fn vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault =
        Vault::open(dir.path(), crate::test_util::embedding_test_config()).expect("open vault");
    (dir, Arc::new(vault))
}

fn put_text(vault: &Vault, byte: u8, text: &str) -> String {
    let mut bytes = [byte; 16];
    bytes[0] = 0x5e;
    let id = crate::entity_id::EntityId::from_bytes(bytes).expect("entity id");
    vault
        .batch()
        .put(
            &id,
            1,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"PRIVATE_BODY_SECRET",
        )
        .text(&id, &[("body", text)])
        .commit()
        .expect("seed text");
    id.to_hex()
}

fn enrichment(term: &str) -> PartialEnrichment {
    PartialEnrichment {
        entity_labels: vec!["test:entity".to_owned()],
        salient_terms: vec![term.to_owned()],
        query_vector: None,
    }
}

struct TestEnricher {
    steps: VecDeque<Result<PartialEnrichment>>,
    texts: Vec<String>,
}

impl TestEnricher {
    fn stable() -> Self {
        Self {
            steps: VecDeque::new(),
            texts: Vec::new(),
        }
    }

    fn terms(terms: &[&str]) -> Self {
        Self {
            steps: terms.iter().map(|term| Ok(enrichment(term))).collect(),
            texts: Vec::new(),
        }
    }
}

impl PartialEnricher for TestEnricher {
    fn enrich_speculative_partial(&mut self, text: &str) -> Result<PartialEnrichment> {
        self.texts.push(text.to_owned());
        self.steps
            .pop_front()
            .unwrap_or_else(|| Ok(enrichment("stable")))
    }
}

struct Peer {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    worker: JoinHandle<io::Result<Vec<String>>>,
    shutdown: Shutdown,
}

impl Peer {
    fn new(vault: Arc<Vault>, enricher: TestEnricher, limits: BridgeLimits) -> Self {
        let (client, server) = UnixStream::pair().expect("unix pair");
        let shutdown = Shutdown::default();
        Self::start(
            client,
            Connection::from_stream(server, shutdown.clone()),
            shutdown,
            vault,
            enricher,
            limits,
        )
    }

    fn start(
        client: UnixStream,
        connection: Connection,
        shutdown: Shutdown,
        vault: Arc<Vault>,
        mut enricher: TestEnricher,
        limits: BridgeLimits,
    ) -> Self {
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(3)))
            .expect("write timeout");
        let reader = BufReader::new(client.try_clone().expect("clone"));
        let worker = thread::spawn(move || {
            connection.serve(vault, &mut enricher, limits)?;
            Ok(enricher.texts)
        });
        Self {
            writer: client,
            reader,
            worker,
            shutdown,
        }
    }

    fn send(&mut self, request: Value) -> Value {
        self.raw(request.to_string().as_bytes())
    }

    fn raw(&mut self, bytes: &[u8]) -> Value {
        self.writer.write_all(bytes).expect("request");
        self.writer.write_all(b"\n").expect("delimiter");
        self.read()
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        let count = self.reader.read_line(&mut line).expect("response");
        assert!(count > 0 && count <= MAX_FRAME_BYTES + 1);
        serde_json::from_str(&line).expect("JSON response")
    }

    fn open(&mut self) -> String {
        let response = self.send(json!({"op":"open", "utterance_id":"turn"}));
        response["handle"]
            .as_str()
            .expect("opened handle")
            .to_owned()
    }

    fn observe(&mut self, op: &str, handle: &str, revision: u64, text: &str) -> Value {
        self.send(json!({"op":op,"handle":handle,"revision":revision,"text":text}))
    }

    fn finish(self) -> Vec<String> {
        let _ = self.writer.shutdown(SocketShutdown::Both);
        self.worker
            .join()
            .expect("worker joined")
            .expect("serve succeeded")
    }
}
