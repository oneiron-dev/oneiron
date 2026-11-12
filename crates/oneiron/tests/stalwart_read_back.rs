//! The Stalwart read-back of an uncertain native mail send (brief 09).
//!
//! FIX 22349: each read of the read-back is bounded as the sent lookup's
//! reads are ([`SENT_LOOKUP_TIMEOUT`]), so a stalled Stalwart cannot hold the
//! replay pass for the client's whole 30 s request bound per read.
//!
//! FIX 22347: one replay pass asks the provider one question, and the sent
//! lookup answers from the same record the read-back reads, so a cancelled
//! submission is no longer a sent send.
//!
//! The Stalwart here is a JMAP stub on a loopback port: it answers the session
//! request and each JMAP method call the client makes, and can hold one
//! method's answer for a set time.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::channel_identity_provider::native_mail::NativeMailRunMode;
use oneiron::channel_identity_provider::stalwart::{
    NativeMailMessage, StalwartClient, StalwartConfig, StalwartSendSink,
};
use oneiron::outbound::{
    EngineSendId, OutboundExecutionSink, OutboundIntent, SENT_LOOKUP_TIMEOUT, SentLookup,
    SentLookupTarget,
};
use oneiron::outbound_intent_ledger::DeliveryReadBack;
use oneiron::test_doors::uncertain_send_questions::{PassQuestions, replay_uncertain_send};
use oneiron::{EntityId, Vault, VaultConfig, outbound_verb_contract};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};

const DOMAIN: &str = "mail.example.test";
const DOMAIN_ID: &str = "domain-1";
const ACCOUNT_ID: &str = "account-1";
const RECIPIENT: &str = "bob@example.org";

/// How the stub answers one JMAP method: its result, after `delay`.
type MethodAnswer = Arc<dyn Fn(&str, &Value) -> (Duration, Value) + Send + Sync>;

/// A loopback Stalwart: the session document, the domain and the one
/// account a native mailbox resolves to, then whatever `answer` says for
/// every other method.
struct StalwartStub {
    session_url: String,
}

impl StalwartStub {
    fn start(account_name: String, answer: MethodAnswer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the stub's port");
        let port = listener.local_addr().expect("stub address").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let answer = Arc::clone(&answer);
                let account_name = account_name.clone();
                std::thread::spawn(move || serve(stream, &account_name, &answer));
            }
        });
        Self {
            session_url: format!("http://127.0.0.1:{port}/jmap/session"),
        }
    }

    fn client(&self) -> StalwartClient {
        let config = StalwartConfig::new(
            &self.session_url,
            "instance-1",
            "owner-1",
            DOMAIN,
            DOMAIN_ID,
            NativeMailRunMode::SelfRun,
        )
        .expect("stub placement");
        StalwartClient::connect(config, HeaderValue::from_static("Bearer stub"))
            .expect("connect to the stub")
    }
}

/// One HTTP exchange on `stream`, then the connection closes.
fn serve(stream: TcpStream, account_name: &str, answer: &MethodAnswer) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stub stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let (delay, reply) = if request_line.starts_with("GET ") {
        (Duration::ZERO, session_document())
    } else {
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let call = &request["methodCalls"][0];
        let method = call[0].as_str().unwrap_or_default();
        let arguments = &call[1];
        let (delay, result) = match method {
            "x:Domain/get" => (
                Duration::ZERO,
                json!({"list": [{
                    "id": DOMAIN_ID, "name": DOMAIN, "isEnabled": true,
                    "catchAllAddress": null, "memberTenantId": null
                }]}),
            ),
            "x:Account/query" => (Duration::ZERO, json!({"ids": [ACCOUNT_ID]})),
            "x:Account/get" => (
                Duration::ZERO,
                json!({"list": [{
                    "id": ACCOUNT_ID, "name": account_name, "domainId": DOMAIN_ID,
                    "@type": "User", "memberTenantId": null
                }]}),
            ),
            _ => answer(method, arguments),
        };
        (
            delay,
            json!({"methodResponses": [[method, result, "mail"]], "sessionState": "stub"}),
        )
    };
    std::thread::sleep(delay);
    let body = reply.to_string();
    let mut stream = reader.into_inner();
    // A client that gave up on a held answer has closed its end: the write
    // fails, and nothing waits on it.
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn session_document() -> Value {
    json!({
        "capabilities": {
            "urn:ietf:params:jmap:core": {},
            "urn:ietf:params:jmap:mail": {},
            "urn:ietf:params:jmap:submission": {},
            "urn:stalwart:jmap": {}
        },
        "apiUrl": "/jmap/api",
        "downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}?type={type}"
    })
}

/// The sender identity, its derived mailbox address, and that mailbox's
/// account name (the address's local part).
fn sender() -> (EntityId, String, String) {
    let identity = EntityId::from_bytes([0x5A; 16]).expect("sender identity");
    let name = format!("mail-{}", identity.to_hex());
    let address = format!("{name}@{DOMAIN}");
    (identity, address, name)
}

/// The one submission of the draft, sent from `from` to the frozen
/// recipient alone: a read-back that gets every answer reads `Delivered`.
fn sent_submission(from: &str) -> Value {
    json!({"list": [{
        "id": "submission-1", "undoStatus": "final",
        "envelope": {"mailFrom": {"email": from}, "rcptTo": [{"email": RECIPIENT}]}
    }]})
}

/// FIX 22349. A Stalwart that holds its `Email/query` answer for 25 s, under
/// the client's 30 s request bound: the read-back gives up after the sent
/// lookup's bound and reads `Unknown`, instead of waiting out the held answer
/// and then making two more calls.
#[test]
fn stalwart_read_back_bounded() {
    let (identity, address, name) = sender();
    let from = address.clone();
    let stub = StalwartStub::start(
        name,
        Arc::new(move |method, _arguments| match method {
            "Email/query" => (Duration::from_secs(25), json!({"ids": ["email-1"]})),
            "EmailSubmission/query" => (Duration::ZERO, json!({"ids": ["submission-1"]})),
            "EmailSubmission/get" => (Duration::ZERO, sent_submission(&from)),
            _ => (Duration::ZERO, json!({})),
        }),
    );
    let client = stub.client();

    let started = Instant::now();
    let read_back = client.read_back_served(identity, &address, "engine-send-1", RECIPIENT);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(15) && read_back == DeliveryReadBack::Unknown,
        "a stalled read-back must read Unknown within the {SENT_LOOKUP_TIMEOUT:?} lookup bound \
         (well under 15 s); it read {read_back:?} after {elapsed:?}"
    );
}

/// FIX 22347. One replay pass of an outcome-free Pending native mail send
/// that its transport looks up (a connector-send TASK's) asks the provider
/// once: the lookup settles it, and no read-back asks the same Stalwart the
/// same question first.
#[test]
fn stalwart_single_verdict_per_pass() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");

    let questions = replay_uncertain_send(&vault);

    assert_eq!(
        questions,
        PassQuestions {
            read_backs: 0,
            lookups: 1,
            sends: 0,
        },
        "one pass asks its provider one question and, held, sends nothing"
    );
}

/// FIX 22347. A draft whose only submission was cancelled was never sent:
/// the read-back reads it `Unknown`, and the sent lookup, which answers from
/// the same record, cannot tell either. Before, the lookup read any
/// submission id as sent, and the send completed as delivered.
#[test]
fn stalwart_lookup_reads_cancelled_submission_as_cannot_tell() {
    let (identity, address, name) = sender();
    let from = address.clone();
    let stub = StalwartStub::start(
        name,
        Arc::new(move |method, _arguments| match method {
            "Email/query" => (Duration::ZERO, json!({"ids": ["email-1"]})),
            "EmailSubmission/query" => (Duration::ZERO, json!({"ids": ["submission-1"]})),
            "EmailSubmission/get" => (
                Duration::ZERO,
                json!({"list": [{
                    "id": "submission-1", "undoStatus": "canceled",
                    "envelope": {"mailFrom": {"email": &from}, "rcptTo": [{"email": RECIPIENT}]}
                }]}),
            ),
            _ => (Duration::ZERO, json!({})),
        }),
    );
    let client = stub.client();
    let message = NativeMailMessage::new(RECIPIENT, "Hello", Some("Hello Bob".to_owned()), None)
        .expect("native mail message");
    let mut sink =
        StalwartSendSink::new(&client, &message, identity, &address).expect("native mail sink");
    let engine_send_id: EngineSendId =
        serde_json::from_value(json!("ab".repeat(32))).expect("engine send id");
    let intent = OutboundIntent {
        actor: "agent".to_owned(),
        on_behalf_of: None,
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: RECIPIENT.to_owned(),
        recipients: Vec::new(),
        content_ref: None,
        idempotency_key: None,
        dedupe_key: None,
        intent_source: "test".to_owned(),
        trigger_ref: "trigger-1".to_owned(),
        job_ref: None,
        mention: None,
    };
    let target = SentLookupTarget {
        intent_ref: "intent-1",
        intent: &intent,
        verb_contract: outbound_verb_contract("email", "send").expect("email send contract"),
        channel_identity_ref: Some(identity),
        send_approved_at: None,
    };

    let found = sink.lookup_sent(&engine_send_id, &target);

    assert_eq!(
        found,
        SentLookup::CannotTell,
        "a cancelled submission proves no send"
    );
}
