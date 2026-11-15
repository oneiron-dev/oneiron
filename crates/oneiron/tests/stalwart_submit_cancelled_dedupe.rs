//! The Stalwart submit dedupe of a draft that was submitted before.
//!
//! FIX 23507: the dedupe reads the same submission record the sent lookup
//! and the read-back answer from, not any submission id. A draft whose only
//! submission was cancelled submits again instead of completing as
//! delivered; a submission that proves the send still skips the new one; an
//! ambiguous record fails before any submit.
//!
//! The Stalwart here is a JMAP stub on a loopback port, as in
//! `stalwart_read_back.rs`: it answers the session request and each JMAP
//! method call the client makes.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oneiron::EntityId;
use oneiron::channel_identity_provider::native_mail::NativeMailRunMode;
use oneiron::channel_identity_provider::stalwart::{
    NativeMailMessage, StalwartClient, StalwartConfig,
};
use oneiron::outbound::OutboundExecutionOutcomeKind;
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

/// The draft and its mailboxes, for a send whose Message-ID names one
/// existing draft.
fn draft_answers(from: &str) -> impl Fn(&str) -> Option<Value> + '_ {
    move |method| match method {
        "Identity/get" => Some(json!({"list": [{"id": "identity-1", "email": from}]})),
        "Mailbox/get" => Some(json!({"list": [
            {"id": "drafts-1", "role": "drafts"},
            {"id": "sent-1", "role": "sent"}
        ]})),
        "Email/query" => Some(json!({"ids": ["email-1"]})),
        _ => None,
    }
}

fn submit(
    client: &StalwartClient,
    identity: EntityId,
    address: &str,
) -> oneiron::outbound::OutboundExecutionOutcome {
    let message = NativeMailMessage::new(RECIPIENT, "Hello", Some("Hello Bob".to_owned()), None)
        .expect("native mail message");
    client.submit_served_text(
        identity,
        address,
        &message,
        "engine-send-1",
        &BTreeMap::new(),
        None,
    )
}

/// FIX 23507. A draft whose only submission was cancelled was never sent:
/// the submit sends it again instead of completing as delivered on the
/// cancelled submission's id. Before, the dedupe read any submission id as
/// delivered, so the owner-released resend sent nothing.
#[test]
fn stalwart_submit_resends_cancelled_submission() {
    let (identity, address, name) = sender();
    let from = address.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let made = Arc::clone(&submissions);
    let stub = StalwartStub::start(
        name,
        Arc::new(move |method, _arguments| {
            if let Some(result) = draft_answers(&from)(method) {
                return (Duration::ZERO, result);
            }
            match method {
                "EmailSubmission/query" => (Duration::ZERO, json!({"ids": ["submission-1"]})),
                "EmailSubmission/get" => (
                    Duration::ZERO,
                    json!({"list": [{
                        "id": "submission-1", "undoStatus": "canceled",
                        "envelope": {
                            "mailFrom": {"email": &from},
                            "rcptTo": [{"email": RECIPIENT}]
                        }
                    }]}),
                ),
                "EmailSubmission/set" => {
                    made.fetch_add(1, Ordering::SeqCst);
                    (
                        Duration::ZERO,
                        json!({"created": {"send": {"id": "submission-2"}}}),
                    )
                }
                _ => (Duration::ZERO, json!({})),
            }
        }),
    );
    let client = stub.client();

    let outcome = submit(&client, identity, &address);

    assert_eq!(
        submissions.load(Ordering::SeqCst),
        1,
        "a cancelled submission is no send: the submit must send again"
    );
    assert!(
        outcome.kind == OutboundExecutionOutcomeKind::DeliveredToChannel
            && outcome.provider_ref.as_deref() == Some("stalwart:submission:submission-2"),
        "the resend is delivered on its own new submission, not the cancelled one: {outcome:?}"
    );
}

/// FIX 23507. A submission that proves the send still skips the new one:
/// the submit completes as delivered on it and makes no second submission.
#[test]
fn stalwart_submit_dedupes_proven_submission() {
    let (identity, address, name) = sender();
    let from = address.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let made = Arc::clone(&submissions);
    let stub = StalwartStub::start(
        name,
        Arc::new(move |method, _arguments| {
            if let Some(result) = draft_answers(&from)(method) {
                return (Duration::ZERO, result);
            }
            match method {
                "EmailSubmission/query" => (Duration::ZERO, json!({"ids": ["submission-1"]})),
                "EmailSubmission/get" => (
                    Duration::ZERO,
                    json!({"list": [{
                        "id": "submission-1", "undoStatus": "final",
                        "envelope": {
                            "mailFrom": {"email": &from},
                            "rcptTo": [{"email": RECIPIENT}]
                        }
                    }]}),
                ),
                "EmailSubmission/set" => {
                    made.fetch_add(1, Ordering::SeqCst);
                    (
                        Duration::ZERO,
                        json!({"created": {"send": {"id": "submission-2"}}}),
                    )
                }
                _ => (Duration::ZERO, json!({})),
            }
        }),
    );
    let client = stub.client();

    let outcome = submit(&client, identity, &address);

    assert_eq!(
        submissions.load(Ordering::SeqCst),
        0,
        "a proven submission must not send twice"
    );
    assert!(
        outcome.kind == OutboundExecutionOutcomeKind::DeliveredToChannel
            && outcome.provider_ref.as_deref() == Some("stalwart:submission:submission-1"),
        "the send is delivered on its proving submission: {outcome:?}"
    );
}

/// FIX 23507. An ambiguous submission record fails before any submit: two
/// emails carry the Message-ID, so no submission id can prove this send.
#[test]
fn stalwart_submit_fails_on_ambiguous_record() {
    let (identity, address, name) = sender();
    let from = address.clone();
    let submissions = Arc::new(AtomicUsize::new(0));
    let made = Arc::clone(&submissions);
    let queries = Arc::new(AtomicUsize::new(0));
    let asked = Arc::clone(&queries);
    let stub = StalwartStub::start(
        name,
        Arc::new(move |method, _arguments| {
            // The draft the send prepared is one email; the dedupe's own
            // read then finds two under the Message-ID.
            if method == "Email/query" {
                let ids = if asked.fetch_add(1, Ordering::SeqCst) == 0 {
                    json!({"ids": ["email-1"]})
                } else {
                    json!({"ids": ["email-1", "email-2"]})
                };
                return (Duration::ZERO, ids);
            }
            if let Some(result) = draft_answers(&from)(method) {
                return (Duration::ZERO, result);
            }
            match method {
                "EmailSubmission/query" => (Duration::ZERO, json!({"ids": ["submission-1"]})),
                "EmailSubmission/set" => {
                    made.fetch_add(1, Ordering::SeqCst);
                    (
                        Duration::ZERO,
                        json!({"created": {"send": {"id": "submission-2"}}}),
                    )
                }
                _ => (Duration::ZERO, json!({})),
            }
        }),
    );
    let client = stub.client();

    let outcome = submit(&client, identity, &address);

    assert_eq!(
        submissions.load(Ordering::SeqCst),
        0,
        "an ambiguous record must fail before any submit"
    );
    assert_eq!(
        outcome.kind,
        OutboundExecutionOutcomeKind::Failed,
        "an ambiguous record fails: {outcome:?}"
    );
}
