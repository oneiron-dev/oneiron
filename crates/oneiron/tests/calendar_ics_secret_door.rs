//! CAL-02: the ICS fetcher reads the secret feed URL at the custody door
//! (ARCH-0060 :266, "URL treated as credential"). A pin over the fetcher's
//! public face, green on main and on the head: main read the URL inline, and
//! the head reads it at the SECRET-02 door (`Vault::inject_secret_at_door`);
//! the observable answers are the same. The transport sees the URL and the
//! precondition; an unbound effector is refused before any HTTP; an
//! unregistered ref is a credential error naming only the ref; a transport
//! error is scrubbed of the URL.
#![cfg(feature = "test-support")]

use std::sync::{Arc, Mutex};

use oneiron::calendar::CalendarError;
use oneiron::calendar::ingest::{
    CustodyDoorIcsFeedFetcher, IcsFeedFetcher, IcsFetchResponse, IcsHttpResponse, IcsHttpTransport,
};
use oneiron::{Vault, VaultConfig};

const CANARY_URL: &str = "https://cal.example.com/secret/CANARY-TOKEN-7f3d9/private.ics";
const CANARY_TOKEN: &str = "CANARY-TOKEN-7f3d9";
const CANARY_EFFECTOR: &str = "connector:ics-feed";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    (dir, vault)
}

/// Registers a custody record whose value is the canary URL, with a `read`
/// binding for the fetcher's effector (the fixture of
/// `tests/it/calendar_ics_ingest_adapter.rs`).
fn register_canary_secret(vault: &Vault, name: &str) {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from(CANARY_EFFECTOR)),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(vec![Value::from("read")]),
        ),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(
                oneiron::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
            )),
        ),
        (Value::from("name"), Value::from(name)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(CANARY_URL.as_bytes().to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        // An ordinary registration's model-access flag (#5169): stored
        // explicitly, as the custody doors register it.
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode custody body");
    let record =
        oneiron::secret_custody::decode_secret_custody_body(&bytes).expect("decode custody body");
    vault
        .register_secret(record)
        .expect("register canary secret");
}

type TransportCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Records the URL and precondition it was called with and answers with a
/// scripted response.
#[derive(Clone)]
struct RecordingTransport {
    calls: TransportCalls,
    response: Arc<Mutex<Result<IcsHttpResponse, String>>>,
}

impl RecordingTransport {
    fn answering(response: Result<IcsHttpResponse, String>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(response)),
        }
    }

    fn calls(&self) -> Vec<(String, Option<String>)> {
        self.calls.lock().expect("calls").clone()
    }
}

impl IcsHttpTransport for RecordingTransport {
    fn get(&self, url: &str, if_none_match: Option<&str>) -> Result<IcsHttpResponse, String> {
        self.calls
            .lock()
            .expect("calls")
            .push((url.to_owned(), if_none_match.map(str::to_owned)));
        self.response.lock().expect("response").clone()
    }
}

#[test]
fn feed_url_is_read_at_the_custody_door_and_never_leaves_it() {
    let (_dir, vault) = temp_vault();
    register_canary_secret(&vault, "ics-feed:canary");

    // The door hands the transport the URL and the precondition.
    let transport = RecordingTransport::answering(Ok(IcsHttpResponse {
        status: 200,
        etag: Some("v9".to_owned()),
        body: b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_vec(),
    }));
    let fetcher = CustodyDoorIcsFeedFetcher::new(&vault, CANARY_EFFECTOR, transport.clone());
    let response = fetcher
        .fetch("ics-feed:canary", Some("v8"))
        .expect("a bound effector fetches");
    let IcsFetchResponse::Complete { etag, .. } = &response else {
        panic!("200 maps to a complete response");
    };
    assert_eq!(etag.as_deref(), Some("v9"));
    assert_eq!(
        transport.calls(),
        vec![(CANARY_URL.to_owned(), Some("v8".to_owned()))]
    );
    assert!(!format!("{response:?}").contains(CANARY_TOKEN));

    // An effector with no binding is refused at the door, before any HTTP.
    let unbound = RecordingTransport::answering(Err("unreachable".to_owned()));
    let denied = CustodyDoorIcsFeedFetcher::new(&vault, "connector:unbound", unbound.clone());
    let Err(error) = denied.fetch("ics-feed:canary", None) else {
        panic!("an unbound effector is refused");
    };
    assert!(matches!(error, CalendarError::IcsCredential { .. }));
    assert!(unbound.calls().is_empty(), "no egress without a binding");

    // An unregistered ref names only the ref.
    let Err(error) = fetcher.fetch("ics-feed:missing", None) else {
        panic!("an unregistered ref is a custody error");
    };
    let rendered = error.to_string();
    assert!(matches!(error, CalendarError::IcsCredential { .. }));
    assert!(rendered.contains("ics-feed:missing"), "{rendered}");
    assert!(!rendered.contains(CANARY_TOKEN));

    // A transport error is scrubbed of the URL.
    let failing = RecordingTransport::answering(Err(format!("could not connect to {CANARY_URL}")));
    let failing = CustodyDoorIcsFeedFetcher::new(&vault, CANARY_EFFECTOR, failing);
    let Err(error) = failing.fetch("ics-feed:canary", None) else {
        panic!("a transport failure is a fetch error");
    };
    let rendered = error.to_string();
    assert!(!rendered.contains(CANARY_TOKEN), "{rendered}");
    assert!(rendered.contains("<redacted-url>"), "{rendered}");
}
