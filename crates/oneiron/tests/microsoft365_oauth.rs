//! Microsoft's code exchange and refresh ([MICROSOFT365-OAUTH-EXCHANGE]):
//! what each posts to the tenant's token endpoint and what the exchange
//! stores, against a token endpoint on a local port; a refusal names
//! Microsoft's error code and never its description; a tenant outside the
//! tenant alphabet sends nothing; and each token step (the Microsoft 365
//! connection's, the `microsoft365.me` check's, the mail wires') reaches its
//! own provider's host only, as a local proxy sees its `CONNECT`s.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test microsoft365_oauth`

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use oneiron::test_doors::microsoft_token::{
    exchange_code_at, mail_wire_refresh_via, microsoft365_me_status_via, refresh_grant_at,
};
use oneiron::test_doors::workspace_token::access_token_via;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One request a test token endpoint took: its request line, its content
/// type and its form, decoded.
struct TakenTestRequest {
    line: String,
    content_type: String,
    form: BTreeMap<String, String>,
}

/// A token endpoint on a local port that answers one request with `status`
/// and the JSON `body`: its origin, and the request it took.
fn test_token_endpoint(
    status: u16,
    body: Value,
) -> TestResult<(
    String,
    thread::JoinHandle<std::io::Result<TakenTestRequest>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("http://{}", listener.local_addr()?);
    let taken = thread::spawn(move || answer_one_test_request(&listener, status, &body));
    Ok((origin, taken))
}

fn answer_one_test_request(
    listener: &TcpListener,
    status: u16,
    body: &Value,
) -> std::io::Result<TakenTestRequest> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let (mut length, mut content_type) = (0_usize, String::new());
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap_or((header, ""));
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .trim()
                .parse()
                .map_err(|_| std::io::Error::other("bad content-length"))?;
        } else if name.eq_ignore_ascii_case("content-type") {
            value.trim().clone_into(&mut content_type);
        }
    }
    let mut form = vec![0_u8; length];
    reader.read_exact(&mut form)?;
    let reply = body.to_string();
    write!(
        stream,
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    )?;
    Ok(TakenTestRequest {
        line: line.trim_end().to_owned(),
        content_type,
        form: decode_test_form(&String::from_utf8_lossy(&form)),
    })
}

/// An `application/x-www-form-urlencoded` body as its fields.
fn decode_test_form(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_test_component(name), decode_test_component(value))
        })
        .collect()
}

/// One form component, `+` and `%XX` decoded.
fn decode_test_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' if at + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap_or("");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                at += 2;
            }
            byte => out.push(byte),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fields `pairs` names, as a form.
fn test_form(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// A proxy on a local port that refuses every `CONNECT` it is sent: its
/// URL, and the targets it was asked for, in order.
fn test_connect_proxy() -> TestResult<(String, Arc<Mutex<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&targets);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let Ok(read_half) = stream.try_clone() else {
                continue;
            };
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if header.trim_end().is_empty() => break,
                    Ok(_) => {}
                }
            }
            if let Ok(mut targets) = seen.lock() {
                targets.push(line.trim_end().to_owned());
            }
            let mut stream = stream;
            let _ = stream.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    Ok((url, targets))
}

/// The targets the proxy was asked for so far.
fn test_connects(targets: &Arc<Mutex<Vec<String>>>) -> TestResult<Vec<String>> {
    Ok(targets
        .lock()
        .map_err(|_| "the proxy's target list is poisoned")?
        .clone())
}

const MICROSOFT_TEST_REDIRECT: &str = "http://localhost:8400/callback";
const MICROSOFT_TEST_SCOPE: &str =
    "https://graph.microsoft.com/Files.ReadWrite https://graph.microsoft.com/User.Read";

#[test]
fn the_code_exchange_posts_to_the_tenant_endpoint_and_stores_a_refreshable_grant() -> TestResult {
    let (origin, taken) = test_token_endpoint(
        200,
        json!({
            "token_type": "Bearer",
            "scope": MICROSOFT_TEST_SCOPE,
            "expires_in": 3599,
            "access_token": "at-1",
            "refresh_token": "rt-1",
        }),
    )?;
    let exchanged = exchange_code_at(
        &origin,
        "client-1",
        Some("secret-1"),
        "organizations",
        "code-1",
        MICROSOFT_TEST_REDIRECT,
        Some("verifier-1"),
    )?;
    let taken = taken.join().map_err(|_| "endpoint thread panicked")??;
    assert_eq!(taken.line, "POST /organizations/oauth2/v2.0/token HTTP/1.1");
    assert_eq!(taken.content_type, "application/x-www-form-urlencoded");
    assert_eq!(
        taken.form,
        test_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "client-1"),
            ("client_secret", "secret-1"),
            ("code", "code-1"),
            ("redirect_uri", MICROSOFT_TEST_REDIRECT),
            ("code_verifier", "verifier-1"),
        ])
    );
    assert!(exchanged.refreshable);
    let stored: Value = serde_json::from_slice(&exchanged.grant)?;
    assert_eq!(
        stored,
        json!({
            "access_token": "at-1",
            "refresh_token": "rt-1",
            "client_id": "client-1",
            "client_secret": "secret-1",
            "tenant": "organizations",
            "scope": MICROSOFT_TEST_SCOPE,
        })
    );
    Ok(())
}

#[test]
fn a_public_client_sends_no_secret_and_access_only_is_not_refreshable() -> TestResult {
    let (origin, taken) = test_token_endpoint(
        200,
        json!({"token_type": "Bearer", "expires_in": 3599, "access_token": "at-1"}),
    )?;
    let directory = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let exchanged = exchange_code_at(
        &origin,
        "client-1",
        None,
        directory,
        "code-1",
        MICROSOFT_TEST_REDIRECT,
        None,
    )?;
    let taken = taken.join().map_err(|_| "endpoint thread panicked")??;
    assert_eq!(
        taken.line,
        format!("POST /{directory}/oauth2/v2.0/token HTTP/1.1")
    );
    assert_eq!(
        taken.form,
        test_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "client-1"),
            ("code", "code-1"),
            ("redirect_uri", MICROSOFT_TEST_REDIRECT),
        ])
    );
    assert!(!exchanged.refreshable);
    let stored: Value = serde_json::from_slice(&exchanged.grant)?;
    assert_eq!(
        stored,
        json!({"access_token": "at-1", "client_id": "client-1", "tenant": directory})
    );
    Ok(())
}

#[test]
fn a_stored_grant_refreshes_at_its_tenant_with_its_granted_scopes() -> TestResult {
    let grant = json!({
        "access_token": "at-1",
        "refresh_token": "rt-1",
        "client_id": "client-1",
        "client_secret": "secret-1",
        "tenant": "contoso.onmicrosoft.com",
        "scope": MICROSOFT_TEST_SCOPE,
    })
    .to_string();
    let (origin, taken) = test_token_endpoint(
        200,
        json!({"access_token": "at-2", "refresh_token": "rt-2", "scope": MICROSOFT_TEST_SCOPE}),
    )?;
    assert_eq!(
        refresh_grant_at(&origin, grant.as_bytes())?.as_deref(),
        Some("at-2")
    );
    let taken = taken.join().map_err(|_| "endpoint thread panicked")??;
    assert_eq!(
        taken.line,
        "POST /contoso.onmicrosoft.com/oauth2/v2.0/token HTTP/1.1"
    );
    assert_eq!(
        taken.form,
        test_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "client-1"),
            ("refresh_token", "rt-1"),
            ("client_secret", "secret-1"),
            ("scope", MICROSOFT_TEST_SCOPE),
        ])
    );
    // Not a refreshable Microsoft grant: nothing is sent (the closed port
    // would refuse a send).
    for other in [
        br#"{"access_token":"at-1","refresh_token":"rt-1","client_id":"client-1"}"#.as_slice(),
        br#"{"access_token":"at-1","client_id":"client-1","tenant":"common"}"#.as_slice(),
        b"bare-access-token".as_slice(),
    ] {
        assert_eq!(refresh_grant_at("http://127.0.0.1:9", other)?, None);
    }
    Ok(())
}

#[test]
fn a_refused_refresh_names_the_error_code_never_the_description() -> TestResult {
    let grant = br#"{"refresh_token":"rt-1","client_id":"client-1","tenant":"common"}"#;
    let (origin, taken) = test_token_endpoint(
        400,
        json!({
            "error": "invalid_grant",
            "error_description": "AADSTS700082: The refresh token has expired due to inactivity.",
            "error_codes": [700_082],
        }),
    )?;
    let refused = refresh_grant_at(&origin, grant).expect_err("Microsoft refused the refresh");
    taken.join().map_err(|_| "endpoint thread panicked")??;
    let refused = refused.to_string();
    assert!(refused.contains("invalid_grant"), "{refused}");
    assert!(refused.contains("HTTP 400"), "{refused}");
    assert!(!refused.contains("AADSTS"), "{refused}");
    Ok(())
}

#[test]
fn a_tenant_outside_the_alphabet_sends_nothing() {
    for tenant in [
        "",
        "evil.example/common",
        "common?x=1",
        "../common",
        ".common",
        "common.",
        "-common",
        "con..toso",
        "contoso com",
        "contoso%2fcommon",
        "contoso@evil.example",
    ] {
        let refused = match exchange_code_at(
            "http://127.0.0.1:9",
            "client-1",
            None,
            tenant,
            "code-1",
            MICROSOFT_TEST_REDIRECT,
            None,
        ) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        assert!(
            refused.contains("the Microsoft tenant is not"),
            "tenant {tenant:?}: {refused}"
        );
        let grant =
            json!({"refresh_token": "rt-1", "client_id": "client-1", "tenant": tenant}).to_string();
        let refused = match refresh_grant_at("http://127.0.0.1:9", grant.as_bytes()) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        // An empty tenant is no tenant: that grant is not refreshed at all.
        assert!(
            tenant.is_empty() || refused.contains("the Microsoft tenant is not"),
            "tenant {tenant:?}: {refused}"
        );
    }
}

#[test]
fn each_token_step_reaches_only_its_own_providers_host() -> TestResult {
    let microsoft = json!({
        "access_token": "ms-access",
        "refresh_token": "ms-refresh",
        "client_id": "ms-client",
        "tenant": "organizations",
    })
    .to_string();
    let google = json!({
        "access_token": "g-access",
        "refresh_token": "g-refresh",
        "client_id": "g-client",
        "client_secret": "g-secret",
    })
    .to_string();
    let ms_access = br#"{"access_token":"ms-access"}"#;
    let (proxy, targets) = test_connect_proxy()?;
    let login = "CONNECT login.microsoftonline.com:443 HTTP/1.1";
    let google_token = "CONNECT oauth2.googleapis.com:443 HTTP/1.1";
    let graph = "CONNECT graph.microsoft.com:443 HTTP/1.1";

    // The Microsoft 365 connection: a Microsoft grant refreshes at
    // Microsoft; a grant naming no tenant is presented as stored.
    assert!(access_token_via("microsoft.excel", microsoft.as_bytes(), &proxy).is_err());
    assert_eq!(
        access_token_via("microsoft.excel", google.as_bytes(), &proxy)?,
        "g-access"
    );
    // A Google connection: a Google grant refreshes at Google; a Microsoft
    // grant is refused before anything is sent.
    assert!(access_token_via("google.sheets", google.as_bytes(), &proxy).is_err());
    assert!(access_token_via("google.sheets", microsoft.as_bytes(), &proxy).is_err());
    assert_eq!(test_connects(&targets)?, [login, google_token]);

    // The check: a Microsoft grant refreshes first; an access-only grant
    // goes straight to Graph.
    assert!(microsoft365_me_status_via(&proxy, microsoft.as_bytes()).is_err());
    assert!(microsoft365_me_status_via(&proxy, ms_access).is_err());
    assert_eq!(
        test_connects(&targets)?,
        [login, google_token, login, graph]
    );

    // The mail wires: each issuer refreshes only its own grants.
    let refused = mail_wire_refresh_via("microsoft", microsoft.as_bytes(), &proxy)
        .expect_err("the proxy refuses Microsoft's endpoint");
    assert!(
        refused
            .to_string()
            .contains("microsoft_credential_refresh_failed"),
        "{refused}"
    );
    assert_eq!(
        mail_wire_refresh_via("microsoft", google.as_bytes(), &proxy)?,
        None
    );
    assert!(mail_wire_refresh_via("google", google.as_bytes(), &proxy).is_err());
    assert!(mail_wire_refresh_via("google", microsoft.as_bytes(), &proxy).is_err());
    assert_eq!(
        test_connects(&targets)?,
        [login, google_token, login, graph, login, google_token]
    );
    Ok(())
}
