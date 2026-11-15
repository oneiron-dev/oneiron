//! A Drive file's content through the broker (GOOGLE-DRIVE-CONTENT-READ,
//! REVIEW-8002): the bytes come back as the provider sent them, or the call
//! fails whole. A reply the strip would change, because it holds a form of
//! the key or a run encoded too deep to rule one out, never answers as the
//! file with a marker in it. A JSON row still answers with the form redacted.
//!
//! Fleet: `cargo test --locked -p oneiron-broker --features test-support --test drive_content_whole`

#![cfg(all(unix, feature = "test-support"))]

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::time::Duration;

use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_broker::{
    BrokerClient, BrokerReply, CallHeader, Failure, Isolation, MARKER, Outcome, SendPolicy,
    ServeConfig, Shape, serve, strip,
};
use zeroize::Zeroizing;

/// A synthetic access token, in the alphabet the broker admits.
const TOKEN: &str = "ya29.test-sentinel-0000";
const DOWNLOAD: &str = "/drive/v3/files/abc?alt=media&supportsAllDrives=true";
const EXPORT: &str = "/drive/v3/files/abc/export?mimeType=text%2Fplain";
const METADATA: &str = "/drive/v3/files/abc?supportsAllDrives=true&fields=id%2Cname";

struct Broker {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    uid: u32,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a broker for this user that trusts the fake's CA.
async fn broker(fake: &FakeProvider) -> Broker {
    let dir = tempfile::tempdir().expect("dir");
    let uid = std::fs::metadata(dir.path()).expect("meta").uid();
    let socket = dir.path().join("broker.sock");
    let task = tokio::spawn(serve(ServeConfig {
        socket: socket.clone(),
        client_uid: uid,
        policy: SendPolicy {
            timeout: Duration::from_secs(20),
            extra_roots: vec![fake.ca_pem().to_vec()],
        },
    }));
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Broker {
        _dir: dir,
        socket,
        uid,
        task,
    }
}

/// One GET of `shape` at `path` through `broker`, with [`TOKEN`].
async fn get(broker: &Broker, fake: &FakeProvider, shape: Shape, path: &str) -> BrokerReply {
    let header = CallHeader::new(
        "call-1".to_owned(),
        shape,
        fake.origin().to_owned(),
        path.to_owned(),
        Vec::new(),
        "drive.v3".to_owned(),
        false,
        b"",
    );
    header
        .check(b"")
        .expect("the request passes the broker's checks");
    BrokerClient::new(
        broker.socket.clone(),
        broker.uid,
        Isolation::SameUser,
        Duration::from_secs(30),
    )
    .expect("client")
    .connect()
    .await
    .expect("connect")
    .call(&header, b"", Zeroizing::new(TOKEN.as_bytes().to_vec()))
    .await
    .expect("call")
}

fn file(media_type: &str, body: &[u8]) -> FakeReply {
    FakeReply {
        status: 200,
        headers: vec![("content-type".to_owned(), media_type.to_owned())],
        body: body.to_vec(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_the_strip_would_rewrite_fails_whole() {
    // The review's case: nine bytes and no credential, yet three decodings
    // leave `%41`, still decodable, so the strip takes the whole run.
    let deep = b"%25252541";
    assert_ne!(
        strip(TOKEN.as_bytes(), deep).as_slice(),
        deep.as_slice(),
        "the strip rewrites a run it cannot read to the end"
    );
    let echoed = format!("notes\nBearer {TOKEN}\n");
    let cases: [(Shape, &str, &[u8]); 3] = [
        (Shape::DriveFileDownload, DOWNLOAD, deep),
        (Shape::DriveFileDownload, DOWNLOAD, echoed.as_bytes()),
        (Shape::DriveFileExport, EXPORT, deep),
    ];
    for (shape, path, body) in cases {
        let fake = FakeProvider::start(file("text/plain", body));
        let broker = broker(&fake).await;
        let reply = get(&broker, &fake, shape, path).await;
        assert_eq!(
            reply.outcome,
            Outcome::Failed {
                reason: Failure::ReplyHoldsKey
            },
            "{shape:?} answered a rewritten file instead of failing: {:?}",
            String::from_utf8_lossy(&reply.body)
        );
        assert!(reply.body.is_empty(), "no byte of the file comes back");
        assert!(!contains(&reply.body, MARKER));
        assert_eq!(fake.seen().len(), 1, "one send");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_the_strip_leaves_alone_comes_back_byte_for_byte() {
    let pdf: &[u8] = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nstream\n\x00\x01\x80\xfe\xff\nendstream\n";
    let cases: [(Shape, &str, &str, &[u8]); 3] = [
        (Shape::DriveFileDownload, DOWNLOAD, "application/pdf", pdf),
        (
            Shape::DriveFileDownload,
            DOWNLOAD,
            "text/plain; charset=utf-8",
            b"Q3 margin 12% of revenue\n",
        ),
        (
            Shape::DriveFileExport,
            EXPORT,
            "text/plain",
            b"# Plan\nShip the drive read.\n",
        ),
    ];
    for (shape, path, media_type, body) in cases {
        assert_eq!(strip(TOKEN.as_bytes(), body).as_slice(), body);
        let fake = FakeProvider::start(file(media_type, body));
        let broker = broker(&fake).await;
        let reply = get(&broker, &fake, shape, path).await;
        let Outcome::Answered { status, headers } = &reply.outcome else {
            panic!("{shape:?} not answered: {:?}", reply.outcome);
        };
        assert_eq!(*status, 200);
        assert_eq!(reply.body.as_slice(), body, "{shape:?}: the file as sent");
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == "content-type" && value == media_type),
            "{shape:?}: the media type comes back: {headers:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_metadata_reply_still_answers_with_the_form_redacted() {
    let body = format!(r#"{{"id":"abc","name":"Bearer {TOKEN}"}}"#);
    let fake = FakeProvider::start(file("application/json", body.as_bytes()));
    let broker = broker(&fake).await;
    let reply = get(&broker, &fake, Shape::DriveFileGet, METADATA).await;
    let Outcome::Answered { status, .. } = reply.outcome else {
        panic!("not answered: {:?}", reply.outcome);
    };
    assert_eq!(status, 200);
    assert!(contains(&reply.body, MARKER), "the form is redacted");
    assert!(!contains(&reply.body, TOKEN.as_bytes()));
    assert!(contains(&reply.body, br#""id":"abc""#), "the rest answers");
}
