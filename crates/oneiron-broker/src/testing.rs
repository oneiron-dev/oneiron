//! A local fake model provider over TLS, for the broker's own tests and the
//! server's paid-leg fixture. No network: it listens on `127.0.0.1` with a
//! certificate from its own throwaway CA, which a test trusts through
//! [`SendPolicy::extra_roots`](crate::SendPolicy::extra_roots). It records
//! every request that reaches it, and answers each through a responder the
//! test sets, which may echo what it was sent.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The largest request head the fake reads.
const MAX_HEAD: usize = 64 << 10;

/// One request that reached the fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    /// The method.
    pub method: String,
    /// The request target.
    pub path: String,
    /// Headers in arrival order, names lowercase.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl SeenRequest {
    /// The first value of `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(seen, _)| seen.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the fake answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeReply {
    /// The status.
    pub status: u16,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl FakeReply {
    /// A JSON reply.
    #[must_use]
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }
}

type Responder = Box<dyn Fn(&SeenRequest) -> FakeReply + Send>;

struct State {
    connections: AtomicUsize,
    seen: Mutex<Vec<SeenRequest>>,
    responder: Mutex<Responder>,
}

/// A running fake provider. Dropping it stops it.
pub struct FakeProvider {
    origin: String,
    ca_pem: Vec<u8>,
    state: Arc<State>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl FakeProvider {
    /// Starts a fake on a free loopback port that answers every request with
    /// `reply`.
    ///
    /// # Panics
    ///
    /// When the loopback port, the certificates or the runtime cannot be set
    /// up; it is a test fixture.
    #[must_use]
    pub fn start(reply: FakeReply) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("ca key"))
            .expect("ca");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("leaf params")
            .signed_by(&leaf_key, &*ca)
            .expect("leaf");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .expect("server config");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let origin = format!("https://{}", listener.local_addr().expect("addr"));
        let state = Arc::new(State {
            connections: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            responder: Mutex::new(Box::new(move |_: &SeenRequest| reply.clone())),
        });
        let listener = {
            let _entered = runtime.enter();
            TcpListener::from_std(listener).expect("listener")
        };
        runtime.spawn(accept(
            listener,
            TlsAcceptor::from(Arc::new(config)),
            Arc::clone(&state),
        ));
        Self {
            origin,
            ca_pem: ca.pem().into_bytes(),
            state,
            runtime: Some(runtime),
        }
    }

    /// `https://127.0.0.1:<port>`.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The fake CA's certificate, for `extra_roots`.
    #[must_use]
    pub fn ca_pem(&self) -> &[u8] {
        &self.ca_pem
    }

    /// Answers each later request with what `responder` makes of it.
    pub fn respond_with(&self, responder: impl Fn(&SeenRequest) -> FakeReply + Send + 'static) {
        *self.state.responder.lock().expect("responder") = Box::new(responder);
    }

    /// Every request that reached the fake, in order.
    #[must_use]
    pub fn seen(&self) -> Vec<SeenRequest> {
        self.state.seen.lock().expect("seen").clone()
    }

    /// TCP connections accepted, including ones whose TLS handshake failed.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn accept(listener: TcpListener, acceptor: TlsAcceptor, state: Arc<State>) {
    while let Ok((tcp, _)) = listener.accept().await {
        state.connections.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let Some(request) = read_request(&mut tls).await else {
                return;
            };
            state.seen.lock().expect("seen").push(request.clone());
            let reply = (state.responder.lock().expect("responder"))(&request);
            let _ = tls.write_all(&encode(&reply)).await;
            let _ = tls.shutdown().await;
        });
    }
}

async fn read_request(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<SeenRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let head_end = loop {
        if let Some(at) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if bytes.len() > MAX_HEAD {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8(bytes[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = bytes[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some(SeenRequest {
        method,
        path,
        headers,
        body,
    })
}

fn encode(reply: &FakeReply) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} Fake\r\n", reply.status).into_bytes();
    for (name, value) in &reply.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            reply.body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&reply.body);
    out
}
