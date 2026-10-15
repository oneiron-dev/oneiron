//! The listener's admission, end to end over real sockets (C4, and the rate
//! law of ARCH-0044 C5): headers that never finish are closed at the
//! deadline, a body that stops arriving gives its connection back while a
//! slow one that keeps arriving is served, a socket past the descriptor floor
//! waits its turn and is served once a connection closes, an off-device
//! address's strangers past its share are shed while its authenticated
//! connections never are, a WebSocket keeps its permit past the header
//! deadline, and routes still see the socket peer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::ConnectInfo;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::routing::{get, post};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{ConnectionLimits, serve};
use crate::admission::Crossing;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// Longer than every deadline these tests set, by far: reaching it means the
/// server kept a socket the test expected it to close.
const PATIENCE: Duration = Duration::from_secs(10);

const REQUEST: &[u8] = b"GET /peer HTTP/1.1\r\nhost: listener\r\n\r\n";

fn app() -> Router {
    Router::new()
        .route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
        )
        .route(
            "/ws",
            get(|upgrade: WebSocketUpgrade| async move {
                upgrade.on_upgrade(|mut socket| async move {
                    while let Some(Ok(message)) = socket.recv().await {
                        if let Message::Text(text) = message
                            && socket.send(Message::Text(text)).await.is_err()
                        {
                            break;
                        }
                    }
                })
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "finished"
            }),
        )
        .route(
            "/length",
            post(|body: Bytes| async move { body.len().to_string() }),
        )
        // Stands in for a route whose caller's credential the server accepts.
        .route(
            "/login",
            get(|| async {
                super::authenticated();
                "welcome"
            }),
        )
}

struct Served {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    questions: Arc<LimitQuestions>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(addr: &str, limits: ConnectionLimits) -> Served {
    let listener = TcpListener::bind(addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let questions = Arc::new(LimitQuestions::default());
    let task = tokio::spawn(serve(
        listener,
        app(),
        limits,
        Arc::clone(&questions),
        async {
            let _ = stopped.await;
        },
    ));
    Served {
        addr,
        stop: Some(stop),
        task,
        questions,
    }
}

/// A loopback peer meets the floor only, so these sockets never reach the
/// unauthenticated share of one.
fn limits(max_connections: usize, header_read_timeout: Duration) -> ConnectionLimits {
    ConnectionLimits {
        max_connections,
        max_unauthenticated_per_peer: 1,
        header_read_timeout,
        body_idle_timeout: PATIENCE,
        queue_wait: PATIENCE,
    }
}

/// Reads one whole response off a keep-alive connection: the head, then
/// exactly `content-length` body bytes.
async fn read_response(stream: &mut TcpStream) -> (u16, String) {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    tokio::time::timeout(PATIENCE, async {
        while !bytes.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.unwrap();
            assert_eq!(read, 1, "connection closed inside a response head");
            bytes.push(byte[0]);
        }
    })
    .await
    .expect("a response head");
    let head = String::from_utf8(bytes).unwrap();
    let status = head[9..12].parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .map_or(0, |value| value.trim().parse().unwrap());
    let mut body = vec![0_u8; length];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut body))
        .await
        .expect("a response body")
        .unwrap();
    (status, String::from_utf8(body).unwrap())
}

/// Everything the server sends until it closes the socket, or `None` if it
/// keeps the socket open past [`PATIENCE`].
async fn until_closed(stream: &mut TcpStream) -> Option<String> {
    let mut bytes = Vec::new();
    let closed = tokio::time::timeout(PATIENCE, async {
        let mut buffer = [0_u8; 512];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            }
        }
    })
    .await;
    closed
        .ok()
        .map(|()| String::from_utf8_lossy(&bytes).into_owned())
}

/// Polls `connect` until a fresh connection is served: a peer that hung up
/// returns its permit when the server sees the hang-up, not before.
async fn served_again(addr: SocketAddr) -> TcpStream {
    tokio::time::timeout(PATIENCE, async {
        loop {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(REQUEST).await.unwrap();
            let mut first = [0_u8; 12];
            if stream.read_exact(&mut first).await.is_ok() && &first[9..12] == b"200" {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a connection is admitted once a permit returns")
}

/// Rule five at the descriptor floor: `callers` sockets past a floor of one,
/// each asking for a slow answer, are all served, and the row asks.
pub(crate) async fn cross_the_floor(callers: usize) -> Crossing {
    let served = start("127.0.0.1:0", limits(1, PATIENCE)).await;
    let calls: Vec<_> = (0..callers)
        .map(|_| {
            let addr = served.addr;
            tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream
                    .write_all(b"GET /slow HTTP/1.1\r\nhost: listener\r\nconnection: close\r\n\r\n")
                    .await
                    .unwrap();
                tokio::time::timeout(PATIENCE * 6, read_response(&mut stream))
                    .await
                    .map(|(status, _)| status)
            })
        })
        .collect();
    let mut refused = 0;
    for call in calls {
        if call.await.unwrap() != Ok(200) {
            refused += 1;
        }
    }
    Crossing {
        refused,
        asked: served.questions.latest(LimitRow::Connections).is_some(),
    }
}

#[tokio::test]
async fn headers_that_never_finish_are_closed_at_the_deadline() {
    let served = start("127.0.0.1:0", limits(8, Duration::from_millis(300))).await;

    let mut dripping = TcpStream::connect(served.addr).await.unwrap();
    dripping
        .write_all(b"GET /peer HTTP/1.1\r\nhost: listener\r\n")
        .await
        .unwrap();
    let mut silent = TcpStream::connect(served.addr).await.unwrap();

    assert!(
        until_closed(&mut dripping).await.is_some(),
        "a request whose headers never finish is closed at the deadline"
    );
    assert!(
        until_closed(&mut silent).await.is_some(),
        "a connection that never sends a byte is closed at the deadline"
    );
}

#[tokio::test]
async fn a_body_that_stops_arriving_gives_its_connection_back() {
    let served = start(
        "127.0.0.1:0",
        ConnectionLimits {
            body_idle_timeout: Duration::from_millis(300),
            ..limits(1, PATIENCE)
        },
    )
    .await;

    // Whole headers, then three of the ten body bytes they promise: the
    // header deadline is behind it and the route is waiting on the body.
    let mut stalled = TcpStream::connect(served.addr).await.unwrap();
    stalled
        .write_all(b"POST /length HTTP/1.1\r\nhost: listener\r\ncontent-length: 10\r\n\r\nabc")
        .await
        .unwrap();
    assert!(
        until_closed(&mut stalled).await.is_some(),
        "a body that stops arriving is ended at the idle limit"
    );
    // Its connection held the only permit, and has given it back.
    let _admitted = served_again(served.addr).await;
}

#[tokio::test]
async fn a_slow_body_that_keeps_arriving_is_served() {
    let served = start(
        "127.0.0.1:0",
        ConnectionLimits {
            body_idle_timeout: Duration::from_millis(300),
            ..limits(1, PATIENCE)
        },
    )
    .await;

    let mut stream = TcpStream::connect(served.addr).await.unwrap();
    stream
        .write_all(b"POST /length HTTP/1.1\r\nhost: listener\r\ncontent-length: 10\r\n\r\n")
        .await
        .unwrap();
    // Every gap is inside the idle limit; together they are well past it.
    for byte in b"0123456789" {
        tokio::time::sleep(Duration::from_millis(120)).await;
        stream.write_all(&[*byte]).await.unwrap();
    }
    assert_eq!(read_response(&mut stream).await, (200, "10".to_owned()));
}

#[tokio::test]
async fn past_the_floor_a_new_socket_waits_its_turn_and_the_row_asks() {
    let served = start("127.0.0.1:0", limits(2, PATIENCE)).await;

    let mut first = TcpStream::connect(served.addr).await.unwrap();
    first.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut first).await.0, 200);
    let mut second = TcpStream::connect(served.addr).await.unwrap();
    second.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut second).await.0, 200);

    // Both keep-alive connections hold their permits. A third socket is
    // neither served nor refused: it waits in the backlog.
    let mut third = TcpStream::connect(served.addr).await.unwrap();
    third.write_all(REQUEST).await.unwrap();
    let mut byte = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), third.read(&mut byte))
            .await
            .is_err(),
        "past the floor a socket waits; it is never answered with a refusal"
    );
    let question = served
        .questions
        .latest(LimitRow::Connections)
        .expect("crossing the floor asks whether everything is okay");
    assert_eq!(question.bound, 2);

    // An admitted connection keeps serving, and hanging up one lets the
    // waiting socket in.
    first.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut first).await.0, 200);
    drop(second);
    assert_eq!(read_response(&mut third).await.0, 200);
}

/// The address this host would send from to reach the outside: an
/// off-device peer as far as the listener can tell. No packet is sent.
fn off_device_address() -> Option<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let local = probe
        .connect("192.0.2.1:9")
        .and_then(|()| probe.local_addr())
        .ok()?
        .ip();
    assert!(!local.is_loopback() && !local.is_unspecified());
    Some(local)
}

#[tokio::test]
async fn an_address_sheds_strangers_past_its_share_but_never_its_authenticated_connections() {
    const LOGIN: &[u8] = b"GET /login HTTP/1.1\r\nhost: listener\r\n\r\n";

    let Some(local) = off_device_address() else {
        eprintln!("no routed interface on this host; the off-device share is unprovable here");
        return;
    };
    let served = start(
        &SocketAddr::new(local, 0).to_string(),
        ConnectionLimits {
            max_connections: 64,
            max_unauthenticated_per_peer: 2,
            header_read_timeout: PATIENCE,
            body_idle_timeout: PATIENCE,
            queue_wait: PATIENCE,
        },
    )
    .await;

    // A fleet on one address: each connection authenticates on its first
    // request and leaves the share, so ten of them hold none of it.
    let mut fleet = Vec::new();
    for _ in 0..10 {
        let mut stream = TcpStream::connect(served.addr).await.unwrap();
        stream.write_all(LOGIN).await.unwrap();
        assert_eq!(
            read_response(&mut stream).await,
            (200, "welcome".to_owned()),
            "an authenticated connection is never shed, however many its address holds"
        );
        fleet.push(stream);
    }

    // Strangers from the same address fill the share, and the next is shed.
    let mut strangers = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(served.addr).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        assert_eq!(read_response(&mut stream).await.0, 200);
        strangers.push(stream);
    }
    let mut flood = TcpStream::connect(served.addr).await.unwrap();
    let answer = until_closed(&mut flood)
        .await
        .expect("a stranger past its address's share is closed at once");
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer:?}");

    // The fleet's connections keep serving all the while.
    for stream in &mut fleet {
        stream.write_all(REQUEST).await.unwrap();
        assert_eq!(read_response(stream).await.0, 200);
    }
}

/// Review r2 (Sol and Astra, P1): the default share (256) is larger than
/// the floor a low open-file limit gives (128 at 256 descriptors), so one
/// address's strangers could hold every socket the floor admits and stop
/// the loop before any other caller could reach it.
#[tokio::test]
async fn strangers_from_one_address_never_fill_the_floor() {
    let Some(local) = off_device_address() else {
        eprintln!("no routed interface on this host; the off-device share is unprovable here");
        return;
    };
    // Every interface: the strangers arrive from the routed address, the
    // other caller from loopback.
    let served = start(
        "0.0.0.0:0",
        ConnectionLimits {
            max_connections: 4,
            max_unauthenticated_per_peer: 256,
            header_read_timeout: PATIENCE,
            body_idle_timeout: PATIENCE,
            queue_wait: PATIENCE,
        },
    )
    .await;
    let port = served.addr.port();

    // Strangers take half the floor, and the next one is shed.
    let mut strangers = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect((local, port)).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        assert_eq!(read_response(&mut stream).await.0, 200);
        strangers.push(stream);
    }
    let mut flood = TcpStream::connect((local, port)).await.unwrap();
    let answer = until_closed(&mut flood)
        .await
        .expect("a stranger past half the floor is closed at once");
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer:?}");

    // Another caller still finds room under the floor.
    let mut caller = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    caller.write_all(REQUEST).await.unwrap();
    assert_eq!(
        tokio::time::timeout(PATIENCE, read_response(&mut caller))
            .await
            .expect("the floor kept room for another caller")
            .0,
        200
    );
}

#[tokio::test]
async fn a_websocket_outlives_the_header_deadline_and_keeps_its_permit() {
    let served = start("127.0.0.1:0", limits(1, Duration::from_millis(200))).await;

    let url = format!("ws://{}/ws", served.addr);
    let (mut socket, _) = production_ws_codec::connect_async(url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    socket
        .send(production_ws_codec::tungstenite::Message::text(
            "still here",
        ))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(PATIENCE, socket.next())
        .await
        .expect("an echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed.into_text().unwrap().as_str(), "still here");

    // The upgraded socket still holds the only permit: the next one waits.
    let mut next = TcpStream::connect(served.addr).await.unwrap();
    next.write_all(REQUEST).await.unwrap();
    let mut byte = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), next.read(&mut byte))
            .await
            .is_err(),
        "the WebSocket's permit is still held"
    );

    drop(socket);
    assert_eq!(read_response(&mut next).await.0, 200);
}

#[tokio::test]
async fn routes_see_the_socket_peer_and_shutdown_drains_requests_in_flight() {
    let mut served = start("127.0.0.1:0", limits(8, PATIENCE)).await;

    let mut stream = TcpStream::connect(served.addr).await.unwrap();
    stream.write_all(REQUEST).await.unwrap();
    let (status, peer) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(peer, stream.local_addr().unwrap().to_string());

    stream
        .write_all(b"GET /slow HTTP/1.1\r\nhost: listener\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = served.stop.take().unwrap().send(());
    assert_eq!(
        read_response(&mut stream).await,
        (200, "finished".to_owned())
    );
    tokio::time::timeout(PATIENCE, &mut served.task)
        .await
        .expect("serve returns once its connections close")
        .unwrap();
    assert!(TcpStream::connect(served.addr).await.is_err());
}
