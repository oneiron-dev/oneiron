//! The listener's admission, end to end over real sockets (C4): headers that
//! never finish are closed at the deadline, a body that stops arriving gives
//! its connection back while a slow one that keeps arriving is served, a
//! socket past the bound is shed while admitted ones keep working, a
//! WebSocket keeps its permit past the header deadline, and routes still see
//! the socket peer.

use std::net::SocketAddr;
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
}

struct Served {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
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
    let task = tokio::spawn(serve(listener, app(), limits, async {
        let _ = stopped.await;
    }));
    Served {
        addr,
        stop: Some(stop),
        task,
    }
}

/// A loopback peer meets the total only, so these sockets never reach the
/// per-peer share of one.
fn limits(max_connections: usize, header_read_timeout: Duration) -> ConnectionLimits {
    ConnectionLimits {
        max_connections,
        max_connections_per_peer: 1,
        header_read_timeout,
        body_idle_timeout: PATIENCE,
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
async fn past_the_bound_new_sockets_are_shed_while_admitted_ones_finish() {
    let served = start("127.0.0.1:0", limits(2, PATIENCE)).await;

    let mut first = TcpStream::connect(served.addr).await.unwrap();
    first.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut first).await.0, 200);
    let mut second = TcpStream::connect(served.addr).await.unwrap();
    second.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut second).await.0, 200);

    // Both keep-alive connections hold their permits; a third socket is
    // refused before a byte of its request is read.
    let mut shed = TcpStream::connect(served.addr).await.unwrap();
    let answer = until_closed(&mut shed)
        .await
        .expect("a socket past the bound is closed at once");
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer:?}");

    // An admitted connection keeps serving.
    first.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut first).await.0, 200);

    // Hanging up returns the permit.
    drop(second);
    let _admitted = served_again(served.addr).await;
}

#[tokio::test]
async fn one_off_device_peer_holds_only_its_share() {
    // The address this host would send from to reach the outside: an
    // off-device peer as far as the listener can tell. No packet is sent.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let routed = probe
        .connect("192.0.2.1:9")
        .and_then(|()| probe.local_addr());
    let Ok(local) = routed.map(|addr| addr.ip()) else {
        eprintln!("no routed interface on this host; the off-device share is unprovable here");
        return;
    };
    assert!(!local.is_loopback() && !local.is_unspecified());
    let served = start(
        &SocketAddr::new(local, 0).to_string(),
        ConnectionLimits {
            max_connections: 8,
            max_connections_per_peer: 1,
            header_read_timeout: PATIENCE,
            body_idle_timeout: PATIENCE,
        },
    )
    .await;

    let mut held = TcpStream::connect(served.addr).await.unwrap();
    held.write_all(REQUEST).await.unwrap();
    assert_eq!(read_response(&mut held).await.0, 200);
    let mut over = TcpStream::connect(served.addr).await.unwrap();
    let answer = until_closed(&mut over)
        .await
        .expect("a peer past its share is closed at once");
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer:?}");
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

    // The upgraded socket still holds the only permit.
    let mut shed = TcpStream::connect(served.addr).await.unwrap();
    let answer = until_closed(&mut shed).await.expect("shed at once");
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer:?}");

    drop(socket);
    let _admitted = served_again(served.addr).await;
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
