//! A server starts on a free port the test owns, says when it is ready, and
//! comes back on the same port after a crash.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;

use oneiron_testkit::fault::crash_and_restart;
use oneiron_testkit::{ServerProcess, ServerSpec};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-testkit-probe-server");

fn get(server: &ServerProcess) -> String {
    let mut stream = TcpStream::connect(server.addr()).expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: probe\r\n\r\n")
        .expect("send");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("read");
    answer.rsplit("\r\n\r\n").next().unwrap_or_default().to_owned()
}

#[test]
fn a_server_answers_on_its_free_port_once_it_says_it_is_ready() {
    let server = ServerProcess::spawn(ServerSpec::new(PROBE)).expect("spawn the probe");
    assert_eq!(server.addr().ip().to_string(), "127.0.0.1");
    assert_ne!(server.addr().port(), 0);
    assert!(server.base_url().starts_with("http://127.0.0.1:"));
    let pid = server.pid().expect("running");
    assert_eq!(get(&server), format!("pid {pid}"));
}

#[test]
fn a_crashed_server_comes_back_on_the_same_port() {
    let mut server = ServerProcess::spawn(ServerSpec::new(PROBE)).expect("spawn the probe");
    let (addr, first) = (server.addr(), server.pid().expect("running"));
    let status = crash_and_restart(&mut server).expect("crash and restart");
    assert!(!status.success(), "SIGKILL is not a clean exit");
    let second = server.pid().expect("running again");
    assert_ne!(first, second);
    assert_eq!(server.addr(), addr);
    assert_eq!(get(&server), format!("pid {second}"));
    server.stop().expect("SIGTERM");
    assert!(server.restart().is_ok());
}

#[test]
fn a_server_that_exits_before_it_is_ready_is_an_error() {
    let error = ServerProcess::spawn(ServerSpec::new("/bin/false")).expect_err("never ready");
    assert!(error.to_string().contains("before it was ready"), "{error}");
}
