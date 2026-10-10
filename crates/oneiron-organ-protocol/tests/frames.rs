//! A frame is bounded by what it decodes to, not only by its bytes: a peer
//! cannot make the other side materialize gigabytes from a compact frame.
//! And a frame's deadline ends with the frame, while an untimed frame keeps
//! to whatever the caller set on its socket.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::{
    DEFAULT_FRAME_LIMIT, FrameError, FromOrgan, MAX_FRAME_VALUES, Notes, Outcome, Proposal, Reply,
    recv_frame, recv_frame_until, send_frame, send_frame_until,
};

/// A valid reply whose report is an array of `count` nils: one byte each on
/// the wire, dozens each once decoded.
fn reply_of_nils(count: u32) -> Vec<u8> {
    let reply = FromOrgan::Reply(Reply {
        id: 1,
        outcome: Outcome::Proposal(Proposal {
            body: None,
            outputs: Vec::new(),
            report: rmpv::Value::Nil,
            notes: Notes::default(),
        }),
    });
    let encoded = rmp_serde::to_vec_named(&reply).expect("encode");
    let key = b"\xa6report\xc0";
    let at = encoded
        .windows(key.len())
        .position(|window| window == key)
        .expect("the report field")
        + key.len()
        - 1;
    let mut body = encoded[..at].to_vec();
    body.push(0xdd);
    body.extend(count.to_be_bytes());
    body.extend(std::iter::repeat_n(0xc0, count as usize));
    body.extend(&encoded[at + 1..]);
    let mut frame = u32::try_from(body.len())
        .expect("len")
        .to_le_bytes()
        .to_vec();
    frame.extend(body);
    frame
}

#[test]
fn a_compact_frame_that_unfolds_into_millions_of_values_is_refused() {
    let (mut organ, engine) = UnixStream::pair().expect("pair");
    let count = u32::try_from(MAX_FRAME_VALUES).expect("fits") + 1;
    let frame = reply_of_nils(count);
    let writer = std::thread::spawn(move || organ.write_all(&frame));
    let started = Instant::now();
    let refused = recv_frame::<FromOrgan>(&engine, 64 * 1024 * 1024);
    assert!(
        matches!(refused, Err(FrameError::Protocol(_))),
        "{refused:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(engine);
    let _ = writer.join();

    // The same shape, small, still decodes.
    let (mut organ, engine) = UnixStream::pair().expect("pair");
    organ.write_all(&reply_of_nils(1000)).expect("write");
    let (reply, _) = recv_frame::<FromOrgan>(&engine, 64 * 1024 * 1024).expect("decode");
    let FromOrgan::Reply(Reply {
        outcome: Outcome::Proposal(proposal),
        ..
    }) = reply
    else {
        panic!("a proposal");
    };
    assert_eq!(proposal.report.as_array().map(Vec::len), Some(1000));
}

#[test]
fn a_timed_frame_leaves_no_timeout_behind() {
    let (ours, theirs) = UnixStream::pair().expect("pair");
    let soon = Some(Instant::now() + Duration::from_millis(50));
    send_frame_until(&ours, &1u8, &[], DEFAULT_FRAME_LIMIT, soon).expect("timed send");
    let (one, _) = recv_frame_until::<u8>(&theirs, DEFAULT_FRAME_LIMIT, soon).expect("timed recv");
    assert_eq!(one, 1);
    // Untimed frames afterwards wait as long as their peer needs, on the
    // same socket or a clone of it.
    let sender = ours.try_clone().expect("clone");
    let late = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        send_frame(&sender, &2u8, &[], DEFAULT_FRAME_LIMIT)
    });
    let (two, _) =
        recv_frame::<u8>(&theirs, DEFAULT_FRAME_LIMIT).expect("an untimed receive waits");
    assert_eq!(two, 2);
    late.join().expect("sender").expect("sent");
    let reader = theirs.try_clone().expect("clone");
    let slow = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        recv_frame::<String>(&reader, DEFAULT_FRAME_LIMIT)
    });
    // Far larger than the socket buffer: the send waits for the reader.
    let big = "x".repeat(4 * 1024 * 1024);
    send_frame(&ours, &big, &[], DEFAULT_FRAME_LIMIT).expect("an untimed send waits");
    let (got, _) = slow.join().expect("reader").expect("frame");
    assert_eq!(got.len(), big.len());
}

#[test]
fn an_untimed_frame_ends_where_the_callers_socket_says() {
    // The caller's own receive timeout ends an untimed read (round-4 repro).
    let (_ours, theirs) = UnixStream::pair().expect("pair");
    theirs
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("timeout");
    let (done, ended) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(recv_frame::<u8>(&theirs, DEFAULT_FRAME_LIMIT).map(|(n, _)| n));
    });
    let got = ended
        .recv_timeout(Duration::from_secs(5))
        .expect("the read ends at the socket's timeout");
    assert!(matches!(got, Err(FrameError::Io(_))), "{got:?}");

    // So does a nonblocking socket with nothing to read.
    let (_ours, theirs) = UnixStream::pair().expect("pair");
    theirs.set_nonblocking(true).expect("nonblocking");
    let (done, ended) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(recv_frame::<u8>(&theirs, DEFAULT_FRAME_LIMIT).map(|(n, _)| n));
    });
    let got = ended
        .recv_timeout(Duration::from_secs(5))
        .expect("the read returns at once");
    assert!(
        matches!(&got, Err(FrameError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock),
        "{got:?}"
    );
}
