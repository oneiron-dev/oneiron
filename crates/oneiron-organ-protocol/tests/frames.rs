//! A frame is bounded by what it decodes to, not only by its bytes: a peer
//! cannot make the other side materialize gigabytes from a compact frame.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::{
    FrameError, FromOrgan, MAX_FRAME_VALUES, Notes, Outcome, Proposal, Reply, recv_frame,
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
