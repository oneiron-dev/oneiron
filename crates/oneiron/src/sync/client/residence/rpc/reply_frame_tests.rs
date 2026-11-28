//! How a residence RPC reads the home's refusal of the rest of an answer
//! (REVIEW-10640 round 2): the live-query lane sends it as one frame numbered
//! 0 and last, in place of whichever chunk was due, and a touch asks again.

use serde_json::{Value, json};

use super::{
    CallReply, HomeRefused, ReplyFrame, RequestEnvelope, RpcFault, TouchFault, reply_frame,
};
use crate::sync::transport::TAG_RPC;

const CALL: u64 = 7;

/// A reply frame as the live-query lane packs one: the tag, then the named
/// envelope.
fn frame(kind: &'static str, id: u64, seq: u64, last: bool, payload: Value) -> Vec<u8> {
    let mut frame = vec![TAG_RPC];
    frame.extend(
        rmp_serde::to_vec_named(&RequestEnvelope {
            kind,
            id,
            seq,
            last,
            payload,
        })
        .expect("the envelope encodes"),
    );
    frame
}

fn result_changed() -> Value {
    json!({"code": "RESULT_CHANGED", "message": "the result changed"})
}

fn refusal(code: &str) -> HomeRefused {
    HomeRefused {
        code: Some(code.to_owned()),
    }
}

#[test]
fn a_refusal_in_place_of_a_later_chunk_replaces_the_answer() {
    let refusal = frame("rpc.err", CALL, 0, true, result_changed());
    for due in [1, 5] {
        assert!(
            matches!(
                reply_frame(&refusal, CALL, due),
                Ok(ReplyFrame::Replaced(HomeRefused { code: Some(code) })) if code == "RESULT_CHANGED"
            ),
            "the home's RESULT_CHANGED where chunk {due} was due replaces the answer"
        );
    }
}

#[test]
fn a_touch_asks_again_when_the_rest_of_its_answer_is_refused() {
    assert!(matches!(
        CallReply::Replaced(refusal("RESULT_CHANGED")).into_touch(),
        Err(TouchFault::Withdrawn)
    ));
    assert!(matches!(
        CallReply::Replaced(refusal("INDEX_REVISION_CHANGED")).into_touch(),
        Err(TouchFault::Other(_))
    ));
    // Every caller but a touch reads a replaced answer as before: the home's
    // fault.
    assert!(matches!(
        CallReply::Replaced(refusal("RESULT_CHANGED")).into_call(),
        Err(RpcFault::Remote(_))
    ));
}

#[test]
fn every_other_frame_out_of_turn_still_breaks_the_reply() {
    let out_of_turn = [
        frame("rpc.res", CALL, 0, true, json!("ab")),
        frame("rpc.err", CALL, 0, false, result_changed()),
        frame("rpc.err", CALL, 2, true, result_changed()),
        frame("rpc.err", CALL + 1, 0, true, result_changed()),
    ];
    for sent in &out_of_turn {
        assert!(matches!(
            reply_frame(sent, CALL, 1),
            Err(RpcFault::Remote(_))
        ));
    }
    let answer_refused = frame("rpc.err", CALL, 0, true, result_changed());
    assert!(matches!(
        reply_frame(&answer_refused, CALL, 0),
        Ok(ReplyFrame::Refused(HomeRefused { code: Some(code) })) if code == "RESULT_CHANGED"
    ));
    let chunk = frame("rpc.res", CALL, 1, false, json!("ab"));
    assert!(matches!(
        reply_frame(&chunk, CALL, 1),
        Ok(ReplyFrame::Chunk { bytes, last: false }) if bytes == b"ab"
    ));
}
