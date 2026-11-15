//! A selector answer leaves a socket only while what it was made under still
//! stands (SELECTOR-RELEASE-POINT = B, a lead ruling, Sun 15 Nov 19:26).
//! ARCH-0040: "Guest revocation narrows immediately and host-alone;
//! already-synced copies are disclosed honestly". ARCH-0077: "Revocation is
//! not rollback. Queued work follows the current Grant decision". Bytes still
//! in this server's queue are not synced copies.
//!
//! - The basis ([`oneiron::sync::SelectorReleaseBasis`]) is the grant's live
//!   bytes while it confers read, the authority fold and the reach its member
//!   reads relationship labels with, read where the answer is made, before it
//!   is filtered.
//! - A socket keeps each queued answer's basis under a token the server mints
//!   (a client may reuse a request id) and tags each frame of the answer
//!   with it. The tag is never a peer wire tag: the socket's release strips
//!   it before every other door.
//! - The release judges the basis once per answer, at its first frame, before
//!   any part of it leaves. The later frames of an answer that stood go as it
//!   was judged; an answer that did not stand sends none.
//! - A federation UPDATE that does not stand is not sent, and its window's
//!   ready request is owed again; a residence reply is replaced by
//!   RESULT_CHANGED.

use std::collections::HashMap;

use base64::Engine;
use oneiron::Vault;
pub(crate) use oneiron::sync::SelectorReleaseBasis;

/// First byte of a queued selector answer on a socket's own direct queue: no
/// wire tag uses it, and the routed app marker is 255.
const SELECTOR_ANSWER: u8 = 254;
/// Marker, token and the last-frame flag.
const HEADER: usize = 10;
/// The longest encoded selector a residence call binds
/// (`livequery/residence.rs` `bound_selector`).
const MAX_ENCODED_SELECTOR: usize = 8192;

/// The basis of a residence call whose params name an encoded selector at
/// their top. `None` when they name none, or one that does not decode, which
/// the call itself refuses with no rows.
pub(crate) fn residence_basis(
    vault: &Vault,
    params: &serde_json::Value,
) -> Option<SelectorReleaseBasis> {
    let encoded = params.get("selector")?.as_str()?;
    if encoded.len() > MAX_ENCODED_SELECTOR {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let selector = oneiron::sync::decode_sync_selector(&bytes).ok()?;
    Some(SelectorReleaseBasis::take(vault, selector.grant_id))
}

/// A socket's queued selector answers, by token. They go with the socket.
#[derive(Default)]
pub(crate) struct SelectorAnswers {
    next: u64,
    queued: HashMap<u64, Judged>,
}

enum Judged {
    Waiting(Box<SelectorReleaseBasis>),
    Stood,
}

/// One frame of a queued selector answer, as its release reads it.
pub(crate) struct QueuedAnswerFrame<'a> {
    token: u64,
    last: bool,
    /// The frame as it was made: a window sync frame or a routed reply.
    pub(crate) frame: &'a [u8],
}

impl SelectorAnswers {
    /// The frames of one answer made under `basis`, tagged for the release.
    pub(crate) fn queue(
        &mut self,
        basis: SelectorReleaseBasis,
        frames: Vec<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        if frames.is_empty() {
            return frames;
        }
        self.next += 1;
        let token = self.next;
        // A test commits its change here, in the gap between the answer's
        // queue and its release.
        #[cfg(oneiron_test_support)]
        crate::test_doors::selector_release::run(basis.grant_id());
        self.queued.insert(token, Judged::Waiting(Box::new(basis)));
        let count = frames.len();
        frames
            .into_iter()
            .enumerate()
            .map(|(at, frame)| tagged(token, at + 1 == count, frame))
            .collect()
    }

    /// Whether `frame` leaves: its answer's basis, judged at the answer's
    /// first frame, stood then. An answer that did not stand sends no
    /// further frame, and an unknown token fails closed.
    pub(crate) fn release(&mut self, vault: &Vault, frame: &QueuedAnswerFrame<'_>) -> bool {
        let stands = match self.queued.remove(&frame.token) {
            Some(Judged::Stood) => true,
            Some(Judged::Waiting(basis)) => basis.stands(vault),
            None => false,
        };
        if stands && !frame.last {
            self.queued.insert(frame.token, Judged::Stood);
        }
        stands
    }
}

/// `data` as a queued selector answer's frame, or `None` when it is not one.
pub(crate) fn queued_answer_frame(data: &[u8]) -> Option<QueuedAnswerFrame<'_>> {
    if data.first() != Some(&SELECTOR_ANSWER) || data.len() < HEADER {
        return None;
    }
    Some(QueuedAnswerFrame {
        token: u64::from_be_bytes(data[1..9].try_into().ok()?),
        last: data[9] != 0,
        frame: &data[HEADER..],
    })
}

fn tagged(token: u64, last: bool, frame: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::with_capacity(HEADER + frame.len());
    data.push(SELECTOR_ANSWER);
    data.extend_from_slice(&token.to_be_bytes());
    data.push(u8::from(last));
    data.extend(frame);
    data
}
