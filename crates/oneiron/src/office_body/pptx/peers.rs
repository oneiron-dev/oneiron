//! Two Loro peers of one deck body, as the OF-510 deck gate's step 4 merges
//! them (FIX 3773). The gate's runner lives in docedit, which links no Loro;
//! `deck-gate-engine` (this crate's bin) hands it this merge, the engine's
//! own body path: the body born from a deck ([`doc::birth`]), each peer's
//! operations applied to the deck it reads and written back by the one
//! writer ([`doc::sync_to`]) with the log appended, the second peer's edit
//! admitted against the base as `Vault::edit_pptx_body` admits an
//! edit read at an older frontier ([`doc::admit`]), and the merged body
//! validated and read back ([`doc::read`]).

use super::{doc, log};
use loro::{ExportMode, LoroDoc};
use oneiron_docedit::live::{DeckOp, LiveDeck, StampedOp};

/// `a`'s and `b`'s operations, each applied in its own peer of one body
/// forked at `base`'s frontier, and the two peers merged into that body in
/// both import orders (a then b, b then a), each read back as a deck, or
/// the engine's reason it refused that order. The outer error is a body
/// that could not be made or a peer whose own edit did not apply.
pub fn merge_deck_peers(
    base: &LiveDeck,
    a: &[DeckOp],
    b: &[DeckOp],
) -> std::result::Result<[std::result::Result<LiveDeck, String>; 2], String> {
    let text = |error: crate::error::Error| error.to_string();
    let origin = LoroDoc::new();
    doc::birth(&origin, base).map_err(text)?;
    origin.commit();
    let frontier = origin.oplog_frontiers();
    let before = origin.oplog_vv();
    let peer = |actor: &str, ops: &[DeckOp]| -> std::result::Result<Vec<u8>, String> {
        let fork = origin
            .fork_at(&frontier)
            .map_err(|error| format!("fork at the base: {error}"))?;
        fork.set_peer_id(LoroDoc::new().peer_id())
            .map_err(|error| format!("peer id: {error}"))?;
        let mut body = doc::read(&fork).map_err(text)?;
        let stamped: Vec<StampedOp> = ops
            .iter()
            .enumerate()
            .map(|(at, op)| StampedOp {
                made_by: actor.to_owned(),
                at: at as u64,
                op: op.clone(),
            })
            .collect();
        for op in &stamped {
            body.deck
                .apply(op)
                .map_err(|error| format!("{actor}: {error}"))?;
        }
        doc::sync_to(&fork, &body.deck).map_err(text)?;
        doc::append_log(&fork, &log::logged(&fork, &stamped)).map_err(text)?;
        fork.commit();
        fork.export(ExportMode::updates(&before))
            .map_err(|error| format!("{actor}: update export: {error}"))
    };
    let updates = [peer("peer-a", a)?, peer("peer-b", b)?];
    let merged = |first: usize| -> std::result::Result<LiveDeck, String> {
        let second = 1 - first;
        let head = origin
            .fork_at(&frontier)
            .map_err(|error| format!("fork at the base: {error}"))?;
        head.import(&updates[first])
            .map_err(|error| format!("import: {error}"))?;
        // The second peer read the body at the base, now older than the head.
        doc::admit(&origin, &head, [a, b][second]).map_err(text)?;
        head.import(&updates[second])
            .map_err(|error| format!("import: {error}"))?;
        doc::validate(&head).map_err(text)?;
        Ok(doc::read(&head).map_err(text)?.deck)
    };
    Ok([merged(0), merged(1)])
}
