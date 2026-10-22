//! Step 4's convergence case (FIX 3773): two Loro peers of one deck body,
//! each forked at the merge base's frontier, edit it concurrently and are
//! merged in both import orders through the engine's own body path (its
//! birth, writer, opaque admission and read; `oneiron::office_body::
//! merge_deck_peers`). Peer A adds a shape and moves the free shape; peer B
//! adds a shape and rewrites the free shape's text. Both orders must read
//! back as one deck, every node's children in one order, with both peers'
//! work, no dangling reference, and one export, each order's kept as a
//! candidate. This is CRDT convergence, unlike the fork-replay cases'
//! landing-order evidence. A runner built without the engine (docedit's own
//! `deck-gate-cases`) cannot merge Loro peers and says so: inconclusive.

use super::super::checks::dangling;
use super::super::edits::{Ids, add, body, frame, shifted};
use super::super::record::Res;
use super::evidence::{Evidence, differences, export_over};
use super::{ORDERS, Prepared};
use crate::edit::Preset;
use crate::live::deck_export::StepOutcome;
use crate::live::oracle_run::PeerMerge;
use crate::live::{DeckOp, LiveDeck, NodeKind};

/// The case's outcome; an `Err` is a failure.
pub(super) fn loro_peers(
    engine: Option<PeerMerge>,
    p: &Prepared,
    evidence: &mut Evidence,
) -> Res<StepOutcome> {
    let Some(engine) = engine else {
        return Ok(StepOutcome::Inconclusive(
            "not run: this runner has no Loro body; the gate's engine half runs deck-gate-engine (crates/oneiron)"
                .to_owned(),
        ));
    };
    let mut ids = Ids::above(&p.head);
    let (na, nb) = (ids.mint(), ids.mint());
    let moved = shifted(p.head.nodes[&p.free].geometry);
    let rewritten = body(&mut ids, "Free shape, peer B");
    let mut side = |node, preset, y, label: &str| {
        vec![
            add(node, p.slide, NodeKind::Shape, label, Some(preset), None),
            DeckOp::SetGeometry {
                node,
                geometry: frame(4_572_000, y, 1_828_800, 685_800),
            },
            DeckOp::SetText {
                node,
                body: body(&mut ids, label),
            },
        ]
    };
    let mut a = side(na, Preset::Rect, 914_400, "Peer A shape");
    let mut b = side(nb, Preset::Ellipse, 1_828_800, "Peer B shape");
    a.push(DeckOp::SetGeometry {
        node: p.free,
        geometry: moved,
    });
    b.push(DeckOp::SetText {
        node: p.free,
        body: rewritten.clone(),
    });
    let merged = engine(&p.head, &a, &b)?;
    let mut decks: Vec<LiveDeck> = Vec::new();
    let mut failures = Vec::new();
    for (order, result) in ORDERS.into_iter().zip(merged) {
        match result {
            Ok(deck) => {
                if let Err(why) = dangling(&deck) {
                    failures.push(format!("{order}: {why}"));
                }
                let export = export_over(&deck, &p.package, order);
                if let Err(why) = &export {
                    failures.push(why.clone());
                }
                evidence.keep(order, export.map(|outcome| outcome.bytes));
                decks.push(deck);
            }
            Err(why) => {
                failures.push(format!("{order}: the engine refused the merge: {why}"));
                evidence.keep(order, Err(why));
            }
        }
    }
    if let [x, y] = decks.as_slice() {
        let found = differences(x, y);
        if !found.is_empty() {
            failures.push(format!(
                "the two import orders read back different decks: {}",
                found.join("; ")
            ));
        }
        if evidence.same_exports() == Some(false) {
            failures.push("the two import orders export different bytes".to_owned());
        }
        for (order, deck) in ORDERS.into_iter().zip([x, y]) {
            let free = deck.nodes.get(&p.free);
            let kept = [na, nb].iter().all(|node| deck.nodes.contains_key(node))
                && free.is_some_and(|node| node.geometry == moved)
                && deck.texts.get(&p.free).map(|text| text.plain()) == Some(rewritten.plain());
            if !kept {
                failures.push(format!(
                    "{order}: the merge does not hold both peers' work (two new shapes, peer A's geometry and peer B's text of the free shape)"
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(StepOutcome::Passed)
    } else {
        Err(failures.join("; "))
    }
}
