//! FIX LIVE-MIRROR-CROSS-MONTH-EDGE-SOURCE-DROPPED: the write door queues an
//! edge by its source row, and an edge from a BASE row to a world's row rides
//! that world's window of the target's birth month. The live pass kept a
//! queued row only when it was learned in the window's month, so an edge from
//! a base row learned in an earlier month never reached a loaded world window
//! until that window was rebuilt.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use crate::sync::WindowKey;
use crate::sync::bridge::{Materializer, format_edge_key};
use crate::sync::manager::WindowManager;
use crate::temporal::TimeRange;

/// The month the earlier base row was learned in.
const EARLIER_MONTH: &str = "2025-11";
/// The month the world's claim was learned in: its world window's month.
const WORLD_MONTH: &str = "2026-02";
/// How often the live window's document is read while the mirror runs.
const POLL: Duration = Duration::from_millis(20);

/// What a loaded world window held after one batch wrote two base→world edges.
pub struct CrossMonthEdgeMirror {
    /// The world's claim was in the window's document once the window opened.
    pub target_loaded: bool,
    /// Neither edge was in the document before the batch committed.
    pub edges_absent_before_write: bool,
    /// The edge from the base row learned in the window's month reached the
    /// document (the live pass ran over the batch).
    pub same_month_edge_mirrored: bool,
    /// The edge from the base row learned in an earlier month reached the
    /// document.
    pub earlier_month_edge_mirrored: bool,
    /// The earlier base row itself entered the world window's document.
    pub earlier_base_row_in_window: bool,
}

/// One row stamped `at` for both its occurrence and its learning.
fn instant(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Writes a WORLD and a claim of that world learned in [`WORLD_MONTH`], a
/// base PERSON learned in that same month and one learned in
/// [`EARLIER_MONTH`], and opens the world's window of the claim's month in a
/// live manager over `vault`. Then one batch writes an edge from each PERSON
/// to the claim through the write door, which queues each edge by its source.
/// The window's document is read until both edges are there or `wait` ends.
///
/// # Errors
///
/// A row that does not write, a window that does not open, or a batch that
/// does not commit.
pub fn base_edges_into_live_world_window(
    vault: &Arc<Vault>,
    wait: Duration,
) -> Result<CrossMonthEdgeMirror> {
    let world_month = WindowKey::new(WORLD_MONTH);
    let earlier_at = WindowKey::new(EARLIER_MONTH)
        .start_timestamp()
        .ok_or(Error::InvariantViolation("the earlier month has no start"))?
        + 60;
    let world_at = world_month
        .start_timestamp()
        .ok_or(Error::InvariantViolation("the world month has no start"))?
        + 60;
    let (world, claim, same_month_person, earlier_person) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    vault.put_entity(
        &earlier_person,
        ENTITY_TYPE_PERSON,
        instant(earlier_at),
        earlier_at,
        b"earlier base person",
    )?;
    vault.put_entity(
        &same_month_person,
        ENTITY_TYPE_PERSON,
        instant(world_at),
        world_at,
        b"same-month base person",
    )?;
    vault.put_entity(
        &world,
        ENTITY_TYPE_WORLD,
        instant(world_at),
        world_at,
        b"world",
    )?;
    let mut body = ClaimBody::new(
        "test.world_fact",
        ClaimSubject::Entity(same_month_person),
        rmpv::Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.world = Some(world);
    vault.put_claim(&claim, &body, instant(world_at), world_at)?;

    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "live-mirror-cross-month-edge",
    ));
    let key = WindowKey::for_month_world(&world_month, world);
    let window = manager.open_window(&key)?;
    let entities = window.doc.get_map("entities");
    let edges = window.doc.get_map("edges");
    let same_month_edge = format_edge_key(&same_month_person, EdgeKind::Mentions, &claim);
    let earlier_month_edge = format_edge_key(&earlier_person, EdgeKind::Mentions, &claim);
    let target_loaded = entities.get(&claim.to_hex()).is_some();
    let edges_absent_before_write =
        edges.get(&same_month_edge).is_none() && edges.get(&earlier_month_edge).is_none();

    vault
        .batch()
        .edge(&same_month_person, EdgeKind::Mentions, &claim, 1.0)
        .edge(&earlier_person, EdgeKind::Mentions, &claim, 1.0)
        .commit()?;

    let deadline = Instant::now() + wait;
    let (mut same_month_edge_mirrored, mut earlier_month_edge_mirrored) = (false, false);
    loop {
        same_month_edge_mirrored =
            same_month_edge_mirrored || edges.get(&same_month_edge).is_some();
        earlier_month_edge_mirrored =
            earlier_month_edge_mirrored || edges.get(&earlier_month_edge).is_some();
        if (same_month_edge_mirrored && earlier_month_edge_mirrored) || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL);
    }
    let earlier_base_row_in_window = entities.get(&earlier_person.to_hex()).is_some();
    Ok(CrossMonthEdgeMirror {
        target_loaded,
        edges_absent_before_write,
        same_month_edge_mirrored,
        earlier_month_edge_mirrored,
        earlier_base_row_in_window,
    })
}
