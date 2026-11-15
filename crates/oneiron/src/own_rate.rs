//! Node-local OF-520 own-rate windows. An own actor's acts count per window,
//! and the first crossing of the advisory threshold in a window leaves one
//! typed check. A check never refuses, holds or narrows the act that crossed.
use crate::{EntityId, Result, Vault};

use crate::store::own_rate_rows::{CHECKS, check_kept, checks_in_order_after};
pub(crate) use crate::store::own_rate_rows::{
    count_in_txn, erase_check_actor_in_txn, erase_window_actor_in_txn, observe_in_txn,
};

pub(crate) use crate::store::own_rate_record::OwnRate;
pub use crate::store::own_rate_record::OwnRateKind;

/// The Dreamer's auto-write rate: 1000 Auto claims an hour per agent actor.
const AUTO_WRITE: OwnRate = OwnRate {
    threshold: 1000,
    window_seconds: 3600,
};

#[cfg(test)]
thread_local! {
    static AUTO_WRITE_THRESHOLD: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test seam: lowers this thread's auto-write threshold until reset with None.
#[cfg(test)]
pub(crate) fn set_auto_write_threshold_for_test(threshold: Option<u64>) {
    AUTO_WRITE_THRESHOLD.with(|cell| cell.set(threshold));
}

pub(crate) fn auto_write_rate() -> OwnRate {
    #[cfg(test)]
    if let Some(threshold) = AUTO_WRITE_THRESHOLD.with(std::cell::Cell::get) {
        return OwnRate {
            threshold,
            ..AUTO_WRITE
        };
    }
    AUTO_WRITE
}

/// Declares [`AutoWriteDoor`] and its `ALL` list from one list of doors, so
/// the check that walks the list cannot miss a door the enum names.
#[cfg(test)]
macro_rules! auto_write_doors {
    ($($(#[doc = $doc:literal])* $door:ident,)*) => {
        /// Every door through which the Dreamer's consolidation writer lands
        /// an Auto claim. Each counts its write on the Dreamer actor's
        /// window and names itself here as it does.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum AutoWriteDoor {
            $($(#[doc = $doc])* $door,)*
        }

        impl AutoWriteDoor {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$door,)*];
        }
    };
}

#[cfg(test)]
auto_write_doors! {
    /// `promote_one`: unscoped and scoped promotions, and the conflict closes
    /// routed through them.
    Promotion,
    /// `attach_ref`: a new evidence assertion on a claim that already stands.
    Attachment,
    /// `grant_deferred_claim_auto_after`: a replacement a Dreamer run parked,
    /// granted Auto through the public or the scoped grant door.
    DeferredGrant,
}

#[cfg(test)]
thread_local! {
    static COUNTED_AUTO_WRITES: std::cell::RefCell<Vec<AutoWriteDoor>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Notes that `door` just counted an Auto write.
#[cfg(test)]
pub(crate) fn counted_auto_write(door: AutoWriteDoor) {
    COUNTED_AUTO_WRITES.with(|doors| doors.borrow_mut().push(door));
}

/// The doors that counted on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_counted_auto_writes() -> Vec<AutoWriteDoor> {
    COUNTED_AUTO_WRITES.with(|doors| std::mem::take(&mut *doors.borrow_mut()))
}

pub use crate::store::own_rate_record::OwnRateCheck;

/// One kept crossing, as the host's OF-520 health check reads it in keeping
/// order (ARCH-0044 C5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptOwnRateCheck {
    /// Its place in keeping order, to read past next: the recorded time it
    /// was kept at (16 hex) and its store-local id (32 hex).
    pub cursor: String,
    /// The recorded time it was kept at.
    pub kept_at: u64,
    pub check: OwnRateCheck,
}

fn order_cursor(kept_at: u64, id: EntityId) -> String {
    format!("{kept_at:016x}{}", id.to_hex())
}

fn parse_order_cursor(cursor: &str) -> Result<(u64, EntityId)> {
    let corrupt = || crate::Error::CorruptedIndex("own rate check cursor");
    let (kept_at, id) = cursor.split_at_checked(16).ok_or_else(corrupt)?;
    let kept_at = u64::from_str_radix(kept_at, 16).map_err(|_| corrupt())?;
    Ok((kept_at, EntityId::from_hex(id).map_err(|_| corrupt())?))
}

/// The subject prefix every own-rate health check shares.
const HEALTH_CHECK_SUBJECT: &str = "own_rate:";

/// The subject prefix every verdict-spend health check shares: one check
/// per caller (`spend:ai.verdict:<caller>`, built by the server's
/// `wire_health::evidence::raise_verdict_spend`).
const SPEND_CHECK_SUBJECT: &str = "spend:ai.verdict:";

/// The subject prefix every wire call-volume health check shares: one
/// check per crossed set's revision (`wire:<set>:<sequence>`, built by the
/// server's `wire_health::evidence::wire_crossing`), naming every actor
/// past its row.
const WIRE_CHECK_SUBJECT: &str = "wire:";

/// The subject prefix every `[limits]` health check shares: one check per
/// row (`limit:<row>`, built by the server's
/// `wire_health::evidence::limit_crossing`), naming the owners whose work
/// crossed it in its summary's `owners`.
const LIMIT_CHECK_SUBJECT: &str = "limit:";

/// The mark an actor's health erase leaves under the health checks' own
/// prefix, in its own transaction, so a later fold of a crossing kept
/// before the erase (or counted from a live window after it) drops the
/// actor instead of naming it again (FIX 3520). The key is the actor's
/// hash (see [`health_erased_key`]), never the actor itself.
const HEALTH_ERASED_ACTOR: &str = "wire:health:v1:erased:";

/// The summary kind of a verdict-spend crossing, which names its caller
/// apart from the grant rule's `actors`, as an own-rate summary names its
/// actor. Mirrors the literal the server's
/// `wire_health::evidence::raise_verdict_spend` keeps; the health erase
/// test fails if they drift apart.
pub(crate) const VERDICT_SPEND_KIND: &str = "ai.verdict.spend";

/// The subject the host's OF-520 health check keeps one own actor's
/// crossings of one kind under (ARCH-0044 C5): `own_rate:<kind>:<actor>`.
/// An answer covers that actor's next crossings of the kind.
pub fn health_check_subject(kind: OwnRateKind, actor: &str) -> String {
    format!("{HEALTH_CHECK_SUBJECT}{}:{actor}", kind.token())
}

/// The key of `actor`'s erased mark ([`HEALTH_ERASED_ACTOR`]): the first
/// half of its hex's hash, as the wire crossed set's subject is a hash, so
/// the mark itself names no one.
fn health_erased_key(actor: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(actor.as_bytes());
    format!("{HEALTH_ERASED_ACTOR}{}", &hasher.finalize().to_hex()[..32])
}

/// What the host's health check asks an own-rate crossing with (ARCH-0044
/// C5): the window, its count and threshold, and the actor, named apart from
/// the grant rule's `actors`, as a spend check names its caller. An actor's
/// erase finds the asks that carry its crossings by this shape.
#[must_use]
pub fn health_check_summary(check: &OwnRateCheck) -> serde_json::Value {
    serde_json::json!({
        "kind": OwnRateCheck::KIND,
        "rate": check.kind,
        "actor": check.actor,
        "window_started_at": check.window_started_at,
        "window_seconds": check.window_seconds,
        "count": check.count,
        "threshold": check.threshold,
    })
}

/// The crossing a health check binds its answer to, the value of its
/// `wire.health.crossing` unit claim: an own-rate summary
/// ([`health_check_summary`]) without its actor, a verdict-spend summary
/// without its caller, a wire summary without any actor, a limit summary
/// without its owners, and any other summary as it is. The claim is
/// canonical and outlives the check, and an actor's erase (FIX 3520) does
/// not reach it, so it never names an actor, whether it is bound before
/// that erase or by a pass that asks after it: the burst it keeps is no
/// one's, and its shape never shifts under an erase. The check and the
/// ask, which the erase takes, name the actors.
#[must_use]
pub fn health_bound_crossing(summary: &serde_json::Value) -> serde_json::Value {
    let mut bound = summary.clone();
    if let Some(fields) = bound.as_object_mut()
        && fields.get("kind").and_then(serde_json::Value::as_str) == Some(OwnRateCheck::KIND)
    {
        fields.remove("actor");
    }
    if is_wire_summary(&bound) {
        retain_wire_summary_actors(&mut bound, |_| false);
    }
    let is_spend =
        bound.get("kind").and_then(serde_json::Value::as_str) == Some(VERDICT_SPEND_KIND);
    if is_spend && let Some(fields) = bound.as_object_mut() {
        fields.remove("caller");
    }
    // A limit summary's owners, like an own-rate actor: a bound crossing
    // with no `owners` is the shape a crossing whose work the host did not
    // know as an owner's already takes.
    if let Some(fields) = bound.as_object_mut() {
        fields.remove("owners");
    }
    bound
}

/// Whether `state` holds the summary of one of `actor`'s own-rate crossings
/// ([`health_check_summary`]) at any depth.
fn names_crossing_of(state: &serde_json::Value, actor: &str) -> bool {
    use serde_json::Value;
    match state {
        Value::Object(fields) => {
            (fields.get("kind").and_then(Value::as_str) == Some(OwnRateCheck::KIND)
                && fields.get("actor").and_then(Value::as_str) == Some(actor))
                || fields.values().any(|field| names_crossing_of(field, actor))
        }
        Value::Array(items) => items.iter().any(|item| names_crossing_of(item, actor)),
        _ => false,
    }
}

/// Whether `state` holds the summary of `actor`'s verdict-spend crossing
/// at any depth: the ask state that names the spend's caller.
fn names_spend_of(state: &serde_json::Value, actor: &str) -> bool {
    use serde_json::Value;
    match state {
        Value::Object(fields) => {
            (fields.get("kind").and_then(Value::as_str) == Some(VERDICT_SPEND_KIND)
                && fields.get("caller").and_then(Value::as_str) == Some(actor))
                || fields.values().any(|field| names_spend_of(field, actor))
        }
        Value::Array(items) => items.iter().any(|item| names_spend_of(item, actor)),
        _ => false,
    }
}

/// Whether `summary` is a wire call-volume crossing (the server's
/// `wire_health::evidence::wire_crossing`): the current shape's
/// `crossed.actors` list, or a stored pre-`crossed` shape's per-caller
/// tool lists, which only a wire summary carries. A stored row of the
/// older shape still decodes, so the erase and the bind must read it as
/// wire too.
fn is_wire_summary(summary: &serde_json::Value) -> bool {
    summary
        .get("crossed")
        .and_then(|crossed| crossed.get("actors"))
        .is_some_and(serde_json::Value::is_array)
        || summary
            .get("actor_tools")
            .is_some_and(serde_json::Value::is_array)
        || summary
            .get("tool_callers")
            .is_some_and(serde_json::Value::is_array)
}

/// Drops every wire actor `keep` refuses from `summary`'s actor lists: the
/// named `actors` rows, the full `crossed.actors` set, the per-caller
/// `actor_tools` rows and each tool's `callers`. A tool left with no caller
/// goes with them; the calls, verbs and refusals stay, since they are no
/// one's. Whether anything went.
fn retain_wire_summary_actors(
    summary: &mut serde_json::Value,
    keep: impl Fn(&str) -> bool,
) -> bool {
    use serde_json::Value;
    let mut changed = false;
    if let Some(rows) = summary.get_mut("actors").and_then(Value::as_array_mut) {
        let before = rows.len();
        rows.retain(|row| row.get("actor").and_then(Value::as_str).is_none_or(&keep));
        changed |= rows.len() != before;
    }
    if let Some(crossed) = summary.get_mut("crossed") {
        if let Some(actors) = crossed.get_mut("actors").and_then(Value::as_array_mut) {
            let before = actors.len();
            actors.retain(|actor| actor.as_str().is_none_or(&keep));
            changed |= actors.len() != before;
        }
    }
    if let Some(rows) = summary.get_mut("actor_tools").and_then(Value::as_array_mut) {
        let before = rows.len();
        rows.retain(|row| row.get("actor").and_then(Value::as_str).is_none_or(&keep));
        changed |= rows.len() != before;
    }
    if let Some(tools) = summary
        .get_mut("tool_callers")
        .and_then(Value::as_array_mut)
    {
        for tool in &mut *tools {
            if let Some(callers) = tool.get_mut("callers").and_then(Value::as_array_mut) {
                let before = callers.len();
                callers.retain(|row| row.get("actor").and_then(Value::as_str).is_none_or(&keep));
                changed |= callers.len() != before;
            }
        }
        let before = tools.len();
        tools.retain(|tool| {
            tool.get("callers")
                .and_then(Value::as_array)
                .is_none_or(|callers| !callers.is_empty())
        });
        changed |= tools.len() != before;
    }
    changed
}

/// Drops `actor` from a wire ask's pack state (the server's
/// `wire_health::state`): its crossing's actor lists and the call's own
/// `actors` rows. The ask stays open over what is left, as the check it was
/// asked for stays too. The grant flag stays as it was while actors are
/// left, a subset of the ones it judged; with none left it is false.
/// Whether anything changed.
fn scrub_wire_pack_state(state: &mut serde_json::Value, actor: &str) -> bool {
    use serde_json::Value;
    if !state.get("crossing").is_some_and(is_wire_summary) {
        return false;
    }
    let mut changed = false;
    if let Some(rows) = state.get_mut("actors").and_then(Value::as_array_mut) {
        let before = rows.len();
        rows.retain(|row| row.get("actor").and_then(Value::as_str) != Some(actor));
        changed |= rows.len() != before;
    }
    let mut crossed_empty = false;
    if let Some(crossing) = state.get_mut("crossing") {
        changed |= retain_wire_summary_actors(crossing, |named| named != actor);
        crossed_empty = crossing
            .get("crossed")
            .and_then(|crossed| crossed.get("actors"))
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
    }
    if crossed_empty {
        if let Some(granted) = state.get_mut("actors_known_under_grant") {
            if granted.as_bool() == Some(true) {
                *granted = Value::Bool(false);
                changed = true;
            }
        }
    }
    changed
}

/// Drops `actor` from a limit ask's pack state: its crossing's `owners`,
/// the owners whose work crossed the row. The ask stays open over the
/// crossing itself, as the check it was asked for stays too. Whether
/// anything changed.
fn scrub_limit_pack_state(state: &mut serde_json::Value, actor: &str) -> bool {
    use serde_json::Value;
    let Some(owners) = state
        .get_mut("crossing")
        .and_then(|crossing| crossing.get_mut("owners"))
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let before = owners.len();
    owners.retain(|owner| owner.as_str() != Some(actor));
    owners.len() != before
}

/// Notes `actor` in `actors`, once.
fn note_health_actor(actors: &mut Vec<String>, actor: &str) {
    if !actors.iter().any(|named| named == actor) {
        actors.push(actor.to_owned());
    }
}

/// Every actor a health crossing's summary names, each once: a wire
/// summary's actor lists (the current and the pre-`crossed` shapes') and
/// a limit summary's `owners`. What a fold judges against the vault's
/// erased marks ([`Vault::health_crossing_drop_erased_in_write_txn`]).
fn health_crossing_actors(summary: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    let mut actors = Vec::new();
    for field in ["actors", "actor_tools"] {
        if let Some(rows) = summary.get(field).and_then(Value::as_array) {
            for row in rows {
                if let Some(actor) = row.get("actor").and_then(Value::as_str) {
                    note_health_actor(&mut actors, actor);
                }
            }
        }
    }
    if let Some(names) = summary
        .get("crossed")
        .and_then(|crossed| crossed.get("actors"))
        .and_then(Value::as_array)
    {
        for actor in names.iter().filter_map(Value::as_str) {
            note_health_actor(&mut actors, actor);
        }
    }
    if let Some(tools) = summary.get("tool_callers").and_then(Value::as_array) {
        for tool in tools {
            if let Some(callers) = tool.get("callers").and_then(Value::as_array) {
                for row in callers {
                    if let Some(actor) = row.get("actor").and_then(Value::as_str) {
                        note_health_actor(&mut actors, actor);
                    }
                }
            }
        }
    }
    if let Some(owners) = summary.get("owners").and_then(Value::as_array) {
        for actor in owners.iter().filter_map(Value::as_str) {
            note_health_actor(&mut actors, actor);
        }
    }
    actors
}

/// The value `key` holds in the msgpack map `value`, when it is one
/// holding it.
fn rmpv_map_get_mut<'a>(value: &'a mut rmpv::Value, key: &str) -> Option<&'a mut rmpv::Value> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter_mut()
        .find(|entry| entry.0.as_str() == Some(key))
        .map(|entry| &mut entry.1)
}

/// The value `key` holds in the msgpack map `value`, when it is one
/// holding it.
fn rmpv_map_get<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, field)| field)
}

/// Whether the msgpack map `row` names `actor` under `field`.
fn rmpv_row_names_actor(row: &rmpv::Value, field: &str, actor: &str) -> bool {
    rmpv_map_get(row, field).and_then(rmpv::Value::as_str) == Some(actor)
}

/// Whether the msgpack map `tool` keeps a callers list that is now empty.
fn rmpv_callers_emptied(tool: &rmpv::Value) -> bool {
    matches!(
        rmpv_map_get(tool, "callers"),
        Some(rmpv::Value::Array(callers)) if callers.is_empty()
    )
}

/// The check body `body` with `actor` dropped from its crossing's actor
/// lists, when it names it: a wire crossing's lists, the same ones
/// [`retain_wire_summary_actors`] scrubs, in their current and their
/// pre-`crossed` shapes alike, and a limit crossing's `owners`. The
/// caller has the row's subject, so the lists are scrubbed whenever they
/// stand, never by a shape marker a stored older row lacks. The host
/// keeps the check under its own shape, which this crate cannot name, so
/// the scrub reads and writes the row's msgpack plainly and touches only
/// those lists. `None` when the row names no one going.
fn scrub_health_check_body(body: &[u8], actor: &str) -> Result<Option<Vec<u8>>> {
    let mut rest = &body[..];
    let mut check = rmpv::decode::read_value(&mut rest)
        .map_err(|_| crate::Error::CorruptedIndex("wire health check"))?;
    if !rest.is_empty() {
        return Err(crate::Error::CorruptedIndex("wire health check"));
    }
    let Some(crossing) = rmpv_map_get_mut(&mut check, "crossing") else {
        return Ok(None);
    };
    let mut changed = false;
    if let Some(actors) = rmpv_map_get_mut(crossing, "actors") {
        if let rmpv::Value::Array(rows) = actors {
            let before = rows.len();
            rows.retain(|row| !rmpv_row_names_actor(row, "actor", actor));
            changed |= rows.len() != before;
        }
    }
    if let Some(crossed) = rmpv_map_get_mut(crossing, "crossed") {
        if let Some(actors) = rmpv_map_get_mut(crossed, "actors") {
            if let rmpv::Value::Array(actors) = actors {
                let before = actors.len();
                actors.retain(|named| named.as_str() != Some(actor));
                changed |= actors.len() != before;
            }
        }
    }
    if let Some(tools) = rmpv_map_get_mut(crossing, "actor_tools") {
        if let rmpv::Value::Array(rows) = tools {
            let before = rows.len();
            rows.retain(|row| !rmpv_row_names_actor(row, "actor", actor));
            changed |= rows.len() != before;
        }
    }
    if let Some(by_tool) = rmpv_map_get_mut(crossing, "tool_callers") {
        if let rmpv::Value::Array(tools) = by_tool {
            for tool in &mut *tools {
                if let Some(callers) = rmpv_map_get_mut(tool, "callers") {
                    if let rmpv::Value::Array(callers) = callers {
                        let before = callers.len();
                        callers.retain(|row| !rmpv_row_names_actor(row, "actor", actor));
                        changed |= callers.len() != before;
                    }
                }
            }
            let before = tools.len();
            tools.retain(|tool| !rmpv_callers_emptied(tool));
            changed |= tools.len() != before;
        }
    }
    if let Some(owners) = rmpv_map_get_mut(crossing, "owners") {
        if let rmpv::Value::Array(owners) = owners {
            let before = owners.len();
            owners.retain(|named| named.as_str() != Some(actor));
            changed |= owners.len() != before;
        }
    }
    if !changed {
        return Ok(None);
    }
    let mut scrubbed = Vec::new();
    rmpv::encode::write_value(&mut scrubbed, &check).map_err(|_| {
        crate::Error::InvariantViolation("wire health check MessagePack encode failed")
    })?;
    Ok(Some(scrubbed))
}

/// Erasing `actor` (FIX 3520) out of the host's health checks, in the
/// erase's own transaction. An own-rate check is one actor's, and so is a
/// verdict-spend check, so theirs go: every subject ending in the actor
/// under either prefix. A wire check names every actor past its row, so it
/// stays with the actor dropped from its lists; its calls, verbs and
/// refusals stay, since they are no one's. A limit check likewise stays
/// over its row, with the actor dropped from the owners whose work
/// crossed it. Each ask such a check raised holds its crossing as the
/// state it was asked over: one over an own-rate or spend crossing drops
/// that state and, while open, leaves the owner's queue; one over a wire
/// or limit crossing keeps waiting over the actors left. An ask a pass
/// raises after this erase is the host's to withdraw, when the pass finds
/// its check gone, or to ask again, when the pass finds its crossing
/// scrubbed. The unit claim an ask binds holds no actor
/// ([`health_bound_crossing`]), so there is none to take. The erase also
/// leaves its hashed mark ([`HEALTH_ERASED_ACTOR`]) in this transaction,
/// so a crossing kept before the erase but folded only after it, or one
/// a live window counts the actor into after it, folds without the actor
/// ([`Vault::health_crossing_drop_erased_in_write_txn`]).
///
/// # Errors
///
/// Storage errors, a check row that cannot be read, or an ask row that
/// cannot be read.
pub(crate) fn erase_health_check_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let checks = "wire:health:v1:check:";
    let actor_id = *actor;
    let actor = actor.to_hex();
    let subject_end = format!(":{actor}");
    let mut deleted = Vec::new();
    let mut rewritten = Vec::new();
    vault.sync_state_visit_prefix_in_write_txn(&*wtxn, checks, |key, body| {
        let Some(subject) = key.strip_prefix(checks) else {
            return Ok::<(), crate::Error>(());
        };
        if subject.starts_with(HEALTH_CHECK_SUBJECT) && subject.ends_with(&subject_end) {
            deleted.push(key.to_owned());
        } else if subject.strip_prefix(SPEND_CHECK_SUBJECT) == Some(actor.as_str()) {
            deleted.push(key.to_owned());
        } else if subject.starts_with(WIRE_CHECK_SUBJECT)
            || subject.starts_with(LIMIT_CHECK_SUBJECT)
        {
            if let Some(scrubbed) = scrub_health_check_body(body, &actor)? {
                rewritten.push((key.to_owned(), scrubbed));
            }
        }
        Ok::<(), crate::Error>(())
    })?;
    if !crate::deletion::names_no_actor(vault, wtxn, &actor_id)? {
        vault.sync_state_put_in_write_txn(wtxn, &health_erased_key(&actor), b"1")?;
    }
    if deleted.is_empty() && rewritten.is_empty() {
        return Ok(());
    }
    for key in &deleted {
        vault.sync_state_delete_in_write_txn(wtxn, key)?;
    }
    for (key, body) in &rewritten {
        vault.sync_state_put_in_write_txn(wtxn, key, body)?;
    }
    crate::llm::decision::forget_ask_states_in_txn(vault, wtxn, |state| {
        names_crossing_of(state, &actor) || names_spend_of(state, &actor)
    })?;
    crate::llm::decision::rewrite_ask_states_in_txn(vault, wtxn, |state| {
        let wire = scrub_wire_pack_state(state, &actor);
        let limit = scrub_limit_pack_state(state, &actor);
        wire || limit
    })
}

impl Vault {
    /// The latest window in which this actor's acts of `kind` crossed the
    /// advisory threshold, if any. A check never refuses an act.
    pub fn own_rate_check(
        &self,
        actor: EntityId,
        kind: OwnRateKind,
    ) -> Result<Option<OwnRateCheck>> {
        let txn = self.store.env.read_txn()?;
        CHECKS.get(&self.store, &txn, &(actor, kind.token().to_owned()))
    }

    /// Up to `limit` kept crossings after `after` (a [`KeptOwnRateCheck::cursor`];
    /// from the first when `None`), in the order they were kept, every actor
    /// and kind: what the host's health check reads past its cursor. A
    /// crossing stays readable for 30 days.
    ///
    /// # Errors
    ///
    /// A cursor this method did not hand out; storage errors.
    pub fn own_rate_checks_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KeptOwnRateCheck>> {
        let after = after.map(parse_order_cursor).transpose()?;
        let txn = self.store.env.read_txn()?;
        Ok(checks_in_order_after(&self.store, &txn, after, limit)?
            .into_iter()
            .map(|((kept_at, id), check)| KeptOwnRateCheck {
                cursor: order_cursor(kept_at, id),
                kept_at,
                check,
            })
            .collect())
    }

    /// Whether the crossing at `cursor` (a [`KeptOwnRateCheck::cursor`]) is
    /// still kept, read in the caller's writer. An actor's erase takes its
    /// kept crossings, so the health check folds no crossing it read before
    /// that erase.
    ///
    /// # Errors
    ///
    /// A cursor [`Self::own_rate_checks_after`] did not hand out; storage
    /// errors.
    #[doc(hidden)]
    pub fn own_rate_check_kept_in_write_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        cursor: &str,
    ) -> Result<bool> {
        check_kept(&self.store, txn, &parse_order_cursor(cursor)?)
    }

    /// Drops every actor this vault marks erased from `crossing`, a health
    /// crossing's summary, read in the caller's writer: from a wire
    /// summary's actor lists and a limit summary's `owners`. A crossing
    /// kept before an actor's erase is not taken where it was kept, and a
    /// live window can count the actor into a crossing kept after it, so
    /// the fold that writes the crossing's check is where the name stops
    /// (FIX 3520), as an own-rate fold stops at [`Self::own_rate_check_kept_in_write_txn`].
    /// The marks are the erase's own hashed one, left in its transaction,
    /// and the vault's hard-delete marker, for an erase whose health scrub
    /// this vault never ran. An actor named
    /// only as a string the wire counted, no entity id, is no erase's to
    /// judge and stays.
    ///
    /// # Errors
    ///
    /// Storage errors.
    #[doc(hidden)]
    pub fn health_crossing_drop_erased_in_write_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        crossing: &mut serde_json::Value,
    ) -> Result<()> {
        use serde_json::Value;
        let mut erased = Vec::new();
        for actor in health_crossing_actors(crossing) {
            let Ok(id) = EntityId::from_hex(&actor) else {
                continue;
            };
            let marked = self
                .sync_state_get_in_write_txn(txn, &health_erased_key(&id.to_hex()))?
                .is_some();
            if marked || self.carrier_actor_erased_in_txn(txn, &id)? {
                erased.push(actor);
            }
        }
        if erased.is_empty() {
            return Ok(());
        }
        retain_wire_summary_actors(crossing, |named| !erased.iter().any(|actor| actor == named));
        if let Some(owners) = crossing.get_mut("owners").and_then(Value::as_array_mut) {
            owners.retain(|owner| {
                owner
                    .as_str()
                    .is_none_or(|named| !erased.iter().any(|actor| actor == named))
            });
        }
        Ok(())
    }
}
