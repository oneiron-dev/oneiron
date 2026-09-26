//! Sync-specific types for the CRDT sync layer.
//!
//! NOTE (ONE-1130): `SyncConfig` stays — the window manager (ONE-1125)
//! reads `default_window_count` — but its former compaction fields (512 KB
//! threshold + 30 s throttle) and the vector-sync flag were removed: the
//! compaction feature they configured is not implemented and nothing read
//! them. The contract values live in ARCH-0023b; re-introduce that config
//! together with the compaction implementation, not before it.

/// Configuration for the sync layer.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Number of windows loaded by default (current + previous month). Default: 2.
    pub default_window_count: u8,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
        }
    }
}

/// A local CRDT update routed to the connection's outbound path.
///
/// Produced by Observer A ([`crate::sync::bridge::OutboundSink`]) for every
/// persisted local commit and consumed by the connection's debounce → wire
/// loop. `update_bytes` are raw Loro update bytes (not wire-encoded yet).
#[derive(Debug)]
pub struct LocalUpdate {
    /// Window key (YYYY-MM or YYYY-MM@<world hex>).
    pub window_key: String,
    /// Raw Loro update bytes (not wire-encoded yet).
    pub update_bytes: Vec<u8>,
}

/// A window key identifying a base or world-scoped monthly Doc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowKey(String);

impl WindowKey {
    /// Creates a new window key from a "YYYY-MM" string.
    ///
    /// Panics on malformed input.
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        assert!(
            parse_window_key_str(&key).is_some(),
            "malformed window key {key:?}; expected YYYY-MM with year >= 1970 and month 01-12"
        );
        Self(key)
    }

    /// Creates a new window key from a "YYYY-MM" string, returning `None`
    /// on malformed input.
    ///
    /// Non-panicking counterpart to [`WindowKey::new`] for wire-derived keys
    /// (the server-side chokepoint for client-supplied window keys).
    pub fn try_new(key: impl Into<String>) -> Option<Self> {
        let key = key.into();
        parse_window_key_str(&key)?;
        Some(Self(key))
    }

    #[cfg(test)]
    pub(super) fn new_unchecked_for_test(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Creates a window key from a Unix timestamp (seconds).
    ///
    /// Timestamps at or beyond year 10000 are clamped to the last
    /// representable window, `"9999-12"`: the ARCH-0023b window-key format is
    /// `YYYY-MM` (exactly 7 bytes), so a larger year would produce a key that
    /// `parse_window_key_str` rejects everywhere — `sync_state` rows written
    /// under such a key become unreachable through validated read paths,
    /// `SyncQueue::push` refuses it, and the wire encoders assert on it.
    /// `learned_at` is caller-supplied, so this conversion must stay total
    /// and bounded.
    pub fn from_timestamp(ts: u64) -> Self {
        // Delegates to the always-compiled deletion module so the `pt:`
        // pending-tombstone marker (written even in non-`sync` builds,
        // ONE-1132) addresses EXACTLY the window this key would name.
        Self(crate::deletion::window_label_from_timestamp(ts))
    }

    /// World-scoped key for a timestamp. Base rows continue to use `from_timestamp`.
    pub fn for_world(ts: u64, world: crate::EntityId) -> Self {
        Self::for_month_world(&Self::from_timestamp(ts), world)
    }

    /// Address a world in the same month as an existing key.
    pub fn for_month_world(month: &Self, world: crate::EntityId) -> Self {
        Self(format!("{}@{}", &month.0[..7], world.to_hex()))
    }

    /// World axis, or `None` for the shared base partition.
    pub fn world(&self) -> Option<crate::EntityId> {
        self.0
            .split_once('@')
            .and_then(|(_, hex)| crate::EntityId::from_hex(hex).ok())
    }

    /// Returns the key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the start timestamp (first second of the month) as Unix seconds.
    /// Returns `None` for pre-1970 dates (negative Unix timestamps).
    pub fn start_timestamp(&self) -> Option<u64> {
        let (year, month) = self.parse_year_month()?;
        date_to_unix(year, month, 1)
    }

    /// Returns the end timestamp (first second of the next month) as Unix seconds.
    /// Returns `None` for pre-1970 dates (negative Unix timestamps).
    pub fn end_timestamp(&self) -> Option<u64> {
        let (year, month) = self.parse_year_month()?;
        let (next_year, next_month) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        date_to_unix(next_year, next_month, 1)
    }

    /// Returns the previous month's `WindowKey`.
    pub fn previous_month(&self) -> Option<WindowKey> {
        let (year, month) = self.parse_year_month()?;
        let (prev_year, prev_month) = if month == 1 {
            (year - 1, 12)
        } else {
            (year, month - 1)
        };
        if prev_year < 1970 {
            return None;
        }
        Some(match self.world() {
            Some(world) => WindowKey::for_month_world(
                &WindowKey(format!("{prev_year:04}-{prev_month:02}")),
                world,
            ),
            None => WindowKey(format!("{prev_year:04}-{prev_month:02}")),
        })
    }

    fn parse_year_month(&self) -> Option<(i32, u32)> {
        parse_window_key_str(&self.0)
    }
}

pub(crate) fn parse_window_key_str(key: &str) -> Option<(i32, u32)> {
    let bytes = key.as_bytes();
    if bytes.len() != 7 && bytes.len() != 40 {
        return None;
    }
    if bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    if bytes.len() == 40 {
        if bytes[7] != b'@'
            || !bytes[8..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return None;
        }
        let world = crate::EntityId::from_hex(&key[8..]).ok()?;
        if world.to_hex() != key[8..] {
            return None;
        }
    }
    let year: i32 = key[..4].parse().ok()?;
    let month: u32 = key[5..7].parse().ok()?;
    if year < 1970 || !(1..=12).contains(&month) {
        return None;
    }
    Some((year, month))
}

/// The ledger-plane partition axis: only CLAIM bodies can name a world.
/// Other entity families remain in the shared base window.
pub(crate) fn entity_world(raw: &[u8]) -> crate::error::Result<Option<crate::EntityId>> {
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    let header =
        EntityMetadataHeader::parse(raw).ok_or(crate::Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.world)
}

/// Validate residence before replay/export. A malformed CLAIM cannot be
/// assigned to any partition and therefore must not cross the wire.
pub(crate) fn entity_belongs_to_window(raw: &[u8], key: &WindowKey) -> bool {
    match entity_world(raw) {
        Ok(world) => {
            world == key.world()
                && (world.is_none()
                    || crate::batch::EntityMetadataHeader::parse(raw).is_some_and(|header| {
                        WindowKey::from_timestamp(header.learned_at).0 == key.0[..7]
                    }))
        }
        // Retain existing base-mode quarantine for malformed opaque carriers.
        // A world window never admits a row with no proven world assignment.
        Err(_) => key.world().is_none(),
    }
}

/// An edge with a world endpoint lives in that world, alongside the shared
/// base endpoint. Edges joining two different worlds are not replicated.
pub(crate) fn edge_worlds_match(
    source: Option<crate::EntityId>,
    target: Option<crate::EntityId>,
    key: &WindowKey,
) -> bool {
    match key.world() {
        None => source.is_none() && target.is_none(),
        Some(world) => {
            (source == Some(world) || target == Some(world))
                && [source, target]
                    .iter()
                    .all(|axis| axis.is_none_or(|id| id == world))
        }
    }
}

pub(crate) fn edge_belongs_to_window(
    vault: &crate::Vault,
    source: &crate::EntityId,
    target: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<bool> {
    let src = vault.get_raw_unsealed(source)?;
    let tgt = vault.get_raw_unsealed(target)?;
    let (Some(src), Some(tgt)) = (src, tgt) else {
        // Preserve the existing base-mode deferred-endpoint handling; a
        // world edge with no proof of its second endpoint cannot travel.
        return Ok(key.world().is_none());
    };
    Ok(edge_worlds_match(
        entity_world(&src)?,
        entity_world(&tgt)?,
        key,
    ))
}

/// Validate a received edge against both CRDT carriers and LMDB rows.
/// World edges require proven endpoints; base edges retain the existing
/// deferred-unknown-endpoint behavior but cannot name a known world claim.
pub(crate) fn edge_belongs_to_window_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &loro::LoroDoc,
    source: &crate::EntityId,
    target: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<bool> {
    let entities = doc.get_map("entities");
    let mut worlds = [None, None];
    for (index, id) in [source, target].iter().enumerate() {
        let in_doc = crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex());
        let stored = vault.store.entities.get(txn, id.as_bytes())?;
        // A malformed peer carrier in a base doc is quarantined by the
        // entity pass. Keep the old deferred-edge behavior instead of
        // converting that remote rejection into local index corruption.
        let doc_world = match in_doc.as_ref().map(|raw| entity_world(raw)) {
            Some(Ok(world)) => Some(world),
            Some(Err(_)) if key.world().is_none() => None,
            Some(Err(_)) => return Ok(false),
            None => None,
        };
        let stored_world = stored.as_ref().map(|raw| entity_world(raw)).transpose()?;
        if let (Some(doc_world), Some(stored_world)) = (doc_world, stored_world)
            && doc_world != stored_world
        {
            return Ok(false);
        }
        worlds[index] = doc_world.or(stored_world);
    }
    if key.world().is_some() && worlds.iter().any(Option::is_none) {
        return Ok(false);
    }
    Ok(edge_worlds_match(
        worlds[0].flatten(),
        worlds[1].flatten(),
        key,
    ))
}

/// Proof of residence for a delete which has no body of its own. An unknown
/// world target must not create a process-wide hard-delete marker: the same
/// entity ID might later be admitted under another world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TombstoneResidence {
    Match,
    Wrong,
    Unknown,
}

pub(crate) fn tombstone_residence_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
    key: &WindowKey,
) -> crate::error::Result<TombstoneResidence> {
    let mapped_key = format!("m:dw:{}", id.to_hex());
    let mapped = vault
        .store
        .sync_state
        .get(txn, &mapped_key)?
        .map(|raw| {
            std::str::from_utf8(&raw)
                .ok()
                .and_then(WindowKey::try_new)
                .ok_or(crate::Error::InvalidKey)
        })
        .transpose()?;
    if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? {
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("entity metadata"))?;
        // The existing protected-record gate owns this refusal. Residence
        // must not replace its typed MaintenanceKindNotWritable reason.
        if crate::registry::is_delete_protected_engine_record(header.entity_type) {
            return Ok(TombstoneResidence::Match);
        }
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            let actual_world = entity_world(&raw)?;
            let matches = actual_world == key.world()
                && (key.world().is_none()
                    || WindowKey::from_timestamp(header.learned_at).0 == key.0[..7])
                && mapped.as_ref().is_none_or(|mapped| mapped == key);
            return Ok(if matches {
                TombstoneResidence::Match
            } else {
                TombstoneResidence::Wrong
            });
        }
    }
    Ok(match mapped {
        Some(mapped) if mapped == *key => TombstoneResidence::Match,
        Some(_) => TombstoneResidence::Wrong,
        None => TombstoneResidence::Unknown,
    })
}

impl std::fmt::Display for WindowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generates the Doc GUID for a window.
pub fn window_doc_guid(user_id: &str, key: &WindowKey) -> String {
    format!("vault:{user_id}:w:{key}")
}

/// Generates the Doc GUID for a root doc.
pub fn root_doc_guid(user_id: &str) -> String {
    format!("vault:{user_id}")
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert year/month/day to Unix timestamp (seconds).
///
/// Returns `None` for pre-1970 dates where the result would be negative.
fn date_to_unix(year: i32, month: u32, day: u32) -> Option<u64> {
    // Days from 1970-01-01 to the given date
    let mut days: i64 = 0;

    // Years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    // Handle years before 1970
    for y in year..1970 {
        days -= if is_leap_year(y) { 366 } else { 365 };
    }

    // Months within the target year
    let month_days = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for &d in &month_days[..(month as usize - 1)] {
        days += d as i64;
    }

    // Days within the month
    days += (day as i64) - 1;

    if days < 0 {
        return None;
    }

    Some((days * 86_400) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_key_from_timestamp() {
        // 2026-02-15 ~ Unix 1771027200
        let key = WindowKey::from_timestamp(1_771_027_200);
        assert_eq!(key.as_str(), "2026-02");
    }

    #[test]
    fn window_key_round_trip_timestamps() {
        let key = WindowKey::new("2026-03");
        let start = key.start_timestamp().unwrap();
        let end = key.end_timestamp().unwrap();
        // March 2026 has 31 days
        assert_eq!(end - start, 31 * 86_400);
        // Verify the start timestamp produces the same key
        assert_eq!(WindowKey::from_timestamp(start).as_str(), "2026-03");
    }

    #[test]
    fn window_key_from_timestamp_epoch() {
        let key = WindowKey::from_timestamp(0);
        assert_eq!(key.as_str(), "1970-01");
    }

    /// `from_timestamp` must stay total, bounded, and inside the ARCH-0023b
    /// `YYYY-MM` key format for ANY u64 input. The pre-fix code (a) cast `ts
    /// as i64`, so ts > i64::MAX wrapped negative and silently produced
    /// "1970-01", (b) walked one year per loop iteration toward the target
    /// (hundreds of billions of iterations for ts near i64::MAX), and (c)
    /// emitted >4-digit years ("10000-01") that `parse_window_key_str`
    /// rejects, stranding any sync_state rows written under them.
    #[test]
    fn window_key_from_timestamp_clamps_far_future_to_last_representable_window() {
        // Last second of year 9999 still maps inside the format.
        let last_valid = date_to_unix(9999, 12, 31).unwrap() + 86_399;
        assert_eq!(WindowKey::from_timestamp(last_valid).as_str(), "9999-12");

        // First second of year 10000 clamps (would otherwise be "10000-01").
        let year_10000 = date_to_unix(10_000, 1, 1).unwrap();
        assert_eq!(WindowKey::from_timestamp(year_10000).as_str(), "9999-12");

        // Extreme values: must terminate promptly and not sign-wrap.
        for ts in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let key = WindowKey::from_timestamp(ts);
            assert_eq!(key.as_str(), "9999-12", "ts={ts}");
            assert!(
                parse_window_key_str(key.as_str()).is_some(),
                "clamped key must satisfy the pinned YYYY-MM format"
            );
        }
    }

    #[test]
    fn window_doc_guid_format() {
        let key = WindowKey::new("2026-02");
        assert_eq!(window_doc_guid("user123", &key), "vault:user123:w:2026-02");
    }

    macro_rules! assert_window_key_new_panics {
        ($name:ident, $input:expr) => {
            #[test]
            #[should_panic(expected = "malformed window key")]
            fn $name() {
                let _ = WindowKey::new($input);
            }
        };
    }

    assert_window_key_new_panics!(window_key_new_panics_on_malformed_input, "2026:03");
    assert_window_key_new_panics!(window_key_new_panics_on_whitespace_input, "2026-03 ");
    assert_window_key_new_panics!(window_key_new_panics_on_invalid_month, "2026-13");
    assert_window_key_new_panics!(window_key_new_panics_on_zero_month, "2026-00");
    assert_window_key_new_panics!(window_key_new_panics_on_pre_epoch_year, "1969-12");
    assert_window_key_new_panics!(window_key_new_panics_on_empty_input, "");

    #[test]
    fn parse_window_key_rejects_invalid_calendar_shapes() {
        for invalid in [
            "2026-13", "2026-00", "abcdefg", "2026-3", "1969-12", "0000-01",
        ] {
            assert!(
                parse_window_key_str(invalid).is_none(),
                "{invalid} should be invalid"
            );
        }
    }

    #[test]
    fn previous_month_stops_at_epoch() {
        let key = WindowKey::new("1970-01");
        assert!(key.previous_month().is_none());
    }

    #[test]
    fn try_new_accepts_valid_and_rejects_malformed_keys() {
        assert_eq!(
            WindowKey::try_new("2026-02").map(|k| k.as_str().to_string()),
            Some("2026-02".to_string())
        );
        for invalid in ["2026-13", "2026-00", "1969-12", "2026-03 ", "garbage", ""] {
            assert!(
                WindowKey::try_new(invalid).is_none(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn world_month_window_key_is_canonical_and_retains_world_when_stepping_back() {
        let world = crate::test_util::entity(0xab);
        let key = WindowKey::for_world(1_771_027_200, world);
        assert_eq!(key.as_str(), format!("2026-02@{}", world.to_hex()));
        assert_eq!(key.world(), Some(world));
        assert_eq!(
            key.previous_month().unwrap().as_str(),
            format!("2026-01@{}", world.to_hex())
        );
        assert_eq!(WindowKey::try_new(key.as_str()), Some(key.clone()));
        assert!(WindowKey::try_new(key.as_str().to_uppercase()).is_none());
        assert_eq!(WindowKey::from_timestamp(1_771_027_200).world(), None);
    }
}
