//! HNSW metadata key/counter literals, error strings, and the one-way prefix.

pub(super) const ENTRY_POINT_KEY: &[u8] = b"entry_point";

pub(crate) const COUNT_KEY: &[u8] = b"count";

/// `hnsw_meta` marker: present (value `[1]`) when the persisted graph
/// maintains the symmetric-link invariant — every stored link `a → b` has
/// its reverse `b → a`, except the documented orphan-protection case where
/// a node's last remaining link is kept one-way instead of emptying its
/// neighbor list. Under the invariant a node's backlinks are exactly its
/// forward neighbor list, so deletes and refreshes never scan the full
/// `hnsw_neighbors` DB (ONE-325). Vaults without the marker keep the legacy
/// asymmetric behavior (full-scan delete, full-rebuild refresh) until the
/// one-time migration runs via `maintain().rebuild_hnsw()`.
pub(super) const SYMMETRIC_LINKS_KEY: &[u8] = b"symmetric_links";

pub(super) const SYMMETRIC_LINKS_ENABLED: u8 = 1;

/// `hnsw_meta` marker: present (value `[1]`) when a SLIM shed (ONE-1933
/// OF-447) dropped the derived graph SHAPE — `hnsw_neighbors`, [`COUNT_KEY`],
/// the entry point and the `ow1:` exception keyspace — while preserving every
/// source row (`vectors`, vector version, model id, HNSW compatibility/config
/// rows, rebuild counters and unrelated `hnsw_meta` keys).
///
/// A present marker means "graph shape absent", never "empty vector corpus":
/// [`hnsw_entity_count`] reports the source-vector count while it is set, and
/// both lazy first-use routes below rebuild deterministically from the
/// surviving vectors under the vault's persisted [`LinkDiscipline`]. A
/// present-but-malformed marker is the existing fail-closed
/// [`Error::CorruptedIndex`] direction, never a silent "not dropped".
pub(crate) const DROPPED_REBUILDABLE_KEY: &[u8] = b"dropped_rebuildable";

pub(super) const DROPPED_REBUILDABLE_ENABLED: u8 = 1;

/// `hnsw_meta` counter (u64 LE): number of times the localized refresh path
/// had to fall back to a full symmetric snapshot rebuild. The fallback is an
/// explicit, measured, rare path (ONE-324 AC10) — this counter is how it is
/// measured.
pub(super) const REFRESH_FALLBACK_REBUILDS_KEY: &[u8] = b"refresh_fallback_rebuilds";

/// `hnsw_meta` counter (u64 LE): number of legacy full-snapshot rebuilds
/// this vault has run (pre-migration refresh contract). Observability for
/// the batched-rebuild coalescing guarantee (ONE-324 AC11): one transaction
/// bumps this at most once no matter how many vector refreshes it carries.
pub(super) const LEGACY_REBUILDS_KEY: &[u8] = b"legacy_snapshot_rebuilds";

pub(super) const ERR_ENTRY_POINT_MISSING: &str = "hnsw count > 0 but entry point is missing";

pub(super) const ERR_ENTRY_POINT_VECTOR_MISSING: &str =
    "hnsw count > 0 but entry point vector is missing";

pub(super) const ERR_ENTRY_POINT_BYTES: &str = "hnsw entry point bytes are malformed";

pub(super) const ERR_COUNT_BYTES: &str = "hnsw count bytes are malformed";

pub(super) const ERR_NEIGHBOR_KEY_BYTES: &str = "hnsw neighbor key bytes are malformed";

pub(super) const ERR_NEIGHBOR_VALUE_BYTES: &str = "hnsw neighbor list bytes are malformed";

pub(super) const ERR_VECTOR_BYTES: &str = "hnsw vector bytes are malformed";

pub(super) const ERR_VECTOR_ROW_TOO_SHORT: &str = "hnsw vector row shorter than scoring dimensions";

pub(super) const ERR_VECTOR_ROW_MISSING_AT_RESCORE: &str =
    "hnsw vector row disappeared between beam traversal and rescore in one snapshot";

pub(super) const ERR_VECTOR_KEY_BYTES: &str = "hnsw vector key bytes are malformed";

pub(super) const ERR_VECTOR_VERSION_BYTES: &str = "hnsw vector version bytes are malformed";

pub(super) const ERR_EMBEDDING_MODEL_EPOCH_BYTES: &str =
    "hnsw embedding model epoch bytes are malformed";

pub(super) const ERR_COUNT_UNDERFLOW: &str = "hnsw node count underflowed during delete";

pub(super) const ERR_COUNT_OVERFLOW: &str = "hnsw node count overflowed";

pub(super) const ERR_REMAINING_NODES_MISSING: &str = "hnsw count > 0 but no nodes remain";

pub(super) const ERR_EXISTING_NODE_ZERO_COUNT: &str = "hnsw node exists but count is zero";

pub(super) const ERR_ZERO_COUNT_GRAPH_NOT_EMPTY: &str =
    "hnsw metadata says count is zero but graph rows still exist";

pub(super) const ERR_SYMMETRIC_MARKER_BYTES: &str =
    "hnsw symmetric-links marker bytes are malformed";

pub(super) const ERR_FALLBACK_COUNTER_BYTES: &str =
    "hnsw refresh fallback counter bytes are malformed";

pub(super) const ERR_LEGACY_REBUILDS_BYTES: &str =
    "hnsw legacy rebuild counter bytes are malformed";

pub(super) const ERR_ONE_WAY_EXCEPTION_BYTES: &str =
    "hnsw one-way exception record bytes are malformed";

pub(super) const ERR_DROPPED_MARKER_BYTES: &str =
    "hnsw dropped-rebuildable marker bytes are malformed";

/// `hnsw_meta` key prefix for one-way-link exception records (ONE-325). When
/// orphan protection keeps a node's last remaining link `holder -> target`
/// one-way (so `holder`'s neighbor list never empties), `holder` is recorded
/// under `ONE_WAY_EXCEPTION_PREFIX ++ target` (a 20-byte key: 4-byte prefix +
/// 16-byte id). Without it the symmetric delete path — which derives backlinks
/// from the deleted node's OWN forward list — would miss `holder` when
/// deleting `target` and leave the deleted id lingering in `holder`'s row
/// forever, breaking the active-index purge contract. Recording the exception
/// lets delete scrub those holders too; the extra work is bounded by the
/// holder count, never the full neighbors DB, so deletes stay
/// neighborhood-local. The prefix is distinct from every other (short, ASCII)
/// `hnsw_meta` key, so rebuilds can clear exactly these rows without touching
/// unrelated metadata.
pub(super) const ONE_WAY_EXCEPTION_PREFIX: &[u8] = b"ow1:";
