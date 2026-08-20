//! Legacy short-id alias rows: resolve/insert/retarget, the short-id
//! counter key, and the short-id prefix re-key migration.

use std::collections::{BTreeMap, BTreeSet};
use std::str;

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;

use super::*;

/// `vault_meta` key prefix for the per-type short-id counters (M2-5 /
/// ONE-1102, storage ABI v3). The full key is the 12-byte ASCII prefix
/// `b"sid_counter:"` followed by the raw entity type byte (13 bytes total);
/// the value is the last issued counter as u64 LE. These counters previously
/// lived as `[type_byte, 0xFF x15]` sentinel rows inside `short_ids`; they
/// were relocated so `short_ids` holds only the contract's manifest rows
/// (ARCH-0019 row n3: `(short_id, content_hash)` -> `entity_id`).
pub(crate) const SHORT_ID_COUNTER_KEY_PREFIX: &[u8] = b"sid_counter:";

pub(crate) const SHORT_ID_COUNTER_KEY_LEN: usize = 13;

const _: () = assert!(SHORT_ID_COUNTER_KEY_PREFIX.len() + 1 == SHORT_ID_COUNTER_KEY_LEN);

/// `vault_meta` key prefix for short-id ALIAS rows (ONE-1930): a retired
/// presentation id that still resolves to a live target.
///
/// The full key is this prefix followed by the legacy presentation id's bytes.
/// The NUL terminates the version tag so `short_id_alias:v1` can never be
/// confused with a hypothetical `short_id_alias:v10` under a prefix scan.
///
/// Deliberately a `vault_meta` row family and NOT a 29th named LMDB database:
/// the manifest set is ABI-pinned and adding to it is a storage-ABI change,
/// while an older reader simply ignores an unknown `vault_meta` prefix. Aliases
/// are additive — every pre-existing forward row keeps working without them.
pub(crate) const SHORT_ID_ALIAS_KEY_PREFIX: &[u8] = b"short_id_alias:v1\0";

/// Record version leading every alias VALUE.
const SHORT_ID_ALIAS_RECORD_VERSION: u8 = 1;

/// Alias value tag: the target is an entity, named by its canonical
/// `short_ids` forward key (`short_id ‖ content_hash`).
const SHORT_ID_ALIAS_TAG_ENTITY: u8 = 0;

/// Alias value tag: the target is a vault, named by its 32-byte
/// [`crate::authority::AuthorityVaultId`].
const SHORT_ID_ALIAS_TAG_VAULT: u8 = 1;

/// `vault_meta` key stamping which presentation-id grammar generation this
/// vault's short-id rows have been brought to.
///
/// ABSENT means the ONE-1930 re-key has not run here yet. The marker is written
/// only after the pass's own collision and count assertions pass, in the same
/// transaction as the rows it describes, so a stamped vault is a migrated
/// vault. Its presence is also what makes reopening idempotent.
pub(crate) const SHORT_ID_GRAMMAR_VERSION_KEY: &[u8] = b"short_id_grammar_version";

/// Grammar generation this engine writes. NOT a storage-ABI version: the row
/// families are unchanged and a predecessor engine still reads every one of
/// them, which is exactly why this ticket needs no [`STORAGE_ABI_VERSION`] bump.
pub(crate) const SHORT_ID_GRAMMAR_VERSION: u16 = 1;

/// Encodes the `vault_meta` key for the short-id counter of `entity_type`.
/// See [`SHORT_ID_COUNTER_KEY_PREFIX`] for the documented key scheme.
pub(crate) fn short_id_counter_key(entity_type: u8) -> [u8; SHORT_ID_COUNTER_KEY_LEN] {
    let mut key = [0u8; SHORT_ID_COUNTER_KEY_LEN];
    key[..SHORT_ID_COUNTER_KEY_PREFIX.len()].copy_from_slice(SHORT_ID_COUNTER_KEY_PREFIX);
    key[SHORT_ID_COUNTER_KEY_PREFIX.len()] = entity_type;
    key
}

impl Store {
    /// Reads the ONE-1930 alias row for a retired presentation id.
    ///
    /// See [`resolve_short_id_alias_in_txn`]: callers reach this only after a
    /// canonical `short_ids` lookup misses.
    pub(crate) fn resolve_short_id_alias(
        &self,
        txn: &RoTxn<'_>,
        legacy_id: &str,
    ) -> Result<Option<ShortIdAliasTarget>> {
        resolve_short_id_alias_in_txn(ShortIdDbs::from_manifest(self), txn, legacy_id)
    }

    /// Installs a retired presentation id as a one-hop alias. THE alias write
    /// door — see [`insert_short_id_alias_in_txn`] for the rules it enforces.
    pub(crate) fn insert_short_id_alias(
        &self,
        txn: &mut RwTxn<'_>,
        legacy_id: &str,
        target: &ShortIdAliasTarget,
    ) -> Result<()> {
        insert_short_id_alias_in_txn(ShortIdDbs::from_manifest(self), txn, legacy_id, target)
    }

    /// Every alias row, as `(legacy_id, target)`.
    pub(crate) fn short_id_aliases(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<(String, ShortIdAliasTarget)>> {
        short_id_aliases_in_txn(ShortIdDbs::from_manifest(self), txn)
    }

    /// Moves an alias that currently names `from` to name `to`.
    pub(crate) fn retarget_short_id_alias(
        &self,
        txn: &mut RwTxn<'_>,
        legacy_id: &str,
        from: &ShortIdAliasTarget,
        to: &ShortIdAliasTarget,
    ) -> Result<bool> {
        retarget_short_id_alias_in_txn(ShortIdDbs::from_manifest(self), txn, legacy_id, from, to)
    }

    /// Runs the presentation-prefix re-key against an explicit map.
    ///
    /// The map is a parameter, not a constant read inside, so the pass can be
    /// driven over real data while [`SHORT_ID_PREFIX_REKEY_V1`] — the map
    /// production actually ships — waits on canon.
    ///
    /// Test-only by construction: production runs this pass inside
    /// [`Store::open`], which has `RawDatabases` but no `Store` yet and so calls
    /// [`rekey_short_ids_v1_in_txn`] directly.
    #[cfg(test)]
    pub(crate) fn rekey_short_ids_v1(
        &self,
        txn: &mut RwTxn<'_>,
        map: &[ShortIdPrefixRekey],
    ) -> Result<u64> {
        rekey_short_ids_v1_in_txn(ShortIdDbs::from_manifest(self), txn, map)
    }
}

/// What a short-id alias row resolves to (ONE-1930).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortIdAliasTarget {
    /// An entity, named by its canonical `short_ids` forward key
    /// (`short_id ‖ content_hash`). The forward key — not the entity id — is
    /// stored so the alias lands on the SAME row the canonical presentation id
    /// lands on, which is what makes a content-hash refresh a one-place fix.
    EntityForwardKey(Vec<u8>),
    /// A vault, named by its durable 32-byte identity.
    Vault(crate::authority::AuthorityVaultId),
}

/// The four row families short-id aliasing and re-keying touch.
///
/// Bundled because the pass runs BOTH inside [`Store::open`] — before a `Store`
/// exists — and at runtime against a live one. One parameter shape means one
/// implementation and, per the blueprint, exactly one alias WRITE door.
#[derive(Clone, Copy)]
pub(crate) struct ShortIdDbs<'a> {
    pub(super) entities: &'a OverlayDb,
    pub(super) short_ids: &'a OverlayDb,
    pub(super) short_ids_reverse: &'a OverlayDb,
    pub(super) vault_meta: &'a OverlayDb,
}

impl<'a> ShortIdDbs<'a> {
    fn from_manifest(dbs: &'a impl ManifestDbs) -> Self {
        Self {
            entities: dbs.entities(),
            short_ids: dbs.short_ids(),
            short_ids_reverse: dbs.short_ids_reverse(),
            vault_meta: dbs.vault_meta(),
        }
    }
}

fn alias_corrupt(context: &'static str) -> Error {
    Error::CorruptedIndex(context)
}

/// `vault_meta` key for one legacy presentation id's alias row.
fn short_id_alias_key(legacy_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(SHORT_ID_ALIAS_KEY_PREFIX.len() + legacy_id.len());
    key.extend_from_slice(SHORT_ID_ALIAS_KEY_PREFIX);
    key.extend_from_slice(legacy_id.as_bytes());
    key
}

fn encode_short_id_alias_target(target: &ShortIdAliasTarget) -> Vec<u8> {
    let mut out = vec![SHORT_ID_ALIAS_RECORD_VERSION];
    match target {
        ShortIdAliasTarget::EntityForwardKey(forward_key) => {
            out.push(SHORT_ID_ALIAS_TAG_ENTITY);
            out.extend_from_slice(forward_key);
        }
        ShortIdAliasTarget::Vault(vault_id) => {
            out.push(SHORT_ID_ALIAS_TAG_VAULT);
            out.extend_from_slice(vault_id);
        }
    }
    out
}

fn decode_short_id_alias_target(raw: &[u8]) -> Result<ShortIdAliasTarget> {
    let [version, tag, payload @ ..] = raw else {
        return Err(alias_corrupt("short id alias record"));
    };
    if *version != SHORT_ID_ALIAS_RECORD_VERSION {
        return Err(alias_corrupt("short id alias record version"));
    }
    match *tag {
        SHORT_ID_ALIAS_TAG_ENTITY => {
            // The payload IS a forward key, so it must parse as one: bad bytes
            // here would otherwise be handed straight to a `short_ids` lookup.
            crate::batch::parse_short_id_value(payload)
                .map_err(|_| alias_corrupt("short id alias target"))?;
            Ok(ShortIdAliasTarget::EntityForwardKey(payload.to_vec()))
        }
        SHORT_ID_ALIAS_TAG_VAULT => payload
            .try_into()
            .map(ShortIdAliasTarget::Vault)
            .map_err(|_| alias_corrupt("short id alias vault target")),
        _ => Err(alias_corrupt("short id alias tag")),
    }
}

/// Reads the alias row for `legacy_id`, if any.
///
/// Callers reach this only AFTER a canonical `short_ids` lookup misses, so a
/// live forward row always wins over an alias and an alias can never shadow a
/// real entity.
pub(crate) fn resolve_short_id_alias_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &RoTxn<'_>,
    legacy_id: &str,
) -> Result<Option<ShortIdAliasTarget>> {
    dbs.vault_meta
        .get(txn, &short_id_alias_key(legacy_id))?
        .as_deref()
        .map(decode_short_id_alias_target)
        .transpose()
}

/// The shapes an ENTITY alias target must never take, checked by EVERY door
/// that writes one: a payload that is not a forward key, a self-cycle, and a
/// second hop through another alias.
///
/// It lives apart from the insert door because the retarget door writes the
/// same rows — a validation that only one of them runs is a validation an
/// alias row can be written around, and the shapes it rejects surface later as
/// `CorruptedIndex` at read time.
fn vet_short_id_alias_target_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &RoTxn<'_>,
    legacy_id: &str,
    target: &ShortIdAliasTarget,
) -> Result<()> {
    let ShortIdAliasTarget::EntityForwardKey(forward_key) = target else {
        return Ok(());
    };
    let (target_short_id, _) = crate::batch::parse_short_id_value(forward_key)
        .map_err(|_| Error::InvariantViolation("short id alias target is not a forward key"))?;
    if target_short_id == legacy_id {
        return Err(Error::InvariantViolation("short id alias targets itself"));
    }
    if resolve_short_id_alias_in_txn(dbs, txn, target_short_id)?.is_some() {
        return Err(Error::InvariantViolation(
            "short id alias targets another alias",
        ));
    }
    Ok(())
}

/// The ONE alias write door — used by the first-open re-key AND by callers
/// installing a legacy id by hand.
///
/// Fails closed on every shape the blueprint forbids:
///
/// * `legacy_id` must be a syntactically valid presentation id.
/// * One hop only: an entity target's own presentation id must not itself be
///   aliased, and must not be `legacy_id` (a self-cycle).
/// * No overwrite: an existing row for `legacy_id` pointing somewhere ELSE is
///   an error. Re-inserting the identical row is a no-op, which is what makes
///   the re-key idempotent across a retry.
pub(crate) fn insert_short_id_alias_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &mut RwTxn<'_>,
    legacy_id: &str,
    target: &ShortIdAliasTarget,
) -> Result<()> {
    crate::entity_id::parse_presentation_id(legacy_id).map_err(|_| {
        Error::InvariantViolation("short id alias legacy id is not a presentation id")
    })?;

    vet_short_id_alias_target_in_txn(dbs, txn, legacy_id, target)?;

    let key = short_id_alias_key(legacy_id);
    if let Some(existing) = dbs.vault_meta.get(txn, &key)? {
        return if decode_short_id_alias_target(&existing)? == *target {
            Ok(())
        } else {
            Err(Error::InvariantViolation(
                "short id alias already names another target",
            ))
        };
    }
    dbs.vault_meta
        .put(txn, &key, &encode_short_id_alias_target(target))?;
    Ok(())
}

/// Every alias row in the vault, as `(legacy_id, target)`.
///
/// Maintenance needs the whole set, and the key format stays owned here rather
/// than being re-derived by every caller that wants to walk it.
pub(crate) fn short_id_aliases_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &RoTxn<'_>,
) -> Result<Vec<(String, ShortIdAliasTarget)>> {
    let mut aliases = Vec::new();
    for row in dbs.vault_meta.prefix_iter(txn, SHORT_ID_ALIAS_KEY_PREFIX)? {
        let (key, value) = row?;
        let legacy_id = str::from_utf8(&key[SHORT_ID_ALIAS_KEY_PREFIX.len()..])
            .map_err(|_| alias_corrupt("short id alias key"))?;
        aliases.push((legacy_id.to_owned(), decode_short_id_alias_target(&value)?));
    }
    Ok(aliases)
}

/// Moves an alias that currently names `from` to name `to`.
///
/// The maintenance counterpart to [`insert_short_id_alias_in_txn`], which
/// refuses to overwrite on purpose. This is not a general overwrite either: it
/// rewrites ONLY a row that still holds `from`, so a stale caller cannot
/// repoint an alias that has already moved. Returns whether the row changed.
///
/// The destination runs the SAME target checks the insert door runs
/// ([`vet_short_id_alias_target_in_txn`]) — moving a row is still writing one.
/// They run after the `from` match so a stale no-op stays a no-op rather than
/// becoming an error.
pub(crate) fn retarget_short_id_alias_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &mut RwTxn<'_>,
    legacy_id: &str,
    from: &ShortIdAliasTarget,
    to: &ShortIdAliasTarget,
) -> Result<bool> {
    let key = short_id_alias_key(legacy_id);
    let Some(existing) = dbs.vault_meta.get(txn, &key)? else {
        return Ok(false);
    };
    if decode_short_id_alias_target(&existing)? != *from {
        return Ok(false);
    }
    vet_short_id_alias_target_in_txn(dbs, txn, legacy_id, to)?;
    dbs.vault_meta
        .put(txn, &key, &encode_short_id_alias_target(to))?;
    Ok(true)
}

/// One entity kind's presentation-prefix move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShortIdPrefixRekey {
    pub kind: &'static str,
    pub type_byte: u8,
    pub old_prefix: &'static str,
    pub new_prefix: &'static str,
}

/// The production prefix-move map.
///
/// EMPTY on this base, and that is a fact about canon rather than an oversight.
/// The four board-facing moves this machinery exists for (`cl→c`, `pr→p`,
/// `sk→s`, `wd→w`) are pinned by `oneiron-docs`
/// `site/src/data/oneiron-contracts.ts`, which `tests/byte_space_v3_conformance.rs`
/// holds the engine registry equal to. The engine follows canon; it does not
/// lead it. When those four rows move in canon, they are added here and gain
/// their old spelling in `EntityTypeRegistryEntry::legacy_short_id_prefixes` —
/// no other code changes.
pub(crate) const SHORT_ID_PREFIX_REKEY_V1: &[ShortIdPrefixRekey] = &[];

/// Re-keys every short id whose kind's declared presentation prefix moved, in
/// the caller's write transaction.
///
/// Per re-keyed entity: the canonical forward row is INSERTED at the new
/// spelling, the reverse row is UPDATED to point at it, the legacy forward row
/// is RETAINED so a predecessor engine and already-published references still
/// resolve, and a one-hop alias row records `old_id → canonical_forward_key`.
/// The decimal counter and the content-hash byte are carried across verbatim
/// (`cl17:a3 → c17:a3`), and `sid_counter:<type_byte>` is never touched — this
/// pass renames, it does not re-number.
///
/// FAIL-CLOSED: a destination forward key already held by a different entity, a
/// short id that does not parse, an entity envelope too short to carry a type
/// byte, or a write count that disagrees with what was staged all return `Err`.
/// The caller runs this inside the open transaction and stamps
/// [`SHORT_ID_GRAMMAR_VERSION_KEY`] only on `Ok`, so any abort rolls the rows
/// and the marker back together.
pub(crate) fn rekey_short_ids_v1_in_txn(
    dbs: ShortIdDbs<'_>,
    txn: &mut RwTxn<'_>,
    map: &[ShortIdPrefixRekey],
) -> Result<u64> {
    /// One entity's move, staged before anything is written.
    struct ShortIdStagedMove {
        reverse_key: Vec<u8>,
        legacy_forward_key: Vec<u8>,
        legacy_short_id: String,
        canonical_forward_key: Vec<u8>,
    }

    if map.is_empty() {
        return Ok(0);
    }

    let mut by_type: BTreeMap<u8, &ShortIdPrefixRekey> = BTreeMap::new();
    for entry in map {
        if by_type.insert(entry.type_byte, entry).is_some() {
            return Err(alias_corrupt("short id re-key duplicate type byte"));
        }
    }

    let mut staged: Vec<ShortIdStagedMove> = Vec::new();
    for row in dbs.short_ids_reverse.iter(txn)? {
        let (reverse_key, value) = row?;
        let (short_id, content_hash) = crate::batch::parse_short_id_value(&value)?;
        let parsed = crate::entity_id::parse_presentation_id(short_id)
            .map_err(|_| alias_corrupt("short id re-key malformed short id"))?;

        // The entity's OWN envelope decides its kind. Trusting the stored
        // prefix instead would re-key rows on the strength of the very spelling
        // this pass exists to correct.
        let Some(blob) = dbs.entities.get(txn, &reverse_key)? else {
            continue;
        };
        let type_byte = *blob
            .first()
            .ok_or_else(|| alias_corrupt("short id re-key malformed entity envelope"))?;
        let Some(entry) = by_type.get(&type_byte) else {
            continue;
        };
        if parsed.prefix != entry.old_prefix {
            continue;
        }

        let canonical_short_id = format!("{}{}", entry.new_prefix, parsed.digits);
        staged.push(ShortIdStagedMove {
            reverse_key: reverse_key.to_vec(),
            legacy_forward_key: crate::batch::encode_short_id_forward_key(short_id, content_hash),
            legacy_short_id: short_id.to_owned(),
            canonical_forward_key: crate::batch::encode_short_id_forward_key(
                &canonical_short_id,
                content_hash,
            ),
        });
    }

    // A destination forward key already occupied by a DIFFERENT entity means
    // the new spelling collides with a live id; re-keying anyway would make one
    // presentation id name two entities.
    let mut destinations: BTreeSet<&[u8]> = BTreeSet::new();
    for staged_move in &staged {
        if !destinations.insert(&staged_move.canonical_forward_key) {
            return Err(alias_corrupt("short id re-key duplicate destination"));
        }
        if let Some(occupant) = dbs.short_ids.get(txn, &staged_move.canonical_forward_key)?
            && *occupant != *staged_move.reverse_key
        {
            tracing::error!(
                legacy = staged_move.legacy_short_id,
                "short id re-key destination already names another entity"
            );
            return Err(alias_corrupt("short id re-key destination collision"));
        }
    }

    for staged_move in &staged {
        // The legacy forward row is deliberately LEFT IN PLACE: it is what a
        // predecessor engine and every already-published `clN:hh` reference
        // still read. The alias row is what carries the legacy id forward when
        // the content hash later drifts.
        dbs.short_ids.put(
            txn,
            &staged_move.canonical_forward_key,
            &staged_move.reverse_key,
        )?;
        dbs.short_ids_reverse.put(
            txn,
            &staged_move.reverse_key,
            &staged_move.canonical_forward_key,
        )?;
        insert_short_id_alias_in_txn(
            dbs,
            txn,
            &staged_move.legacy_short_id,
            &ShortIdAliasTarget::EntityForwardKey(staged_move.canonical_forward_key.clone()),
        )?;
    }

    // Post-assertions: every staged move landed, and every legacy forward row
    // it promised to retain is still readable.
    for staged_move in &staged {
        let landed = dbs
            .short_ids
            .get(txn, &staged_move.canonical_forward_key)?
            .ok_or_else(|| alias_corrupt("short id re-key destination missing"))?;
        if *landed != *staged_move.reverse_key {
            return Err(alias_corrupt("short id re-key destination mismatch"));
        }
        if dbs
            .short_ids
            .get(txn, &staged_move.legacy_forward_key)?
            .is_none()
        {
            return Err(alias_corrupt(
                "short id re-key dropped a legacy forward row",
            ));
        }
    }

    Ok(staged.len() as u64)
}
