//! The owner's notices on an agent pack's travel (FIX 5493, owner ruling
//! 1-EXPORT = B). His own export carries his private worlds as his will, and
//! names each world his recipient choice would have kept from where it goes;
//! an import names the receiving world whose current setting does not cover
//! the install it lands on, asks him to double-check it, and still lands.
//!
//! A notice is typed (CALLS `FIX 5493 notice codes`): its type, the world as
//! hex and as the owner reads its name, and the recipient limit's own
//! content-free reason. `body` is that notice in the default wording
//! ([`PACK_NOTICE_WORDING`], CALLS `FIX 5493 notice wording`); a host renders
//! its own from the typed fields. A world's name is the owner's alone: it
//! rides only on his own response and his own receipt
//! ([`screen_owner_notice_fields`]). A world's id rides only on the share
//! receipt, whose off-device screen reads it: a notice in a result names its
//! world by name, so no result names a kept row by id, and every release
//! check off this device passes it as it passed the result before.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::BornWith;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::provenance::made_by::MadeByInputRole;
use crate::settings::{ReadDestination, RecipientLimit, ReleaseHold};

/// The owner's own export carried a world his recipient choice would keep
/// from where the pack goes.
pub const OWNER_PACK_EXPORT_RECIPIENT_NOTICE: &str = "owner_pack_export_recipient_notice";
/// An import lands in a world whose current setting does not cover this
/// install's machine.
pub const AGENT_PACK_IMPORT_DOUBLE_CHECK: &str = "agent_pack_import_double_check";
/// The channel every pack travel notice is said on.
pub const PACK_NOTICE_CHANNEL: &str = "share_travel";
/// The voice: the system's, never an agent's or a persona's.
pub const PACK_NOTICE_VOICE: &str = "system";
/// The audience: the owner alone.
pub const PACK_NOTICE_AUDIENCE: &str = "owner";

/// The default words of each notice, the one wording hook (CALLS `FIX 5493
/// notice wording`). `{world_name}` and `{reason}` are filled in; a host
/// that says it otherwise renders from the notice's typed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackNoticeWording {
    /// The owner's own export.
    pub export: &'static str,
    /// An import, said before it lands and kept on its receipt.
    pub import: &'static str,
    /// What an import's check reads, said after it: the sender's world
    /// settings never travel with a pack (CALLS `FIX 5493 import scope`).
    pub import_scope: &'static str,
    /// `{world_name}` for a world whose body names none a read may show.
    pub unnamed: &'static str,
}

/// The wording every pack travel notice is rendered in.
pub const PACK_NOTICE_WORDING: PackNoticeWording = PackNoticeWording {
    export: "Included {world_name} in your export. Your recipient choice would keep it from \
             this destination: {reason}.",
    import: "Please double-check {world_name} before import: {reason}. The import will continue.",
    import_scope: "The sender's world settings do not travel with a pack; this is this world's \
                   current setting for this machine.",
    unnamed: "an unnamed world",
};

/// One world a pack's travel names to the owner, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorldRecipientNotice {
    /// [`OWNER_PACK_EXPORT_RECIPIENT_NOTICE`] or
    /// [`AGENT_PACK_IMPORT_DOUBLE_CHECK`].
    pub notice_type: String,
    /// [`PACK_NOTICE_CHANNEL`].
    pub channel: String,
    /// [`PACK_NOTICE_VOICE`].
    pub voice: String,
    /// [`PACK_NOTICE_AUDIENCE`].
    pub audience: String,
    /// The world, hex: on the share receipt only, whose off-device screen
    /// reads it. A notice in a result names its world by name alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_ref: Option<String>,
    /// The world's name as the owner reads it; absent when its body names
    /// none a read may show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_name: Option<String>,
    /// Why, content-free: the owner's recipient limit for this machine, or
    /// the integrity hold that keeps it from being judged.
    pub reason: String,
    /// The notice in [`PACK_NOTICE_WORDING`].
    pub body: String,
}

impl WorldRecipientNotice {
    fn new(
        notice_type: &str,
        world: EntityId,
        world_name: Option<String>,
        reason: &str,
        template: &str,
    ) -> Self {
        let shown = world_name.as_deref().unwrap_or(PACK_NOTICE_WORDING.unnamed);
        let body = template
            .replace("{world_name}", shown)
            .replace("{reason}", reason);
        Self {
            notice_type: notice_type.to_owned(),
            channel: PACK_NOTICE_CHANNEL.to_owned(),
            voice: PACK_NOTICE_VOICE.to_owned(),
            audience: PACK_NOTICE_AUDIENCE.to_owned(),
            world_ref: Some(world.to_hex()),
            world_name,
            reason: reason.to_owned(),
            body,
        }
    }

    /// The owner's own export carried `world`, which `limit` would keep from
    /// where it goes.
    pub(crate) fn export(
        world: EntityId,
        world_name: Option<String>,
        limit: RecipientLimit,
    ) -> Self {
        Self::new(
            OWNER_PACK_EXPORT_RECIPIENT_NOTICE,
            world,
            world_name,
            limit.reason(),
            PACK_NOTICE_WORDING.export,
        )
    }

    /// This notice as a result carries it: by its world's name, never its
    /// id.
    pub(crate) fn in_result(self) -> Self {
        Self {
            world_ref: None,
            ..self
        }
    }

    /// An import lands in `world`, which `hold` keeps from this install. It
    /// rides on results alone (the install receipt and the preview), so it
    /// names the world by name.
    pub(crate) fn import(world: EntityId, world_name: Option<String>, hold: ReleaseHold) -> Self {
        let template = format!(
            "{} {}",
            PACK_NOTICE_WORDING.import, PACK_NOTICE_WORDING.import_scope
        );
        Self::new(
            AGENT_PACK_IMPORT_DOUBLE_CHECK,
            world,
            world_name,
            hold.reason(),
            &template,
        )
        .in_result()
    }
}

/// The share receipt field prefix each notice's fields sit under:
/// `notice.<n>.<field>`.
const NOTICE_FIELD_PREFIX: &str = "notice.";

/// A notice's fields only the owner reads: they name his world.
const OWNER_ONLY_NOTICE_FIELDS: [&str; 2] = ["world_name", "body"];

/// The share receipt's fields for `notices`: `world_refs`, the worlds named
/// (the off-device receipt screen reads them), and each notice's fields in
/// order.
pub(super) fn receipt_fields(notices: &[WorldRecipientNotice]) -> Vec<(String, String)> {
    if notices.is_empty() {
        return Vec::new();
    }
    let worlds = notices
        .iter()
        .filter_map(|notice| notice.world_ref.as_deref())
        .collect::<Vec<_>>()
        .join(",");
    let mut fields = vec![("world_refs".to_owned(), worlds)];
    for (index, notice) in notices.iter().enumerate() {
        let key = |field: &str| format!("{NOTICE_FIELD_PREFIX}{index}.{field}");
        fields.push((key("type"), notice.notice_type.clone()));
        if let Some(world) = &notice.world_ref {
            fields.push((key("world_ref"), world.clone()));
        }
        fields.push((key("reason"), notice.reason.clone()));
        if let Some(name) = &notice.world_name {
            fields.push((key("world_name"), name.clone()));
        }
        fields.push((key("body"), notice.body.clone()));
    }
    fields
}

/// Drops every notice field only the owner reads from `receipts` when
/// `reader` is not the owner (`secret_sight`, as his export asks): any other
/// reader sees each notice's type, world ref and reason, never the world's
/// name. A reader whose standing cannot be read is not the owner.
pub(crate) fn screen_owner_notice_fields(
    reader: &crate::memory::Memory<'_>,
    receipts: &mut [crate::receipt::ReceiptRecord],
) {
    let names = |fields: &BTreeMap<String, String>| fields.keys().any(|key| owner_only(key));
    if !receipts.iter().any(|receipt| names(&receipt.fields))
        || reader
            .secret_sight()
            .is_ok_and(|sight| sight == crate::secret_custody::SecretSight::Owner)
    {
        return;
    }
    for receipt in receipts {
        receipt.fields.retain(|key, _| !owner_only(key));
    }
}

fn owner_only(key: &str) -> bool {
    key.strip_prefix(NOTICE_FIELD_PREFIX)
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(_, field)| OWNER_ONLY_NOTICE_FIELDS.contains(&field))
}

/// `world`'s name as the owner reads it in `txn`, when its live WORLD body
/// names one a read may show.
pub(crate) fn world_label_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: &EntityId,
) -> Result<Option<String>> {
    let Some(raw) = EntityStoreRead::port_entity_raw(&vault.store, txn, world)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_WORLD {
        return Ok(None);
    }
    Ok(super::agent_pack_export::world_name(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    ))
}

/// The rows the born-with text that travelled was read from: the agent's
/// own (its why and keep) and, when its prompt travelled, each prompt row of
/// its birth `lane` admits, as `born_with_text_in_txn` reads them.
pub(super) fn born_with_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lane: &crate::claim::ScopedRead<'_>,
    agent: &EntityId,
    born_with: &BornWith,
) -> Result<Vec<EntityId>> {
    let mut rows = Vec::new();
    if born_with.is_empty() {
        return Ok(rows);
    }
    rows.push(*agent);
    if born_with.contains_key(&super::BornWithField::Prompt)
        && let Some(birth) = crate::provenance::birth::row_birth_in_txn(&vault.store, txn, agent)?
    {
        for input in &birth.made_by.inputs {
            if input.role == MadeByInputRole::Prompt
                && lane.entity_raw_live_in(txn, &input.row)?.is_some()
            {
                rows.push(input.row);
            }
        }
    }
    Ok(rows)
}

/// The owner's own export's notices, judged in the export's one `txn` over
/// `rows`, the rows whose bytes it selected: each world they lie in that his
/// recipient choice keeps from `onward`, where the pack goes on from here
/// (CALLS `FIX 5493 local export destination`), with why. `None` when one of
/// them cannot be placed while a world is withheld from `actual`, the
/// machine this surface's connection proved: his exception overrides his
/// recipient choice alone, never an unplaced row, so his share then reads as
/// it did before. A conflicted vault root refuses as the read it replaces
/// did. The knowledge it kept home that `actual` may not read is struck from
/// `omitted`, as the read before the ruling never listed it: a list of ids
/// names no row kept from where it goes.
pub(super) fn owner_export_notices_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &[EntityId],
    omitted: &mut Vec<crate::agent_def::OmittedClaim>,
    actual: &ReadDestination,
    onward: &ReadDestination,
) -> Result<Option<Vec<WorldRecipientNotice>>> {
    let flagged = if actual.is_off_device() {
        crate::settings::device_local_worlds_for(vault, txn, actual)?
    } else {
        BTreeSet::new()
    };
    if !flagged.is_empty() {
        let mut kept = Vec::with_capacity(omitted.len());
        for row in omitted.drain(..) {
            if !crate::settings::device_local_keeps_among(&vault.store, txn, &flagged, &row.claim)?
            {
                kept.push(row);
            }
        }
        *omitted = kept;
    }
    let mut worlds = BTreeSet::new();
    for row in rows {
        let carried = match crate::settings::carried_worlds_in(&vault.store, txn, row) {
            Ok(carried) => carried,
            Err(Error::CorruptedIndex(_)) if !flagged.is_empty() => return Ok(None),
            Err(Error::CorruptedIndex(_)) => continue,
            Err(error) => return Err(error),
        };
        if carried.unknown && !flagged.is_empty() {
            return Ok(None);
        }
        worlds.extend(carried.worlds);
    }
    let mut notices = Vec::new();
    for (world, limit) in crate::settings::recipient_limits_in(vault, txn, &worlds, onward)? {
        let name = world_label_in_txn(vault, txn, &world)?;
        notices.push(WorldRecipientNotice::export(world, name, limit));
    }
    Ok(Some(notices))
}

/// Whether `bytes` spell, as a whole 32-digit hex token, a row a world
/// withheld from `actual` keeps now: the payload scan every release off this
/// device runs (a result, a code run's answer, a keyed replay). The owner's
/// own export whose result would trip it reads as it did before the ruling
/// instead, so no request that answered before is refused (FIX 5493).
pub(super) fn names_kept_row(
    vault: &Vault,
    actual: &ReadDestination,
    bytes: &[u8],
) -> Result<bool> {
    if !actual.is_off_device() {
        return Ok(false);
    }
    let mut ids = BTreeSet::new();
    for run in bytes.split(|byte| !byte.is_ascii_hexdigit()) {
        if run.len() == 32
            && let Ok(hex) = std::str::from_utf8(run)
            && let Ok(id) = EntityId::from_hex(&hex.to_ascii_lowercase())
        {
            ids.insert(id);
        }
    }
    if ids.is_empty() {
        return Ok(false);
    }
    let named = ids.len();
    Ok(vault
        .off_device_readable_for(ids.into_iter().collect(), actual)?
        .len()
        != named)
}
