//! The layer's reads and quarantine: the default a read starts from, the packs that hold a key,
//! and the strictest rows a yes without its table leaves.

use super::*;

/// The default a read starts from where no vault row or pin decides (DESIGN 1.5 "The read",
/// step 1).
pub(in crate::setting) struct LayerDefault {
    /// The value the vault accepted, the build's default for a key no head names, or the key's
    /// strictest value when the accepted row is lost.
    pub(in crate::setting) value: EncodedValue,
    /// The pack whose accepted row is gone or does not decode: the read is unreadable there.
    pub(in crate::setting) lost: Option<SettingScope>,
}

/// The prefix every layer row of `name` starts with: its item-less value rows at a pack.
fn pack_rows_prefix(name: &str) -> Vec<u8> {
    let mut prefix = RowKey::item_prefix(name, None);
    prefix.push(SettingMode::Value.tag());
    prefix.push(ScopeKind::Pack.tag());
    prefix
}

/// One layer row of a key: its pack; its value, or `None` when it does not decode; and, for a row
/// an owner's yes wrote in an installed pack's layer, the sequence of that change (pass 34, 3.2;
/// RULING L1-PACK-LAYER-READ = A). The door writes its own rows with no actor, so a row that
/// names one is a yes's.
pub(super) type LayerRow = (String, Option<EncodedValue>, Option<u64>);

/// Every layer row of `spec`, by pack ([`LayerRow`]).
pub(super) fn layer_rows_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Vec<LayerRow>> {
    let mut rows = Vec::new();
    for row in table_of(spec).iter_raw_from(dbs, txn, &pack_rows_prefix(spec.name))? {
        let (key, bytes) = row?;
        let Some(RowKey {
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Pack(pack),
            ..
        }) = RowKey::decode(&key)
        else {
            continue;
        };
        let stored = rmp_serde::from_slice::<StoredRow>(&bytes).ok();
        let yes = stored
            .as_ref()
            .filter(|row| pack != ENGINE_PACK && row.by.is_some())
            .map(|row| row.change);
        let value = stored
            .map(|row| row.value)
            .filter(|value| spec.kind.decodes(value));
        rows.push((pack, value, yes));
    }
    Ok(rows)
}

/// The pack whose readable row the newest owner's yes wrote in an installed pack's layer, among
/// `rows` (RULING L1-PACK-LAYER-READ = A): the row a key that does not read met reads first.
pub(super) fn newest_yes_pack(rows: &[LayerRow]) -> Option<String> {
    rows.iter()
        .filter(|(_, value, _)| value.is_some())
        .filter_map(|(pack, _, yes)| yes.map(|change| (change, pack)))
        .max_by_key(|(change, _)| *change)
        .map(|(_, pack)| pack.clone())
}

/// The value the layer's readable rows read: on a key whose rows meet, their meet, so no pack
/// loosens it; on any other key, the row of `yes_pack`, the installed pack whose row the newest
/// owner's yes wrote ([`newest_yes_pack`]; RULING L1-PACK-LAYER-READ = A), else the engine pack's
/// row, else the first.
pub(in crate::setting) fn fold_layer(
    spec: &SettingSpec,
    rows: &[(String, EncodedValue)],
    yes_pack: Option<&str>,
) -> Option<EncodedValue> {
    if spec.reads_met() {
        rows.iter()
            .map(|(_, value)| value.clone())
            .reduce(|met, value| spec.kind.meet(&met, &value).unwrap_or(met))
    } else {
        yes_pack
            .and_then(|chosen| rows.iter().find(|(pack, _)| pack == chosen))
            .or_else(|| rows.iter().find(|(pack, _)| pack == ENGINE_PACK))
            .or_else(|| rows.first())
            .map(|(_, value)| value.clone())
    }
}

/// The packs whose layer holds a row of `spec` here, readable or not: the packs a birth of a key
/// `born` from `spec` names (stage 7c-3b).
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn packs_holding_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Vec<String>> {
    Ok(layer_rows_in_txn(dbs, txn, spec)?
        .into_iter()
        .map(|(pack, _, _)| pack)
        .collect())
}

/// The live head act of `pack` that names the table this install's own head names (stage
/// 7c-3b): what a birth names for a default the pack gives. Where none is live (the door last
/// acted before the vault had a root, or another machine's head with other defaults replaced
/// it), this install's head is appended in `txn` first, when the vault has a root and this
/// install can carry. `None` where the door never ran for the pack here, its head predates
/// versions, or the append fails (logged).
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn pack_head_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
) -> Result<Option<AuthorityEntryHash>> {
    let Some(head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(None);
    };
    let Some(digest) = oneiron_hex::decode::<32>(&head.digest) else {
        return Ok(None);
    };
    if let Some((hash, _)) = vault
        .setting_pack_heads_in_txn(txn, pack)?
        .into_iter()
        .find(|(_, live)| live.digest == digest)
    {
        return Ok(Some(hash));
    }
    if head.version.is_empty()
        || !rooted_in_txn(vault, txn)?
        || !vault.can_carry_owner_act_in_txn(txn)?
    {
        return Ok(None);
    }
    let table = shipped_table(vault, txn, pack, &digest)?;
    let mut held: Vec<String> = head
        .proposal
        .iter()
        .flat_map(|proposal| {
            proposal
                .defaults
                .iter()
                .map(|proposed| proposed.key.clone())
        })
        .collect();
    held.sort_unstable();
    held.dedup();
    match append_head_with_table_in_txn(vault, txn, (pack, &head.version, digest, held), table) {
        Ok(hash) => Ok(Some(hash)),
        Err(error) => {
            tracing::warn!(
                pack,
                kind = ?error.kind(),
                "a birth found no head act of the pack and appended none: its born rows stand on this install"
            );
            Ok(None)
        }
    }
}

/// `spec`'s row in `pack`'s layer as a birth that names a head of the table `digest` reads it,
/// where this install's head of `pack` names that table (stage 7c-3b): this install's own row of
/// the key, the record of what it accepted from that table, a held key's earlier value included,
/// before each owner's yes the birth did not see (stage 7c-3d; DESIGN 1.6: a later change of the
/// default does not move a birth). The key's landings are walked newest first while the row is
/// the one a landing wrote, as a pass puts them back ([`revert_landings_in_txn`]): a landing whose
/// table (hex) `named` holds, the birth naming a yes to it, stops the walk; any other gives back
/// the row it replaced. `None` where the door never ran for the pack here or its head names
/// another table: the table is not proved here. `Some(None)` where the row reached is gone (a
/// landing replaced no row) or does not decode.
///
/// # Errors
///
/// `named`'s errors; storage errors.
pub(in crate::setting) fn birth_pack_row_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    (pack, digest): (&str, &[u8; 32]),
    spec: &SettingSpec,
    mut named: impl FnMut(&str) -> Result<bool>,
) -> Result<Option<Option<EncodedValue>>> {
    let Some(head) = head_in_txn(dbs, txn, pack)?
        .filter(|head| oneiron_hex::decode::<32>(&head.digest).is_some_and(|ours| ours == *digest))
    else {
        return Ok(None);
    };
    let table = table_of(spec);
    let mut row = table.get_bytes(dbs, txn, &pack_row_key(spec.name, pack))?;
    for landing in head
        .landed
        .iter()
        .rev()
        .filter(|landing| landing.key == spec.name)
    {
        if row.as_deref().map(row_digest).as_deref() != Some(landing.wrote.as_str())
            || named(&landing.table)?
        {
            break;
        }
        row = landing
            .prior
            .as_ref()
            .map(|prior| table.encode_value(prior))
            .transpose()?;
    }
    Ok(Some(
        row.and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
            .map(|row| row.value)
            .filter(|value| spec.kind.decodes(value)),
    ))
}

/// The tables (their digests) of the owner's yeses whose landings `spec`'s row in `pack`'s layer
/// stands on here (stage 7c-3d), newest first: the key's landings walked as a reader walks them
/// ([`birth_pack_row_in_txn`]), while the row is the one each wrote. What a birth names yeses to,
/// beside the pack's head: each table it names a yes to stops a reader's walk there, so a birth
/// that names an older table's yes still reads it where the newest table's yes no longer counts.
/// Empty where no yes wrote the row here.
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn yes_landing_tables_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    pack: &str,
    spec: &SettingSpec,
) -> Result<Vec<[u8; 32]>> {
    let Some(head) = head_in_txn(dbs, txn, pack)? else {
        return Ok(Vec::new());
    };
    let table = table_of(spec);
    let mut row = table.get_bytes(dbs, txn, &pack_row_key(spec.name, pack))?;
    let mut tables = Vec::new();
    for landing in head
        .landed
        .iter()
        .rev()
        .filter(|landing| landing.key == spec.name)
    {
        if row.as_deref().map(row_digest).as_deref() != Some(landing.wrote.as_str()) {
            break;
        }
        if let Some(digest) = oneiron_hex::decode::<32>(&landing.table)
            && !tables.contains(&digest)
        {
            tables.push(digest);
        }
        row = landing
            .prior
            .as_ref()
            .map(|prior| table.encode_value(prior))
            .transpose()?;
    }
    Ok(tables)
}

/// The read's default for `spec`: what the vault accepted from its packs. A key a head names
/// whose row is gone or does not decode reads strictest. A key no head names reads the build's
/// default: it is new in this build, and that is the value the door lands for it.
///
/// # Errors
///
/// `CorruptedIndex` for a lost row of a key that names no strictest value; storage errors.
pub(in crate::setting) fn layer_default_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<LayerDefault> {
    let rows = layer_rows_in_txn(dbs, txn, spec)?;
    if let Some((pack, _, _)) = rows.iter().find(|(_, value, _)| value.is_none()) {
        return lost(spec, pack);
    }
    let yes_pack = newest_yes_pack(&rows);
    let readable: Vec<(String, EncodedValue)> = rows
        .into_iter()
        .filter_map(|(pack, value, _)| value.map(|value| (pack, value)))
        .collect();
    if let Some(value) = fold_layer(spec, &readable, yes_pack.as_deref()) {
        return Ok(LayerDefault { value, lost: None });
    }
    for row in HEADS.iter_raw_from(dbs, txn, &[])? {
        let (pack, bytes) = row?;
        let names = rmp_serde::from_slice::<PackHead>(&bytes)
            .map(|head| {
                head.accepted
                    .binary_search_by(|key| key.as_str().cmp(spec.name))
                    .is_ok()
            })
            // A head that does not decode may name any key: read it as naming this one.
            .unwrap_or(true);
        if names {
            return lost(spec, &String::from_utf8_lossy(&pack));
        }
    }
    Ok(LayerDefault {
        value: spec.kind.default_value()?,
        lost: None,
    })
}

pub(super) fn lost(spec: &SettingSpec, pack: &str) -> Result<LayerDefault> {
    Ok(LayerDefault {
        value: spec.kind.strictest_value()?.ok_or(Error::CorruptedIndex(
            "a setting's accepted default is lost and its key names no strictest value",
        ))?,
        lost: Some(SettingScope::Pack(pack.to_owned())),
    })
}

/// The bytes of `pack`'s table whose digest is `digest` where this install holds it: the `engine`
/// pack's own defaults, which this build ships (stage 7c-3c), or the table an installed pack's
/// Active source carries (pass 34, 3.2; row L1). `None` for any other table.
///
/// # Errors
///
/// A key whose default does not encode; storage errors.
pub(super) fn shipped_table(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pack: &str,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if pack != ENGINE_PACK {
        return super::installed::installed_table(vault, txn, pack, digest);
    }
    let defaults = engine_pack_defaults()?;
    if defaults_digest(pack, &defaults).into_bytes() != *digest {
        return Ok(None);
    }
    table_bytes(pack, &defaults).map(Some)
}

/// Appends `pack`'s head as one act in `txn`, with its table's bytes `table` beside it where
/// given (stage 7c-3c), in one savepoint: both, or neither. The row is the act's own, put after
/// the append (stage 7c-3c review). The entry's hash.
///
/// # Errors
///
/// The append's typed refusal; the put's refusal; storage errors.
pub(super) fn append_head_with_table_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, version, digest, held): (&str, &str, [u8; 32], Vec<String>),
    table: Option<Vec<u8>>,
) -> Result<AuthorityEntryHash> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let hash =
        vault.append_setting_pack_head_in_txn(&mut savepoint, pack, version, digest, held)?;
    if let Some(table) = &table {
        put_pack_table_in_txn(vault, &mut savepoint, (pack, &digest, &hash), table)?;
    }
    savepoint.commit()?;
    Ok(hash)
}

/// The waiting defaults of every pack, by key: what `vault.settings.list` shows.
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn proposed_defaults_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(String, ProposedDefaultView)>> {
    let mut views = Vec::new();
    for row in HEADS.iter_raw_from(dbs, txn, &[])? {
        let (pack, bytes) = row?;
        let Ok(head) = rmp_serde::from_slice::<PackHead>(&bytes) else {
            continue;
        };
        let Some(proposal) = head.proposal else {
            continue;
        };
        let pack = String::from_utf8_lossy(&pack).into_owned();
        for proposed in proposal.defaults {
            let value = spec_named(&proposed.key)
                .ok()
                .and_then(|spec| spec.kind.to_json(&proposed.value))
                .unwrap_or(serde_json::Value::Null);
            views.push((
                proposed.key,
                ProposedDefaultView {
                    pack: pack.clone(),
                    value,
                    direction: proposed.direction,
                    proposal: proposal.digest.clone(),
                },
            ));
        }
    }
    Ok(views)
}

/// Writes each of `keys` this build knows as a row of `pack`'s layer that does not decode, and
/// takes it out of the pack's waiting proposal (stage 7c-3c): the owner accepted its default of a
/// table whose bytes here are not that table, or were erased here, so it reads the key's
/// strictest value, unreadable, as a lost row does (DESIGN 1.6, "Fold states"). No change row and
/// no hook: no value was read. Each row it writes is a landing of the yes to `table` (hex), put
/// back once no yes that counts in full names its key (stage 7c-3c review). Answers the keys whose
/// row moved.
///
/// # Errors
///
/// Storage errors.
pub(super) fn quarantine_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, table): (&str, &str),
    keys: &[String],
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let mut head = head_in_txn(&vault.store, txn, pack)?.unwrap_or_default();
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut moved = Vec::new();
    for key in keys {
        let Ok(spec) = spec_named(key) else {
            continue;
        };
        let at = pack_row_key(spec.name, pack);
        let prior = table_of(spec)
            .get_bytes(&vault.store, txn, &at)?
            .map(|bytes| {
                rmp_serde::from_slice::<StoredRow>(&bytes).unwrap_or_else(|_| unreadable_row(now))
            });
        table_of(spec).put(&vault.store, txn, &at, &unreadable_row(now))?;
        let proposed = head.proposal.as_ref().and_then(|proposal| {
            proposal
                .defaults
                .iter()
                .find(|proposed| proposed.key == spec.name)
                .map(|proposed| (head.digest.clone(), proposed.clone()))
        });
        head.landed.push(YesLanding {
            key: spec.name.to_owned(),
            table: table.to_owned(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed,
        });
        accepted.insert(spec.name.to_owned());
        moved.push(spec);
    }
    if let Some(proposal) = head.proposal.take() {
        let kept: Vec<ProposedDefault> = proposal
            .defaults
            .into_iter()
            .filter(|proposed| keys.binary_search(&proposed.key).is_err())
            .collect();
        head.proposal = (!kept.is_empty()).then(|| PackProposal {
            digest: proposal_digest(pack, &head.digest, &kept),
            defaults: kept,
        });
    }
    head.accepted = accepted.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    Ok(moved)
}

/// A layer row that reads its key's strictest value, unreadable ([`quarantine_in_txn`]).
fn unreadable_row(now: u64) -> StoredRow {
    StoredRow {
        value: EncodedValue(vec![UNREADABLE_VALUE]),
        by: None,
        setter: Setter::Pack,
        set_at: now,
        change: 0,
        weight_runs: None,
        local: None,
        seeded: false,
    }
}
