//! Appends setting acts, projects stored rows, and runs projection passes.

use super::*;

/// Whether an owner's change of a row of `spec` travels as its signed act (stage 7a-2): a
/// `sync: vault` key that is not learned, whose seed weight does not travel yet. Its value rides
/// inside the act where the key's value type is closed and its JSON fits, else beside it (stage
/// 7c-1, [`slot_value`]). A carried row travels too (stage 7a-4): a move's copy brings it
/// to every machine, and the owner's clear of it is his act.
pub(in crate::setting) fn travels(spec: &SettingSpec) -> bool {
    spec.sync == SettingSync::Vault && !spec.is_learned()
}

/// Whether the vault has an authority root, a conflicted one included: a vault without one is
/// one machine, and its door writes the row alone, as before stage 7 (the cut
/// `project_depth/fold.rs` makes).
pub(in crate::setting) fn rooted_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let view = vault.authority_view_readonly_in_txn(txn)?;
    Ok(view.vault_id.is_some() || view.vault_root_is_conflicted())
}

/// Appends the owner `owner`'s applied change `recorded` of a row of `spec` that travels as its
/// signed act, in the change's write `txn`, from `surface`, with its value inside the act or
/// beside it ([`slot_value`]); names the entry on the change row; and projects the row
/// from the fold in the same write. It signs on `ground`, or with no owner proof where that is
/// `None`.
///
/// # Errors
///
/// The append's typed refusal (no live machine profile to carry the act, a fold that does not
/// count it, more heads than one entry names), or a storage error: the change fails with it.
pub(in crate::setting) fn append_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ground: Option<&OwnerProofGround>,
    spec: &'static SettingSpec,
    (owner, surface): (EntityId, ActSurface),
    recorded: &SettingChange,
) -> Result<()> {
    let json = recorded
        .value
        .as_ref()
        .map(|value| json_bytes(spec, value))
        .transpose()?;
    let slot = RowKey {
        name: recorded.key.clone(),
        item: recorded.item.clone(),
        mode: recorded.mode,
        scope: recorded.scope.clone(),
    };
    let target = setting_slot_target(&slot)?;
    let prior = setting_value_digest(&match &recorded.prior {
        Some(prior) => json_bytes(spec, prior)?,
        None => b"null".to_vec(),
    });
    let (value, beside) = slot_value(spec, json);
    let signed = vault.append_setting_slot_act_in_txn(
        txn,
        ground,
        SettingSlotAct {
            owner,
            surface,
            rows: vec![SettingSlotRow {
                slot: slot.clone(),
                prior,
                value,
            }],
        },
    )?;
    // An act that waits for the owner's proof changes nothing, here as on every other machine:
    // the door refuses it with the reason, and nothing of the change is stored (module doc).
    if vault.setting_act_waits_in_txn(txn, signed)? {
        return Err(Error::Record(RecordError::OwnerKeyRequired));
    }
    if let Some(json) = beside {
        put_beside_value_in_txn(vault, txn, (&slot, &signed), &json)?;
    }
    record_signed_entry_in_txn(&vault.store, txn, recorded, signed)?;
    let now = recorded.at;
    let projected = project_target_in_txn(vault, txn, target, now)?;
    if projected.changed.is_empty()
        && let Some((standing, with)) = projected.receipt
    {
        record_receipt_in_txn(&vault.store, txn, recorded.sequence, standing, with)?;
    }
    Ok(())
}

/// The value's JSON bytes: what an act carries inline, and what its digest is over (the digest
/// stage 7a-1's acts keep).
pub(in crate::setting) fn json_bytes(spec: &SettingSpec, value: &EncodedValue) -> Result<Vec<u8>> {
    let json = spec.kind.to_json(value).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&json).map_err(|_| Error::InvariantViolation("setting act encoding"))
}

/// The basis a row's projection records (stage 7b-2): the target's act `revision` while every
/// act a reader of it meets counts in full here, its heads do not conflict and none waits for
/// the owner's proof, as stage 7a-2 recorded it; otherwise a fingerprint of the revision, of each
/// act's count, where the heads conflict of the act the register holds in force (`in_force`, the
/// last act every head descends from, judged the same way: an act no count names), and of each
/// act that waits (stage 7b-3). So a pass reads the row again when a head's count moves and its
/// revision does not (a removal it raced arrives, a hold ends), when the conflict's act loses its
/// standing, and when a proposal arrives or its ask ends. A row whose acts a copy among them
/// names records each named act too, by what it counts for on its own row (`name_counts`; row
/// SETTING-COPY-NAME-IGNORES-COUNT), so a pass reads the copy again when one of those counts
/// moves and the row's own revision does not.
pub(super) fn basis_of(
    revision: [u8; 32],
    (counts, name_counts): (&ChoiceCounts, &NameCounts),
    (conflict, in_force): (bool, Option<AuthorityEntryHash>),
    asking: &BTreeSet<AuthorityEntryHash>,
) -> [u8; 32] {
    if !conflict
        && asking.is_empty()
        && name_counts.is_empty()
        && counts
            .values()
            .all(|counted| counted.count == ChoiceCount::Full)
    {
        return revision;
    }
    let mut basis = Fingerprinter::new(purposes::setting::PROJECTION_BASIS);
    basis.part(&revision).u64(counts.len() as u64);
    for (act, counted) in counts {
        basis.part(act).u64(count_tag(counted.count));
    }
    if conflict {
        basis.u64(1).part(&in_force.unwrap_or([0; 32]));
    }
    if !asking.is_empty() {
        basis.u64(asking.len() as u64);
        for act in asking {
            basis.part(act);
        }
    }
    if !name_counts.is_empty() {
        basis.part(b"name_counts").u64(name_counts.len() as u64);
        for (row, counts) in name_counts {
            basis.part(row.as_bytes()).u64(counts.len() as u64);
            for (act, counted) in counts {
                basis.part(act).u64(count_tag(counted.count));
            }
        }
    }
    basis.finish().into_bytes()
}

/// A count as [`basis_of`] records it.
fn count_tag(count: ChoiceCount) -> u64 {
    match count {
        ChoiceCount::Full => 0,
        ChoiceCount::Safe { held: false } => 1,
        ChoiceCount::Safe { held: true } => 2,
        ChoiceCount::Disputed => 3,
    }
}

pub(super) fn target_key(target: EntityId) -> Vec<u8> {
    target.as_bytes().to_vec()
}

/// What `slot`'s empty slot gives (DESIGN 1.6, "What the empty slot gives"): on a vault value row
/// the accepted default; on a born thing's own value row the strictest value, since the thing must
/// have its row (stage 7c-2); on any other slot no bound.
pub(super) fn empty_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
) -> Result<Option<EncodedValue>> {
    if is_vault_value_row(slot) {
        Ok(Some(layer_default_in_txn(&vault.store, txn, spec)?.value))
    } else if is_born_value_slot(spec, slot) {
        spec.kind.strictest_value()
    } else {
        Ok(None)
    }
}

/// The bound this install's own carry keeps on the carried row `slot`, which bounds its
/// projection (stage 7a-4, RULING SETTING-7A-4-COPY Q2 = A): what its carry wrote
/// (`StoredRow::local`), or, on a row an older build's carry wrote with none, the row's value,
/// which the projection then writes as `local`. A row the projection wrote from a copy keeps no
/// bound: every other machine reads the copy alone, so a value a copy gave never holds a later
/// read of it, as one that arrives after the copy. `None` once the owner released the row
/// (every head a clear of it), and where no row decodes.
pub(super) fn own_carry_bound_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
    heads: &[Head],
) -> Result<Option<EncodedValue>> {
    if heads.iter().all(|head| !head.carries_value()) {
        return Ok(None);
    }
    let Some(row) = table_of(spec)
        .get_bytes(&vault.store, txn, &slot.encode())?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
    else {
        return Ok(None);
    };
    if row.local.is_some() {
        return Ok(row.local);
    }
    let projected = change_in_txn(&vault.store, txn, row.change)?
        .is_some_and(|change| change.standing.is_some());
    Ok((!projected && spec.kind.decodes(&row.value)).then_some(row.value))
}

/// `projected` met with the bound a carried row keeps here ([`own_carry_bound_in_txn`], stage
/// 7a-4): a copy never loosens what this install carried. A quarantined row stays quarantined.
pub(super) fn met_with_local(
    spec: &SettingSpec,
    mut projected: Projected,
    local: Option<&EncodedValue>,
) -> Projected {
    let Some(local) = local else {
        return projected;
    };
    if projected.keep || projected.standing == ChangeStanding::Quarantined {
        return projected;
    }
    projected.value = Some(match projected.value.take() {
        Some(value) => spec
            .kind
            .meet(&value, local)
            .unwrap_or_else(|| local.clone()),
        None => local.clone(),
    });
    projected
}

/// Projects a pack's target (stage 7c-3c): its heads name no row, and the pack's own read lands
/// each owner's yes that counts here ([`project_pack_in_txn`]). Recorded once read, so a pass
/// over the same revision reads nothing; not while a yes waits for its table's bytes, so a later
/// pass, and the put of that row, reads them again.
pub(super) fn project_pack_target_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, basis): (EntityId, [u8; 32]),
    fold: &SettingSlotFold,
    now: u64,
) -> Result<TargetProjected> {
    let read = project_pack_in_txn(vault, txn, fold, now)?;
    let why = if read.awaiting {
        Inert::ForNow
    } else {
        Inert::ForGood
    };
    leave_in_txn(vault, txn, (target, basis, why), BesideReads::default())?;
    Ok(TargetProjected {
        changed: read.moved,
        receipt: None,
    })
}

/// Leaves the row of `target` as it is (`Inert`), recording its `basis` when no build writes a
/// row from those acts; while a value beside an act has not arrived, that the row reads
/// `Pending` and the rows beside acts it read (`reads`); and while this build does not know their
/// key, that the row reads `Pending` and the key's name. Both keep what the last projection left
/// ([`pending_as_last_in_txn`]). Returns no changed key.
pub(super) fn leave_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, basis, why): (EntityId, [u8; 32], Inert),
    reads: BesideReads,
) -> Result<TargetProjected> {
    let projection = match why {
        Inert::ForNow => return Ok(TargetProjected::UNMOVED),
        Inert::ForGood => Projection {
            slot: Vec::new(),
            basis,
            standing: SettingStanding::Settled,
            pin_read_as_value: false,
            beside: Vec::new(),
            unknown_key: None,
        },
        Inert::UnknownKey(key) => {
            pending_as_last_in_txn(vault, txn, (target, basis), Vec::new(), Some(key))?
        }
        Inert::Awaiting => {
            pending_as_last_in_txn(vault, txn, (target, basis), reads.into_seen(false), None)?
        }
    };
    record_projection_in_txn(vault, txn, target, &projection)?;
    Ok(TargetProjected::UNMOVED)
}

/// Records `projection` as `target`'s, in `txn`, and names the rows beside acts it read in
/// place of the rows the last one read, so a put of one notes the pass ([`watch_rows_in_txn`]).
pub(super) fn record_projection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    projection: &Projection,
) -> Result<()> {
    let key = target_key(target);
    let rows_of = |projection: &Projection| -> Vec<EntityId> {
        projection.beside.iter().map(|seen| seen.row).collect()
    };
    let last = PROJECTIONS
        .get(&vault.store, txn, &key)?
        .map(|last| rows_of(&last))
        .unwrap_or_default();
    watch_rows_in_txn(&vault.store, txn, target, (&last, &rows_of(projection)))?;
    PROJECTIONS.put(&vault.store, txn, &key, projection)?;
    // A refusal of the target's acts no longer stands once they are projected (`refusal`).
    REFUSALS.delete(&vault.store, txn, &key)?;
    Ok(())
}

/// A `Pending` projection of `target` at `basis` with the rows beside acts it read (`beside`) and
/// the key this build does not know (`unknown_key`), that keeps what the last projection of
/// `target` left: its row, and how a pin at that row reads. A read then takes the row as it did
/// before these acts until a pass reads them again, under this build or one that knows the key.
fn pending_as_last_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (target, basis): (EntityId, [u8; 32]),
    beside: Vec<BesideSeen>,
    unknown_key: Option<String>,
) -> Result<Projection> {
    let last = PROJECTIONS.get(&vault.store, txn, &target_key(target))?;
    Ok(Projection {
        slot: last
            .as_ref()
            .map(|last| last.slot.clone())
            .unwrap_or_default(),
        basis,
        standing: SettingStanding::Pending,
        pin_read_as_value: last.is_some_and(|last| last.pin_read_as_value),
        beside,
        unknown_key,
    })
}

/// Writes `projected` as the row `slot` of `spec` when it differs from the stored row, or the
/// stored row is not the deciding act's: the row, one change row credited to the deciding act,
/// and the key's hook. A birth that reads here (`birth`, [`birth_of_in_txn`]) over no stored row
/// is the thing's start, as the creation door writes it (stage 7c-3b): the row alone, change 0,
/// with no change row and no hook. Whether it wrote. A carried row, and a row a copy decided, is
/// the engine's, with its `local` bound (stage 7a-4); every other row is the deciding owner's.
pub(super) fn write_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (spec, slot): (&'static SettingSpec, &RowKey),
    projected: &Projected,
    (local, birth): (Option<&EncodedValue>, Option<bool>),
    now: u64,
) -> Result<bool> {
    let deciding = projected.deciding;
    if projected.keep {
        return Ok(false);
    }
    let (setter, by, surface) = match deciding.owner {
        Some(owner) if slot.mode != SettingMode::Carried => {
            (Setter::Owner, Some(owner), deciding.surface)
        }
        _ => (Setter::Engine { ask: None }, None, None),
    };
    let table = table_of(spec);
    let key = slot.encode();
    let stored = table
        .get_bytes(&vault.store, txn, &key)?
        .map(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok());
    let same = match (&stored, &projected.value) {
        (None, None) => true,
        (Some(Some(row)), Some(value)) => {
            row.value == *value
                && row.setter == setter
                && row.by == by
                && row.local.as_ref() == local
        }
        _ => false,
    };
    if same {
        return Ok(false);
    }
    // A birth over no row is the thing's start, as the door that created it wrote it on its own
    // install (stage 7c-3b, `born.rs`): no change row, no move.
    if let (Some(seeded), None, Some(value)) = (birth, &stored, &projected.value) {
        table.put(
            &vault.store,
            txn,
            &key,
            &StoredRow {
                value: value.clone(),
                by,
                setter,
                set_at: now,
                change: 0,
                weight_runs: None,
                local: local.cloned(),
                seeded,
            },
        )?;
        return Ok(true);
    }
    let prior = stored.flatten().map(|row| row.value);
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: slot.item.clone(),
            scope: slot.scope.clone(),
            mode: slot.mode,
            by,
            setter,
            prior: prior.clone().filter(|_| !projected.erased),
            value: projected.value.clone(),
            at: now,
            why: None,
            weight_runs: None,
            direction: None,
            surface,
            signed: Some(deciding.act),
            with: projected.with.clone(),
            standing: Some(projected.standing),
        },
    )?;
    match &projected.value {
        Some(value) => table.put(
            &vault.store,
            txn,
            &key,
            &StoredRow {
                value: value.clone(),
                by,
                setter,
                set_at: now,
                change: recorded.sequence,
                weight_runs: None,
                local: local.cloned(),
                seeded: birth.unwrap_or(false),
            },
        )?,
        None => {
            table.delete(&vault.store, txn, &key)?;
        }
    }
    // The key's hook reads the row as it stood before the change, an erased value included
    // (a seat or a feed it takes out of service): the history keeps none of it.
    if let Some(on_change) = spec.on_change
        && let Err(error) = on_change(vault, txn, &SettingChange { prior, ..recorded })
    {
        // The act the refused value came from, for the owner's notice of the refusal (`refusal`).
        REFUSED_DECIDING_ACT.with(|refused| refused.set(Some(deciding.act)));
        return Err(error);
    }
    Ok(true)
}

/// The row beside an act `row` as the last projection of the target that reads it recorded it;
/// `None` where no projection reads it now.
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn beside_source_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<BesideSource>> {
    let Some(target) = super::super::beside::watched_target_in_txn(dbs, txn, row)? else {
        return Ok(None);
    };
    let Some(projection) = PROJECTIONS.get(dbs, txn, &target_key(target))? else {
        return Ok(None);
    };
    let (Some(slot), Some(seen)) = (
        RowKey::decode(&projection.slot),
        projection.beside.iter().find(|seen| seen.row == *row),
    ) else {
        return Ok(None);
    };
    let stored = match spec_named(&slot.name) {
        Ok(spec) if seen.kept => table_of(spec)
            .get_bytes(dbs, txn, &slot.encode())?
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
            .map(|stored| stored.value),
        _ => None,
    };
    Ok(Some(BesideSource {
        slot,
        digest: seen.digest,
        stored,
    }))
}

/// Whether the pin row `slot` reads as a value row at its scope (stage 7b-3): its projection
/// found an act it comes from that does not count in full here, so it narrows and releases
/// nothing. A pin no projection wrote reads as a pin.
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn pin_reads_as_value_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
) -> Result<bool> {
    if slot.mode != SettingMode::Pin {
        return Ok(false);
    }
    Ok(PROJECTIONS
        .get(dbs, txn, &target_key(setting_slot_target(slot)?))?
        .is_some_and(|projection| projection.pin_read_as_value))
}

/// How the acts behind the rows of `spec` a read walks stand: the least settled of the pin, value
/// and carried rows on `chain`, for `item` and the item-less rows (stage 7a-2; carried rows stage
/// 7a-4). A key that stays on its install is always settled; a key no act names reads no
/// projection and is settled too.
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn standing_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<SettingStanding> {
    if spec.sync != SettingSync::Vault {
        return Ok(SettingStanding::Settled);
    }
    let items: Vec<Option<&str>> = match item {
        Some(_) => vec![item, None],
        None => vec![None],
    };
    let mut standing = SettingStanding::Settled;
    for scope in chain {
        for row_item in &items {
            for mode in [SettingMode::Pin, SettingMode::Value, SettingMode::Carried] {
                let slot = RowKey {
                    name: spec.name.to_owned(),
                    item: row_item.map(str::to_owned),
                    mode,
                    scope: scope.clone(),
                };
                if let Some(projection) =
                    PROJECTIONS.get(dbs, txn, &target_key(setting_slot_target(&slot)?))?
                {
                    standing = standing.max(projection.standing);
                }
            }
        }
    }
    Ok(standing)
}

impl Vault {
    /// Projects every setting row whose signed acts moved since it was last projected, in one
    /// write, and runs the `after_commit` of each key whose row changed (stage 7a-2). A vault
    /// with no authority root, or with no setting act, writes nothing. A row its key's hook
    /// refuses here stays as it was, and raises the owner's notice of it (`refusal`).
    ///
    /// First, in its own write, the owner's rows no act backs are published as batch acts, once
    /// per vault (stage 7a-3, [`Self::publish_settings`]); a fault there is logged, and the
    /// projection goes on.
    ///
    /// # Errors
    ///
    /// Storage errors; a key's hook's error.
    pub fn project_settings(&self) -> Result<SettingsProjected> {
        match self.publish_settings() {
            Ok(Some(published)) if published.acts > 0 => tracing::info!(
                acts = published.acts,
                rows = published.rows,
                "the owner's setting rows no act backed were published as batch acts"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the owner's setting rows no act backs were not published; the next authority commit or open tries again"
            ),
        }
        let mut moved: Vec<(EntityId, Option<WriteTurn>)> = {
            let txn = self.store.env.read_txn()?;
            if !rooted_in_txn(self, &txn)? {
                return Ok(SettingsProjected::default());
            }
            let mut moved = Vec::new();
            for target in self.policy_setting_revisions_in_txn(&txn)? {
                let fallback = (target.conflict, target.in_force);
                let counts = (&target.counts, &target.name_counts);
                let basis = basis_of(target.revision, counts, fallback, &target.asking);
                let moved_here =
                    match PROJECTIONS.get(&self.store, &txn, &target_key(target.target))? {
                        Some(projection) => moved_since(self, &txn, &projection, basis)?,
                        None => true,
                    };
                if moved_here {
                    // The packs first (stage 7c-3c): a birth read in this pass reads the layer
                    // rows an owner's yes lands. A target is a pack's by its acts, read in this
                    // snapshot, so a yes to a table this install has not weighed yet goes first
                    // too (stage 7c-3c review).
                    let later = !self.setting_target_is_pack_in_txn(&txn, target.target)?;
                    let turn = write_turn_of_target_in_txn(self, &txn, target.target)?;
                    moved.push((later, target.target, turn));
                }
            }
            moved.sort_by_key(|(later, _, _)| *later);
            moved
                .into_iter()
                .map(|(_, target, turn)| (target, turn))
                .collect::<Vec<_>>()
        };
        // The turns of the keys whose rows the pass may change, taken before its writer opens, as
        // a change of such a key takes its own ([`WriteTurn`]): a feed's uninstall or a seat's
        // then never lands inside a running calendar admission. A turn this thread already holds
        // (a pass run by a commit of the turn's holder) leaves those rows for the pass that runs
        // once it is released ([`project_deferred_settings`]).
        let turns: BTreeMap<&str, WriteTurn> = moved
            .iter()
            .filter_map(|(_, turn)| turn.map(|turn| (turn.name, turn)))
            .collect();
        let mut held = Vec::with_capacity(turns.len());
        let mut deferred = BTreeSet::new();
        for turn in turns.values() {
            match (turn.take)(self) {
                Ok(guard) => held.push(guard),
                Err(Error::InvalidConfig(_)) => {
                    deferred.insert(turn.name);
                }
                Err(error) => return Err(error),
            }
        }
        if !deferred.is_empty() {
            moved.retain(|(_, turn)| turn.is_none_or(|turn| !deferred.contains(turn.name)));
            PROJECTION_DEFERRED.with(|owed| owed.set(true));
            crate::federation::note_authority_row();
        }
        if moved.is_empty() {
            return Ok(SettingsProjected::default());
        }
        let changed = self.with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut changed: Vec<&'static SettingSpec> = Vec::new();
            for (target, _) in &moved {
                REFUSED_DECIDING_ACT.with(|refused| refused.set(None));
                // Each row in a savepoint of its own: one a key's hook refuses on this install
                // (its manifest, a seat installed here) stays as it was, and the others land.
                // A savepoint that commits hands the work its writes queued for after the commit
                // (the live sync mirror, the wakes) to the pass's write (`batch::savepoint_in_txn`).
                match crate::batch::savepoint_in_txn(self, txn, |savepoint| {
                    project_target_in_txn(self, savepoint, *target, now).map(Some)
                }) {
                    Ok(projected) => {
                        changed.extend(projected.into_iter().flat_map(|projected| projected.changed));
                    }
                    Err(Error::InvalidConfig(reason)) => {
                        tracing::warn!(
                            reason = %reason,
                            "the next pass reads again a setting row its key refused here"
                        );
                        record_refusal_in_txn(self, txn, *target)?;
                        let deciding = REFUSED_DECIDING_ACT.with(Cell::take);
                        // The owner's notice of it (`refusal`), in a savepoint of its own: a
                        // fault there is logged, and the pass goes on.
                        if let Err(error) = crate::batch::savepoint_in_txn(self, txn, |notice| {
                            let refused = (*target, reason.as_str(), deciding);
                            raise_refusal_notice_in_txn(self, notice, refused, now).map(Some)
                        }) {
                            tracing::warn!(
                                kind = ?error.kind(),
                                "the owner's notice of a setting row its key refused here was not raised; the next pass tries again"
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(changed)
        })?;
        for spec in &changed {
            if let Some(after_commit) = spec.after_commit {
                after_commit(self);
            }
        }
        Ok(SettingsProjected {
            moved: moved.len(),
            rows_changed: changed.len(),
        })
    }

    /// [`Self::project_settings`] once a commit stored an authority row (`noted`), whichever
    /// door stored it: a peer's acts, an import, a machine's standing or a Grant changed. A no-op
    /// otherwise; a failure is logged, and the next such commit or the next open tries again.
    pub(crate) fn project_settings_after_authority_ingest(&self, noted: bool) {
        if !noted {
            return;
        }
        if let Err(error) = self.project_settings() {
            tracing::warn!(
                kind = ?error.kind(),
                "the setting rows were not projected from their signed acts; the next authority commit or open tries again"
            );
        }
    }
}

thread_local! {
    /// Set on a thread whose projection pass left rows for later because the thread held their
    /// key's turn ([`Vault::project_settings`]); [`project_deferred_settings`] runs that pass.
    static PROJECTION_DEFERRED: Cell<bool> = const { Cell::new(false) };
    /// The act the value a key's hook refused in this thread's pass came from
    /// ([`write_row_in_txn`]), for the owner's notice of the refusal; the pass clears it before
    /// each row.
    static REFUSED_DECIDING_ACT: Cell<Option<AuthorityEntryHash>> = const { Cell::new(None) };
}

/// Runs the projection pass a pass on this thread left for later because the thread held a key's
/// turn, once the turn's holder released it ([`Vault::set_setting`]). A no-op where none was
/// left; a failure is logged, and the next authority commit or open tries again. Any other holder
/// of a turn leaves the pass to the next watched commit on its thread, which the deferring pass
/// noted, or to the open.
pub(crate) fn project_deferred_settings(vault: &Vault) {
    let deferred = PROJECTION_DEFERRED.with(|owed| owed.replace(false));
    vault.project_settings_after_authority_ingest(deferred);
}

/// The turn the key of the acts on `target` takes before a write of its row opens
/// ([`WriteTurn`]), read before the pass's writer opens; `None` for a key that names none, or acts
/// that name no row this build writes.
fn write_turn_of_target_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<WriteTurn>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(None);
    };
    Ok(fold
        .live
        .iter()
        .find_map(|head| head_of(head).ok())
        .and_then(|head| spec_named(&head.slot.name).ok())
        .and_then(|spec| spec.write_turn))
}
