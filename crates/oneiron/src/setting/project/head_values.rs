//! Reads and combines setting heads, beside values, and the acts they replace.

use super::*;

impl BesideReads {
    /// Reads the row beside the act `act` on the row `slot` whose value's JSON bytes have BLAKE3
    /// `digest`, in `txn`, and notes what it held.
    fn read_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        (slot, act): (&RowKey, &AuthorityEntryHash),
        digest: [u8; 32],
    ) -> Result<BesideRead> {
        let row = beside_row_id(slot, &digest, act)?;
        let read = beside_row_read_in_txn(vault, txn, row, digest)?;
        let held = read.held();
        let mut seen = self.0.borrow_mut();
        let kept = seen.get(&row).is_some_and(|seen| seen.kept);
        seen.insert(
            row,
            BesideSeen {
                row,
                digest,
                held,
                kept,
            },
        );
        Ok(read)
    }

    /// Reads again, in `txn`, each row the row's value came from as the target's last projection
    /// recorded it (`last`), and notes it as kept. Whether one that held its act's value then
    /// does not now: erased here, or no longer matching its act (stage 7c-1).
    pub(super) fn carry_kept_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        last: &[BesideSeen],
    ) -> Result<bool> {
        let mut lost = false;
        for kept in last.iter().filter(|seen| seen.kept) {
            let held = beside_row_read_in_txn(vault, txn, kept.row, kept.digest)?.held();
            lost |= kept.held == BesideHeld::Value && held == BesideHeld::Unreadable;
            self.0
                .borrow_mut()
                .entry(kept.row)
                .and_modify(|seen| seen.kept = true)
                .or_insert(BesideSeen {
                    held,
                    kept: true,
                    ..*kept
                });
        }
        Ok(lost)
    }

    /// Whether a row read holds something that is not its act's value, or was erased here.
    fn any_unreadable(&self) -> bool {
        self.0
            .borrow()
            .values()
            .any(|seen| seen.held == BesideHeld::Unreadable)
    }

    /// The rows read, in row order; each one the row's value came from where `kept`.
    pub(super) fn into_seen(self, kept: bool) -> Vec<BesideSeen> {
        self.0
            .into_inner()
            .into_values()
            .map(|seen| BesideSeen {
                kept: seen.kept || kept,
                ..seen
            })
            .collect()
    }
}

/// How the acts a reader of one row meets stand by their counts and proposals alone (stage
/// 7b-3), the acts the copies among them name included (row SETTING-COPY-NAME-IGNORES-COUNT): a
/// proposal that still asks, else an act held back by this install's own counting, else a safe
/// move the log alone shows, else every act in full. A conflict or a quarantine the combine finds
/// outranks it.
fn counted_standing(fold: &SettingSlotFold) -> ChangeStanding {
    if !fold.asking.is_empty() {
        return ChangeStanding::Pending;
    }
    let counts = || {
        fold.counts
            .values()
            .chain(fold.name_counts.values().flat_map(BTreeMap::values))
            .map(|counted| counted.count)
    };
    if counts().any(|count| count == ChoiceCount::Safe { held: true }) {
        ChangeStanding::Held
    } else if counts().any(|count| count != ChoiceCount::Full) {
        ChangeStanding::Narrowed
    } else {
        ChangeStanding::Full
    }
}

/// The head `head` reads as, or why it leaves the row as it is.
pub(super) fn head_of(head: &SettingSlotHead) -> std::result::Result<Head, Inert> {
    if let Some(copy) = &head.copy {
        let body = if copy.is_birth() {
            HeadBody::Birth(copy.names.clone())
        } else {
            HeadBody::Copy(copy.names.clone())
        };
        return Ok(Head {
            act: head.act,
            decider: None,
            slot: copy.slot.clone(),
            body,
        });
    }
    // A pack's head (stage 7c-3a) names no row: each machine's pack door weighs its own
    // build's defaults, and the pack's own read lands an owner's yes (stage 7c-3c,
    // [`project_pack_target_in_txn`]), before any head is read here.
    if head.pack.is_some() {
        return Err(Inert::ForGood);
    }
    let Some(set) = &head.set else {
        return Err(Inert::ForNow);
    };
    // The eight older settings' doors sign acts that keep only digests, and an act of another
    // kind names no row: no build writes a row from either.
    if set.act.act != OwnerActKind::PolicySetting || PolicySetting::parse(&set.setting).is_some() {
        return Err(Inert::ForGood);
    }
    let body = match (set.value, &set.inline) {
        (Some(digest), None) => HeadBody::Beside(digest),
        (_, inline) => HeadBody::Inline(inline.clone()),
    };
    let slot = match &set.slot {
        Some(slot) => slot.clone(),
        None => RowKey {
            name: set.setting.clone(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        },
    };
    Ok(Head {
        act: head.act,
        decider: Some((set.act.owner, set.act.surface)),
        slot,
        body,
    })
}

/// A head's value under `spec`, read in `txn`: `None` for a clear, and for a copy whose acts
/// leave no bound. [`Short::Unreadable`] for a value this build cannot decode or whose check
/// refuses it, a value beside the act that does not match its digest or was erased, and a copy
/// whose acts read so on a key that names no strictest value; [`Inert::Awaiting`] for a value
/// beside the act that has not reached this install. `name_counts` and `depth` read a copy
/// ([`copy_value_in_txn`]).
fn value_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    head: &Head,
    depth: usize,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    match &head.body {
        HeadBody::Inline(None) => Ok(Ok(None)),
        HeadBody::Inline(Some(bytes)) => {
            Ok(inline_value(spec, bytes).map_err(|()| Short::Unreadable))
        }
        HeadBody::Beside(digest) => {
            beside_of(vault, txn, reads, spec, (&head.slot, &head.act), *digest)
        }
        HeadBody::Copy(names) => {
            copy_value_in_txn(vault, txn, (reads, name_counts), spec, names, depth)
        }
        HeadBody::Birth(names) => {
            let read = birth_value_in_txn(vault, txn, (reads, name_counts), spec, names, depth)?;
            Ok(read.map(|(value, _)| value))
        }
    }
}

/// The value beside the act `act` on the row `slot` whose JSON bytes have BLAKE3 `digest`, under
/// `spec`, noted in `reads` (stage 7c-1; [`value_of`]).
fn beside_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reads: &BesideReads,
    spec: &SettingSpec,
    (slot, act): (&RowKey, &AuthorityEntryHash),
    digest: [u8; 32],
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    Ok(match reads.read_in_txn(vault, txn, (slot, act), digest)? {
        BesideRead::Here(bytes) => match inline_value(spec, &bytes) {
            Ok(Some(value)) => Ok(Some(without_erased_mentions_in_txn(
                vault, txn, spec, &bytes, value,
            )?)),
            Ok(None) => Ok(None),
            Err(()) => Err(Short::Unreadable),
        },
        BesideRead::Absent => Err(Short::Inert(Inert::Awaiting)),
        BesideRead::Unreadable => Err(Short::Unreadable),
    })
}

/// A value's JSON bytes under `spec`; `Err` when this build cannot decode them or the key's
/// check refuses them.
fn inline_value(spec: &SettingSpec, bytes: &[u8]) -> std::result::Result<Option<EncodedValue>, ()> {
    let json: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    spec.kind.from_json(json).map(Some).map_err(|_| ())
}

/// [`copy_value_in_txn`], and whether a name gave no bound (a clear, or a copy that leaves
/// none). A copy of a project row skips such a name, since that row's empty slot gives no bound;
/// a birth's copy of a vault value row meets it as that row's empty slot, the accepted default
/// ([`birth_value_in_txn`]).
pub(super) fn copy_meet_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    names: &[SettingCopyName],
    depth: usize,
) -> Result<std::result::Result<(Option<EncodedValue>, bool), Short>> {
    let mut met: Option<EncodedValue> = None;
    let mut unbound = false;
    for name in names {
        let read = name_value_in_txn(vault, txn, (reads, name_counts), spec, name, depth)?;
        let value = match read {
            Ok(Some(value)) => value,
            Ok(None) => {
                unbound = true;
                continue;
            }
            Err(Short::Unreadable) => match spec.kind.strictest_value()? {
                Some(strictest) => strictest,
                None => return Ok(Err(Short::Unreadable)),
            },
            Err(inert @ Short::Inert(_)) => return Ok(Err(inert)),
        };
        met = Some(match met {
            None => value,
            Some(so_far) => match spec.kind.meet(&so_far, &value) {
                Some(meet) => meet,
                None => return Ok(Err(Short::Unreadable)),
            },
        });
    }
    Ok(Ok((met, unbound)))
}

/// A birth's value (stage 7c-3b; DESIGN 1.6, `born`), and whether it is a copy of a pack's
/// default (seeded). The born key `spec` copies the key its `born` names: a birth that names
/// another key's rows reads as one this install cannot read ([`Short::Unreadable`]). Its vault
/// names read as the source's vault value row reads them, under the source's own spec
/// ([`copy_meet_in_txn`]): a bound there is the value, explicit. A name there that gives no
/// bound (a clear) gives what that row's empty slot gives, the accepted default: where it stands
/// beside a bound, the value is their meet with the default its pack names give, still explicit;
/// with no pack name it reads as one this install cannot read. Where the vault names give no
/// bound, its pack names give the value ([`pack_name_value_in_txn`]), met as the layer meets
/// them, seeded: each pack's head name, read before every owner's yes the birth does not name
/// beside it (stage 7c-3d). A pack name whose table this install does not prove leaves the row
/// as it is for now ([`Inert::ForNow`]: the born thing reads strictest, pending, until a pass
/// proves it), and on a row a copy names reads as one this install cannot read. `None` when no
/// name gives a bound. A value the born key does not decode is unreadable.
pub(super) fn birth_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    names: &[SettingCopyName],
    depth: usize,
) -> Result<std::result::Result<(Option<EncodedValue>, bool), Short>> {
    let source = match spec.born.map(|born| spec_named(born.from)) {
        Some(Ok(source)) if names.iter().all(|name| name.slot.name == source.name) => source,
        _ => return Ok(Err(Short::Unreadable)),
    };
    let decoded = |value: EncodedValue, seeded: bool| {
        if spec.kind.decodes(&value) {
            Ok((Some(value), seeded))
        } else {
            Err(Short::Unreadable)
        }
    };
    let (at_vault, at_packs): (Vec<SettingCopyName>, Vec<SettingCopyName>) = names
        .iter()
        .cloned()
        .partition(|name| name.slot.scope == SettingScope::Vault);
    let explicit =
        match copy_meet_in_txn(vault, txn, (reads, name_counts), source, &at_vault, depth)? {
            Ok((Some(value), false)) => return Ok(decoded(value, false)),
            Ok((explicit, _)) => explicit,
            Err(short) => return Ok(Err(short)),
        };
    let (yeses, heads): (Vec<SettingCopyName>, Vec<SettingCopyName>) = at_packs
        .into_iter()
        .partition(|name| name.slot.item.is_some());
    let mut rows = Vec::with_capacity(heads.len());
    for name in &heads {
        let SettingScope::Pack(pack) = &name.slot.scope else {
            return Ok(Err(Short::Unreadable));
        };
        let named = (name_counts, yeses.as_slice());
        let value = match pack_name_value_in_txn(vault, txn, named, source, pack, name.act)? {
            Some(Some(value)) => value,
            Some(None) => match source.kind.strictest_value()? {
                Some(strictest) => strictest,
                None => return Ok(Err(Short::Unreadable)),
            },
            None if depth == 0 => return Ok(Err(Short::Inert(Inert::ForNow))),
            None => return Ok(Err(Short::Unreadable)),
        };
        rows.push((pack.clone(), value));
    }
    // A birth's copy names heads, not the rows a yes wrote here, so it reads the engine pack's
    // row first as before ([BIRTH-COPY-PACK-YES-ROW]).
    Ok(match (explicit, fold_layer(source, &rows, None)) {
        (None, Some(layer)) => decoded(layer, true),
        (None, None) => Ok((None, false)),
        // A bound beside a clear on the vault row: the clear gives the default.
        (Some(value), Some(layer)) => match source.kind.meet(&value, &layer) {
            Some(met) => decoded(met, false),
            None => Err(Short::Unreadable),
        },
        (Some(_), None) => Err(Short::Unreadable),
    })
}

/// What a birth's name of `pack`'s head act `act` gives a row of `source` here (stage 7c-3b):
/// where the head counts in full here and names the table this install's own head of the pack
/// names, this install's row of `source` in that pack, the record of what it accepted from that
/// table, before each owner's yes the birth did not see ([`birth_pack_row_in_txn`]; stage 7c-3d):
/// the birth names the yeses it saw among `yeses` ([`birth_names_yes_in_txn`]). `Some(None)` where
/// this install refused the head, holds no full count of it, holds no head of the pack under it,
/// or its row is gone: the name reads as one this install cannot read. `None` where the head names
/// a table this install's head does not: the table is not proved here.
fn pack_name_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (name_counts, yeses): (&NameCounts, &[SettingCopyName]),
    source: &SettingSpec,
    pack: &str,
    act: AuthorityEntryHash,
) -> Result<Option<Option<EncodedValue>>> {
    if vault.policy_setting_act_refused_in_txn(txn, act)? {
        return Ok(Some(None));
    }
    let target = setting_pack_target(pack)?;
    let full = name_counts
        .get(&target)
        .and_then(|counts| counts.get(&act))
        .is_some_and(|named| named.count == ChoiceCount::Full);
    let head = vault.setting_slot_head_in_txn(txn, target, act)?.pack;
    let Some(head) = head.filter(|head| full && head.pack == pack) else {
        return Ok(Some(None));
    };
    birth_pack_row_in_txn(&vault.store, txn, (pack, &head.digest), source, |table| {
        birth_names_yes_in_txn(vault, txn, (name_counts, yeses), (source, pack), table)
    })
}

/// Whether a birth names, among `yeses`, an owner's yes to `pack`'s table `table` (hex) that
/// accepts `source` and counts in full here (stage 7c-3d): a yes it saw, whose landing of the key
/// it reads. A yes this install refused, does not count in full, or does not hold is none.
///
/// # Errors
///
/// A target that does not encode; storage errors.
fn birth_names_yes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (name_counts, yeses): (&NameCounts, &[SettingCopyName]),
    (source, pack): (&SettingSpec, &str),
    table: &str,
) -> Result<bool> {
    for yes in yeses {
        let SettingScope::Pack(at) = &yes.slot.scope else {
            continue;
        };
        let Some(digest) = birth_yes_table(&yes.slot) else {
            continue;
        };
        if at != pack
            || oneiron_hex::encode(&digest) != table
            || vault.policy_setting_act_refused_in_txn(txn, yes.act)?
        {
            continue;
        }
        let target = setting_pack_accept_target(pack, &digest)?;
        let full = name_counts
            .get(&target)
            .and_then(|counts| counts.get(&yes.act))
            .is_some_and(|named| named.count == ChoiceCount::Full);
        let accepts = vault
            .setting_slot_head_in_txn(txn, target, yes.act)?
            .pack
            .is_some_and(|head| {
                head.pack == pack
                    && head.digest == digest
                    && head
                        .accept
                        .is_some_and(|accept| accept.accepted.iter().any(|key| key == source.name))
            });
        if full && accepts {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Combines the live heads of one row (module doc), each read by what it counts for here
/// (stage 7b-2; the comparator, a disputed act, the standing and `with` stage 7b-3).
pub(super) fn combine(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reads: &BesideReads,
    (spec, target): (&'static SettingSpec, EntityId),
    heads: &[Head],
    fold: &SettingSlotFold,
) -> Result<std::result::Result<Projected, Inert>> {
    let Some(newest) = heads.first() else {
        return Ok(Err(Inert::ForNow));
    };
    let strictest = spec.kind.strictest_value()?;
    let others = |deciding: &Credit| -> Vec<AuthorityEntryHash> {
        heads
            .iter()
            .map(|head| head.act)
            .filter(|act| *act != deciding.act)
            .collect()
    };
    let quarantined = || quarantined_of(strictest.is_some(), (newest, heads), reads);
    // Two copies of one act the row's reading meets disagree: what it says cannot be read.
    if fold
        .counts
        .values()
        .any(|counted| counted.count == ChoiceCount::Disputed)
    {
        return Ok(Ok(quarantined()));
    }
    let counted = counted_standing(fold);
    if let Some(rule) = rule_of(spec) {
        let empty = empty_of_in_txn(vault, txn, spec, &newest.slot)?;
        let mut walk = Walk {
            vault,
            txn,
            reads,
            name_counts: &fold.name_counts,
            spec,
            target,
            slot: &newest.slot,
            counts: &fold.counts,
            rule,
            strictest: strictest.clone(),
            empty,
            given: BTreeMap::new(),
            conflict: Cell::new(false),
            depth: 0,
        };
        let mut given = Vec::with_capacity(heads.len());
        let mut inert = None;
        for head in heads {
            match walk.gives(head.act)? {
                Ok(gives) => given.push(gives),
                Err(Short::Unreadable) => return Ok(Ok(quarantined())),
                Err(Short::Inert(why)) => inert = inert.or(Some(why)),
            }
        }
        // A value that does not decode quarantines the row whichever head it is under; only then
        // does an act this build cannot read yet leave the row as it is.
        if let Some(why) = inert {
            return Ok(Err(why));
        }
        let Ok(joined) = walk.join(given) else {
            return Ok(Ok(quarantined()));
        };
        let standing = if walk.conflict.get() {
            ChangeStanding::Conflict
        } else {
            counted
        };
        let deciding = newest.credit();
        return Ok(Ok(Projected {
            value: joined,
            keep: false,
            erased: false,
            standing,
            with: others(&deciding),
            deciding,
        }));
    }
    let mut inert = None;
    for head in heads {
        match value_of(vault, txn, (reads, &fold.name_counts), spec, head, 0)? {
            Ok(_) => {}
            Err(Short::Unreadable) => return Ok(Ok(quarantined())),
            Err(Short::Inert(why)) => inert = inert.or(Some(why)),
        }
    }
    if let Some(why) = inert {
        return Ok(Err(why));
    }
    // No order or a neutral key: nothing is safer than anything else, so an act that does not
    // count in full gives what it replaced, and heads that differ conflict: the last value every
    // head descends from stays (owner_choice.rs `in_force`), or no row.
    let standing = if fold.conflict {
        ChangeStanding::Conflict
    } else {
        counted
    };
    let Some(agreed) = &fold.in_force else {
        let deciding = newest.credit();
        return Ok(Ok(Projected {
            value: None,
            keep: false,
            erased: false,
            standing,
            with: others(&deciding),
            deciding,
        }));
    };
    let agreed = match head_of(agreed) {
        Ok(head) if head.slot == newest.slot => head,
        Ok(_) => return Ok(Err(Inert::ForGood)),
        Err(why) => return Ok(Err(why)),
    };
    let read = value_of(vault, txn, (reads, &fold.name_counts), spec, &agreed, 0)?;
    Ok(match read {
        Ok(value) => Ok({
            let deciding = agreed.credit();
            Projected {
                value,
                keep: false,
                erased: false,
                standing,
                with: others(&deciding),
                deciding,
            }
        }),
        Err(Short::Unreadable) => Ok(quarantined()),
        Err(Short::Inert(why)) => Err(why),
    })
}

/// What a quarantined row of the heads `heads`, the newest first, keeps (DESIGN 1.6, "Fold
/// states"), on a key that names a strictest value where `has_strictest`: the unreadable
/// marker, which every read takes as that strictest value. On a key that names none, the row as
/// it is; but no row where a value beside an act it read (`reads`) was erased here or does not
/// match its act, so no read takes that value and the key reads its default (stage 7c-1).
pub(super) fn quarantined_of(
    has_strictest: bool,
    (newest, heads): (&Head, &[Head]),
    reads: &BesideReads,
) -> Projected {
    let unwritten = !has_strictest && reads.any_unreadable();
    let deciding = newest.credit();
    Projected {
        value: (!unwritten).then(|| EncodedValue(vec![UNREADABLE_VALUE])),
        keep: !has_strictest && !unwritten,
        erased: reads.any_unreadable(),
        standing: ChangeStanding::Quarantined,
        with: heads
            .iter()
            .map(|head| head.act)
            .filter(|act| *act != deciding.act)
            .collect(),
        deciding,
    }
}

impl Walk<'_, '_> {
    /// What `act` gives the row. The acts a safe move replaced are read first, without
    /// recursion; an act the counts do not name (no frontier here keeps it) gives no row.
    pub(super) fn gives(
        &mut self,
        act: AuthorityEntryHash,
    ) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
        let counts = self.counts;
        let mut stack = vec![(act, false)];
        while let Some((next, expanded)) = stack.pop() {
            if self.given.contains_key(&next) {
                continue;
            }
            let Some(counted) = counts.get(&next) else {
                self.given.insert(next, None);
                continue;
            };
            // What a disputed act says cannot be read (the row's own walk never meets one: the
            // combine quarantines the row first).
            if counted.count == ChoiceCount::Disputed {
                return Ok(Err(Short::Unreadable));
            }
            let safe = counted.count != ChoiceCount::Full;
            if safe && !expanded {
                stack.push((next, true));
                stack.extend(
                    counted
                        .replaced
                        .iter()
                        .filter(|replaced| !self.given.contains_key(*replaced))
                        .map(|replaced| (*replaced, false)),
                );
                continue;
            }
            let own = match self.own_value(next)? {
                Ok(own) => own,
                Err(short) => return Ok(Err(short)),
            };
            let gives = if safe {
                let from = counted
                    .replaced
                    .iter()
                    .map(|replaced| self.given.get(replaced).cloned().flatten());
                let Ok(from) = self.join(from.collect::<Vec<_>>()) else {
                    return Ok(Err(Short::Unreadable));
                };
                let Ok(gives) = self.safe_move(own, from) else {
                    return Ok(Err(Short::Unreadable));
                };
                gives
            } else {
                own
            };
            self.given.insert(next, gives);
        }
        Ok(Ok(self.given.get(&act).cloned().flatten()))
    }

    /// `act`'s own value on the row, read back from the log here: `None` for a clear.
    fn own_value(
        &self,
        act: AuthorityEntryHash,
    ) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
        let head = match head_of(&self.vault.setting_slot_head_in_txn(
            self.txn,
            self.target,
            act,
        )?) {
            Ok(head) if head.slot == *self.slot => head,
            Ok(_) => return Ok(Err(self.short_of(Inert::ForGood))),
            Err(why) => return Ok(Err(self.short_of(why))),
        };
        let reads = (self.reads, self.name_counts);
        value_of(self.vault, self.txn, reads, self.spec, &head, self.depth)
    }

    /// How an act on the way that leaves its row as it is (`why`) ends the walk: as `why` on the
    /// row a pass projects; on a row a copy names, as a name this install cannot read
    /// ([`name_value_in_txn`]), unless its value beside it has not come yet.
    fn short_of(&self, why: Inert) -> Short {
        match why {
            Inert::Awaiting => Short::Inert(Inert::Awaiting),
            why if self.depth == 0 => Short::Inert(why),
            _ => Short::Unreadable,
        }
    }

    /// What the heads or replaced acts `given` give the row together, by the walk's rule: their
    /// meet ([`Self::meet_all`]), or the one no wider than every other
    /// ([`Self::no_wider_of_all`]). No row when there is none.
    fn join(
        &self,
        given: Vec<Option<EncodedValue>>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        match self.rule {
            Rule::Meet => self.meet_all(given),
            Rule::Comparator => self.no_wider_of_all(&given),
        }
    }

    /// What a safe move of value `own` over `from`, what it replaced, gives, by the walk's rule:
    /// their meet; or `own` where the comparator says it is no wider than `from`, else `from`.
    fn safe_move(
        &self,
        own: Option<EncodedValue>,
        from: Option<EncodedValue>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        match self.rule {
            Rule::Meet => self.meet(own, from),
            Rule::Comparator => Ok(if self.no_wider(own.as_ref(), from.as_ref())? {
                own
            } else {
                from
            }),
        }
    }

    /// Whether `left` is no wider than `right` under the key's comparator. No row reads as what
    /// no row gives here ([`Self::empty`]). Where that is no row too: two of them are equal; a
    /// value is no wider than no row on a value row (adding a bound only narrows) and not on a
    /// pin (no pin leaves the value rows to decide, so a pin may widen them); no row is no
    /// narrower than a value. `Err` where the comparator cannot judge the two values.
    fn no_wider(
        &self,
        left: Option<&EncodedValue>,
        right: Option<&EncodedValue>,
    ) -> std::result::Result<bool, ()> {
        let left = left.or(self.empty.as_ref());
        let right = right.or(self.empty.as_ref());
        match (left, right) {
            (None, None) => Ok(true),
            (Some(_), None) => Ok(self.slot.mode != SettingMode::Pin),
            (None, Some(_)) => Ok(false),
            (Some(left), Some(right)) => self.spec.kind.no_wider(left, right).ok_or(()),
        }
    }

    /// The first of `given` that is no wider than every other ([`Self::no_wider`]); where none
    /// is, the key's strictest value, and the row is in conflict. No row when `given` is empty.
    /// `Err` where the comparator cannot judge two of them, or the key names no strictest value
    /// for heads it cannot order.
    fn no_wider_of_all(
        &self,
        given: &[Option<EncodedValue>],
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        for (index, candidate) in given.iter().enumerate() {
            let mut stands = true;
            for (other_index, other) in given.iter().enumerate() {
                if index != other_index && !self.no_wider(candidate.as_ref(), other.as_ref())? {
                    stands = false;
                    break;
                }
            }
            if stands {
                return Ok(candidate.clone());
            }
        }
        if given.is_empty() {
            return Ok(None);
        }
        self.conflict.set(true);
        self.strictest.clone().map(Some).ok_or(())
    }

    /// The meet of what each of `given` gives the row ([`Self::meet`], folded from the first):
    /// no row when there is none (an act that replaced nothing replaced the empty slot), or when
    /// each gives no row. `Err` where two values do not meet.
    fn meet_all(
        &self,
        given: Vec<Option<EncodedValue>>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        let mut given = given.into_iter();
        let Some(mut met) = given.next() else {
            return Ok(None);
        };
        for one in given {
            met = self.meet(met, one)?;
        }
        Ok(met)
    }

    /// The stricter of two things the row is given: their meet; no row on both sides is no row,
    /// and no row against a value is what no row gives there ([`Self::empty`]). `Err` where two
    /// values do not meet.
    fn meet(
        &self,
        left: Option<EncodedValue>,
        right: Option<EncodedValue>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        let (value, other) = match (left, right) {
            (None, None) => return Ok(None),
            (Some(value), None) | (None, Some(value)) => (value, self.empty.clone()),
            (Some(left), Some(right)) => (left, Some(right)),
        };
        match other {
            None => Ok(Some(value)),
            Some(other) => self.spec.kind.meet(&value, &other).map(Some).ok_or(()),
        }
    }
}
