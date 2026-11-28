//! The pack door: weighing a pack's defaults against what the vault accepted,
//! and landing each owner's yes that counts in full here.

use super::*;

/// What reading a pack's heads did here ([`project_pack_in_txn`]).
pub(in crate::setting) struct PackRead {
    /// The keys whose layer row moved: their `after_commit` runs once the write commits.
    pub(in crate::setting) moved: Vec<&'static SettingSpec>,
    /// A yes names a newer table whose bytes have not reached this install: a later pass reads
    /// the heads again.
    pub(in crate::setting) awaiting: bool,
}

/// Whether the pack door acts on `head` for a build that ships `version` of the pack, whose
/// defaults digest is `digest` (hex): not when the head weighed these defaults, and not when the
/// head holds a newer version than the build's (DESIGN 1.6, "Packs across machines": an older
/// build never proposes its older defaults back). An equal version with other defaults acts:
/// every build of one release names one version, so the rule tells releases apart, not builds.
fn door_acts(head: &PackHead, version: &str, digest: &str) -> bool {
    head.digest != digest && crate::gate::version_gt(&head.version, version) != Some(true)
}

/// The pack door: weighs `pack`'s `defaults`, as its build ships `version` of the pack, against
/// what the vault accepted from it, in the caller's write. `layer` lists the keys the pack's
/// install named; `None` is every key (the `engine` pack). A default outside the layer is a
/// proposal, tighter or not. Answers `None` when the door does not act ([`door_acts`]): the head
/// weighed these defaults, or holds a newer version. On a rooted vault whose install can carry,
/// the door appends the new head as one act in the same write (stage 7c-3a), with the table's
/// bytes beside it (stage 7c-3c); an append it cannot make is logged, and the rows stand.
///
/// # Errors
///
/// `InvalidConfig` for an empty pack name; a key's `on_change` refusal; storage errors.
pub(crate) fn apply_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
    (version, defaults): (&str, &[(&'static SettingSpec, EncodedValue)]),
    layer: Option<&[&str]>,
) -> Result<Option<PackApplied>> {
    if pack.is_empty() {
        return Err(Error::InvalidConfig("a pack has a name".into()));
    }
    let digest = defaults_digest(pack, defaults).into_bytes();
    weigh_in_txn(vault, txn, (pack, version, digest), defaults, (layer, true))
}

/// [`apply_pack_defaults_in_txn`] over `defaults` of the table whose digest is `digest`: this
/// build's own, or (stage 7c-3c) the keys this build knows of a table an owner's yes proved,
/// whose digest is the whole table's. With `append`, the door appends its head where it can; a
/// table a yes proved appends none, since the yes is its head.
fn weigh_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, version, digest_bytes): (&str, &str, [u8; 32]),
    defaults: &[(&'static SettingSpec, EncodedValue)],
    (layer, append): (Option<&[&str]>, bool),
) -> Result<Option<PackApplied>> {
    let digest = oneiron_hex::encode(&digest_bytes);
    let mut head = head_in_txn(&vault.store, txn, pack)?.unwrap_or_default();
    if !door_acts(&head, version, &digest) {
        return Ok(None);
    }
    lift_quarantines_in_txn(vault, txn, pack, &mut head, defaults)?;
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut applied = PackApplied::default();
    let mut proposals = Vec::new();
    for (spec, value) in defaults {
        let spec: &'static SettingSpec = *spec;
        let name = spec.name.to_owned();
        let table = table_of(spec);
        let key = pack_row_key(spec.name, pack);
        let prior_bytes = table.get_bytes(&vault.store, txn, &key)?;
        let prior = match prior_bytes.as_deref() {
            None if accepted.contains(&name) => {
                applied.lost.push(name);
                continue;
            }
            None => None,
            Some(bytes) => match rmp_serde::from_slice::<StoredRow>(bytes)
                .ok()
                .filter(|row| spec.kind.decodes(&row.value))
            {
                Some(row) => Some(row),
                None => {
                    applied.lost.push(name);
                    continue;
                }
            },
        };
        let in_layer = layer.is_none_or(|keys| keys.contains(&spec.name));
        match &prior {
            Some(row) if row.value == *value => {
                accepted.insert(name);
                continue;
            }
            None if pack == ENGINE_PACK && in_layer => {
                // A key new in this build: nothing can be compared, so its first default lands.
                // It is no move, so it writes no change row.
                let row = StoredRow {
                    value: value.clone(),
                    by: None,
                    setter: Setter::Pack,
                    set_at: now,
                    change: 0,
                    weight_runs: None,
                    local: None,
                    seeded: false,
                };
                table.put(&vault.store, txn, &key, &row)?;
                accepted.insert(name.clone());
                applied.landed.push(name);
                continue;
            }
            _ => {}
        }
        // A move on the layer: judged against what its readers read before and after it. A
        // default the door writes itself names no actor, so it is no yes's row; one it proposes
        // lands by the owner's yes, whose row is then the newest (RULING L1-PACK-LAYER-READ = A).
        let rows = layer_rows_in_txn(&vault.store, txn, spec)?;
        let before_yes = newest_yes_pack(&rows);
        let other_rows: Vec<LayerRow> = rows.into_iter().filter(|(at, _, _)| at != pack).collect();
        let after_yes = if in_layer {
            newest_yes_pack(&other_rows)
        } else {
            Some(pack.to_owned())
        };
        let others: Vec<(String, EncodedValue)> = other_rows
            .into_iter()
            .filter_map(|(at, value, _)| value.map(|value| (at, value)))
            .collect();
        let mut before_rows = others.clone();
        if let Some(row) = &prior {
            before_rows.push((pack.to_owned(), row.value.clone()));
        }
        let mut after_rows = others;
        after_rows.push((pack.to_owned(), value.clone()));
        let before = match fold_layer(spec, &before_rows, before_yes.as_deref()) {
            Some(before) => before,
            None => spec.kind.default_value()?,
        };
        let after =
            fold_layer(spec, &after_rows, after_yes.as_deref()).unwrap_or_else(|| value.clone());
        let direction = layer_direction(spec, &after, &before);
        if !in_layer
            || !matches!(
                direction,
                ChangeDirection::Tighter | ChangeDirection::Neutral
            )
        {
            proposals.push(ProposedDefault {
                key: name.clone(),
                value: value.clone(),
                replaced: prior_bytes.as_deref().map(row_digest),
                direction,
            });
            applied.proposed.push(name);
            continue;
        }
        write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value,
                prior: prior.map(|row| row.value),
                by: None,
                direction,
                why: format!("pack `{pack}` defaults {}", &digest[..16]),
                at: now,
                signed: None,
            },
        )?;
        accepted.insert(name.clone());
        applied.moved.push(name);
    }
    let proposal = (!proposals.is_empty()).then(|| PackProposal {
        digest: proposal_digest(pack, &digest, &proposals),
        defaults: proposals,
    });
    HEADS.put(
        &vault.store,
        txn,
        &pack.as_bytes().to_vec(),
        &PackHead {
            digest,
            accepted: accepted.into_iter().collect(),
            proposal,
            version: version.to_owned(),
            landed: head.landed,
        },
    )?;
    // The owner's yeses to this table that count here land now (stage 7c-3c): a yes another
    // machine carried before this one weighed the table, which no head below holds back.
    for spec in take_live_accepts_in_txn(vault, txn, (pack, digest_bytes), now)? {
        applied.proposed.retain(|key| key != spec.name);
        applied.moved.push(spec.name.to_owned());
    }
    let held: Vec<String> = head_in_txn(&vault.store, txn, pack)?
        .and_then(|head| head.proposal)
        .map(|proposal| {
            proposal
                .defaults
                .into_iter()
                .map(|proposed| proposed.key)
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    if append
        && rooted_in_txn(vault, txn)?
        && vault.can_carry_owner_act_in_txn(txn)?
        && let Err(error) = table_bytes(pack, defaults).and_then(|table| {
            append_head_with_table_in_txn(
                vault,
                txn,
                (pack, version, digest_bytes, held),
                Some(table),
            )
        })
    {
        tracing::warn!(
            pack,
            kind = ?error.kind(),
            "the pack door's head was not appended: its rows stand on this install, and other machines weigh their own builds' defaults"
        );
    }
    Ok(Some(applied))
}

/// One write of a layer row by the door.
struct LayerWrite<'a> {
    value: &'a EncodedValue,
    prior: Option<EncodedValue>,
    by: Option<crate::entity_id::EntityId>,
    direction: ChangeDirection,
    why: String,
    at: u64,
    /// The owner's yes that made the write, a peer's (stage 7c-3c review): the change row names
    /// it. A local yes names its act once it is appended ([`record_signed_entry_in_txn`]).
    signed: Option<AuthorityEntryHash>,
}

/// Writes `spec`'s row in `pack`'s layer, with its change row and the key's `on_change`, and
/// answers the change row.
fn write_layer_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    pack: &str,
    write: LayerWrite<'_>,
) -> Result<SettingChange> {
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: None,
            scope: SettingScope::Pack(pack.to_owned()),
            mode: SettingMode::Value,
            by: write.by,
            setter: Setter::Pack,
            prior: write.prior,
            value: Some(write.value.clone()),
            at: write.at,
            why: Some(write.why),
            weight_runs: None,
            direction: Some(write.direction),
            surface: None,
            signed: write.signed,
            with: Vec::new(),
            standing: None,
        },
    )?;
    let row = StoredRow {
        value: write.value.clone(),
        by: write.by,
        setter: Setter::Pack,
        set_at: write.at,
        change: recorded.sequence,
        weight_runs: None,
        local: None,
        seeded: false,
    };
    table_of(spec).put(&vault.store, txn, &pack_row_key(spec.name, pack), &row)?;
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(recorded)
}

impl Vault {
    /// The `engine` pack's run at open: weighs this build's defaults against what the vault
    /// accepted, in its own write, and skips at once when the head already weighed them. Runs
    /// each moved key's `after_commit` once the write committed.
    ///
    /// # Errors
    ///
    /// As [`apply_pack_defaults_in_txn`].
    pub(crate) fn apply_engine_pack(&self) -> Result<Option<PackApplied>> {
        let defaults = engine_pack_defaults()?;
        {
            let txn = self.store.env.read_txn()?;
            let digest = defaults_digest(ENGINE_PACK, &defaults).to_hex();
            if head_in_txn(&self.store, &txn, ENGINE_PACK)?
                .is_some_and(|head| !door_acts(&head, ENGINE_PACK_VERSION, &digest))
            {
                return Ok(None);
            }
        }
        self.apply_pack_defaults(ENGINE_PACK, (ENGINE_PACK_VERSION, &defaults), None)
    }

    /// [`apply_pack_defaults_in_txn`] in its own write, then each moved key's `after_commit`.
    ///
    /// # Errors
    ///
    /// As [`apply_pack_defaults_in_txn`].
    pub(crate) fn apply_pack_defaults(
        &self,
        pack: &str,
        shipped: (&str, &[(&'static SettingSpec, EncodedValue)]),
        layer: Option<&[&str]>,
    ) -> Result<Option<PackApplied>> {
        self.with_write_txn_grouped_after_commit(
            |txn| apply_pack_defaults_in_txn(self, txn, pack, shipped, layer),
            |applied| {
                if let Some(applied) = &applied {
                    run_layer_after_commit(self, &applied.moved);
                }
                Ok(applied)
            },
        )
    }

    /// The owner says yes to `pack`'s waiting proposal `proposal`: each of its defaults replaces
    /// the row it was proposed over, with a change row by the owner, and the proposal closes.
    /// All or none: when any row moved since the proposal, nothing lands, and the next run of the
    /// pack door proposes again. On a rooted vault the yes travels as one head act with his act
    /// (stage 7c-3c), appended in the same write, or the yes is refused. Answers the keys whose
    /// default landed.
    ///
    /// The yes can carry an owner key's proof, and a pack's held defaults are the ones it may
    /// not move by itself, so the door asks for the person at this device before its write. It
    /// asks after the checks it can make on a read of the store (`checked_accept_in_txn`), so a
    /// yes they refuse raises no prompt; the write makes each of them again.
    ///
    /// # Errors
    ///
    /// On a read before the door asks, and again in its write: an owner proof that no longer
    /// holds; `InvalidConfig` for a pack with no head, a proposal that is not the pack's waiting
    /// one, a row that moved since, or a key this build does not know; on a rooted vault,
    /// `CorruptedIndex` for a head whose digest is not 64 hex digits, and the append's typed
    /// refusal for an install that cannot carry the owner's act. Then the presence
    /// check's refusal ([`Vault::owner_presence`]). In the write: on a rooted vault, the
    /// append's typed refusal, and `OwnerKeyRequired` for a yes that would wait for the owner's
    /// proof; a key's `on_change` refusal; storage errors.
    pub fn accept_pack_defaults(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        proposal: &str,
    ) -> Result<Vec<String>> {
        // The yes's own checks, on a read the door drops before it asks.
        {
            let txn = self.store.env.read_txn()?;
            checked_accept_in_txn(self, &txn, owner, pack, proposal)?;
        }
        // The confirm is for an owner proof, so it stands before the write
        // opens, while the door holds nothing: the prompt can block.
        let witness = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::ACCEPT_PACK_DEFAULTS,
        )?;
        let ground = OwnerProofGround::witnessed(&witness);
        self.with_write_txn_grouped_after_commit(
            |txn| accept_pack_defaults_in_txn(self, txn, &ground, owner, pack, proposal),
            |keys| {
                run_layer_after_commit(self, &keys);
                Ok(keys)
            },
        )
    }
}

fn accept_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ground: &OwnerProofGround,
    owner: &AuthenticatedOwner,
    pack: &str,
    proposal: &str,
) -> Result<Vec<String>> {
    let CheckedAccept {
        by,
        mut head,
        waiting,
        checked,
    } = checked_accept_in_txn(vault, txn, owner, pack, proposal)?;
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut keys = Vec::with_capacity(checked.len());
    let mut changes = Vec::with_capacity(checked.len());
    let mut landings = Vec::with_capacity(checked.len());
    for (proposed, (spec, prior)) in waiting.defaults.iter().zip(checked) {
        changes.push(write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value: &proposed.value,
                prior: prior.as_ref().map(|row| row.value.clone()),
                by: Some(by),
                direction: proposed.direction,
                why: format!(
                    "the owner accepted proposal {} of pack `{pack}`",
                    &proposal[..proposal.len().min(16)]
                ),
                at: now,
                signed: None,
            },
        )?);
        landings.push(YesLanding {
            key: proposed.key.clone(),
            table: head.digest.clone(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed: Some((head.digest.clone(), proposed.clone())),
        });
        accepted.insert(proposed.key.clone());
        keys.push(proposed.key.clone());
    }
    head.accepted = accepted.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    // The yes that travels is the act its change rows name, and what keeps its rows here: a pass
    // puts them back once no yes that counts in full names their keys (stage 7c-3c review).
    if rooted_in_txn(vault, txn)?
        && let Some(signed) =
            append_yes_in_txn(vault, txn, ground, (pack, &head), (by, keys.clone()))?
    {
        for change in &changes {
            record_signed_entry_in_txn(&vault.store, txn, change, signed)?;
        }
        head.landed.extend(landings);
        HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    }
    Ok(keys)
}

/// Appends the owner `owner`'s yes to the keys `accepted` of the table `head` (`pack`'s, after
/// the yes) names, in the yes's write `txn` (stage 7c-3c): one head act with his act, naming the
/// head's version and digest and the keys still held, with the table's bytes in a row of its own
/// beside it where this build ships the table or a copy of it here is the table (stage 7c-3c
/// review: so a build that weighed the table from the bytes beside a yes passes them on). The act
/// is the write: an append this install cannot make,
/// or a yes that would wait for his proof, refuses the yes, as an owner's change of a row that
/// travels is refused (ruling CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B). A head from before
/// versions names no version an act carries: that yes stays on this install, as such a head's
/// birth does (logged). The yes accepts `accepted` and every key a live yes to the same table
/// that counts in full here accepts (stage 7c-3c review): it replaces those yeses, so the keys
/// the owner accepted there stay accepted; a yes that counts only as a safe move is not carried,
/// so a new yes never makes it count in full. Answers the appended act; `None` where the yes
/// stays on this install. The act signs on `ground`, the door's.
///
/// # Errors
///
/// The append's typed refusal; `OwnerKeyRequired`; `CorruptedIndex` for a head whose digest is
/// not 64 hex digits; storage errors.
fn append_yes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ground: &OwnerProofGround,
    (pack, head): (&str, &PackHead),
    (owner, mut accepted): (EntityId, Vec<String>),
) -> Result<Option<AuthorityEntryHash>> {
    let digest = head_defaults_digest(head)?;
    if head.version.is_empty() {
        tracing::warn!(
            pack,
            "the owner's yes names a pack head from before versions: it stays on this install"
        );
        return Ok(None);
    }
    // The bytes are read before the append, while the yeses it replaces are live.
    let table = match shipped_table(vault, txn, pack, &digest)? {
        Some(table) => Some(table),
        None => {
            let acts = table_acts_in_txn(vault, txn, (pack, &digest), None)?;
            match pack_table_read_in_txn(vault, txn, (pack, &digest), &acts, |bytes| {
                table_of_bytes(pack, &digest, bytes).is_some()
            })? {
                BesideRead::Here(table) => Some(table),
                BesideRead::Absent | BesideRead::Unreadable => None,
            }
        }
    };
    accepted.extend(counted_accepts_in_txn(vault, txn, pack, &digest)?.unwrap_or_default());
    let held: BTreeSet<String> = head
        .proposal
        .iter()
        .flat_map(|proposal| {
            proposal
                .defaults
                .iter()
                .map(|proposed| proposed.key.clone())
        })
        .collect();
    accepted.retain(|key| !held.contains(key));
    accepted.sort_unstable();
    accepted.dedup();
    let signed = vault.append_setting_pack_accept_in_txn(
        txn,
        ground,
        (pack, &head.version, digest, held.into_iter().collect()),
        (owner, ActSurface::ThisInstall),
        accepted,
    )?;
    if vault.setting_act_waits_in_txn(txn, signed)? {
        return Err(Error::Record(RecordError::OwnerKeyRequired));
    }
    if let Some(table) = table {
        put_pack_table_in_txn(vault, txn, (pack, &digest, &signed), &table)?;
    }
    Ok(Some(signed))
}

/// Reads `fold`, the acts on a pack's target or on the target of the owner's yeses to one of its
/// tables, in `txn` (stage 7c-3c; DESIGN 1.6 "Packs across machines"). A pack door's head changes
/// nothing here: this install's own door weighs its own build's defaults (stage 7c-3a). Each
/// owner's yes that counts in full here lands ([`land_yes_in_txn`]); one that does not changes
/// nothing, as a proposal or a safe move that would loosen changes nothing. First, each row a yes
/// landed that no yes counted in full names any more is put back ([`revert_landings_in_txn`]).
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
pub(in crate::setting) fn project_pack_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fold: &SettingSlotFold,
    now: u64,
) -> Result<PackRead> {
    let mut read = PackRead {
        moved: revert_landings_in_txn(vault, txn, now)?,
        awaiting: false,
    };
    for head in &fold.live {
        let Some(yes) = counted_yes(fold, head) else {
            continue;
        };
        match land_yes_in_txn(vault, txn, (head.act, yes), now)? {
            Some(moved) => read.moved.extend(moved),
            None => read.awaiting = true,
        }
    }
    Ok(read)
}

/// Lands, in the pack door's write, each of the owner's yeses to `pack`'s table `digest` that
/// counts in full here (stage 7c-3c): the door just weighed that table, and a yes another
/// machine carried before lands its keys from the door's proposal ([`take_accepted_in_txn`]).
/// Answers the keys whose layer row moved.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn take_live_accepts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, digest): (&str, [u8; 32]),
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let target = setting_pack_accept_target(pack, &digest)?;
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(Vec::new());
    };
    let mut moved = Vec::new();
    for head in &fold.live {
        if let Some(yes) = counted_yes(&fold, head) {
            moved.extend(take_accepted_in_txn(vault, txn, (head.act, yes), now)?);
        }
    }
    Ok(moved)
}

/// Lands the owner's yes `yes`, the entry `act`, here (stage 7c-3c), and answers the keys whose
/// layer row moved; `None` while it waits for its table's bytes.
/// - Where this install's head names the yes's table, each key of the yes that this install's
///   waiting proposal holds lands ([`take_accepted_in_txn`]).
/// - Where the yes names a table of the `engine` pack of a version newer than this install's
///   head's, the yes proves that table, and its bytes come from any copy here that is the table,
///   beside the yes or another act that names it ([`table_acts_in_txn`]). With none, the yes's
///   own row decides: absent, the yes waits and every row reads as before it; not that table, or
///   erased here, each key the yes accepts reads its strictest value ([`quarantine_in_txn`]).
///   With that table, where this build knows each of its keys and reads each of its defaults,
///   the door weighs it as a build that ships it would, records the yes's version and digest,
///   appends no head (no build of this install shipped it), and lands every yes to it that
///   counts here, this one with them.
/// - Otherwise (an older table, an equal version with another table, a newer table with a key
///   this build does not know or a default it cannot read, a pack whose door never ran here)
///   nothing changes here: this install's own proposal waits for a holder, and the door of a
///   build that ships the yes's table lands it ([`take_live_accepts_in_txn`]).
fn land_yes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (act, yes): (AuthorityEntryHash, &SettingPackHead),
    now: u64,
) -> Result<Option<Vec<&'static SettingSpec>>> {
    let Some(accept) = &yes.accept else {
        return Ok(Some(Vec::new()));
    };
    let pack = yes.pack.as_str();
    let Some(head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(Some(Vec::new()));
    };
    let mut moved = Vec::new();
    if head.digest != oneiron_hex::encode(&yes.digest) {
        let newer = head.version.is_empty()
            || crate::gate::version_gt(&yes.version, &head.version) == Some(true);
        if pack != ENGINE_PACK || !newer {
            return Ok(Some(moved));
        }
        let acts = table_acts_in_txn(vault, txn, (pack, &yes.digest), Some(act))?;
        let read = pack_table_read_in_txn(vault, txn, (pack, &yes.digest), &acts, |bytes| {
            table_of_bytes(pack, &yes.digest, bytes).is_some()
        })?;
        let table = match read {
            BesideRead::Absent => return Ok(None),
            BesideRead::Unreadable => {
                let table = oneiron_hex::encode(&yes.digest);
                return quarantine_in_txn(vault, txn, (pack, &table), &accept.accepted, now)
                    .map(Some);
            }
            BesideRead::Here(bytes) => table_of_bytes(pack, &yes.digest, &bytes).ok_or(
                Error::InvariantViolation("a pack table that matched reads again"),
            )?,
        };
        let Some(defaults) = table
            .into_iter()
            .map(|(name, value)| {
                let spec = spec_named(&name).ok()?;
                spec.kind.decodes(&value).then_some((spec, value))
            })
            .collect::<Option<Vec<(&'static SettingSpec, EncodedValue)>>>()
        else {
            return Ok(Some(moved));
        };
        if let Some(applied) = weigh_in_txn(
            vault,
            txn,
            (pack, &yes.version, yes.digest),
            &defaults,
            (None, false),
        )? {
            moved.extend(applied.moved.iter().filter_map(|key| spec_named(key).ok()));
        }
    }
    moved.extend(take_accepted_in_txn(vault, txn, (act, yes), now)?);
    Ok(Some(moved))
}

/// Lands each key the owner's yes `yes` (the entry `act`) accepts that this install's waiting
/// proposal of its pack holds, where this install's head names the yes's table (stage 7c-3c):
/// the proposal's default replaces the row it was proposed over, with a change row by the owner
/// naming the yes, and leaves the proposal, which closes when nothing waits in it. A key whose
/// row moved since the proposal stays in it, as the accept door refuses such a row. Answers the
/// keys whose row moved.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn take_accepted_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (act, yes): (AuthorityEntryHash, &SettingPackHead),
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let pack = yes.pack.as_str();
    let Some(accept) = &yes.accept else {
        return Ok(Vec::new());
    };
    let (owner, accepted) = (accept.act.owner, accept.accepted.as_slice());
    let Some(mut head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(Vec::new());
    };
    if head.digest != oneiron_hex::encode(&yes.digest) {
        return Ok(Vec::new());
    }
    let Some(proposal) = head.proposal.take() else {
        return Ok(Vec::new());
    };
    let mut landed: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut kept = Vec::new();
    let mut moved = Vec::new();
    for proposed in proposal.defaults {
        let spec = match spec_named(&proposed.key) {
            Ok(spec) if accepted.binary_search(&proposed.key).is_ok() => spec,
            _ => {
                kept.push(proposed);
                continue;
            }
        };
        let current =
            table_of(spec).get_bytes(&vault.store, txn, &pack_row_key(spec.name, pack))?;
        if current.as_deref().map(row_digest) != proposed.replaced
            || !spec.kind.decodes(&proposed.value)
        {
            kept.push(proposed);
            continue;
        }
        let prior = current
            .as_deref()
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
        write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value: &proposed.value,
                prior: prior.as_ref().map(|row| row.value.clone()),
                by: Some(owner),
                direction: proposed.direction,
                why: format!(
                    "the owner accepted defaults {} of pack `{pack}` (act {})",
                    &head.digest[..head.digest.len().min(16)],
                    &oneiron_hex::encode(&act)[..16]
                ),
                at: now,
                signed: Some(act),
            },
        )?;
        head.landed.push(YesLanding {
            key: proposed.key.clone(),
            table: head.digest.clone(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed: Some((head.digest.clone(), proposed.clone())),
        });
        landed.insert(proposed.key.clone());
        moved.push(spec);
    }
    if moved.is_empty() {
        return Ok(moved);
    }
    head.proposal = (!kept.is_empty()).then(|| PackProposal {
        digest: proposal_digest(pack, &head.digest, &kept),
        defaults: kept,
    });
    head.accepted = landed.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    Ok(moved)
}

/// Runs the `after_commit` of each key in `keys` once.
fn run_layer_after_commit(vault: &Vault, keys: &[String]) {
    for key in keys {
        if let Some(after_commit) = spec_named(key).ok().and_then(|spec| spec.after_commit) {
            after_commit(vault);
        }
    }
}
