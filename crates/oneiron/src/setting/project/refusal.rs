//! The owner's notice of a row a key's hook refused at projection (row
//! SETTING-PROJECTED-ROW-REFUSING-HOOKS; Engine ANSWER 21 Nov 13:08: every refused projection of
//! a signed setting act raises an owner-visible settings notice on every machine, which names
//! both acts and offers a one-step fix).
//!
//! A pass that projects a row its key's hook refuses here leaves the row as it was, and the next
//! pass reads it again ([`Vault::project_settings`]), unless the key lands it all the same
//! ([`RefusedProjection::Land`], the booking pair: SETTING-PROJECTED-EMERGENCY-PAIR = A). Then the
//! row takes the act's value without the hook ([`land_refused_row_in_txn`]), as on every machine
//! that folds the act, and the key's reader holds the line. In the same write it raises one
//! NOTIFICATION per owner of the vault, kind `Ask`, producer
//! [`SETTING_REFUSAL_NOTIFICATION_PRODUCER`]. It names the acts that head the row and the act the
//! refused value came from: one of them, or, where the heads differ and the row takes the value
//! they all come from, that act. For a key whose hook judges its row against other rows
//! ([`super::super::RefusalPeers`]) it names the acts behind those rows too: each act by its row,
//! its value where the key's value type is closed (an open value, such as free text, is not
//! quoted), and the machine whose install signed it. Its event is every act it names, in hash
//! order, every row it names, in id order, and the owner it is for: a machine that refuses the
//! other side of the same pair raises the same row, a later pass that refuses again adds nothing,
//! and the refusals of two rows one act heads, each judged against its own rows, raise a notice
//! each (REVIEW-10306 round 2). The row travels as an entity,
//! so a machine that refused nothing shows it too; a copy another machine raised alone lands with
//! the seen and acknowledged marks of both copies (`sync::ingest::notification_marks`).
//! `source.detail` holds the owner's words, `source.result` the log entry of the act the refused
//! value came from, and `subject_refs` the log entry of every act it names.
//!
//! The pass also records the refusal here ([`REFUSALS`]): the basis of the acts it refused. A
//! refusal stands while the row's acts are as they were then and no projection of them stands;
//! an act that arrived since, which no pass has read yet, is not refused here. A row its key
//! landed all the same is projected at those acts: its refusal stands while the key's
//! `conflict` reads the rows as conflicting, so a change of the other row that ends the conflict
//! ends it too. A later act whose value such a row holds already runs no hook, so the pass reads
//! the key's `conflict` for it instead, and refuses it while the rows conflict
//! ([`equal_row_refusal_in_txn`]). The pass lands every such row before it raises any notice
//! ([`land_refused_rows_in_txn`]): the words read the rows as it leaves them, and a landed row
//! whose rows no longer conflict then raises none.
//!
//! Its tap is read when the row is read ([`setting_refusal_tap_in_txn`]): one `vault.settings.set`
//! of every row this install still refuses an act of and of every row its key's hook judges such
//! a row against, each to the value it holds here, which the owner may edit. The owner's change
//! of them is ONE act ([`Vault::set_settings`]), whose rows are all written before any hook runs.
//! It signs a refused row even where this install's row already holds the value
//! ([`slot_refused_here_in_txn`]), so the act replaces the refused one on every machine, and each
//! machine's pass projects every row of it, whichever it reads first. A key whose hook refuses a
//! change to no value of a row a machine holds in service (`refusal_offers_clear`, a calendar
//! seat) leaves out a row that holds no value here: the machine that holds the row would refuse
//! its act.

use super::*;

use oneiron_authority::authority::{AuthorityOp, authority_log_entity_id_from_hash};

use super::super::RefusedProjection;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};

/// The producer of the owner's notice of a refused projection (module doc).
pub(crate) const SETTING_REFUSAL_NOTIFICATION_PRODUCER: &str = "setting.projection";

thread_local! {
    /// Set while this thread's pass lands a row its key's hook refused here, for a key that lands
    /// such a row all the same ([`land_refused_row_in_txn`]): the row's write runs no hook.
    static LANDING_REFUSED_ROW: Cell<bool> = const { Cell::new(false) };
}

/// Whether the write of a row of `spec` runs without its hook: the pass lands a row the hook
/// refused, of a key that lands it all the same ([`RefusedProjection::Land`]).
pub(super) fn hook_waived(spec: &SettingSpec) -> bool {
    LANDING_REFUSED_ROW.with(Cell::get)
        && matches!(spec.refused_projection, RefusedProjection::Land { .. })
}

/// The words that refuse an equal row of `spec` at `slot`, whose write runs no hook: on a key
/// whose reader holds the line ([`RefusedProjection::Land`]), its `conflict` while the rows
/// conflict, so a later act whose value the row holds already is refused here as the act it
/// replaces was, and its refusal and the notice's tap stand (REVIEW-10343 P1-1). `None` on any
/// other key, and while the pass lands a refused row ([`hook_waived`]).
///
/// # Errors
///
/// Storage errors.
pub(super) fn equal_row_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
) -> Result<Option<String>> {
    match spec.refused_projection {
        RefusedProjection::Land { conflict } if !hook_waived(spec) => conflict(vault, txn, slot),
        _ => Ok(None),
    }
}

/// Lands, in the pass's write `txn` at `now`, each row of `refused` (its target, its hook's
/// reason, the act the refused value came from) whose key lands such a row all the same
/// ([`land_refused_row_in_txn`]), every one before the pass raises any notice, so two rows each
/// refused against the other's last value both land, and each notice reads the pair the pass
/// leaves (REVIEW-10343 P1-2). Adds the keys whose rows changed to `changed`, and logs each row
/// left for the next pass. Whether each row landed, in `refused`'s order.
///
/// # Errors
///
/// Storage errors.
pub(super) fn land_refused_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    refused: &[(EntityId, String, Option<AuthorityEntryHash>)],
    now: u64,
    changed: &mut Vec<&'static SettingSpec>,
) -> Result<Vec<bool>> {
    let mut landings = Vec::with_capacity(refused.len());
    for (target, reason, _) in refused {
        let landed = land_refused_row_in_txn(vault, txn, *target, now)?;
        if landed.is_none() {
            tracing::warn!(
                reason = %reason,
                "the next pass reads again a setting row its key refused here"
            );
        }
        landings.push(landed.is_some());
        changed.extend(landed.into_iter().flatten());
    }
    Ok(landings)
}

/// Lands the row of `target` that its key's hook refused in this pass, without the hook, in a
/// savepoint of the pass's write `txn`, at `now`, where the key lands such a row all the same
/// ([`RefusedProjection::Land`]): the keys whose rows changed. `None` for a key that leaves the
/// row for the next pass, and where the row's value itself is refused (logged): the next pass
/// reads it again.
///
/// # Errors
///
/// Storage errors.
fn land_refused_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    now: u64,
) -> Result<Option<Vec<&'static SettingSpec>>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(None);
    };
    let lands = fold
        .live
        .iter()
        .find_map(|head| head_of(head).ok())
        .and_then(|head| spec_named(&head.slot.name).ok())
        .is_some_and(|spec| matches!(spec.refused_projection, RefusedProjection::Land { .. }));
    if !lands {
        return Ok(None);
    }
    LANDING_REFUSED_ROW.with(|landing| landing.set(true));
    let landed = crate::batch::savepoint_in_txn(vault, txn, |savepoint| {
        project_target_in_txn(vault, savepoint, target, now).map(Some)
    });
    LANDING_REFUSED_ROW.with(|landing| landing.set(false));
    match landed {
        Ok(projected) => Ok(Some(
            projected
                .map(|projected| projected.changed)
                .unwrap_or_default(),
        )),
        Err(Error::InvalidConfig(reason)) => {
            tracing::warn!(
                reason = %reason,
                "a setting row its key lands all the same was refused; the next pass reads it again"
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// A setting act a notice names.
struct NamedAct {
    act: AuthorityEntryHash,
    slot: RowKey,
    /// The value it sets, as JSON; `None` for a clear, and for a value beside the act that is not
    /// here.
    value: Option<serde_json::Value>,
    clears: bool,
    /// The machine whose install signed it.
    machine: EntityId,
}

/// A row the refused row's key judges it against, with the acts behind it and the value it
/// holds here.
struct Peer {
    slot: RowKey,
    acts: Vec<NamedAct>,
    here: Option<serde_json::Value>,
}

/// Raises the owner's notice that this install's pass refused the row of `target`, with its
/// key's hook's `reason`, in the pass's write `txn` once the row's own savepoint rolled back, at
/// `now`: one row per owner of the vault (module doc). `deciding` is the act the refused value
/// came from, where the pass knows it; `landed`, whether the pass landed the row all the same
/// ([`land_refused_row_in_txn`]), once it landed every such row. A target with no setting act
/// among its heads, on a key this build does not know, or landed with rows that no longer
/// conflict, raises none.
///
/// # Errors
///
/// Storage errors; the key's peers' read.
pub(super) fn raise_refusal_notice_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, reason, deciding): (EntityId, &str, Option<AuthorityEntryHash>),
    landed: bool,
    now: u64,
) -> Result<()> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(());
    };
    let heads = named_acts_in_txn(vault, txn, &fold)?;
    let Some(first) = heads.first() else {
        return Ok(());
    };
    // The value the heads that differ all come from, where the refused value came from it.
    let kept = match (deciding, &fold.in_force) {
        (Some(act), Some(in_force))
            if in_force.act == act && heads.iter().all(|named| named.act != act) =>
        {
            named_act_in_txn(vault, txn, in_force)?
        }
        _ => None,
    };
    let refused = kept
        .as_ref()
        .or_else(|| heads.iter().find(|named| Some(named.act) == deciding))
        .unwrap_or(first);
    let Ok(spec) = spec_named(&refused.slot.name) else {
        return Ok(());
    };
    let conflict = match spec.refused_projection {
        RefusedProjection::Land { conflict } => conflict(vault, txn, &refused.slot)?,
        RefusedProjection::Retry => None,
    };
    // A landed row stands refused only while its rows conflict ([`refused_slot_in_txn`]).
    if landed && conflict.is_none() {
        return Ok(());
    }
    let mut targets = vec![target];
    let mut peers = Vec::new();
    if let Some(peers_of) = spec.refusal_peers {
        for slot in peers_of(vault, txn, &refused.slot, refused.value.as_ref())? {
            let peer = setting_slot_target(&slot)?;
            if targets.contains(&peer) {
                continue;
            }
            targets.push(peer);
            let acts = match vault.setting_slot_fold_in_txn(txn, peer)? {
                Some(fold) => named_acts_in_txn(vault, txn, &fold)?,
                None => Vec::new(),
            };
            let here = match spec_named(&slot.name) {
                Ok(peer_spec) => value_here_in_txn(vault, txn, peer_spec, &slot)?,
                Err(_) => None,
            };
            peers.push(Peer { slot, acts, here });
        }
    }
    let acts: BTreeSet<AuthorityEntryHash> = heads
        .iter()
        .chain(&kept)
        .chain(peers.iter().flat_map(|peer| &peer.acts))
        .map(|named| named.act)
        .collect();
    let event_acts = acts
        .iter()
        .map(|act| oneiron_hex::encode(act))
        .collect::<Vec<_>>()
        .join("+");
    let event_rows = targets
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(EntityId::to_hex)
        .collect::<Vec<_>>()
        .join("+");
    let subject_refs = acts
        .iter()
        .map(authority_log_entity_id_from_hash)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let result = authority_log_entity_id_from_hash(&refused.act)?.to_hex();
    let detail = refusal_words_in_txn(
        vault,
        txn,
        (&heads, kept.as_ref()),
        &peers,
        (reason, landed, conflict.as_deref()),
    )?;
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: SETTING_REFUSAL_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{event_acts}:{event_rows}:{}", owner.to_hex()),
                    result: Some(result.clone()),
                    detail: Some(detail.clone()),
                    ..NotificationSource::default()
                },
                subject_refs: subject_refs.clone(),
                recipient: Some(owner),
                created_at: now,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

/// Records that this install's pass found the key's hook refusing the row of `target`'s acts as
/// they stand, in the pass's write `txn` once the row's own savepoint rolled back ([`REFUSALS`]).
/// A target with no acts records nothing.
///
/// # Errors
///
/// Storage errors.
pub(super) fn record_refusal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
) -> Result<()> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(());
    };
    REFUSALS.put(&vault.store, txn, &target_key(target), &fold_basis(&fold))
}

/// The basis of `fold`'s acts as a pass reads them ([`basis_of`]).
fn fold_basis(fold: &SettingSlotFold) -> [u8; 32] {
    let in_force = fold.in_force.as_ref().map(|head| head.act);
    basis_of(
        fold.revision,
        (&fold.counts, &fold.name_counts),
        (fold.conflict, in_force),
        &fold.asking,
    )
}

/// The setting acts among `fold`'s live heads, in the fold's order ([`named_act_in_txn`]).
fn named_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &SettingSlotFold,
) -> Result<Vec<NamedAct>> {
    let mut named = Vec::new();
    for head in &fold.live {
        named.extend(named_act_in_txn(vault, txn, head)?);
    }
    Ok(named)
}

/// `head` as a notice names it; `None` for a move's copy, a pack's head and an act of another
/// kind, which are no setting act of the owner's.
fn named_act_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    head: &SettingSlotHead,
) -> Result<Option<NamedAct>> {
    let (Some(set), Ok(read)) = (&head.set, head_of(head)) else {
        return Ok(None);
    };
    let value = match &read.body {
        HeadBody::Inline(Some(json)) => serde_json::from_slice(json).ok(),
        HeadBody::Beside(digest) => {
            let row = beside_row_id(&read.slot, digest, &head.act)?;
            match beside_row_read_in_txn(vault, txn, row, *digest)? {
                BesideRead::Here(json) => serde_json::from_slice(&json).ok(),
                BesideRead::Absent | BesideRead::Unreadable => None,
            }
        }
        HeadBody::Inline(None) | HeadBody::Copy(_) | HeadBody::Birth(_) => None,
    };
    Ok(Some(NamedAct {
        act: head.act,
        clears: matches!(read.body, HeadBody::Inline(None)),
        slot: read.slot,
        value,
        machine: set.machine,
    }))
}

/// The value the row `slot` of `spec` holds here, as JSON: its stored row, else what its empty
/// slot gives ([`empty_of_in_txn`]); `None` where neither gives one.
fn value_here_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
) -> Result<Option<serde_json::Value>> {
    let stored = table_of(spec)
        .get_bytes(&vault.store, txn, &slot.encode())?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
        .map(|row| row.value);
    let value = match stored {
        Some(value) => Some(value),
        None => empty_of_in_txn(vault, txn, spec, slot)?,
    };
    Ok(value.and_then(|value| spec.kind.to_json(&value)))
}

/// The owner's words of a refusal: the key's words of the conflict its reader refuses, where it
/// gives them (`conflict`), which machine did not apply which act, with the hook's reason, or
/// applied it all the same (`landed`) (the heads of the row, or the act whose value differing
/// `heads` keep, `kept`), the acts it meets, and the fix. A landed row's words give no reason:
/// the hook read the rows before the pass landed them, and `conflict` reads them as it left them.
fn refusal_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (heads, kept): (&[NamedAct], Option<&NamedAct>),
    peers: &[Peer],
    (reason, landed, conflict): (&str, bool, Option<&str>),
) -> Result<String> {
    let here = match vault.serving_machine_in_txn(txn)? {
        Some(machine) => machine_label_in_txn(vault, txn, machine)?,
        None => "This machine".to_owned(),
    };
    let named = heads
        .iter()
        .map(|named| act_words_in_txn(vault, txn, named))
        .collect::<Result<Vec<_>>>()?
        .join(" and ");
    let refused = match kept {
        Some(kept) => format!(
            "{}, which the row keeps while {named} differ",
            act_words_in_txn(vault, txn, kept)?
        ),
        None => named,
    };
    let reason = reason.trim_end_matches('.');
    let mut words = conflict
        .map(|words| format!("{words} "))
        .unwrap_or_default();
    if landed {
        words.push_str(&format!("{here} applied {refused}, as every machine does."));
    } else {
        words.push_str(&format!("{here} did not apply {refused}: {reason}."));
    }
    let mut met = Vec::with_capacity(peers.len());
    for peer in peers {
        if peer.acts.is_empty() {
            let mut phrase = row_words(&peer.slot);
            if let Some(value) = &peer.here
                && quotes_value(&peer.slot)
            {
                phrase.push_str(&format!(" = {value}"));
            }
            phrase.push_str(&format!(" as {here} holds it"));
            met.push(phrase);
        } else {
            for named in &peer.acts {
                met.push(act_words_in_txn(vault, txn, named)?);
            }
        }
    }
    if !met.is_empty() {
        words.push_str(&format!(" It meets {}.", met.join(" and ")));
    }
    words.push_str(" Set the value you want to keep, and every machine takes it.");
    let slot = heads.first().or(kept).map(|named| &named.slot);
    if let Some(slot) = slot
        && spec_named(&slot.name).is_ok_and(|spec| !spec.refusal_offers_clear)
    {
        words.push_str(&format!(
            " No tap leaves {} with no value: a machine that holds it in service refuses that.",
            row_words(slot)
        ));
    }
    Ok(words)
}

/// One act as the owner's words name it: "your `key` = value, set on <machine>".
fn act_words_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, named: &NamedAct) -> Result<String> {
    let row = row_words(&named.slot);
    let what = match &named.value {
        _ if named.clears => format!("your clear of {row}"),
        Some(value) if quotes_value(&named.slot) => format!("your {row} = {value}"),
        _ => format!("your change of {row}"),
    };
    Ok(format!(
        "{what}, set on {}",
        machine_label_in_txn(vault, txn, named.machine)?
    ))
}

/// A row as the owner's words name it: its key, its item, and a scope other than the vault.
fn row_words(slot: &RowKey) -> String {
    let mut words = format!("`{}`", slot.name);
    if let Some(item) = &slot.item {
        words.push_str(&format!(" for `{item}`"));
    }
    if slot.scope != SettingScope::Vault {
        words.push_str(&format!(" at a {} scope", slot.scope.kind().as_str()));
    }
    words
}

/// Whether the owner's words quote a value of `slot`'s key: only one of a closed value type,
/// which carries no free text.
fn quotes_value(slot: &RowKey) -> bool {
    spec_named(&slot.name).is_ok_and(|spec| spec.kind.travels_inline())
}

/// The name `machine` is shown by, else its id's first eight hex digits.
fn machine_label_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, machine: EntityId) -> Result<String> {
    Ok(vault
        .machine_shown_name_in_txn(txn, machine)?
        .unwrap_or_else(|| format!("machine {}", &machine.to_hex()[..8])))
}

/// The row `target`'s acts name where this install's key's hook refuses them: one of its live
/// heads is a setting act (one of `acts`, where given), this install's pass recorded a refusal of
/// its acts as they are ([`REFUSALS`]), and no projection is recorded at them. `None` where the
/// projection stands, where no pass has read the acts as they are (an act that arrived since the
/// last refusal is not refused here), or where no such act heads the row.
fn refused_slot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    acts: Option<&BTreeSet<AuthorityEntryHash>>,
) -> Result<Option<RowKey>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(None);
    };
    let Some(slot) = fold
        .live
        .iter()
        .filter(|head| head.set.is_some() && acts.is_none_or(|acts| acts.contains(&head.act)))
        .find_map(|head| head_of(head).ok())
        .map(|head| head.slot)
    else {
        return Ok(None);
    };
    let basis = fold_basis(&fold);
    if REFUSALS.get(&vault.store, txn, &target_key(target))? != Some(basis) {
        return Ok(None);
    }
    let stands = match PROJECTIONS.get(&vault.store, txn, &target_key(target))? {
        Some(projection) => !moved_since(vault, txn, &projection, basis)?,
        None => false,
    };
    if !stands {
        return Ok(Some(slot));
    }
    // A row its key landed all the same: the refusal stands while the rows conflict.
    match spec_named(&slot.name).map(|spec| spec.refused_projection) {
        Ok(RefusedProjection::Land { conflict }) => Ok(conflict(vault, txn, &slot)?.map(|_| slot)),
        _ => Ok(None),
    }
}

/// Whether this install refuses an act that heads the row `slot` ([`refused_slot_in_txn`]): the
/// owner's equal value of such a row signs its act all the same, so it replaces the refused one
/// on every machine (module doc).
///
/// # Errors
///
/// Storage errors.
pub(in crate::setting) fn slot_refused_here_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
) -> Result<bool> {
    let target = setting_slot_target(slot)?;
    Ok(refused_slot_in_txn(vault, txn, target, None)?.is_some_and(|refused| refused == *slot))
}

/// The tap the owner's notice of a refused projection offers on this install now, from the acts
/// its `event` names (module doc): the input of one `vault.settings.set` of each row an act heads
/// and this install still refuses ([`refused_slot_in_txn`]), then of each row the key's hook
/// judges such a row against ([`super::super::RefusalPeers`]), each named once, to the value it
/// holds here, which the owner may edit before he taps. Every row past the first is a further
/// row of the same change, so the owner's tap is one act. A carried row is left out, since only
/// a move writes one, and so is a row with no value here on a key that does not offer that
/// (`refusal_offers_clear`). `None` where no refusal stands here, and for an event of another
/// shape.
///
/// # Errors
///
/// Storage errors; the key's peers' read.
pub(crate) fn setting_refusal_tap_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &str,
) -> Result<Option<serde_json::Value>> {
    let Some((acts, _owner)) = event.split_once(':') else {
        return Ok(None);
    };
    let acts: BTreeSet<AuthorityEntryHash> = acts
        .split('+')
        .filter_map(oneiron_hex::decode::<32>)
        .collect();
    let mut targets = BTreeSet::new();
    let mut refused = Vec::new();
    let mut peers = Vec::new();
    for act in &acts {
        let id = authority_log_entity_id_from_hash(act)?;
        let Some(entry) = vault.get_authority_log_entry_in_txn(txn, &id)? else {
            continue;
        };
        let AuthorityOp::PolicySettingSet(set) = entry.op else {
            continue;
        };
        // Every row the act names: its first, and each further row of a batch or of the owner's
        // change of several rows.
        let rows = std::iter::once((set.setting, set.slot))
            .chain(set.more.into_iter().map(|row| (row.setting, row.slot)));
        for (setting, slot) in rows {
            let slot = slot.unwrap_or_else(|| RowKey {
                name: setting,
                item: None,
                mode: SettingMode::Value,
                scope: SettingScope::Vault,
            });
            let target = setting_slot_target(&slot)?;
            if !targets.insert(target) {
                continue;
            }
            let Some(row) = refused_slot_in_txn(vault, txn, target, Some(&acts))? else {
                continue;
            };
            if let Ok(spec) = spec_named(&row.name)
                && let Some(peers_of) = spec.refusal_peers
            {
                let value = match vault.setting_slot_fold_in_txn(txn, target)? {
                    Some(fold) => named_acts_in_txn(vault, txn, &fold)?
                        .into_iter()
                        .next()
                        .and_then(|named| named.value),
                    None => None,
                };
                peers.extend(peers_of(vault, txn, &row, value.as_ref())?);
            }
            refused.push(row);
        }
    }
    let mut rows = Vec::new();
    for slot in refused.into_iter().chain(peers) {
        if slot.mode == SettingMode::Carried || rows.iter().any(|(listed, _)| *listed == slot) {
            continue;
        }
        let Ok(spec) = spec_named(&slot.name) else {
            continue;
        };
        let value = value_here_in_txn(vault, txn, spec, &slot)?;
        if !spec.refusal_offers_clear && value.as_ref().is_none_or(serde_json::Value::is_null) {
            continue;
        }
        rows.push((slot, value));
    }
    let mut rows = rows.into_iter().map(|(slot, value)| {
        serde_json::json!({
            "key": slot.name,
            "item": slot.item,
            "scope": slot.scope,
            "pin": slot.mode == SettingMode::Pin,
            "value": value,
        })
    });
    let Some(mut tap) = rows.next() else {
        return Ok(None);
    };
    let further: Vec<serde_json::Value> = rows.collect();
    if !further.is_empty() {
        tap["further"] = serde_json::Value::Array(further);
    }
    Ok(Some(tap))
}
