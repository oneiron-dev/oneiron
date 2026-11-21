//! The owner's notice of a row a key's hook refused at projection (row
//! SETTING-PROJECTED-ROW-REFUSING-HOOKS; Engine ANSWER 21 Nov 13:08: every refused projection of
//! a signed setting act raises an owner-visible settings notice on every machine, which names
//! both acts and offers a one-step fix).
//!
//! A pass that projects a row its key's hook refuses here leaves the row as it was, and the next
//! pass reads it again ([`Vault::project_settings`]). In the same write it raises one
//! NOTIFICATION per owner of the vault, kind `Ask`, producer
//! [`SETTING_REFUSAL_NOTIFICATION_PRODUCER`]. It names the refused act and, for a key whose hook
//! judges its row against other rows ([`super::super::RefusalPeers`]), the acts behind those
//! rows: each by its row, its value where the key's value type is closed (an open value, such as
//! free text, is not quoted), and the machine whose install signed it. Its event is every act it
//! names, in hash order, and the owner it is for: a machine that refuses the other side of the
//! same pair raises the same row, and a later pass that refuses again adds nothing. The row
//! travels as an entity, so a machine that refused nothing shows it too. `source.detail` holds
//! the owner's words, `source.result` the log entry of the act this install refused, and
//! `subject_refs` the log entry of every act it names.
//!
//! Its taps are read when the row is read ([`setting_refusal_taps_in_txn`]): for each row this
//! install still refuses an act of, one `vault.settings.set` of that row to the value it holds
//! here, which the owner may edit. The owner's set signs its act even where this install's row
//! already holds the value ([`slot_refused_here_in_txn`]), so the act replaces the refused one
//! on every machine, and each machine's next pass projects the row again.

use super::*;

use oneiron_authority::authority::{AuthorityOp, authority_log_entity_id_from_hash};

use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};

/// The producer of the owner's notice of a refused projection (module doc).
pub(crate) const SETTING_REFUSAL_NOTIFICATION_PRODUCER: &str = "setting.projection";

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
/// `now`: one row per owner of the vault (module doc). A target with no setting act among its
/// heads, or on a key this build does not know, raises none.
///
/// # Errors
///
/// Storage errors; the key's peers' read.
pub(super) fn raise_refusal_notice_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, reason): (EntityId, &str),
    now: u64,
) -> Result<()> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(());
    };
    let refused = named_acts_in_txn(vault, txn, &fold)?;
    let Some(first) = refused.first() else {
        return Ok(());
    };
    let Ok(spec) = spec_named(&first.slot.name) else {
        return Ok(());
    };
    let mut targets = vec![target];
    let mut peers = Vec::new();
    if let Some(peers_of) = spec.refusal_peers {
        for slot in peers_of(vault, txn, &first.slot, first.value.as_ref())? {
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
    let acts: BTreeSet<AuthorityEntryHash> = refused
        .iter()
        .chain(peers.iter().flat_map(|peer| &peer.acts))
        .map(|named| named.act)
        .collect();
    let event_acts = acts
        .iter()
        .map(|act| oneiron_hex::encode(act))
        .collect::<Vec<_>>()
        .join("+");
    let subject_refs = acts
        .iter()
        .map(authority_log_entity_id_from_hash)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let result = authority_log_entity_id_from_hash(&first.act)?.to_hex();
    let detail = refusal_words_in_txn(vault, txn, &refused, &peers, reason)?;
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: SETTING_REFUSAL_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{event_acts}:{}", owner.to_hex()),
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

/// The setting acts among `fold`'s live heads, in the fold's order. A move's copy, a pack's head
/// and an act of another kind are no setting act of the owner's, and name nothing here.
fn named_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &SettingSlotFold,
) -> Result<Vec<NamedAct>> {
    let mut named = Vec::new();
    for head in &fold.live {
        let (Some(set), Ok(read)) = (&head.set, head_of(head)) else {
            continue;
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
        named.push(NamedAct {
            act: head.act,
            clears: matches!(read.body, HeadBody::Inline(None)),
            slot: read.slot,
            value,
            machine: set.machine,
        });
    }
    Ok(named)
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

/// The owner's words of a refusal: which machine did not apply which act, the hook's reason, the
/// acts it meets, and the fix.
fn refusal_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    refused: &[NamedAct],
    peers: &[Peer],
    reason: &str,
) -> Result<String> {
    let here = match vault.serving_machine_in_txn(txn)? {
        Some(machine) => machine_label_in_txn(vault, txn, machine)?,
        None => "This machine".to_owned(),
    };
    let refused = refused
        .iter()
        .map(|named| act_words_in_txn(vault, txn, named))
        .collect::<Result<Vec<_>>>()?;
    let mut words = format!(
        "{here} did not apply {}: {}.",
        refused.join(" and "),
        reason.trim_end_matches('.')
    );
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

/// The row `target`'s acts name where this install's projection of them does not stand: one of
/// its live heads is a setting act (one of `acts`, where given), and no projection is recorded at
/// its acts as they are, so the next pass reads it again (a row its key's hook refused here).
/// `None` where the projection stands, or no such act heads the row.
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
    let in_force = fold.in_force.as_ref().map(|head| head.act);
    let basis = basis_of(
        fold.revision,
        (&fold.counts, &fold.name_counts),
        (fold.conflict, in_force),
        &fold.asking,
    );
    let stands = match PROJECTIONS.get(&vault.store, txn, &target_key(target))? {
        Some(projection) => !moved_since(vault, txn, &projection, basis)?,
        None => false,
    };
    Ok((!stands).then_some(slot))
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

/// The taps the owner's notice of a refused projection offers on this install now, from its
/// `event` (module doc): for each row an act it names heads and this install still refuses
/// ([`refused_slot_in_txn`]), the input of one `vault.settings.set` of that row to the value it
/// holds here, which the owner may edit before he taps. A carried row offers none, since only a
/// move writes one; an event of another shape offers none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn setting_refusal_taps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &str,
) -> Result<Vec<serde_json::Value>> {
    let Some((acts, _owner)) = event.split_once(':') else {
        return Ok(Vec::new());
    };
    let acts: BTreeSet<AuthorityEntryHash> = acts
        .split('+')
        .filter_map(oneiron_hex::decode::<32>)
        .collect();
    let mut targets = BTreeSet::new();
    let mut taps = Vec::new();
    for act in &acts {
        let id = authority_log_entity_id_from_hash(act)?;
        let Some(entry) = vault.get_authority_log_entry_in_txn(txn, &id)? else {
            continue;
        };
        let AuthorityOp::PolicySettingSet(set) = entry.op else {
            continue;
        };
        let slot = set.slot.unwrap_or_else(|| RowKey {
            name: set.setting.clone(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        });
        let target = setting_slot_target(&slot)?;
        if !targets.insert(target) {
            continue;
        }
        let Some(refused) = refused_slot_in_txn(vault, txn, target, Some(&acts))? else {
            continue;
        };
        let Ok(spec) = spec_named(&refused.name) else {
            continue;
        };
        if refused.mode == SettingMode::Carried {
            continue;
        }
        taps.push(serde_json::json!({
            "key": refused.name,
            "item": refused.item,
            "scope": refused.scope,
            "pin": refused.mode == SettingMode::Pin,
            "value": value_here_in_txn(vault, txn, spec, &refused)?,
        }));
    }
    Ok(taps)
}
