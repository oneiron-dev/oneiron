//! The polymorphic restrictive rows (FIX 5137-5139): calls whose restrictive
//! part is in what they carry, judged on the caller's own args, with the
//! vault's help where the args only name it. Only that part is pinned; the
//! rest of the call stays the hooks' to change, under the door's own checks.
//!
//! - `vault.batch` (FIX 5137): each put that withdraws an access grant (its
//!   type, its id and a `revoked` status) is kept by its id ([`keep_puts`]):
//!   a hook's change that still withdraws the grant applies, one that does
//!   not, or that drops the put, gives way to the caller's own put.
//! - `vault.packs.connector.accept` (FIX 5138): the reviewed `basis`, each
//!   row the caller set to `never_allow`, and an `all_manual` tightening.
//!   Other rows, new grants and facets keep their ordinary checks.
//! - `vault.shared.execute` (FIX 5139): its `act_id`, when the saved act it
//!   names deletes the vault, erases or removes an owner. A transfer of
//!   ownership is not restrictive here.

use serde_json::Value;

use crate::Vault;
use crate::connector_key::SlateDisposition;
use crate::federation::SharedActKind;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::task_verb::sdk::ConnectorPackBasis;

use super::{Pinned, RESTRICTIVE_TARGETS_PINNED, entity, shown};

/// A polymorphic call's landing parts: its verb, its pinned fields, its
/// row's own check, and a batch's kept grant withdrawals.
type Parts = (
    &'static str,
    Vec<Pinned>,
    Option<fn(&Value) -> bool>,
    Vec<Value>,
);

/// The landing parts of a call of `verb` on the caller's own `args` when
/// what it carries makes it restrictive; `None` otherwise.
pub(super) fn restrictive(vault: &Vault, verb: &str, args: &Value) -> Option<Parts> {
    match verb {
        "vault.batch" => {
            let puts: Vec<Value> = args
                .get("entities")?
                .as_array()?
                .iter()
                .filter(|put| withdraws_a_grant(put))
                .cloned()
                .collect();
            (!puts.is_empty()).then_some(("vault.batch", Vec::new(), None, puts))
        }
        "vault.packs.connector.accept" => {
            let mut pins = vec![pinned(&["basis"], basis)];
            if let Some(rows) = args.get("rows").and_then(Value::as_object) {
                pins.extend(
                    rows.iter()
                        .filter(|(_, setting)| {
                            setting.as_str() == Some(SlateDisposition::NeverAllow.as_str())
                        })
                        .map(|(row, _)| Pinned {
                            path: vec!["rows".to_owned(), row.clone()],
                            parse: disposition,
                        }),
                );
            }
            let all_manual = args.get("all_manual") == Some(&Value::Bool(true));
            if all_manual {
                pins.push(pinned(&["all_manual"], Value::is_boolean));
            }
            (pins.len() > 1).then_some(("vault.packs.connector.accept", pins, None, Vec::new()))
        }
        "vault.shared.execute" => {
            let act = args.get("act_id")?.as_str()?;
            let saved = vault.pending_authority_act(act).ok()??;
            matches!(
                SharedActKind::parse(&saved.act)?,
                SharedActKind::DeleteVault | SharedActKind::Erase | SharedActKind::RemoveOwner
            )
            .then(|| {
                (
                    "vault.shared.execute",
                    vec![pinned(&["act_id"], entity)],
                    None,
                    Vec::new(),
                )
            })
        }
        _ => None,
    }
}

/// Whether every part a polymorphic call of `verb` writes withdraws or
/// erases (FIX 11201): a batch every put of which withdraws an access grant,
/// or a shared act that deletes the vault, erases or removes an owner. A
/// connector pack accept stamps the pack's consent, whatever rows it denies,
/// so it is never one; nor is any other call.
///
/// # Errors
/// The pending shared act's read failing.
pub(super) fn wholly_restrictive(vault: &Vault, verb: &str, args: &Value) -> crate::Result<bool> {
    Ok(match verb {
        "vault.batch" => args
            .get("entities")
            .and_then(Value::as_array)
            .is_some_and(|puts| !puts.is_empty() && puts.iter().all(withdraws_a_grant)),
        "vault.shared.execute" => {
            let Some(act) = args.get("act_id").and_then(Value::as_str) else {
                return Ok(false);
            };
            vault.pending_authority_act(act)?.is_some_and(|saved| {
                matches!(
                    SharedActKind::parse(&saved.act),
                    Some(
                        SharedActKind::DeleteVault
                            | SharedActKind::Erase
                            | SharedActKind::RemoveOwner
                    )
                )
            })
        }
        _ => false,
    })
}

fn pinned(path: &[&str], parse: fn(&Value) -> bool) -> Pinned {
    Pinned {
        path: path.iter().map(|key| (*key).to_owned()).collect(),
        parse,
    }
}

/// A put that withdraws an access grant: the grant type, an existing id and
/// a `revoked` status in its body.
fn withdraws_a_grant(put: &Value) -> bool {
    put.get("entity_type")
        .or_else(|| put.get("entityType"))
        .and_then(Value::as_u64)
        == Some(u64::from(ENTITY_TYPE_ACCESS_GRANT))
        && put
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| crate::EntityId::from_hex(id.trim()).is_ok())
        && put
            .get("body")
            .and_then(|body| body.get("status"))
            .and_then(Value::as_str)
            == Some("revoked")
}

/// The reviewed basis an accept names, as the door decodes it.
fn basis(value: &Value) -> bool {
    <ConnectorPackBasis as serde::Deserialize>::deserialize(value).is_ok()
}

/// One of the four capability settings.
fn disposition(value: &Value) -> bool {
    value.as_str().and_then(SlateDisposition::parse).is_some()
}

/// Keeps each of a batch's grant withdrawals `kept` in `candidate`, by its
/// id: a put a hook changed that still withdraws the grant stays as the hook
/// wrote it (the caller's own while [`RESTRICTIVE_TARGETS_PINNED`]); one
/// that no longer does, or that a hook dropped, gives way to the caller's
/// own put. The notes say what changed (`applied` adds one for a change that
/// stands). `None` when the caller's puts cannot be put back: no list of
/// puts is left.
pub(super) fn keep_puts(
    kept: &[Value],
    candidate: &mut Value,
    applied: bool,
) -> Option<Vec<String>> {
    let entities = candidate.get_mut("entities")?.as_array_mut()?;
    let mut notes = Vec::new();
    for put in kept {
        let id = put.get("id");
        let named = shown(id);
        match entities.iter().position(|other| other.get("id") == id) {
            Some(at) if entities[at] == *put => {}
            Some(at) if withdraws_a_grant(&entities[at]) && !RESTRICTIVE_TARGETS_PINNED => {
                if applied {
                    notes.push(format!(
                        "a hook changed this batch's withdrawal of grant {named}"
                    ));
                }
            }
            Some(at) => {
                entities[at] = put.clone();
                notes.push(format!(
                    "a hook changed this batch's withdrawal of grant {named}; the change was ignored"
                ));
            }
            None => {
                entities.push(put.clone());
                notes.push(format!(
                    "a hook took this batch's withdrawal of grant {named} out; it was put back"
                ));
            }
        }
    }
    Some(notes)
}
