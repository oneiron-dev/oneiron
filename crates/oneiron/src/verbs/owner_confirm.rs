//! The owner-checked preview and confirm of DEC-0006 #undo-class :146: a
//! one-way verb always goes through it, on every surface.
//!
//! One table ([`OWNER_CONFIRM_ROWS`]) names every gated verb. A preview shows
//! what the call takes and retains the caller's own row; the call passes its
//! confirm back and [`admit`] needs that live row. The grant-widen tiered
//! confirm, FIX-LIST [GRANT-WIDEN-TIERED-CONFIRM], joins this same table and
//! adds its tier as the proof [`admit`] asks of a GrantWiden row, so there is
//! one confirm path, not two.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::legal_hold::LegalHoldLiftAndEraseRequest;
use super::note_history::{NoteHistoryPurgeExecuteRequest, NoteHistoryPurgeRequest};
use super::outbound_call_erase::OutboundCallRequestEraseRequest;
use super::record_erase::{RecordEraseConfirmRequest, record_erase_view};
use super::shared::SharedDeleteProposeRequest;
use crate::check_in::{UndoClass, VerbActClass, verb_act_class};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MEMORY_CODE_OWNER_CONFIRM_REQUIRED, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The shared preview verb: the owner's preview of one one-way act.
pub const OWNER_CONFIRM_PREVIEW_VERB: &str = "vault.owner_confirm.preview";

/// How long a kept preview stays confirmable: ten minutes on the vault's
/// recording clock (FIX 12522).
pub const OWNER_CONFIRM_TTL_SECS: u64 = 600;

/// The proof the gated verb's own door takes. It matches each row's
/// `host_door_proof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerConfirmProof {
    /// The vault owner's proof, as `/v1/owner` takes it.
    Owner,
    /// A live person's own proof.
    SharedPerson,
}

/// How long a retained preview row lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKeep {
    /// The row lives [`OWNER_CONFIRM_TTL_SECS`] on the vault clock. It is
    /// not cleared when used.
    Ttl,
    /// The row never expires. It is replaced by the caller's next preview
    /// of the same verb, and it is cleared when a confirm uses it (FIX 1462:
    /// "no second press, token or expiry", Engine 11:34).
    UntilUsed,
}

/// One gated verb: its name, the proof its door takes, and how its retained
/// preview rows live.
#[derive(Debug, Clone, Copy)]
pub struct OwnerConfirmRow {
    /// The gated verb's name.
    pub verb: &'static str,
    /// The proof the gated verb's own door takes.
    pub proof: OwnerConfirmProof,
    /// How the verb's retained preview rows live.
    pub keep: PreviewKeep,
}

/// Every verb the shared confirm gates, in verb-name order.
pub static OWNER_CONFIRM_ROWS: [OwnerConfirmRow; 6] = [
    OwnerConfirmRow {
        verb: "vault.legal_holds.lift_and_erase",
        proof: OwnerConfirmProof::Owner,
        keep: PreviewKeep::UntilUsed,
    },
    OwnerConfirmRow {
        verb: "vault.notes.history_purge",
        proof: OwnerConfirmProof::Owner,
        keep: PreviewKeep::Ttl,
    },
    OwnerConfirmRow {
        verb: "vault.notes.history_purge_execute",
        proof: OwnerConfirmProof::Owner,
        keep: PreviewKeep::Ttl,
    },
    OwnerConfirmRow {
        verb: "vault.outbound_calls.request.erase",
        proof: OwnerConfirmProof::Owner,
        keep: PreviewKeep::Ttl,
    },
    OwnerConfirmRow {
        verb: "vault.records.erase_confirm",
        proof: OwnerConfirmProof::SharedPerson,
        keep: PreviewKeep::Ttl,
    },
    OwnerConfirmRow {
        verb: "vault.shared.propose_delete",
        proof: OwnerConfirmProof::SharedPerson,
        keep: PreviewKeep::Ttl,
    },
];

/// The row gating `verb`; `None` for a verb the shared confirm does not gate.
#[must_use]
pub fn owner_confirm_row(verb: &str) -> Option<&'static OwnerConfirmRow> {
    OWNER_CONFIRM_ROWS.iter().find(|row| row.verb == verb)
}

/// The previews a caller was shown and may still confirm, one live row per
/// caller and confirm digest: FIX 12522, generalized from the record erase
/// to every one-way verb. Confirm requires the caller's own live row for the
/// digest it names, so a hook that rewrites the call to another target's
/// valid preview cannot redirect the act to what the caller never previewed.
const OWNER_CONFIRMS: SideTable<(EntityId, [u8; 32]), OwnerConfirmStored, Named> =
    SideTable::new(&side_table::OWNER_CONFIRM_PREVIEW);

/// One retained preview: the verb previewed, and when it was issued and,
/// for a kept row, expires on the vault's recording clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerConfirmStored {
    verb: String,
    issued_at: u64,
    expires_at: Option<u64>,
}

/// An erased caller's retained previews go, in the actor erase's own writer.
pub(crate) fn owner_confirm_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    OWNER_CONFIRMS.delete_from(&vault.store, wtxn, actor.as_bytes())?;
    Ok(())
}

/// The confirm digest of one previewed call: `verb`, the caller, the typed
/// input without `confirm`, and the shown view, each length-prefixed. Both
/// values come from serializing typed Rust values, never from client JSON as
/// it arrived (the workspace's serde_json keeps map order).
fn digest(verb: &str, caller: &EntityId, input: &Value, view: &Value) -> [u8; 32] {
    let input_bytes = serde_json::to_vec(input).unwrap_or_default();
    let view_bytes = serde_json::to_vec(view).unwrap_or_default();
    let parts: [&[u8]; 4] = [
        verb.as_bytes(),
        caller.as_bytes(),
        &input_bytes,
        &view_bytes,
    ];
    let mut hash = blake3::Hasher::new_derive_key("oneiron/owner-confirm/v1");
    for part in parts {
        hash.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(part);
    }
    *hash.finalize().as_bytes()
}

/// One gated call's confirm, parsed but not yet looked up: the verb, the
/// typed input without `confirm`, and the digest the call names.
pub(crate) struct OwnerConfirmAsk {
    verb: &'static str,
    input: Value,
    confirm: [u8; 32],
}

/// Parses the confirm the gated call carries: the typed `input` without its
/// `confirm` key, and the digest that key names. It does no lookup. A call
/// with no confirm, a null one, or one that is not 64 lowercase hex is
/// refused with [`MEMORY_CODE_OWNER_CONFIRM_REQUIRED`].
pub(crate) fn asked(verb: &'static str, input: &impl Serialize) -> MemoryResult<OwnerConfirmAsk> {
    let bare = serde_json::to_value(input)
        .map_err(|_| MemoryError::bad_request("the one-way call does not encode"))?;
    let confirm = bare
        .get("confirm")
        .and_then(Value::as_str)
        .and_then(|text| {
            if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return None;
            }
            crate::task_verb::decode_hex::<32>(text)
        })
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_OWNER_CONFIRM_REQUIRED,
                "this one-way act needs the owner's confirm of its preview",
                &["Preview it with vault.owner_confirm.preview, show what it takes, and pass its confirm back."],
            )
        })?;
    Ok(OwnerConfirmAsk {
        verb,
        input: without_confirm(bare),
        confirm,
    })
}

/// `value` without its `confirm` key, every other key in its own order. The
/// workspace's serde_json keeps map order, and there `Map::remove` moves the
/// last key into the gap, so a call that carries its confirm and the same
/// call previewed without one would hash apart.
fn without_confirm(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| key != "confirm")
                .collect(),
        ),
        other => other,
    }
}

/// Admits the gated call `ask` names when its confirm is the caller's live
/// preview of this call as it stands now: the digest of the verb, the
/// caller, the input and `view` equals the confirm, and the caller's own row
/// for that digest exists, names the same verb, and is live. Anything else
/// is refused with [`MEMORY_CODE_OWNER_CONFIRM_REQUIRED`]. A row kept until
/// used is deleted here, in one write txn with the check, so a confirm lands
/// once. An erased caller is refused: their rows went with them.
pub(crate) fn admit(
    vault: &Vault,
    caller: &AuthenticatedOwner,
    ask: OwnerConfirmAsk,
    view: &impl Serialize,
) -> MemoryResult<()> {
    let OwnerConfirmAsk {
        verb,
        input,
        confirm,
    } = ask;
    let shown = serde_json::to_value(view)
        .map_err(|_| MemoryError::bad_request("the one-way call does not encode"))?;
    let caller_id = caller.actor_for_read(vault)?;
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_OWNER_CONFIRM_REQUIRED,
            "this confirm is not the caller's live preview of this call as it stands now",
            &["Preview it again and confirm what it shows now."],
        )
    };
    if digest(verb, &caller_id, &input, &shown) != confirm {
        return Err(refused());
    }
    let Some(row) = owner_confirm_row(verb) else {
        return Err(refused());
    };
    let now = vault.store.clock.now_recorded_at();
    vault.try_with_write_txn_grouped(|txn| {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &caller_id)? {
            return Err(refused());
        }
        let stored: Option<OwnerConfirmStored> =
            OWNER_CONFIRMS.get(&vault.store, txn, &(caller_id, confirm))?;
        let live = matches!(&stored, Some(kept) if kept.verb == verb && kept.expires_at.is_none_or(|at| at >= now));
        if !live {
            return Err(refused());
        }
        if row.keep == PreviewKeep::UntilUsed {
            OWNER_CONFIRMS.delete(&vault.store, txn, &(caller_id, confirm))?;
        }
        Ok(())
    })?;
    Ok(())
}

/// Retains the caller's preview of one call in one grouped write txn: every
/// expired row goes, and for a verb kept until used so do the caller's other
/// rows of that verb. It answers the 64-hex confirm. An erased caller is
/// refused, as the record erase's preview was (review P1 on #4445).
fn retain(
    vault: &Vault,
    caller: &AuthenticatedOwner,
    verb: &'static str,
    input: &Value,
    view: &Value,
) -> MemoryResult<String> {
    let row = owner_confirm_row(verb)
        .ok_or_else(|| MemoryError::bad_request(format!("{verb} takes no owner confirm")))?;
    let caller_id = caller.actor_for_read(vault)?;
    let confirm = digest(verb, &caller_id, input, view);
    let now = vault.store.clock.now_recorded_at();
    let stored = OwnerConfirmStored {
        verb: verb.to_owned(),
        issued_at: now,
        expires_at: match row.keep {
            PreviewKeep::Ttl => Some(now + OWNER_CONFIRM_TTL_SECS),
            PreviewKeep::UntilUsed => None,
        },
    };
    vault
        .with_write_txn_grouped(|txn| {
            if vault.local_hard_delete_marker_exists_in_txn(txn, &caller_id)? {
                return Err(crate::Error::InvariantViolation(
                    "owner confirm caller was erased",
                ));
            }
            // Rows key by caller and digest, not by issue time, so expiry has
            // no order to stop at: every expired row goes.
            let mut expired = Vec::new();
            for entry in OWNER_CONFIRMS.iter_from(&vault.store, txn, &[])? {
                let (key, kept) = entry?;
                if kept.expires_at.is_some_and(|at| at < now) {
                    expired.push(key);
                }
            }
            for key in &expired {
                OWNER_CONFIRMS.delete(&vault.store, txn, key)?;
            }
            if row.keep == PreviewKeep::UntilUsed {
                let mut stale = Vec::new();
                for entry in OWNER_CONFIRMS.iter_from(&vault.store, txn, caller_id.as_bytes())? {
                    let (key, kept) = entry?;
                    if kept.verb == verb {
                        stale.push(key);
                    }
                }
                for key in &stale {
                    OWNER_CONFIRMS.delete(&vault.store, txn, key)?;
                }
            }
            OWNER_CONFIRMS.put(&vault.store, txn, &(caller_id, confirm), &stored)
        })
        .map_err(MemoryError::from)?;
    Ok(bytes_to_hex_lower(&confirm))
}

/// `input` as the gated verb's typed input, beside itself re-encoded without
/// `confirm`, as [`asked`] hashes it.
fn confirm_free_input<T>(input: Value) -> MemoryResult<(T, Value)>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let typed: T = serde_json::from_value(input).map_err(|error| {
        MemoryError::bad_request(format!("invalid owner confirm input: {error}"))
    })?;
    let bare = serde_json::to_value(&typed)
        .map_err(|_| MemoryError::bad_request("the owner confirm input does not encode"))?;
    Ok((typed, without_confirm(bare)))
}

/// `vault.owner_confirm.preview`'s input: the one-way verb to preview, and
/// its input as that verb takes it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmPreviewRequest {
    /// The gated verb's name, one of [`OWNER_CONFIRM_ROWS`].
    pub verb: String,
    /// The gated call's input, as the gated verb takes it.
    pub input: Value,
}

/// `vault.owner_confirm.preview`'s answer: what the one-way act takes, its
/// classes, and the confirm its call passes back.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerConfirmPreview {
    /// The gated verb's name.
    pub verb: String,
    /// The gated row's `act_class` token.
    pub act_class: String,
    /// The gated act's undo class.
    pub undo_class: UndoClass,
    /// What the act takes: the gated verb's own view, or none for a verb
    /// with none.
    pub takes: Option<Value>,
    /// The 64-hex confirm the gated call passes back.
    pub confirm: String,
}

/// `vault.owner_confirm.preview`: the owner's preview of one one-way act.
/// It decodes the input as the gated verb's typed input, computes the same
/// view the gated fn computes through that verb's own view fn, and retains
/// the caller's row. A verb with no row is refused.
pub fn preview_owner_confirm(
    memory: &Memory<'_>,
    caller: &AuthenticatedOwner,
    request: OwnerConfirmPreviewRequest,
) -> MemoryResult<OwnerConfirmPreview> {
    let verb = request.verb.as_str();
    let row = owner_confirm_row(verb)
        .ok_or_else(|| MemoryError::bad_request(format!("{verb} takes no owner confirm")))?;
    let vault = memory.vault();
    let (input, shown, takes_view) = match verb {
        "vault.records.erase_confirm" => {
            let (typed, bare) = confirm_free_input::<RecordEraseConfirmRequest>(request.input)?;
            let (_, view) = record_erase_view(memory, &typed.record)?;
            let shown = serde_json::to_value(&view)
                .map_err(|_| MemoryError::bad_request("the erase preview does not encode"))?;
            (bare, shown, true)
        }
        "vault.legal_holds.lift_and_erase" => {
            let (typed, bare) = confirm_free_input::<LegalHoldLiftAndEraseRequest>(request.input)?;
            let shown = vault.lift_and_erase_shown_state(
                caller,
                &typed.records,
                typed.claim_free_partition,
            )?;
            let shown = serde_json::to_value(&shown)
                .map_err(|_| MemoryError::bad_request("the hold preview does not encode"))?;
            (bare, shown, true)
        }
        "vault.notes.history_purge" => {
            let (_, bare) = confirm_free_input::<NoteHistoryPurgeRequest>(request.input)?;
            (bare, Value::Null, false)
        }
        "vault.notes.history_purge_execute" => {
            let (_, bare) = confirm_free_input::<NoteHistoryPurgeExecuteRequest>(request.input)?;
            (bare, Value::Null, false)
        }
        "vault.outbound_calls.request.erase" => {
            let (_, bare) = confirm_free_input::<OutboundCallRequestEraseRequest>(request.input)?;
            (bare, Value::Null, false)
        }
        "vault.shared.propose_delete" => {
            let (_, bare) = confirm_free_input::<SharedDeleteProposeRequest>(request.input)?;
            (bare, Value::Null, false)
        }
        _ => {
            return Err(MemoryError::bad_request(format!(
                "{verb} takes no owner confirm"
            )));
        }
    };
    let (act_class, undo_class) = match verb_act_class(verb) {
        Some(VerbActClass::Act(act)) => (act.as_str().to_owned(), act.row().undo),
        _ => {
            return Err(MemoryError::bad_request(format!(
                "{verb} takes no owner confirm"
            )));
        }
    };
    let confirm = retain(vault, caller, row.verb, &input, &shown)?;
    Ok(OwnerConfirmPreview {
        verb: request.verb,
        act_class,
        undo_class,
        takes: takes_view.then_some(shown),
        confirm,
    })
}

/// `vault.owner_confirm.preview` on an embedded handle: the embedded owner's
/// own preview.
pub fn preview_owner_confirm_embedded(
    memory: &Memory<'_>,
    request: OwnerConfirmPreviewRequest,
) -> MemoryResult<OwnerConfirmPreview> {
    let owner = memory.embedded_owner(OWNER_CONFIRM_PREVIEW_VERB)?;
    preview_owner_confirm(memory, &owner, request)
}
