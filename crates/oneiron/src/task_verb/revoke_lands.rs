//! The owner's revoke always lands (FIX 5076; Engine 10-19): what a verb hook
//! may change on a revoke, erase or withdrawal, and what the call runs on
//! when its change cannot.
//!
//! A restrictive call is a call of one of the rows below, judged on the
//! caller's own args, never on a hook's rewrite. Its pinned fields are what
//! it acts on: the target ids and refs, the record set, the confirmed preview
//! digest or reviewed revision, and the restrictive choice. Three places use
//! this one table, whatever the transport:
//!
//! - the pre chain pins each rewrite ([`Landing::select`]): a pinned change
//!   that fails the door's own pure parse falls back to the prior value, and
//!   a rewrite the row's check still refuses is ignored, never a hook failure
//!   that sends the revoke to an ask;
//! - every door's final decode settles the args the chain left ([`settle`]):
//!   args that do not decode as the door's typed input give way to the
//!   caller's own;
//! - the post boundary tells the owner, in one inbox notice per call, what a
//!   hook changed or what was ignored ([`notify`]).
//!
//! Real refusals of the caller's own input stay: authority, legal holds,
//! shared-act windows and vetoes, a stale confirmed preview, storage errors.
//! A hook may still annotate, explicitly Skip or explicitly Ask.
//!
//! Three rows are restrictive only by what they carry, judged on the
//! caller's own args with the vault's help ([`payload`], FIX 5137-5139):
//! `vault.batch`'s grant withdrawals, `vault.packs.connector.accept`'s
//! revoking dispositions and `vault.shared.execute`'s delete, erase and
//! remove-owner acts. Only those parts are pinned; the rest of such a call
//! stays the hooks' to change.

mod payload;

use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::runtime_hooks::{InvocationId, VerbHookPre};
use crate::{EntityId, Vault};

/// Whether a hook's valid change to a restrictive call's pinned field is
/// ignored. `false` (today's behaviour): it applies, and the owner's notice
/// names it. `true`: the caller's value stays, and the notice says the change
/// was ignored. Either way a change that fails the door's own parse, or a
/// rewrite that fails the row's check or the door's typed decode, falls back
/// to the caller's input (Engine 10-19 12:2x; the owner is being asked).
pub const RESTRICTIVE_TARGETS_PINNED: bool = false;

/// The producer of a restrictive call's owner notice.
const REVOKE_LANDS_PRODUCER: &str = "revoke_lands";
/// The longest notice detail, in bytes.
const NOTICE_DETAIL_MAX: usize = 2_048;
/// The longest value a notice shows, in bytes.
const NOTICE_VALUE_MAX: usize = 96;

/// One field a restrictive row acts on: its path in the args, and the door's
/// own pure parse of its value ([`typed`] when serde's decode is the parse).
struct Pin {
    path: &'static [&'static str],
    parse: fn(&Value) -> bool,
}

/// When a row's call is restrictive, judged on the caller's own args.
enum When {
    Always,
    /// When the value at the path passes the test: a conditional withdrawal.
    Holds(&'static [&'static str], fn(&Value) -> bool),
}

/// One restrictive row: its verb, when a call of it is restrictive, its
/// pinned fields, and the door's own pure check over several of them.
pub(crate) struct Row {
    verb: &'static str,
    when: When,
    pins: &'static [Pin],
    check: Option<fn(&Value) -> bool>,
}

const fn pin(path: &'static [&'static str], parse: fn(&Value) -> bool) -> Pin {
    Pin { path, parse }
}

/// A row restrictive on every call, with no check of its own, as a struct
/// literal: its pins live as long as the table.
macro_rules! always {
    ($verb:literal, [$($pin:expr),+ $(,)?] $(,)?) => {
        Row {
            verb: $verb,
            when: When::Always,
            pins: &[$($pin),+],
            check: None,
        }
    };
}

/// The restrictive rows (sweep rows D01-D39; the owner HTTP doors H1-H4 share
/// D01, D02, D11 and D35's verbs). `vault.batch`, `vault.packs.connector.accept`
/// and `vault.shared.execute` are polymorphic: [`payload`] judges them.
const ROWS: &[Row] = &[
    always!("vault.guests.revoke", [pin(&["grant_ref"], typed)]),
    always!("vault.support_grants.revoke", [pin(&["grant_ref"], hex32)]),
    always!("vault.agents.grants.revoke", [pin(&["grant_ref"], entity)]),
    always!("vault.repo.git_push.revoke", [pin(&["grant_ref"], entity)]),
    always!(
        "vault.federation.connect.disconnect",
        [pin(&["pact"], hex32)]
    ),
    always!("vault.shares.revoke", [pin(&["share_ref"], entity)]),
    always!("vault.consent.revoke", [pin(&["grant"], hex32)]),
    always!(
        "vault.trusted_contacts.revoke",
        [pin(&["person_ref"], entity), pin(&["contact_ref"], entity)],
    ),
    always!(
        "vault.connectors.proxy.revoke_write",
        [
            pin(&["actor"], entity),
            pin(&["key"], entity),
            pin(&["revision"], typed),
        ],
    ),
    always!(
        "vault.connectors.subscriptions.revoke",
        [pin(&["subscription"], entity_trimmed)],
    ),
    always!("vault.mesh.revoke_machine", [pin(&["machine"], typed)]),
    Row {
        verb: "vault.mesh.set_alpn_grant",
        when: When::Holds(&["allow"], denies),
        pins: &[
            pin(&["machine"], typed),
            pin(&["endpoint_key"], typed),
            pin(&["alpn"], typed),
            pin(&["allow"], typed),
        ],
        check: None,
    },
    always!(
        "vault.legal_holds.lift_and_erase",
        [pin(&["records"], records)],
    ),
    always!(
        "vault.records.erase_confirm",
        [
            pin(&["record"], typed),
            pin(&["preview_digest"], digest),
            pin(&["also_same_bytes"], typed),
        ],
    ),
    always!(
        "vault.delete",
        [pin(&["entity_ref"], entity_ref), pin(&["reason"], typed)],
    ),
    always!(
        "vault.forget",
        [
            pin(&["claim_ref"], entity_ref),
            pin(&["subject_ref"], entity_ref),
            pin(&["predicate"], text),
        ],
    ),
    always!("vault.claims.retract", [pin(&["claim_ref"], entity_ref)]),
    always!(
        "vault.notes.history_purge",
        [pin(&["note_ref"], entity_ref)]
    ),
    always!(
        "vault.notes.history_purge_execute",
        [pin(&["act_id"], typed)],
    ),
    // A hook's reason code or review date that breaks the answer's shape
    // (one on a delete choice, or a bad one on any other) is ignored, not a
    // refusal of the delete (FIX 5140).
    Row {
        verb: "vault.courtesy_delete.answer",
        when: When::Always,
        pins: &[
            pin(&["pact"], hex32),
            pin(&["request"], hex16),
            pin(&["choice"], typed),
            pin(&["delete"], entities),
            pin(&["hold"], entities),
            pin(&["reason_code"], typed),
            pin(&["review_at"], typed),
        ],
        check: Some(courtesy_answer_shape),
    },
    always!(
        "vault.skill_hubs.publishers.revoke",
        [pin(&["hub"], typed), pin(&["identity"], typed)],
    ),
    always!("vault.packs.remove", [pin(&["pack"], typed)]),
    Row {
        verb: "vault.packs.sections.revoke",
        when: When::Always,
        pins: &[
            pin(&["claim_ref"], entity_trimmed),
            pin(&["section_id"], typed),
        ],
        check: Some(names_a_section),
    },
    always!(
        "vault.members.remove",
        [pin(&["vault_id"], typed), pin(&["member"], entity)],
    ),
    always!("vault.members.leave", [pin(&["vault_id"], typed)]),
    always!(
        "vault.members.withdraw_invitation",
        [
            pin(&["vault_id"], typed),
            pin(&["member"], entity),
            pin(&["invitation"], typed),
        ],
    ),
    always!(
        "vault.artifacts.live_preview.revoke_invite",
        [
            pin(&["session_ref"], typed),
            pin(&["lease_ref"], typed),
            pin(&["principal_ref"], typed),
        ],
    ),
    always!(
        "vault.artifacts.live_preview.revoke_share",
        [pin(&["session_ref"], typed), pin(&["lease_ref"], typed)],
    ),
    always!(
        "self.secrets.teardown",
        [pin(&["live_run"], typed), pin(&["spec", "grant"], entity)],
    ),
    Row {
        verb: "vault.voices.render_consent",
        when: When::Holds(&["state"], withdrawn),
        pins: &[pin(&["voice_id"], typed), pin(&["state"], typed)],
        check: None,
    },
    always!(
        "vault.voices.targets.evict",
        [pin(&["voice_id"], typed), pin(&["target"], typed)],
    ),
    always!("vault.consent.graduation.demote", [pin(&["scope"], typed)]),
    always!("self.consent.graduation.demote", [pin(&["scope"], typed)]),
    always!(
        "self.focus.unsubscribe",
        [
            pin(&["scopes"], typed),
            pin(&["live_run"], typed),
            pin(&["spec", "scopes"], typed),
        ],
    ),
    Row {
        verb: "vault.kv.delete",
        when: When::Always,
        pins: &[pin(&["namespace"], typed), pin(&["key"], typed)],
        check: Some(kv_address),
    },
    always!(
        "vault.campaign.unsubscribe",
        [
            pin(&["campaign_ref"], entity),
            pin(&["person_ref"], entity),
            pin(&["channel"], typed),
            pin(&["evidence_ref"], entity),
        ],
    ),
    always!(
        "vault.embedding_spaces.probes.delete",
        [pin(&["id"], hex16)],
    ),
    always!(
        "vault.channel_identities.release",
        [pin(&["identity_ref"], typed)],
    ),
    always!("vault.code.symbols.release", [pin(&["task"], typed)]),
    always!(
        "vault.artifacts.unpublish",
        [pin(&["artifact"], typed), pin(&["channel"], typed)],
    ),
    always!(
        "calendar.connector.kill",
        [pin(&["seat_ref"], seat_ref), pin(&["reason_ref"], seat_ref)],
    ),
];

/// No parse past serde's own decode of the row's typed input, which the
/// rewrite check and the door's final decode run.
fn typed(_: &Value) -> bool {
    true
}

/// A 32-hex entity id, as `EntityId::from_hex` takes it.
fn entity(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| EntityId::from_hex(text).is_ok())
}

/// A 32-hex entity id with surrounding space trimmed, as the subscription
/// and plugin-section doors take it.
fn entity_trimmed(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| EntityId::from_hex(text.trim()).is_ok())
}

/// An entity ref as `resolve_entity_ref` reads it: a 32-hex id or a short
/// ref, space trimmed.
fn entity_ref(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        let text = text.trim();
        if text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            EntityId::from_hex(text).is_ok()
        } else {
            crate::entity_id::parse_short_ref_syntax(text).is_ok()
        }
    })
}

/// `digits` hex digits.
fn hex_digits(value: &Value, digits: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == digits && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// 32 bytes of hex: a pact, a grant digest, a support grant id.
fn hex32(value: &Value) -> bool {
    hex_digits(value, 64)
}

/// 16 bytes of hex: a probe id, a courtesy ask's nonce.
fn hex16(value: &Value) -> bool {
    hex_digits(value, 32)
}

/// A preview digest as the erase preview answers it: lowercase BLAKE3 hex.
fn digest(value: &Value) -> bool {
    hex32(value)
        && value
            .as_str()
            .is_some_and(|text| !text.bytes().any(|byte| byte.is_ascii_uppercase()))
}

/// A non-empty record set.
fn records(value: &Value) -> bool {
    value.as_array().is_some_and(|items| !items.is_empty())
}

/// A list of 32-hex entity ids.
fn entities(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(entity))
}

/// Non-empty text.
fn text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

/// A calendar seat or kill-reason ref, as the seat checks it.
fn seat_ref(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(crate::calendar::connectors::seat_ref_parses)
}

/// `allow: false`: the revoke side of an ALPN grant.
fn denies(value: &Value) -> bool {
    value == &Value::Bool(false)
}

/// A withdrawn voice consent.
fn withdrawn(value: &Value) -> bool {
    value.as_str() == Some("withdrawn")
}

/// A plugin-section revoke names a claim or a section.
fn names_a_section(args: &Value) -> bool {
    ["claim_ref", "section_id"]
        .iter()
        .any(|field| args.get(field).is_some_and(|value| !value.is_null()))
}

/// A courtesy answer's shape, as the engine checks it before its delete loop
/// (`Vault::answer_cooperative_deletion_as`): a delete choice carries no
/// reason code or review date; any other carries a short snake_case reason
/// code and a review date, and deletes nothing.
fn courtesy_answer_shape(args: &Value) -> bool {
    let present = |field: &str| args.get(field).is_some_and(|value| !value.is_null());
    if args.get("choice").and_then(Value::as_str) == Some("delete") {
        return !present("reason_code") && !present("review_at");
    }
    let code = args.get("reason_code").and_then(Value::as_str);
    code.is_some_and(|code| {
        !code.is_empty()
            && code.len() <= crate::deletion::MAX_REASON_CODE_LEN
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }) && present("review_at")
        && args
            .get("delete")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
}

/// A KV address the KV doors take.
fn kv_address(args: &Value) -> bool {
    <crate::memory::KeyValueAddress as serde::Deserialize>::deserialize(args)
        .is_ok_and(|address| crate::memory::key_value_address_parses(&address))
}

/// The restrictive row a call of `verb` on the caller's own `args` is, with
/// its pinned fields; `None` for any other call.
pub(crate) fn restrictive(verb: &str, args: &Value) -> Option<&'static Row> {
    let row = ROWS.iter().find(|row| row.verb == verb)?;
    match row.when {
        When::Always => Some(row),
        When::Holds(path, test) => lookup(args, path).is_some_and(test).then_some(row),
    }
}

/// Whether a call of `verb` on the caller's own `args` is wholly an owner's
/// restriction-only act, an erase or a revoke and nothing else: the one
/// classification a transport asks before it admits the call, so its
/// ingress, owner proof, hooks and door read the restriction-only clock as
/// this boundary's run does (FIX 11201). A table row the call meets is one,
/// but a courtesy answer only when it deletes; a polymorphic call only when
/// every part it writes withdraws or erases ([`payload::wholly_restrictive`]).
/// A call that also grants, sets or keeps anything is not, whatever the hooks
/// pin of it.
///
/// # Errors
/// A read the classification needs (the kind of a pending shared act)
/// failing: no answer is guessed from it.
pub fn restriction_only_call(vault: &Vault, verb: &str, args: &Value) -> crate::Result<bool> {
    if verb == "vault.courtesy_delete.answer" {
        return Ok(args.get("choice").and_then(Value::as_str) == Some("delete"));
    }
    if restrictive(verb, args).is_some() {
        return Ok(true);
    }
    payload::wholly_restrictive(vault, verb, args)
}

/// A restrictive call's landing: its verb, its pinned fields and its row's
/// own check, the caller's own args, and what the owner's notice says about
/// the hooks' changes.
pub(crate) struct Landing {
    verb: &'static str,
    pins: Vec<Pinned>,
    check: Option<fn(&Value) -> bool>,
    /// The grant withdrawals of a `vault.batch` call, as the caller sent
    /// them ([`payload`]); empty for every other call.
    puts: Vec<Value>,
    original: Value,
    notes: Vec<String>,
}

/// One field a restrictive call pins: its path in the args, and the door's
/// own pure parse of its value.
struct Pinned {
    path: Vec<String>,
    parse: fn(&Value) -> bool,
}

impl fmt::Debug for Landing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Landing")
            .field("verb", &self.verb)
            .field("notes", &self.notes)
            .finish_non_exhaustive()
    }
}

impl Landing {
    /// The landing of a call of `verb` on the caller's own `args`: `Some`
    /// only for a restrictive call, a polymorphic row's judged on what it
    /// carries ([`payload`]).
    pub(crate) fn of(vault: &Vault, verb: &str, args: &Value) -> Option<Self> {
        let (verb, pins, check, puts) = match restrictive(verb, args) {
            Some(row) => (
                row.verb,
                row.pins
                    .iter()
                    .map(|pin| Pinned {
                        path: pin.path.iter().map(|key| (*key).to_owned()).collect(),
                        parse: pin.parse,
                    })
                    .collect(),
                row.check,
                Vec::new(),
            ),
            None => payload::restrictive(vault, verb, args)?,
        };
        Some(Self {
            verb,
            pins,
            check,
            puts,
            original: args.clone(),
            notes: Vec::new(),
        })
    }

    /// The args a hook's rewrite `next` leaves after `prior`: a changed
    /// pinned field that fails the door's parse, or any one while
    /// [`RESTRICTIVE_TARGETS_PINNED`], back at its prior value, the rest as
    /// the hook wrote it. When `check` refuses that, the prior args, and the
    /// refusal for the hook's run record.
    pub(crate) fn select(
        &mut self,
        prior: &Value,
        next: Value,
        check: &dyn Fn(&Value) -> Result<(), String>,
    ) -> (Value, Option<String>) {
        let mut chosen = next;
        let notes = self.pin(prior, &mut chosen, true);
        match check(&chosen) {
            Ok(()) => {
                self.notes.extend(notes);
                (chosen, None)
            }
            Err(reason) => {
                let reason = format!("the rewritten args are refused: {reason}");
                self.notes.push(format!(
                    "a hook's rewrite was ignored ({reason}), so the revoke kept the input it had"
                ));
                (prior.clone(), Some(reason))
            }
        }
    }

    /// Puts each pinned field of `candidate` that changed from `base` back
    /// when its new value fails the door's parse, or while
    /// [`RESTRICTIVE_TARGETS_PINNED`]; every one of them when the row's own
    /// check then fails. The notes say what changed; `applied` adds one for a
    /// change that stands.
    fn pin(&self, base: &Value, candidate: &mut Value, applied: bool) -> Vec<String> {
        let mut notes = Vec::new();
        for pin in &self.pins {
            let before = lookup(base, &pin.path);
            let after = lookup(candidate, &pin.path).cloned();
            if before == after.as_ref() {
                continue;
            }
            let change = format!(
                "{} {} → {}",
                pin.path.join("."),
                shown(before),
                shown(after.as_ref())
            );
            if !after.as_ref().is_some_and(pin.parse) {
                restore(candidate, &pin.path, before.cloned());
                notes.push(format!(
                    "a hook changed what this revoke acts on: {change}; it fails the door's check and was ignored"
                ));
            } else if RESTRICTIVE_TARGETS_PINNED {
                restore(candidate, &pin.path, before.cloned());
                notes.push(format!(
                    "a hook changed what this revoke acts on: {change}; the change was ignored"
                ));
            } else if applied {
                notes.push(format!("a hook changed what this revoke acts on: {change}"));
            }
        }
        let pinned_differs = self
            .pins
            .iter()
            .any(|pin| lookup(base, &pin.path) != lookup(candidate, &pin.path));
        if pinned_differs
            && let Some(check) = self.check
            && !check(candidate)
        {
            for pin in &self.pins {
                restore(candidate, &pin.path, lookup(base, &pin.path).cloned());
            }
            notes.clear();
            notes.push(
                "a hook's change to what this revoke acts on fails the door's check and was ignored"
                    .to_owned(),
            );
        }
        if !self.puts.is_empty() {
            match payload::keep_puts(&self.puts, candidate, applied) {
                Some(kept) => notes.extend(kept),
                None => {
                    *candidate = base.clone();
                    notes.push(
                        "a hook's change to this batch's grant withdrawals could not be put back, so the batch kept the input it had"
                            .to_owned(),
                    );
                }
            }
        }
        notes
    }

    /// The caller's own target, as the notice shows it: its first pinned
    /// field the args hold.
    fn target(&self) -> Option<String> {
        self.pins
            .iter()
            .find_map(|pin| lookup(&self.original, &pin.path))
            .or_else(|| self.puts.first().and_then(|put| put.get("id")))
            .map(|value| shown(Some(value)))
    }
}

/// The final pass over a restrictive call's args before its door decodes
/// them (FIX 5076): its pinned fields pinned once more against the caller's
/// own, then, when the args a hook changed still fail `decodes` (the door's
/// typed input), the caller's own args, with a note. The args of any other
/// call stay as the chain left them. Cheap, and the same on every pass.
pub fn settle(pre: &mut VerbHookPre, decodes: &dyn Fn(&Value) -> bool) {
    let Some(landing) = pre.landing.as_mut() else {
        return;
    };
    let original = landing.original.clone();
    let notes = landing.pin(&original, &mut pre.args, false);
    landing.notes.extend(notes);
    if pre.args != original && !decodes(&pre.args) {
        pre.args = original;
        landing.notes.push(format!(
            "the args the hooks left do not decode as {}'s input, so it ran on the caller's own input",
            landing.verb
        ));
    }
}

/// Whether `value` decodes as `T`: a door's typed input, for [`settle`].
#[must_use]
pub fn decodes<T: DeserializeOwned>(value: &Value) -> bool {
    <T as serde::Deserialize>::deserialize(value).is_ok()
}

/// Tells the vault's owners, in their inbox, what hooks changed or what was
/// ignored on a restrictive call that ran (FIX 5076): one Finding per owner
/// per logical call, keyed by its invocation, naming the verb, the
/// invocation and the caller's target. A call that keeps no record names no
/// invocation in the vault (FIX 5382): its notice is keyed by the hidden id
/// that stands for it in this process, and its text leaves the invocation
/// out. A notice that does not record is logged; the committed revoke
/// stands.
pub fn notify(vault: &Vault, pre: &VerbHookPre) {
    let Some(landing) = pre
        .landing
        .as_ref()
        .filter(|landing| !landing.notes.is_empty())
    else {
        return;
    };
    if let Err(error) = record_notice(vault, pre, landing) {
        tracing::warn!(
            verb = %pre.call().verb,
            %error,
            "a restrictive call's owner notice of a hook's change did not record"
        );
    }
}

fn record_notice(vault: &Vault, pre: &VerbHookPre, landing: &Landing) -> crate::Result<()> {
    let call = pre.call();
    let (invocation, detail) = match pre.session() {
        Some(key) => (
            InvocationId(
                vault
                    .verb_hook_state
                    .session
                    .hidden_invocation(key, call.invocation.0),
            )
            .to_hex(),
            format!("{}: {}", call.verb, landing.notes.join("; ")),
        ),
        None => {
            let invocation = call.invocation.to_hex();
            let detail = format!(
                "{} (invocation {invocation}): {}",
                call.verb,
                landing.notes.join("; ")
            );
            (invocation, detail)
        }
    };
    let detail = clip(&detail, NOTICE_DETAIL_MAX);
    let target = landing.target();
    vault.with_write_txn(|txn| {
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        for owner in crate::policy_model::owners_in_txn(vault, txn)? {
            vault.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Finding,
                    source: NotificationSource {
                        producer: REVOKE_LANDS_PRODUCER.to_owned(),
                        event: format!("{invocation}:{}", owner.to_hex()),
                        result: target.clone(),
                        detail: Some(detail.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    })
}

/// The value at `path` in `args`.
fn lookup<'v, S: AsRef<str>>(args: &'v Value, path: &[S]) -> Option<&'v Value> {
    path.iter()
        .try_fold(args, |node, key| node.get(key.as_ref()))
}

/// Puts `old` at `path` in `args`, or takes the field away when `old` is
/// `None`.
fn restore<S: AsRef<str>>(args: &mut Value, path: &[S], old: Option<Value>) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut node = args;
    for key in parents {
        let key = key.as_ref();
        let Some(map) = node.as_object_mut() else {
            return;
        };
        if old.is_none() && !map.contains_key(key) {
            return;
        }
        node = map
            .entry(key.to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    let Some(map) = node.as_object_mut() else {
        return;
    };
    match old {
        Some(old) => {
            map.insert(last.as_ref().to_owned(), old);
        }
        None => {
            map.remove(last.as_ref());
        }
    }
}

/// A value as a notice shows it: compact JSON, bounded, or `(none)`.
fn shown(value: Option<&Value>) -> String {
    value.map_or_else(
        || "(none)".to_owned(),
        |value| clip(&value.to_string(), NOTICE_VALUE_MAX),
    )
}

/// `text` cut to at most `max` bytes on a character boundary, with `…` when
/// cut.
fn clip(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}
