//! A program's secret slots (FIX 8028, OF-560; ARCH-0069 secret custody):
//! a program never holds a secret, nor the handle a run found it as.
//!
//! A proposal's type, routine step or check that names a secret (its
//! `secret`), or that types or checks plain text where its target read as a
//! secret field, takes a typed slot instead (`secret_slot_policy`, CALLS
//! row): a lone `{{name}}` slot is marked secret, and any other text (a
//! handle, a literal) becomes a new slot named for its kind, its value
//! going into the run's arguments. The program keeps `secret: "{{name}}"`
//! and the slot's name and kind ([`SecretParam`]); its proof keeps no
//! secret slot's value, and no handle its replay's receipts show.
//!
//! A run fills a secret slot from its arguments (`secret_slot_arg_policy`,
//! CALLS row): a handle (`scN`, or as a row shows it) is typed or checked
//! by handle, the host lending its bytes at the send; any other value is
//! the slot's own text, typed as text or checked as a value, so a run given
//! a password itself still runs. A fresh replay is the same run: it may
//! name the solved run's handle again, or another its own reads took.
//!
//! A one-time code is spent once (`otp_replay_policy`, CALLS row): a
//! replay that missed while a one-time-code slot gave the solved run's own
//! code is refused [`WorkflowCheck::SecretReplay`], naming those slots,
//! never counted as a pass.

use super::WorkflowProgram;
#[cfg(feature = "driver")]
use super::{AdmissionRefusal, fill_slots};
use crate::{BatchStep, ExpectInput, SecretKind};
#[cfg(feature = "driver")]
use crate::{
    BrowserDriver, BrowserError, EffectReceipt, FindInput, OperandGap, ReplayAction, Row,
    TypeOperand, WorkflowCheck,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "driver")]
use serde_json::Value;
use std::collections::BTreeMap;

/// One of a program's parameters that takes a secret: its name, among the
/// program's `params`, and the kind of secret it takes. A run's argument
/// for it names a handle the run holds (or is the secret's own text); the
/// program and its proof hold neither.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretParam {
    pub name: String,
    pub kind: SecretKind,
}

/// Whether `text` names a run-bound handle, bare (`sc12`, `sc12:ab`) or as
/// a row shows it (`[secret sc12]`, a card's `…1234 [secret sc12]`).
pub(crate) fn handle_form(text: &str) -> bool {
    let text = text.trim();
    let bare = match text.split_once("[secret ") {
        Some((_, rest)) => match rest.strip_suffix(']') {
            Some(handle) => handle.trim(),
            None => return false,
        },
        None => text,
    };
    let short = match bare.split_once(':') {
        Some((short, hash)) if hash.len() == 2 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            short
        }
        Some(_) => return false,
        None => bare,
    };
    short
        .strip_prefix("sc")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `program`'s secret slots are distinct parameters of its own.
pub(super) fn distinct(program: &WorkflowProgram) -> bool {
    let secret = &program.secret_params;
    (0..secret.len()).all(|at| {
        program.params.contains(&secret[at].name)
            && !secret[..at].iter().any(|slot| slot.name == secret[at].name)
    })
}

/// A filled step's or check's secret arms, as a run takes them: a handle
/// stays the secret it names; any other text is the slot's own, typed as
/// text or checked as a value (`secret_slot_arg_policy`).
pub(super) fn bind(steps: &mut [BatchStep], checks: &mut [ExpectInput]) {
    for step in steps {
        match step {
            BatchStep::Type { text, secret, .. } => as_plain(secret, text),
            BatchStep::Expect { value, secret, .. } => as_plain(secret, value),
            BatchStep::Decide(step) => as_plain(&mut step.secret, &mut step.text),
            _ => {}
        }
    }
    for check in checks {
        as_plain(&mut check.secret, &mut check.value);
    }
}

/// Moves a secret arm that names no handle to its plain arm, when that is
/// empty; one naming both stays as it is, for the step to refuse.
fn as_plain(secret: &mut Option<String>, plain: &mut Option<String>) {
    if plain.is_none() && secret.as_deref().is_some_and(|named| !handle_form(named)) {
        *plain = secret.take();
    }
}

/// The kind of secret each step's and check's target held as the proposing
/// session last read it, read before its handles go back to locators.
#[cfg(feature = "driver")]
pub(super) struct Targets {
    steps: Vec<Option<SecretKind>>,
    checks: Vec<Option<SecretKind>>,
}

#[cfg(feature = "driver")]
impl Targets {
    pub(super) fn read<D: BrowserDriver + ?Sized>(
        driver: &D,
        steps: &[BatchStep],
        checks: &[ExpectInput],
    ) -> Self {
        // The handle's record, else what the session's receipts kept of the
        // act that typed there (FIX 8344): a record gone, or a row the
        // solved page no longer shows, still slots the secret it took.
        let kind = |target: &String| -> Option<SecretKind> {
            let held = driver.handle_info(target).and_then(|info| info.secret);
            held.or_else(|| operand_kind(&driver.typed_operand(target)?))
        };
        Self {
            steps: steps
                .iter()
                .map(|step| step.targets().into_iter().find_map(kind))
                .collect(),
            checks: checks
                .iter()
                .map(|check| check.target.as_ref().and_then(kind))
                .collect(),
        }
    }

    /// Puts `program`'s secrets in slots (`secret_slot_policy`): each
    /// step's and check's, its target's kind read on the session, else on
    /// the solved page's `rows`. A new slot's values go into `args`, and
    /// into `replay_args` where those are given.
    pub(super) fn slot<D: BrowserDriver + ?Sized>(
        self,
        driver: &D,
        rows: &[Row],
        program: &mut WorkflowProgram,
        args: &mut BTreeMap<String, String>,
        replay_args: &mut BTreeMap<String, String>,
    ) -> Result<(), BrowserError> {
        let mut slots = Slots {
            driver,
            params: &mut program.params,
            secret: &mut program.secret_params,
            args,
            replay_args,
        };
        for (step, held) in program.steps.iter_mut().zip(self.steps) {
            let target = held.or_else(|| shown_kind(driver, rows, step));
            match step {
                BatchStep::Type { text, secret, .. } => slots.arm(secret, text, target)?,
                BatchStep::Expect { value, secret, .. } => slots.arm(secret, value, target)?,
                BatchStep::Decide(step) => slots.arm(&mut step.secret, &mut step.text, target)?,
                // A Fill takes a secret slot as a type does (FIX 8900).
                BatchStep::Fill { field, .. } => {
                    slots.arm(&mut field.secret, &mut field.supplied, target)?;
                }
                _ => {}
            }
            stable_names(step);
        }
        for (check, held) in program.postcondition.iter_mut().zip(self.checks) {
            let target = held
                .or_else(|| checked_kind(rows, check.target.as_ref(), &check.role, &check.name));
            slots.arm(&mut check.secret, &mut check.value, target)?;
            stable_name(&mut check.name);
        }
        Ok(())
    }
}

/// A proposal's parameters and values, as its secrets take slots.
#[cfg(feature = "driver")]
struct Slots<'a, D: ?Sized> {
    driver: &'a D,
    params: &'a mut Vec<String>,
    secret: &'a mut Vec<SecretParam>,
    args: &'a mut BTreeMap<String, String>,
    replay_args: &'a mut BTreeMap<String, String>,
}

#[cfg(feature = "driver")]
impl<D: BrowserDriver + ?Sized> Slots<'_, D> {
    /// One step's or check's entry: its `secret`, or its plain text (a
    /// type's `text`, a check's `value`) where `target` read as a secret,
    /// becomes `secret: "{{slot}}"`. The slot's kind is the one the
    /// session's read gave the handle it names, else its target's, else a
    /// password's.
    fn arm(
        &mut self,
        secret: &mut Option<String>,
        plain: &mut Option<String>,
        target: Option<SecretKind>,
    ) -> Result<(), BrowserError> {
        let (named, from_plain) = match (secret.take(), plain.take()) {
            (Some(named), None) => (named, false),
            (None, Some(text)) if target.is_some() && !text.is_empty() => (text, true),
            (named, text) => {
                *secret = named;
                *plain = text;
                return Ok(());
            }
        };
        let driver = self.driver;
        let held = |value: Option<&String>| {
            value
                .filter(|_| !from_plain)
                .and_then(|value| driver.secret_kind(value))
        };
        let lone = lone_slot(&named).filter(|name| self.params.iter().any(|param| param == name));
        let slot = match lone {
            Some(name) => {
                let kind = held(self.args.get(name))
                    .or(target)
                    .unwrap_or(SecretKind::Password);
                self.mark(name, kind);
                name.to_owned()
            }
            None => {
                let solved = filled(&named, self.args)?;
                // Values that fill nothing are the held-out check's to name.
                let replay = (!self.replay_args.is_empty())
                    .then(|| filled(&named, self.replay_args).unwrap_or_else(|_| solved.clone()));
                let kind = held(Some(&solved))
                    .or(target)
                    .unwrap_or(SecretKind::Password);
                self.mint(kind, solved, replay)
            }
        };
        *secret = Some(format!("{{{{{slot}}}}}"));
        Ok(())
    }

    /// The slot a secret of `kind` with these values takes, in the book.
    fn mint(&mut self, kind: SecretKind, solved: String, replay: Option<String>) -> String {
        self.book().mint(kind, solved, replay)
    }

    /// Marks parameter `name` as taking a secret of `kind`, once.
    fn mark(&mut self, name: &str, kind: SecretKind) {
        self.book().mark(name, kind);
    }

    /// The proposal's parameters and values, as the book that slots them.
    fn book(&mut self) -> SlotBook<'_> {
        SlotBook {
            params: &mut *self.params,
            secret: &mut *self.secret,
            args: &mut *self.args,
            replay_args: &mut *self.replay_args,
        }
    }
}

/// A proposal's parameters and values as its secrets take slots: the one
/// book admission's slots and a draft's (CUA E7) are written in.
pub(super) struct SlotBook<'a> {
    pub(super) params: &'a mut Vec<String>,
    pub(super) secret: &'a mut Vec<SecretParam>,
    pub(super) args: &'a mut BTreeMap<String, String>,
    pub(super) replay_args: &'a mut BTreeMap<String, String>,
}

impl SlotBook<'_> {
    /// The slot a secret of `kind` with these values takes: the secret slot
    /// that holds them already, else a new one named for its kind.
    pub(super) fn mint(
        &mut self,
        kind: SecretKind,
        solved: String,
        replay: Option<String>,
    ) -> String {
        let taken = self.secret.iter().find(|slot| {
            slot.kind == kind
                && self.args.get(&slot.name) == Some(&solved)
                && replay
                    .as_ref()
                    .is_none_or(|replay| self.replay_args.get(&slot.name) == Some(replay))
        });
        if let Some(slot) = taken {
            return slot.name.clone();
        }
        let name = self.unbound(kind);
        self.args.insert(name.clone(), solved);
        if let Some(replay) = replay {
            self.replay_args.insert(name.clone(), replay);
        }
        name
    }

    /// A new secret slot of `kind`, named for its kind, that no value binds
    /// yet: a parameter marked secret, with no arg (CUA E9a: a secret a
    /// page withheld, for the caller to bind).
    pub(super) fn unbound(&mut self, kind: SecretKind) -> String {
        let word = slot_word(kind);
        let (mut name, mut nth) = (word.to_owned(), 1_u32);
        while self.params.contains(&name) {
            nth += 1;
            name = format!("{word}_{nth}");
        }
        self.params.push(name.clone());
        self.mark(&name, kind);
        name
    }

    /// Marks parameter `name` as taking a secret of `kind`, once.
    pub(super) fn mark(&mut self, name: &str, kind: SecretKind) {
        if !self.secret.iter().any(|slot| slot.name == name) {
            self.secret.push(SecretParam {
                name: name.to_owned(),
                kind,
            });
        }
    }
}

/// The name a new slot of `kind` starts from.
const fn slot_word(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Card => "card",
        SecretKind::Cvv => "cvv",
        SecretKind::Otp => "otp",
        SecretKind::Password => "password",
    }
}

/// The name `text` is when it is one slot alone, `{{name}}`.
#[cfg(feature = "driver")]
fn lone_slot(text: &str) -> Option<&str> {
    let inner = text.strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.contains("{{") && !inner.contains("}}")).then(|| inner.trim())
}

/// `text` with its slots filled from `args`.
#[cfg(feature = "driver")]
fn filled(text: &str, args: &BTreeMap<String, String>) -> Result<String, BrowserError> {
    let mut value = Value::String(text.to_owned());
    fill_slots(&mut value, args)?;
    Ok(value.as_str().unwrap_or_default().to_owned())
}

/// The row of `rows` that `target` names, by its locator or its handle.
#[cfg(feature = "driver")]
fn named<'r>(rows: &'r [Row], target: &str) -> Option<&'r Row> {
    rows.iter()
        .find(|row| row.locator == target || row.target == target)
}

/// The kind of secret a row shows, when it shows one.
#[cfg(feature = "driver")]
fn row_kind(row: &Row) -> Option<SecretKind> {
    row.secret.as_ref().map(|secret| secret.kind)
}

/// The kind of secret an act's kept operand is: its handle's or its
/// withheld secret's; none for text the classifier called none.
#[cfg(feature = "driver")]
fn operand_kind(operand: &TypeOperand) -> Option<SecretKind> {
    match operand {
        TypeOperand::Secret { kind, .. } => Some(*kind),
        TypeOperand::Withheld { kind, .. } => *kind,
        TypeOperand::Literal { .. } => None,
    }
}

/// The run-local handle a row's name shows, cut from a match text a
/// program keeps (FIX 8343): the text up to its first `[secret ` display,
/// that display's opening kept, so it still names a secret's row as each
/// run shows it (a name matches as a substring), with no handle that
/// dies with this run.
#[cfg(feature = "driver")]
fn stable_name(name: &mut Option<String>) {
    let Some(text) = name.as_mut() else {
        return;
    };
    let mut from = 0;
    while let Some(at) = text[from..].find(SECRET_DISPLAY).map(|at| at + from) {
        let open = at + SECRET_DISPLAY.len();
        let shown = text[open..]
            .find(']')
            .map(|close| &text[at..=open + close])
            .filter(|shown| handle_form(shown));
        if shown.is_some() {
            text.truncate(open);
            return;
        }
        from = open;
    }
}

/// How a row shows a secret's handle: `[secret sc12]`.
#[cfg(feature = "driver")]
const SECRET_DISPLAY: &str = "[secret ";

/// A step's role/name match texts, as [`stable_name`] keeps them.
#[cfg(feature = "driver")]
fn stable_names(step: &mut BatchStep) {
    match step {
        BatchStep::WaitFor { name, .. } | BatchStep::Expect { name, .. } => stable_name(name),
        BatchStep::Decide(step) => stable_name(&mut step.name),
        _ => {}
    }
}

/// The kind of secret the solved page shows where `step` acts: its type's
/// target, its check's row, or its routine step's candidates. A routine
/// step's text that the session's receipts show was typed as text into
/// one of its candidates is no secret, whatever another candidate holds
/// (FIX 8345).
#[cfg(feature = "driver")]
fn shown_kind<D: BrowserDriver + ?Sized>(
    driver: &D,
    rows: &[Row],
    step: &BatchStep,
) -> Option<SecretKind> {
    match step {
        BatchStep::Type { target, .. } => named(rows, target).and_then(row_kind),
        BatchStep::Expect {
            target, role, name, ..
        } => checked_kind(rows, target.as_ref(), role, name),
        BatchStep::Decide(step) => {
            let query = FindInput {
                role: step.role.clone(),
                name: step.name.clone(),
                cursor: None,
            };
            let candidates: Vec<&Row> = rows
                .iter()
                .filter(|row| {
                    if step.targets.is_empty() {
                        query.matches(row)
                    } else {
                        step.targets
                            .iter()
                            .any(|target| *target == row.locator || *target == row.target)
                    }
                })
                .collect();
            let typed_as_text = step.text.as_ref().is_some_and(|text| {
                candidates.iter().any(|row| {
                    matches!(
                        driver.typed_operand(&row.locator),
                        Some(TypeOperand::Literal { text: typed }) if typed == *text
                    )
                })
            });
            if typed_as_text {
                return None;
            }
            candidates.into_iter().find_map(row_kind)
        }
        _ => None,
    }
}

/// The kind of secret the row a check reads shows on the solved page: the
/// row `target` names, else the first `role` and `name` match.
#[cfg(feature = "driver")]
fn checked_kind(
    rows: &[Row],
    target: Option<&String>,
    role: &Option<String>,
    name: &Option<String>,
) -> Option<SecretKind> {
    let row = match target {
        Some(target) => named(rows, target),
        None => {
            let query = FindInput {
                role: role.clone(),
                name: name.clone(),
                cursor: None,
            };
            rows.iter().find(|row| query.matches(row))
        }
    };
    row.and_then(row_kind)
}

/// `values` as a proof keeps them: no secret slot's.
#[cfg(feature = "driver")]
pub(super) fn public(
    program: &WorkflowProgram,
    mut values: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    for slot in &program.secret_params {
        values.remove(&slot.name);
    }
    values
}

/// The check a replay that missed failed (`otp_replay_policy`): its own,
/// or, where a one-time-code slot gave the replay the solved run's own
/// code, the secret replay's, naming those slots.
#[cfg(feature = "driver")]
pub(super) fn replay_check(
    program: &WorkflowProgram,
    args: &BTreeMap<String, String>,
    replay_args: &BTreeMap<String, String>,
    held_out: bool,
) -> (WorkflowCheck, Option<AdmissionRefusal>) {
    let replayed = if held_out { replay_args } else { args };
    let slots: Vec<String> = program
        .secret_params
        .iter()
        .filter(|slot| {
            slot.kind == SecretKind::Otp && replayed.get(&slot.name) == args.get(&slot.name)
        })
        .map(|slot| slot.name.clone())
        .collect();
    if slots.is_empty() {
        (WorkflowCheck::Replay, None)
    } else {
        let refusal = AdmissionRefusal::SecretReplay { slots };
        (WorkflowCheck::SecretReplay, Some(refusal))
    }
}

/// Each secret slot's own text a run gave as its value (not a handle),
/// with the slot's kind: what a proof's receipts keep no copy of (CUA E7).
#[cfg(feature = "driver")]
pub(super) fn values(
    program: &WorkflowProgram,
    args: &BTreeMap<String, String>,
    replay_args: &BTreeMap<String, String>,
) -> Vec<(String, SecretKind)> {
    program
        .secret_params
        .iter()
        .flat_map(|slot| {
            [args.get(&slot.name), replay_args.get(&slot.name)]
                .into_iter()
                .flatten()
                .filter(|value| !value.is_empty() && !handle_form(value))
                .map(move |value| (value.clone(), slot.kind))
        })
        .collect()
}

/// A receipt's replay as a proof keeps it (CUA E7, FIX 8028): a type's
/// secret, by its handle or as text holding one of `values`, and a Fill
/// whose field holds one, withheld (`unbound`), never the handle or text.
#[cfg(feature = "driver")]
fn withhold(receipt: &mut EffectReceipt, values: &[(String, SecretKind)]) {
    let held = |text: &str| {
        values
            .iter()
            .find(|(value, _)| text.contains(value.as_str()))
            .map(|(_, kind)| *kind)
    };
    let cut = |kind| TypeOperand::Withheld {
        kind,
        cause: OperandGap::Unbound,
    };
    let Some(action) = &mut receipt.action else {
        return;
    };
    match action {
        ReplayAction::Type { operand, .. } => {
            let kind = match operand {
                TypeOperand::Secret { kind, .. } => Some(Some(*kind)),
                TypeOperand::Literal { text } => held(text.as_str()).map(Some),
                TypeOperand::Withheld { .. } => None,
            };
            if let Some(kind) = kind {
                *operand = cut(kind);
            }
        }
        ReplayAction::Fill { locator, field } => {
            let mut texts = field
                .supplied
                .iter()
                .chain(&field.template)
                .chain(&field.instruction)
                .chain(field.references.iter().map(|reference| &reference.text))
                .chain(field.enum_values.iter().flatten());
            if let Some(kind) = texts.find_map(|text| held(text.as_str())) {
                let locator = std::mem::take(locator);
                *action = ReplayAction::Type {
                    locator,
                    operand: cut(Some(kind)),
                    clear: true,
                };
            }
        }
        ReplayAction::Open { .. } | ReplayAction::Click { .. } | ReplayAction::Select { .. } => {}
    }
}

/// A replay's receipts and decisions as a proof keeps them: `[secret]` in
/// place of every handle a row's name or value showed, as a locator holds
/// it, and each receipt's replay withheld where it holds a secret
/// (`withhold`), so the proof keeps no handle of a run.
#[cfg(feature = "driver")]
pub(super) fn unbound(
    receipts: Vec<EffectReceipt>,
    mut decisions: Vec<Value>,
    values: &[(String, SecretKind)],
) -> (Vec<EffectReceipt>, Vec<Value>) {
    for decision in &mut decisions {
        unbind(decision);
    }
    let receipts = receipts
        .into_iter()
        .map(|mut receipt| {
            withhold(&mut receipt, values);
            let Ok(mut value) = serde_json::to_value(&receipt) else {
                return receipt;
            };
            if !unbind(&mut value) {
                return receipt;
            }
            serde_json::from_value(value).unwrap_or(receipt)
        })
        .collect();
    (receipts, decisions)
}

/// Puts `[secret]` in place of every `[secret scN]` in `value`'s strings:
/// whether it put any.
#[cfg(feature = "driver")]
fn unbind(value: &mut Value) -> bool {
    match value {
        Value::String(text) if text.contains("[secret ") => {
            let mut kept = String::with_capacity(text.len());
            let mut rest = text.as_str();
            let mut put = false;
            while let Some(open) = rest.find("[secret ") {
                kept.push_str(&rest[..open]);
                let shown = &rest[open..];
                match shown.find(']') {
                    Some(close) if handle_form(&shown[..=close]) => {
                        kept.push_str(crate::secret_fields::SECRET_MARK);
                        rest = &shown[close + 1..];
                        put = true;
                    }
                    _ => {
                        kept.push_str("[secret ");
                        rest = &shown["[secret ".len()..];
                    }
                }
            }
            kept.push_str(rest);
            if put {
                *text = kept;
            }
            put
        }
        Value::Array(items) => items.iter_mut().fold(false, |put, item| unbind(item) | put),
        Value::Object(fields) => fields
            .values_mut()
            .fold(false, |put, field| unbind(field) | put),
        _ => false,
    }
}
