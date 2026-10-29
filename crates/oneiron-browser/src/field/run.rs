//! A Fill step running (moved out of `field` whole): its text resolved
//! in order and typed, its generation, its read back, and a routine
//! choice among texts.

use super::spec::{FieldSpec, Prepared};
use super::write::{
    FIELD_WRITER, FieldWrite, FieldWriteError, FieldWriter, TextCheck, TextVerdict,
};
use super::{FieldTextReason, TextProvenance, TextSource, field_text};
use crate::observation::rows_named;
use crate::stop::Stop;
use crate::{
    AskUpReason, BatchStopCause, BrowserDriver, BrowserError, ClockScope, ExpectInput, Observation,
    Routine, RoutineAnswer, Row, StrictDenial, StrictDenied, TypeInput, asked_up,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// One Fill step: its text resolved in order, then typed into `target`,
/// replacing the field's text (`fill_replaces`, CALLS row), on the ordinary
/// type path, its receipt naming where the text came from; then the field
/// read back.
pub(crate) fn fill<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    routine: &mut Routine<'_>,
    writer: &dyn FieldWriter,
    target: String,
    field: FieldSpec,
) -> Result<Observation, Stop> {
    let prepared = field.prepare()?;
    // A secret goes in unread, on the type path (FIX 8900).
    if field.secret.is_some() {
        return fill_secret(driver, routine, target, field);
    }
    // A look the caller never sees, as a routine step's: the page, and the
    // field's row as it shows it now.
    let page = driver.observe_hidden()?;
    let (rows, _) = rows_named(
        std::slice::from_ref(&target),
        &page.rows,
        &page.scope,
        |named| driver.handle_info(named),
    );
    let row = rows.into_iter().next();
    if row.as_ref().is_some_and(|row| row.secret.is_some()) {
        return Err(field_text(
            FieldTextReason::SecretField,
            "the field is a secret: a type step types a secret by its handle",
        ));
    }
    let on = Field {
        page: &page,
        row: row.as_ref(),
    };
    let (text, mut provenance) = resolve(routine, writer, &field, prepared, &on)?;
    // The field as the step named it is the receipt's replay (CUA E7).
    provenance.fill = Some(field);
    let typed = driver.fill_text(
        TypeInput {
            target: target.clone(),
            text: Some(text.clone()),
            secret: None,
            clear: true,
            base: routine.base.clone(),
        },
        provenance,
    )?;
    read_back(driver, &typed, &target, &text)?;
    Ok(typed)
}

/// A Fill whose source is a `secret` (FIX 8900): a handle typed by its
/// handle, the host lending its bytes at the send, or a library slot's own
/// text typed as text (`secret_slot_arg_policy`); never read back, as a
/// secret field shows only its handle.
fn fill_secret<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    routine: &Routine<'_>,
    target: String,
    mut field: FieldSpec,
) -> Result<Observation, Stop> {
    let named = field.secret.take().unwrap_or_default();
    let (text, secret) = if !field.secret_is_text && crate::library::handle_form(&named) {
        (None, Some(named.clone()))
    } else {
        (Some(named.clone()), None)
    };
    field.secret = Some(named);
    let mut provenance = TextProvenance::supplied();
    provenance.fill = Some(field);
    let typed = driver.fill_text(
        TypeInput {
            target,
            text,
            secret,
            clear: true,
            base: routine.base.clone(),
        },
        provenance,
    )?;
    Ok(typed)
}

/// The field a Fill types into: the page the step read, and the field's
/// row there when the read found it.
struct Field<'a> {
    page: &'a Observation,
    row: Option<&'a Row>,
}

impl Field<'_> {
    /// The field as a question names it.
    fn named(&self) -> String {
        match self.row {
            Some(row) => format!("the {} \"{}\" field", row.role, row.name),
            None => "the field".to_owned(),
        }
    }

    /// The state a reference choice or a check reads: the page, the field
    /// and what the step says the text is for.
    fn state(&self, field: &FieldSpec) -> Value {
        let mut state = json!({"url": self.page.url, "title": self.page.title});
        if let Some(row) = self.row {
            state["field"] = json!({"role": row.role, "name": row.name});
        }
        if let Some(instruction) = &field.instruction {
            state["instruction"] = json!(instruction);
        }
        if let Some(options) = &field.enum_values {
            state["enum_values"] = json!(options);
        }
        state
    }
}

/// The step's text and its provenance, in `fill_order`.
fn resolve(
    routine: &mut Routine<'_>,
    writer: &dyn FieldWriter,
    field: &FieldSpec,
    prepared: Prepared,
    on: &Field<'_>,
) -> Result<(String, TextProvenance), Stop> {
    if let Some(text) = &field.supplied {
        return Ok((text.clone(), TextProvenance::supplied()));
    }
    let Prepared {
        mut references,
        template,
    } = prepared;
    let chosen = match references.len() {
        0 => None,
        1 => references.pop(),
        _ => {
            let question = format!("Which reference's text belongs in {}?", on.named());
            // Each reference is offered by a short token of its own, mapped
            // back to its full id (`choice_token_policy`, FIX 8904): an id
            // of any length is never cut, nor refused by the choice.
            let tokens: Vec<String> = (1..=references.len()).map(choice_token).collect();
            let mut state = on.state(field);
            state["references"] = json!(
                tokens
                    .iter()
                    .zip(&references)
                    .map(|(token, text)| (token.clone(), json!({"id": text.id, "text": text.text})))
                    .collect::<BTreeMap<_, _>>()
            );
            // A final NONE falls through to the template (`fill_none`,
            // CALLS row).
            routine
                .select(&question, &tokens, state)?
                .and_then(|token| tokens.iter().position(|offered| *offered == token))
                .map(|at| references.swap_remove(at))
        }
    };
    if let Some(chosen) = chosen {
        let provenance = TextProvenance {
            source: TextSource::Reference,
            text_ref: Some(chosen.id),
            fill: None,
        };
        return Ok((chosen.text, provenance));
    }
    if let Some(template) = template {
        let provenance = TextProvenance {
            source: TextSource::Template,
            text_ref: Some(template_ref(&template)),
            fill: None,
        };
        return Ok((template, provenance));
    }
    if field.generate {
        return generate(routine, writer, field, on);
    }
    Err(field_text(
        FieldTextReason::NoText,
        "no reference fit, and no template or generation followed",
    ))
}

/// The prefix of a reference's choice token (`choice_token_policy`, CALLS
/// row): the `n`th reference is offered as `r<n>`.
const CHOICE_TOKEN: &str = "r";

/// The choice token of the `n`th reference, from 1.
fn choice_token(n: usize) -> String {
    format!("{CHOICE_TOKEN}{n}")
}

/// A template's `text_ref`: the digest of its text as the step typed it.
fn template_ref(template: &str) -> String {
    format!("blake3:{}", blake3::hash(template.as_bytes()).to_hex())
}

/// The writer's text (`fill_generate`, CALLS row): one call, never retried,
/// then one yes/no check, and only YES types it. A strict run asks no
/// writer: the step goes up first, its decision a strict denial at zero
/// tokens (`fill_strict`, CALLS row).
fn generate(
    routine: &mut Routine<'_>,
    writer: &dyn FieldWriter,
    field: &FieldSpec,
    on: &Field<'_>,
) -> Result<(String, TextProvenance), Stop> {
    let question = format!(
        "Does the written text belong in {}, as its instruction asks?",
        on.named()
    );
    if routine.no_model {
        let denied = StrictDenial::FieldGenerationRequiresModel;
        routine
            .decisions
            .push(StrictDenied::decision(denied, &question));
        let error = BrowserError::AskUp(
            "a strict run's fill only a model could write; no writer was asked".to_owned(),
        );
        let reason = AskUpReason::Strict { denied };
        return Err(Stop::new(asked_up(reason), error));
    }
    // The writer runs under the subgoal's one clock (FIX 8903): past it,
    // no writer is asked.
    if let Some(stop) = crate::stop::clock_out(routine.until_ms) {
        return Err(stop);
    }
    let (role, name) = on
        .row
        .map_or_else(Default::default, |row| (row.role.clone(), row.name.clone()));
    let ask = FieldWrite {
        instruction: field.instruction.clone(),
        references: field.references.clone(),
        enum_values: field.enum_values.clone(),
        role,
        name,
        url: on.page.url.clone(),
        title: on.page.title.clone(),
        until_ms: routine.until_ms,
    };
    let written = writer.write(&ask).map_err(|error| match error {
        FieldWriteError::Unavailable(detail) => {
            field_text(FieldTextReason::WriterUnavailable, detail)
        }
        FieldWriteError::Refused(detail) => field_text(FieldTextReason::WriterRefused, detail),
        FieldWriteError::Failed(detail) => field_text(FieldTextReason::WriterFailed, detail),
        FieldWriteError::OutOfTime(detail) => Stop::new(
            BatchStopCause::Clock {
                scope: ClockScope::Decision,
            },
            BrowserError::Timeout(detail),
        ),
    })?;
    let mut record = serde_json::Map::new();
    record.insert(FIELD_WRITER.to_owned(), written.record);
    routine.decisions.push(Value::Object(record));
    if let Some(options) = &field.enum_values
        && !options.contains(&written.text)
    {
        let source = TextSource::Generated;
        return Err(field_text(
            FieldTextReason::NotAnOption { source },
            "the written text is none of the field's enum_values",
        ));
    }
    let mut state = on.state(field);
    state["text"] = json!(written.text);
    // The check runs under the same clock: past it, the text is not typed.
    if let Some(stop) = crate::stop::clock_out(routine.until_ms) {
        return Err(stop);
    }
    let checked = routine.decider.check_text(TextCheck {
        question: &question,
        state,
        until_ms: routine.until_ms,
    });
    let reply =
        checked.map_err(|error| field_text(FieldTextReason::CheckFailed, error.to_string()))?;
    routine.decisions.push(reply.decision);
    match reply.verdict {
        TextVerdict::Yes => {
            let provenance = TextProvenance {
                source: TextSource::Generated,
                text_ref: Some(written.call),
                fill: None,
            };
            Ok((written.text, provenance))
        }
        TextVerdict::No => Err(field_text(
            FieldTextReason::CheckedNo,
            "the check of the written text answered NO",
        )),
        TextVerdict::Abstain => Err(field_text(
            FieldTextReason::CheckAbstained,
            "the check of the written text gave no answer",
        )),
    }
}

/// The field read back after the type (`fill_readback`, CALLS row): a row
/// the read shows with a value other than the text typed stops
/// `page_rejected`, the effect's receipt kept with the stop. A read that
/// shows no row, no value or a secret proves nothing, and the step stands.
fn read_back<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    typed: &Observation,
    target: &str,
    text: &str,
) -> Result<(), Stop> {
    let acted = typed
        .receipt
        .as_ref()
        .and_then(|receipt| receipt.target.clone())
        .unwrap_or_else(|| target.to_owned());
    let read = driver.expect(ExpectInput {
        target: Some(acted),
        ..ExpectInput::default()
    });
    let shown = read
        .ok()
        .and_then(|read| read.row)
        .filter(|row| row.secret.is_none())
        .and_then(|row| row.value);
    match shown {
        Some(shown) if !accepted(&shown, text) => {
            let mut stop = field_text(
                FieldTextReason::PageRejected,
                "the field reads back other text than the step typed",
            );
            stop.receipt = typed.receipt.clone();
            Err(stop)
        }
        _ => Ok(()),
    }
}

/// Whether a field showing `shown` holds `typed`: the same text, its
/// spaces collapsed, as a row shows a value; a value the row clipped (its
/// `…`) holds the text it begins.
fn accepted(shown: &str, typed: &str) -> bool {
    let collapsed = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (shown, typed) = (collapsed(shown), collapsed(typed));
    shown == typed
        || shown
            .strip_suffix('…')
            .is_some_and(|begun| typed.starts_with(begun))
}

impl Routine<'_> {
    /// A choice among `labels` that acts on nothing (CUA E6): a Fill's
    /// references by id. It asks as a look does, in pages, NONE on one
    /// page asking the next, under the subgoal's clock, each decision kept;
    /// NONE on the last page is no choice. A reobserve, an ask-up, a strict
    /// denial or the clock goes up, as a routine step's would.
    pub(crate) fn select(
        &mut self,
        question: &str,
        labels: &[String],
        state: Value,
    ) -> Result<Option<String>, Stop> {
        let reply = self.ask(question, labels, None, state)?;
        match reply.answer {
            RoutineAnswer::Act { candidate } if labels.contains(&candidate) => Ok(Some(candidate)),
            RoutineAnswer::None => Ok(None),
            RoutineAnswer::Reobserve => {
                let error = BrowserError::AskUp(
                    "the decider asked to look again at a choice of texts, which has no page to look at"
                        .to_owned(),
                );
                Err(Stop::new(asked_up(AskUpReason::Reobserve), error))
            }
            RoutineAnswer::AskUp { reason } => {
                let detail = reason
                    .as_deref()
                    .unwrap_or("the decider asked up")
                    .to_owned();
                let reason = AskUpReason::Asked { ladder: reason };
                Err(Stop::new(asked_up(reason), BrowserError::AskUp(detail)))
            }
            RoutineAnswer::Denied { denial } => {
                let error = BrowserError::AskUp(format!(
                    "a strict run's choice only a model could answer ({denial:?}); no model was asked"
                ));
                let reason = AskUpReason::Strict { denied: denial };
                Err(Stop::new(asked_up(reason), error))
            }
            RoutineAnswer::Deadline => {
                let error = BrowserError::AskUp(
                    "the subgoal's clock ran out before the decider answered".to_owned(),
                );
                let scope = ClockScope::Decision;
                Err(Stop::new(BatchStopCause::Clock { scope }, error))
            }
            other => {
                let error = BrowserError::Decider(format!("{other:?} does not answer this choice"));
                Err(Stop::new(asked_up(AskUpReason::WrongAnswer), error))
            }
        }
    }
}
