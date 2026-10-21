//! A Fill step's text (CUA E6, DESIGN-2 §4 "Field text = A"): what one
//! field takes, resolved in code before any model writes it, and where the
//! text came from, which the effect's receipt names.
//!
//! A Fill names its text four ways, tried in one order (`fill_order`, CALLS
//! row): `supplied` text is typed as given, ahead of everything else; else
//! the step's references, one typing with no decision and several becoming
//! a routine choice among their ids, NONE falling through; else its
//! template, its `{{slots}}` filled from the run's arguments before the
//! batch began; else, only with `generate`, one call of the host's writer,
//! typed once one yes/no check of it answers YES. A strict run's generation
//! goes up before any writer is asked.
//!
//! Every Fill's template and options are checked as its batch starts,
//! before any step, decision or writer call (`fill_precheck`). No text is
//! refused or cut for its length: the page's own read of the field after
//! the type says whether it took the text (`fill_readback`). A field the
//! page shows as a secret takes no text of any source: a `type` step types
//! a secret by its handle.

use crate::observation::rows_named;
use crate::stop::Stop;
use crate::{
    AskUpReason, BatchStopCause, BrowserDriver, BrowserError, ClockScope, EffectReceipt,
    ExpectInput, Observation, ObserveInput, Routine, RoutineAnswer, Row, StrictDenial,
    StrictDenied, TypeInput, asked_up,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// What a Fill step types into its field: `supplied` text, else one of its
/// `references`, else its `template`, else, with `generate`, text the
/// host's writer writes to its `instruction`. With `enum_values`, the field
/// takes only one of those texts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// The text itself, typed as given: no reference, template or writer
    /// is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplied: Option<String>,
    /// Texts the field may take, each by its own id. One types as it is;
    /// several are a routine choice among their ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<TextReference>,
    /// The text with `{{name}}` slots, which a library run fills from its
    /// arguments; a slot left unfilled stops the batch before it starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// When no reference fits and there is no template, the host's writer
    /// writes the text, typed once a yes/no check of it answers YES.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub generate: bool,
    /// What the text is for, which a reference choice, the writer and the
    /// check read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    /// The only texts the field takes, compared exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
}

/// One text a Fill step may type, by an id the step's caller gave it: the
/// id names the text on the effect's receipt, and never an element.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextReference {
    pub id: String,
    pub text: String,
}

/// Where a typed text came from, as its effect's receipt names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextSource {
    /// The caller's own text: a `type`, or a Fill's `supplied`.
    Supplied,
    /// One of a Fill's references.
    Reference,
    /// A Fill's template.
    Template,
    /// The host's writer, checked YES.
    Generated,
}

/// Why a Fill step's text was not typed, or not taken (CUA E6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum FieldTextReason {
    /// No source gave text: none was named, no reference fit, and no
    /// template or generation followed.
    NoText,
    /// The template holds a slot nothing filled.
    MissingSlot { slot: String },
    /// The template opens a `{{` slot it never closes.
    UnclosedSlot,
    /// The text from `source` is none of the field's `enum_values`; from
    /// references, none of them is.
    NotAnOption { source: TextSource },
    /// The page shows the field as a secret: a `type` step types a secret
    /// by its handle, and a Fill types no text there.
    SecretField,
    /// The host has no writer for the field, or none serves its role.
    WriterUnavailable,
    /// The writer's model admission refused the call, before it went out.
    WriterRefused,
    /// The writer's call failed, or answered no text.
    WriterFailed,
    /// The check of the written text answered NO.
    CheckedNo,
    /// The check of the written text gave no answer.
    CheckAbstained,
    /// The check could not be asked, or failed.
    CheckFailed,
    /// After the type, the page's field reads back other text than the
    /// step typed: the page did not take it as typed.
    PageRejected,
}

/// Where the text an effect typed came from: its source and reference, as
/// its receipt names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextProvenance {
    pub source: TextSource,
    /// The text's reference (`fill_text_ref`, CALLS row): a reference's
    /// id, a template's digest (`blake3:` and hex), or the writer call's
    /// id; none for supplied text.
    pub text_ref: Option<String>,
}

impl TextProvenance {
    /// The caller's own text, which names no reference.
    #[must_use]
    pub const fn supplied() -> Self {
        Self {
            source: TextSource::Supplied,
            text_ref: None,
        }
    }

    /// Names this provenance on `receipt`.
    pub fn stamp(self, receipt: &mut EffectReceipt) {
        receipt.text_source = Some(self.source);
        receipt.text_ref = self.text_ref;
    }
}

/// One writer call's ask: the field as the page shows it, the page, and
/// what the step gave the writer to go on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldWrite {
    /// What the text is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    /// The step's references, none of which the step typed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<TextReference>,
    /// The only texts the field takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// The field's row: its role and accessible name, empty when the step's
    /// read did not find it.
    pub role: String,
    pub name: String,
    pub url: String,
    pub title: String,
}

/// What the writer wrote.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldWritten {
    pub text: String,
    /// The call's id, as the host names it: the text's `text_ref`.
    pub call: String,
    /// The call's record, kept among the batch's decisions under
    /// [`FIELD_WRITER`]: its role, model and usage.
    pub record: Value,
}

/// Why the writer wrote nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldWriteError {
    /// The host has no writer, or no model serves its role.
    Unavailable(String),
    /// The model's admission refused the call before it went out.
    Refused(String),
    /// The call failed, or answered no text.
    Failed(String),
}

/// The host's field writer (CUA E6): one model call, admitted on the
/// host's browser planner role and spent on the caller's run, that writes
/// one field's text. The batch asks it once per Fill that reaches
/// generation, and never retries it.
pub trait FieldWriter: Send + Sync {
    /// Writes the text `ask` names.
    ///
    /// # Errors
    ///
    /// Why no text was written.
    fn write(&self, ask: &FieldWrite) -> Result<FieldWritten, FieldWriteError>;
}

/// No writer: a Fill that reaches generation stops `writer_unavailable`.
pub struct NoWriter;

impl FieldWriter for NoWriter {
    fn write(&self, _ask: &FieldWrite) -> Result<FieldWritten, FieldWriteError> {
        Err(FieldWriteError::Unavailable(
            "this browser host has no field writer".to_owned(),
        ))
    }
}

/// A yes/no check of a written text, asked of the host's decider: its
/// question, and the state it reads, which holds the text.
pub struct TextCheck<'a> {
    pub question: &'a str,
    pub state: Value,
}

/// A text check's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextVerdict {
    Yes,
    No,
    /// No rung answered.
    Abstain,
}

/// The decider's answer to a text check, with the decision's record for
/// the batch's decisions.
#[derive(Clone, Debug)]
pub struct TextCheckReply {
    pub verdict: TextVerdict,
    pub decision: Value,
}

/// The key a batch's `decisions` entry holds a writer call's record under.
pub const FIELD_WRITER: &str = "field_writer";

/// A Fill's text sources once checked: the references it may type and its
/// template, its slots filled.
pub(crate) struct Prepared {
    references: Vec<TextReference>,
    template: Option<String>,
}

impl FieldSpec {
    /// The step's check before its batch runs any step (`fill_precheck`,
    /// CALLS row), at no decision's or model's cost: its references name
    /// distinct ids, its template holds no slot left unfilled, and with
    /// `enum_values` its supplied text and its template are options, and
    /// only its references that are options stay. A step with no source
    /// left stops here too. Supplied text is checked alone: nothing else
    /// is read beside it.
    pub(crate) fn prepare(&self) -> Result<Prepared, Stop> {
        let fits = |text: &str| {
            self.enum_values
                .as_ref()
                .is_none_or(|options| options.iter().any(|option| option == text))
        };
        if let Some(supplied) = &self.supplied {
            if !fits(supplied) {
                let source = TextSource::Supplied;
                return Err(field_text(
                    FieldTextReason::NotAnOption { source },
                    "the supplied text is none of the field's enum_values",
                ));
            }
            return Ok(Prepared {
                references: Vec::new(),
                template: None,
            });
        }
        let ids = &self.references;
        if (1..ids.len()).any(|at| ids[..at].iter().any(|seen| seen.id == ids[at].id)) {
            return Err(
                BrowserError::Input("a fill's references name distinct ids".to_owned()).into(),
            );
        }
        let template = match &self.template {
            Some(template) => {
                let filled = crate::library::fill_text(template, &BTreeMap::new()).map_err(
                    |gap| match gap {
                        crate::library::SlotGap::Missing(slot) => {
                            let detail = format!("the template's slot {{{{{slot}}}}} is unfilled");
                            field_text(FieldTextReason::MissingSlot { slot }, detail)
                        }
                        crate::library::SlotGap::Unclosed => field_text(
                            FieldTextReason::UnclosedSlot,
                            "the template opens a {{ slot it never closes",
                        ),
                    },
                )?;
                if !fits(&filled) {
                    let source = TextSource::Template;
                    return Err(field_text(
                        FieldTextReason::NotAnOption { source },
                        "the template's text is none of the field's enum_values",
                    ));
                }
                Some(filled)
            }
            None => None,
        };
        let references: Vec<TextReference> = self
            .references
            .iter()
            .filter(|reference| fits(&reference.text))
            .cloned()
            .collect();
        if references.is_empty() && template.is_none() && !self.generate {
            return Err(if self.references.is_empty() {
                field_text(
                    FieldTextReason::NoText,
                    "the fill names no supplied text, reference, template or generation",
                )
            } else {
                let source = TextSource::Reference;
                field_text(
                    FieldTextReason::NotAnOption { source },
                    "no reference's text is one of the field's enum_values",
                )
            });
        }
        Ok(Prepared {
            references,
            template,
        })
    }
}

/// A Fill step's stop for `reason`.
fn field_text(reason: FieldTextReason, detail: impl Into<String>) -> Stop {
    Stop::new(
        BatchStopCause::FieldText { reason },
        BrowserError::FieldText(detail.into()),
    )
}

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
    // A look the caller never sees, as a routine step's: the page, and the
    // field's row as it shows it now.
    let page = driver.observe(ObserveInput {
        full: true,
        ..ObserveInput::default()
    })?;
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
    let (text, provenance) = resolve(routine, writer, &field, prepared, &on)?;
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
            let ids: Vec<String> = references.iter().map(|text| text.id.clone()).collect();
            let mut state = on.state(field);
            state["references"] = json!(
                references
                    .iter()
                    .map(|text| (text.id.clone(), text.text.clone()))
                    .collect::<BTreeMap<_, _>>()
            );
            // A final NONE falls through to the template (`fill_none`,
            // CALLS row).
            routine
                .select(&question, &ids, state)?
                .and_then(|id| references.into_iter().find(|text| text.id == id))
        }
    };
    if let Some(chosen) = chosen {
        let provenance = TextProvenance {
            source: TextSource::Reference,
            text_ref: Some(chosen.id),
        };
        return Ok((chosen.text, provenance));
    }
    if let Some(template) = template {
        let provenance = TextProvenance {
            source: TextSource::Template,
            text_ref: Some(template_ref(&template)),
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
    };
    let written = writer.write(&ask).map_err(|error| match error {
        FieldWriteError::Unavailable(detail) => {
            field_text(FieldTextReason::WriterUnavailable, detail)
        }
        FieldWriteError::Refused(detail) => field_text(FieldTextReason::WriterRefused, detail),
        FieldWriteError::Failed(detail) => field_text(FieldTextReason::WriterFailed, detail),
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
    let checked = routine.decider.check_text(TextCheck {
        question: &question,
        state,
    });
    let reply =
        checked.map_err(|error| field_text(FieldTextReason::CheckFailed, error.to_string()))?;
    routine.decisions.push(reply.decision);
    match reply.verdict {
        TextVerdict::Yes => {
            let provenance = TextProvenance {
                source: TextSource::Generated,
                text_ref: Some(written.call),
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
