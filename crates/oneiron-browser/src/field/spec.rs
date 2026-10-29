//! What a Fill step types (moved out of `field` whole): the step's text
//! sources and their check before the batch runs any step.

use super::{FieldTextReason, TextSource, field_text};
use crate::BrowserError;
use crate::stop::Stop;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a Fill step types into its field: `supplied` text, else one of its
/// `references`, else its `template`, else, with `generate`, text the
/// host's writer writes to its `instruction`. With `enum_values`, the field
/// takes only one of those texts. A `secret` is a source of its own.
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
    /// A run-bound secret handle the field takes (FIX 8900), typed unread
    /// through the host's custody as a `type` step's `secret` is, into a
    /// secret field too; a library slot's own text in its place is typed
    /// as text. It names no other source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// One text a Fill step may type, by an id the step's caller gave it: the
/// id names the text on the effect's receipt, and never an element.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextReference {
    pub id: String,
    pub text: String,
}

/// A Fill's text sources once checked: the references it may type and its
/// template, its slots filled.
pub(crate) struct Prepared {
    pub(super) references: Vec<TextReference>,
    pub(super) template: Option<String>,
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
        // A secret is typed unread, so it names no other source and no
        // option is compared with it (FIX 8900).
        if self.secret.is_some() {
            let others = self.supplied.is_some()
                || !self.references.is_empty()
                || self.template.is_some()
                || self.generate;
            if others {
                return Err(BrowserError::Input(
                    "a fill's secret names no other source".to_owned(),
                )
                .into());
            }
            return Ok(Prepared {
                references: Vec::new(),
                template: None,
            });
        }
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
