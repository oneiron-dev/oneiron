//! What a post chain judges: the caller's view of the verb's result, as a
//! value or, for a skill answer nesting past what a value may hold on the
//! host's stack, as JSON text the host never reads into one
//! (SKILL-ANSWER-DEEP-JSON-STACK-SAFE). A hook's input carries the text
//! verbatim; a Redact over it runs on [`redact::hide_in_text`].

use serde_json::Value;
use serde_json::value::RawValue;

use crate::{Error, Result};

use super::super::redact;

/// The caller's view of the result, as a hook's input reads it.
#[derive(Clone, Copy)]
pub(in crate::runtime_hooks::verb) enum ResultView<'v> {
    Value(&'v Value),
    Text(&'v RawValue),
}

/// A view a post chain runs over and narrows.
pub(in crate::runtime_hooks::verb) trait PostView {
    /// The view as a hook's input reads it.
    fn result_view(&self) -> ResultView<'_>;

    /// Applies a Redact's `paths`, in order. `origin` keeps the result as
    /// its producer gave it, before the first Redact narrowed it.
    fn redact(&mut self, origin: &mut Option<Value>, paths: &[String]) -> Result<()>;
}

impl PostView for Value {
    fn result_view(&self) -> ResultView<'_> {
        ResultView::Value(self)
    }

    fn redact(&mut self, origin: &mut Option<Value>, paths: &[String]) -> Result<()> {
        origin.get_or_insert_with(|| self.clone());
        for path in paths {
            redact::hide(self, path);
        }
        Ok(())
    }
}

/// A skill answer's view held as JSON text, framed as the code-mode bridge
/// frames its reply, `{"output": <answer>}`, so a Redact names the paths it
/// names in a value view. Such a view is a write's result
/// (`self.skills.call`) and no pack, so a hook's input takes it whole and
/// it serves no row ([`super::super::served::rows`] needs a top-level
/// `pack_version`).
pub(crate) struct TextView {
    text: Box<RawValue>,
    /// Whether a Redact hid anything in it.
    narrowed: bool,
}

impl TextView {
    /// The view of skill answer `answer`.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] when the framed text does not read as
    /// JSON, which a checked answer never makes.
    pub(crate) fn of_skill_answer(answer: &RawValue) -> Result<Self> {
        let text = RawValue::from_string(format!("{{\"output\":{}}}", answer.get()))
            .map_err(|_| Error::InvariantViolation("a framed skill answer does not read"))?;
        Ok(Self {
            text,
            narrowed: false,
        })
    }

    /// The view's JSON text.
    pub(crate) fn text(&self) -> &str {
        self.text.get()
    }

    /// Whether a Redact hid anything, so the view differs from the answer.
    pub(crate) fn narrowed(&self) -> bool {
        self.narrowed
    }
}

impl PostView for TextView {
    fn result_view(&self) -> ResultView<'_> {
        ResultView::Text(&self.text)
    }

    /// A write's result: its hooks' inputs take it whole and never read
    /// `origin`, so none is kept.
    fn redact(&mut self, _origin: &mut Option<Value>, paths: &[String]) -> Result<()> {
        if let Some(text) = redact::hide_in_text(self.text.get(), paths)? {
            self.text = RawValue::from_string(text)
                .map_err(|_| Error::InvariantViolation("a redacted text view does not read"))?;
            self.narrowed = true;
        }
        Ok(())
    }
}
