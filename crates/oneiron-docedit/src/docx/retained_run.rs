//! Re-emit the permitted simple run without dropping unknown attributes.
use super::writer::{Run, escape_text};

impl Run {
    pub(super) fn fragment(&self, text: &str, deleted: bool) -> String {
        let mut opening = self.text_opening.clone();
        // Original text can acquire boundary whitespace after a split.
        if let Some(start) = opening.find("xml:space=") {
            let value = start + "xml:space=".len();
            if let Some(quote @ (b'\'' | b'"')) = opening.as_bytes().get(value).copied()
                && let Some(end) = opening[value + 1..].find(char::from(quote))
            {
                opening.replace_range(value + 1..value + 1 + end, "preserve");
            }
        } else if text.starts_with([' ', '\t', '\n', '\r'])
            || text.ends_with([' ', '\t', '\n', '\r'])
        {
            opening.insert_str(opening.len() - 1, " xml:space=\"preserve\"");
        }
        let close = if deleted {
            opening = opening.replacen("<w:t", "<w:delText", 1);
            "</w:delText>"
        } else {
            "</w:t>"
        };
        format!(
            "{}{}{}{}{close}</w:r>",
            self.opening,
            self.rpr.as_deref().unwrap_or_default(),
            opening,
            escape_text(text)
        )
    }
}
