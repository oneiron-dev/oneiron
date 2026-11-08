//! The one HTML escaper the authorize pages interpolate through: a client's name and host come
//! from whoever registered it, so every value a page names passes here first.

/// `text` with the five characters HTML gives meaning to replaced by their character
/// references, so it reads as text inside an element and inside a quoted attribute alike.
pub(super) fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}
