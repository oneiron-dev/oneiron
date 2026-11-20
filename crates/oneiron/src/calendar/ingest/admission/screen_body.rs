//! The CAL-09 screen body of one VEVENT, as admission hands it to the
//! inbound screen.

use crate::calendar::ics::ParsedVEvent;
use crate::calendar::safeguard::CalendarInboundBody;

/// The CAL-09 screen body for one VEVENT: its description plus any ATTACH
/// values as attachment text, exactly as the source expressed them.
pub(super) fn screen_body(event: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: event.description.clone().unwrap_or_default(),
        attachment_text: attachment_text(&event.raw_component),
    }
}

/// Every ATTACH of one raw VEVENT as text: an inline `ENCODING=BASE64`
/// attachment's content when it decodes to UTF-8 text, else the value as the
/// source wrote it (a URI, or inline bytes that are no text). A component
/// that does not read again yields none; its parse already succeeded once.
fn attachment_text(raw_component: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(raw_component) else {
        return Vec::new();
    };
    let unfolded = icalendar::parser::unfold(text);
    let Ok(components) = icalendar::parser::read_calendar_simple(&unfolded) else {
        return Vec::new();
    };
    components
        .iter()
        .flat_map(|component| component.properties.iter())
        .filter(|prop| prop.name.as_str().eq_ignore_ascii_case("ATTACH"))
        .map(|prop| {
            let base64 = prop.params.iter().any(|param| {
                param.key.as_str().eq_ignore_ascii_case("ENCODING")
                    && param
                        .val
                        .as_ref()
                        .is_some_and(|val| val.as_str().eq_ignore_ascii_case("BASE64"))
            });
            let value = prop.val.as_str().trim();
            if base64 {
                use base64::Engine;
                if let Some(content) = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                {
                    return content;
                }
            }
            value.to_owned()
        })
        .collect()
}
