//! The confession ask and its parse (OF-544, ARCH-0079): after a DONE line,
//! one fenced block naming each assigned objective, whether it was met, and
//! any flaw or doubt. A workflow step and a Dreamer-lane TASK's realization
//! ask in these words; a reply that gives none, or one that does not parse,
//! confesses nothing.

use crate::self_heal::audit::ObjectiveConfession;

/// The fence that opens a confession block, after its DONE line.
const CONFESSION_FENCE: &str = "```oneiron-confession";

/// The ask for a confession against `objectives`, after the task.
#[must_use]
pub fn confession_ask(objectives: &[String]) -> String {
    let listed = serde_json::to_string(objectives).unwrap_or_default();
    format!(
        "Objectives assigned to this attempt: {listed}\n\
         When your result is complete, end it with a line that is exactly DONE, then one \
         block fenced ```oneiron-confession holding \
         {{\"objectives\":[{{\"objective\":\"<the assigned objective, copied exactly>\",\
         \"met\":<true or false>,\"flaw\":<null or what is wrong>,\
         \"uncertainty\":<null or what you are unsure of>}}]}} with one row per assigned \
         objective, in order. Say plainly what you did not meet, any flaw and any doubt: a \
         confession never costs the score. Nothing follows the closing fence."
    )
}

/// The confession `output` ends with, when it is a DONE line, then one
/// ```oneiron-confession block whose rows name exactly `objectives`, in
/// order. Anything else is no confession.
#[must_use]
pub fn parse_confession(output: &[u8], objectives: &[String]) -> Option<Vec<ObjectiveConfession>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Block {
        objectives: Vec<ObjectiveConfession>,
    }
    let text = std::str::from_utf8(output).ok()?.trim_end();
    let (head, block) = text.strip_suffix("```")?.rsplit_once(CONFESSION_FENCE)?;
    let head = head.trim_end();
    if head != "DONE" && !head.ends_with("\nDONE") {
        return None;
    }
    let rows = serde_json::from_str::<Block>(block.trim()).ok()?.objectives;
    let named = rows.iter().map(|row| &row.objective);
    (rows.len() == objectives.len() && named.eq(objectives)).then_some(rows)
}
