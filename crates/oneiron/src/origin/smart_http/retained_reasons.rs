//! A push refusal's reasons, bounded where they are kept (FIX 5942). Every
//! scan, ref check and owner check still runs over the whole push and every
//! reason it meets still refuses; only how many reasons are held, and how
//! long the line the hook prints is, are bounded.

/// How many of a refusal's reasons are kept, in the order they are met
/// (CALLS: FIX 5942 retained push reasons). Each later one is counted, and
/// its text is never built.
pub(super) const DOOR_RETAINED_REASONS: usize = 8;

/// The longest verdict line the door publishes to the hook (CALLS: FIX 5942
/// retained push reasons).
pub(super) const DOOR_VERDICT_MAX_BYTES: usize = 4096;

/// The entry that follows the kept reasons when more were met.
const OMITTED_REASONS: &str = "omitted_reasons=";

/// The mark a verdict line ends with when its kept reasons did not all fit.
const DETAILS_TRUNCATED: &str = "details_truncated=true";

const SEPARATOR: &str = "; ";

/// The reasons one refusal met so far: the first [`DOOR_RETAINED_REASONS`]
/// as text, the rest as a count.
#[derive(Debug, Default)]
pub(super) struct RetainedReasons {
    kept: Vec<String>,
    omitted: u64,
}

impl RetainedReasons {
    /// One reason, already built.
    pub(super) fn one(reason: String) -> Self {
        Self {
            kept: vec![reason],
            omitted: 0,
        }
    }

    /// Meets one more reason; `reason` builds its text only when it is kept.
    pub(super) fn push_with(&mut self, reason: impl FnOnce() -> String) {
        if self.kept.len() < DOOR_RETAINED_REASONS {
            self.kept.push(reason());
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    /// Whether no reason was met, kept or counted.
    pub(super) fn is_empty(&self) -> bool {
        self.kept.is_empty() && self.omitted == 0
    }

    /// The kept reasons in the order met, then one `omitted_reasons=K` entry
    /// when `K` more were met.
    pub(super) fn into_reasons(self) -> Vec<String> {
        let mut reasons = self.kept;
        if self.omitted > 0 {
            reasons.push(format!("{OMITTED_REASONS}{}", self.omitted));
        }
        reasons
    }
}

/// `prefix` and `reasons` joined by `"; "`, built one reason at a time and
/// never longer than [`DOOR_VERDICT_MAX_BYTES`]. A final `omitted_reasons=K`
/// entry always appears whole; a kept reason that does not fit is cut at a
/// character boundary, the rest are left out, and the line ends
/// `details_truncated=true`.
pub(super) fn bounded_verdict_line(prefix: &str, reasons: &[String]) -> String {
    let (details, omitted) = match reasons.split_last() {
        Some((last, rest)) if is_omitted_entry(last) => (rest, Some(last.as_str())),
        _ => (reasons, None),
    };
    let reserved = omitted.map_or(0, |entry| SEPARATOR.len() + entry.len())
        + SEPARATOR.len()
        + DETAILS_TRUNCATED.len();
    let budget = DOOR_VERDICT_MAX_BYTES.saturating_sub(reserved);
    let mut line = String::with_capacity(DOOR_VERDICT_MAX_BYTES.min(prefix.len() + 64));
    line.push_str(char_prefix(prefix, budget));
    let start = line.len();
    let mut truncated = start < prefix.len();
    for reason in details {
        if truncated {
            break;
        }
        let separator = if line.len() > start { SEPARATOR } else { "" };
        let room = budget.saturating_sub(line.len() + separator.len());
        let piece = char_prefix(reason, room);
        if piece.is_empty() && !reason.is_empty() {
            truncated = true;
            break;
        }
        line.push_str(separator);
        line.push_str(piece);
        truncated = piece.len() < reason.len();
    }
    for (entry, shown) in [(omitted, true), (Some(DETAILS_TRUNCATED), truncated)] {
        if let Some(entry) = entry.filter(|_| shown) {
            if line.len() > start {
                line.push_str(SEPARATOR);
            }
            line.push_str(entry);
        }
    }
    line
}

/// Whether `reason` is the count [`RetainedReasons::into_reasons`] appends.
fn is_omitted_entry(reason: &str) -> bool {
    reason
        .strip_prefix(OMITTED_REASONS)
        .is_some_and(|count| !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The longest prefix of `text` at most `max` bytes long that ends on a
/// character boundary.
fn char_prefix(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
