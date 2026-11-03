//! The entries of [`super::BLOCKLIST`], parsed once for every scan.

use std::sync::LazyLock;

/// Each entry of the built deny list, in file order: its lines, trimmed,
/// less blank lines and `#` comments.
pub(super) static ENTRIES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    super::BLOCKLIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});
