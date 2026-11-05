//! Stored plugin-section install claim predicate.

/// The one claim predicate an owner consents to for a plugin section install.
/// One Proposed claim under this predicate covers install PLUS section
/// admission; no second approval object and no new gate consent kind exist.
pub const PREDICATE_PLUGIN_SECTION_INSTALL: &str = "plugin.section_install";
