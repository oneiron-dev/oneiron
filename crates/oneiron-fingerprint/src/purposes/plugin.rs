//! Purposes of plugin sections (`crates/oneiron/src/context_board/plugin`) and the
//! Dreamer's plugin suggestions (`dreamer_plugin_suggest`).

purposes! {}

legacy_purposes! {
    /// The digest of a section manifest's canonical bytes
    /// (`context_board::plugin::codec::section_manifest_digest`): plain SHA-256, no tag. An
    /// install claim carries it beside the manifest bytes and is refused when they differ,
    /// and owner consent binds it.
    SECTION_MANIFEST = (Sha256, NotHashed, "oneiron.plugin.section_manifest.v1");

    /// A Dreamer plugin suggestion's key (`dreamer_plugin_suggest::plugin_suggestion_key`):
    /// SHA-256, the tag's bytes, then the pattern key, the pack id and the version, each as
    /// its u64 big-endian length and its bytes, then the manifest's [`SECTION_MANIFEST`]
    /// digest. A suggestion the owner has answered stays quiet by its key, so a new key
    /// would ask every answered question again.
    SUGGESTION_KEY = (Sha256, HashedFirst, "oneiron.plugin_suggestion.v1");
}
