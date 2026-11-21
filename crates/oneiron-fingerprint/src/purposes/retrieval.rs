//! Purposes of the retrieval crate (`oneiron-retrieval`).

purposes! {}

legacy_purposes! {
    /// The analyzer manifest hash (`AnalyzerManifest::canonical_hash`). SHA-256 of the
    /// manifest's `serde_json` text, with no tag written. Stored beside the manifest JSON
    /// in the text index's `ANALYZER_MANIFEST` table (`_hash` key,
    /// `vault/doctor_manifest.rs` `write_text_index_manifest`) and read back as
    /// `text_analyzer_manifest_hash` by the replay identity trace.
    ANALYZER_MANIFEST = (Sha256, NotHashed, "oneiron.retrieval.analyzer_manifest.v1");
}
