//! The field manifest: how the normaliser treats every object key the
//! golden-day trace holds (the receipt envelope, each receipt kind's
//! `fields`, the verb answers the day reads, and the trace's own frame).
//!
//! A key is classified by name wherever it appears. A key the manifest does
//! not name fails the normalisation with its JSON path, so a new field is
//! classified here on purpose, and the version below goes up with it. Keep
//! a value exact unless a fresh run of the same script can change it for a
//! reason that is not a change of behaviour: a record id the run mints, a
//! random key, nonce or signature, or a reading of real time.

/// The manifest's version, written into every golden dump. Bump it with any
/// change below, and regenerate the golden file in the same commit.
pub const SCHEMA_VERSION: u32 = 1;

/// How one key's value is normalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// Kept byte for byte, its object keys sorted: content, outcomes, reason
    /// codes, counts, logical (fake clock) times, content hashes.
    Exact,
    /// A reading of real time (a duration, a wall-clock stamp): replaced by
    /// [`super::normalise::MEASURED`], its presence kept.
    Measured,
    /// A record id the run mints: replaced by the scenario name it is bound
    /// to, else by `<kind>#<n>`, numbered in first-seen order. Equal ids get
    /// equal names. A string may hold a comma-separated list of them.
    Ref(&'static str),
    /// Bytes a run draws at random, or a hash or cursor over them (a key, a
    /// nonce, a signature, a page cursor): named like a ref, so only their
    /// equality is compared.
    Opaque(&'static str),
    /// An object or array whose own keys are classified in turn.
    Container,
}

use FieldClass::{Container, Exact, Measured, Opaque, Ref};

/// Every key the golden-day trace may hold, with its class. A key listed
/// twice keeps its first class.
pub const MANIFEST: &[(&str, FieldClass)] = &[
    // The trace's own frame (src/golden_day/mod.rs).
    ("steps", Container),
    ("step", Exact),
    ("verb", Exact),
    ("caller", Exact),
    ("at", Exact),
    ("input", Container),
    ("answer", Container),
    ("refused", Exact),
    ("provider_seen", Container),
    ("digest", Exact),
    ("route", Exact),
    ("streamed", Exact),
    ("model", Exact),
    ("streams", Container),
    ("gate_ledger", Container),
    ("family", Container),
    ("authority_audit", Container),
    ("rows", Container),
    ("pages", Container),
    ("page_count", Exact),
    // The Dreamer pass report (src/golden_day/mod.rs, from DreamerPassReport).
    ("wake", Exact),
    ("wake_queued", Exact),
    ("stop", Exact),
    ("admitted", Exact),
    ("completed", Exact),
    ("failed", Exact),
    ("deferred", Exact),
    ("parked", Exact),
    ("landings", Exact),
    ("sources_truncated", Exact),
    ("claim_authoring_fallback", Exact),
    ("attempts", Container),
    ("attempt_id", Ref("attempt")),
    ("attempt_type", Exact),
    ("execution", Exact),
    ("landed", Ref("claim")),
    ("pended", Ref("claim")),
    ("rejected", Container),
    ("rejected_claim", Ref("claim")),
    ("rejection", Exact),
    ("unlent", Exact),
    ("queue", Container),
    ("park_reason", Exact),
    ("state", Exact),
    // The receipt page and its envelope (vault.receipts; memory/reads/receipt_page.rs,
    // memory/claims/mod.rs MemoryReceipt).
    ("receipts", Container),
    ("next_after", Opaque("cursor")),
    ("effective_limit", Exact),
    ("limit_clamped", Exact),
    ("undecodable", Exact),
    ("receipt_ref", Ref("receipt")),
    ("kind", Exact),
    ("outcome", Exact),
    ("created_at", Exact),
    ("reason_codes", Exact),
    ("actor_class", Exact),
    ("actor_ref", Ref("actor")),
    ("content_kind", Exact),
    ("claim_ref", Ref("claim")),
    ("claim", Container),
    ("fields", Container),
    // Receipt fields every family projector may copy in (receipt/family.rs).
    ("trigger_ref", Ref("trigger")),
    ("job_ref", Ref("job")),
    ("on_behalf_of", Ref("actor")),
    // The day's verb inputs (src/golden_day/mod.rs).
    ("conversation_ref", Ref("conversation")),
    ("turn_ref", Ref("turn")),
    ("messages", Container),
    ("id", Ref("record")),
    ("author", Exact),
    ("message_type", Exact),
    ("content", Exact),
    ("is_visible", Exact),
    ("order", Exact),
    ("occurred_at", Exact),
    ("learned_at", Exact),
    ("predicate", Exact),
    ("subject_ref", Ref("entity")),
    // A claim's value, and a read verb's whole answer: walked, so the refs
    // inside an answer are named; a scalar stays as it is.
    ("value", Container),
    ("confidence", Exact),
    ("source", Exact),
    ("query", Exact),
    ("effort", Exact),
    ("limit", Exact),
    ("as_of", Exact),
    ("entity_ref", Ref("entity")),
    ("grant_ref", Ref("grant")),
    ("agent", Ref("actor")),
    ("agent_def_ref", Ref("actor")),
    ("definition", Exact),
    ("authority_scope", Exact),
    ("after", Opaque("cursor")),
    ("changed", Exact),
    ("seen", Exact),
    // Verb answers met in the day's first run (golden-day-5ee779ee27fd.log).
    // vault.witness:
    ("turn_id", Ref("turn")),
    ("turn_short_id", Ref("short")),
    ("message_short_ids", Ref("short")),
    ("turn", Container),
    ("wake_outcome", Exact),
    // A record ref (`{kind, id, short_id, label}`) and short ids: a short id
    // and a label derive from the record's id, so they are named as refs.
    ("record", Container),
    ("short_id", Ref("short")),
    ("short_ref", Ref("short")),
    ("label", Ref("label")),
    ("id_hex", Ref("record")),
    // vault.remember:
    ("claim_short_id", Ref("short")),
    ("approval", Exact),
    ("superseded", Container),
    ("superseded_short_id", Ref("short")),
    // vault.agents.create and vault.agents.grants.mint / .revoke:
    ("approval_status", Exact),
    ("lifecycle_status", Exact),
    ("grant", Container),
    ("delegated_by", Ref("actor")),
    ("confers", Exact),
    ("revoke_command", Exact),
    ("act_ref", Opaque("act")),
    // vault.recall:
    ("items", Container),
    ("source_revision_ref", Ref("revision")),
    ("value_text", Exact),
    ("hedge_bucket", Exact),
    ("confidence_basis", Exact),
    ("provenance", Container),
    ("source_revision_ids", Ref("record")),
    ("evidence_turn_ids", Ref("turn")),
    ("world", Ref("world")),
    ("facet", Ref("facet")),
    ("project_ref", Ref("project")),
    ("salience", Exact),
    ("cited_messages", Container),
    ("conversation_id", Ref("conversation")),
    ("scope_honesty", Exact),
    ("retrieval_meta", Exact),
    ("pack_version", Exact),
    ("rendered", Exact),
    // Every read's narrowing receipt: axes and counts only, no refs.
    ("narrowing", Exact),
    // vault.search.bm25, vault.claims.list, vault.get:
    ("score", Exact),
    ("snippet", Exact),
    ("lifecycle", Exact),
    ("world_ref", Ref("world")),
    ("scope", Exact),
    ("claim_scope", Container),
    ("world_id", Ref("world")),
    ("scope_facet_id", Ref("facet")),
    ("scope_project_id", Ref("project")),
    ("scope_relationship_id", Exact),
    ("made_by", Container),
    ("valid_from", Exact),
    ("valid_to", Exact),
    ("stale", Exact),
    ("body", Exact),
    ("occurred_start", Exact),
    ("occurred_end", Exact),
    // Receipt family fields (receipt/field_set.rs, gate receipts).
    ("diff_handle", Ref("diff")),
    ("read_frontier_hash", Opaque("frontier")),
    ("policy_manifest_version", Exact),
    ("receipt_reason", Exact),
    // vault.authority.audit pages and rows (receipt/authority_audit.rs): the
    // entry hash covers signatures by keys a run draws, so it is opaque.
    ("scanned", Exact),
    ("entry_ref", Opaque("entry")),
    ("entry_hash", Opaque("entry_hash")),
    ("event_kind", Exact),
    ("source_op", Exact),
    ("detail", Exact),
    ("advisory_ts", Exact),
    ("signer_key", Opaque("key")),
    ("cosigner_keys", Opaque("key")),
    ("seq", Exact),
    ("fold_valid", Exact),
    ("vault_ref", Opaque("vault")),
    ("holder_ref", Ref("actor")),
    ("expires_at", Exact),
    // Real time (receipt/family.rs hook receipts; runtime_hooks/body.rs).
    ("wall_ms", Measured),
    ("duration_ms", Measured),
    ("elapsed_ms", Measured),
    ("overrun_ms", Measured),
    ("callback_ms", Measured),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::MANIFEST;

    #[test]
    fn every_key_is_listed_once() {
        let mut seen = BTreeSet::new();
        let twice: Vec<&str> = MANIFEST
            .iter()
            .filter(|(key, _)| !seen.insert(*key))
            .map(|(key, _)| *key)
            .collect();
        assert!(twice.is_empty(), "listed twice: {twice:?}");
    }
}
