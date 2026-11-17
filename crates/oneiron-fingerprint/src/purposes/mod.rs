//! The purpose registry: every [`Purpose`] and every [`LegacyPurpose`] the engine uses,
//! one file per engine area.
//!
//! A site declares its purpose with one entry in its area file:
//!
//! ```text
//! purposes! {
//!     /// Replay digest of `tasks.post`. Parts: actor, key, brief digest, assignee.
//!     POST_REQUEST = "oneiron.tasks.post.request.v1";
//! }
//! legacy_purposes! {
//!     /// Saved-query evidence hash. SHA-256: the tag, then each field as a u64-BE
//!     /// length and its bytes. Stored in memo rows (`VerdictMemoKey.evidence_hash`).
//!     SAVED_QUERY_EVIDENCE = (Sha256, HashedFirst, "oneiron.saved_query.evidence.v2");
//! }
//! ```
//!
//! Every area file writes both blocks (an empty block is fine), and the one `areas!`
//! line below both declares the file's module and adds its purposes to the
//! distinctness assertion, so no area can be left out of it. Two purposes with one
//! context string, of either kind, do not compile.
//!
//! Rules for a string:
//! - a moved site keeps its literal exactly, with no respelling;
//! - a site that has no tag gets `oneiron.<area>.<thing>.v1`;
//! - one constant per site: a purpose is for an id or for a 32-byte fingerprint, not both;
//! - a change to what is hashed is a new version (`.v2`), declared as a new constant.

use crate::{LegacyPurpose, Purpose};

/// Declares v1 purposes, and the file's `ALL` slice for the distinctness assertion.
macro_rules! purposes {
    ($($(#[$doc:meta])* $name:ident = $context:literal;)*) => {
        $($(#[$doc])* pub const $name: $crate::Purpose = $crate::Purpose::new($context);)*
        /// Every v1 purpose this file declares.
        pub const ALL: &[$crate::Purpose] = &[$($name),*];
    };
}

/// Declares legacy purposes as `NAME = (hash, tag mode, "tag");`, and the file's
/// `LEGACY` slice for the distinctness assertion.
macro_rules! legacy_purposes {
    ($($(#[$doc:meta])* $name:ident = ($hash:ident, $tag_mode:ident, $tag:literal);)*) => {
        $($(#[$doc])* pub const $name: $crate::LegacyPurpose = $crate::LegacyPurpose::new(
            $tag,
            $crate::LegacyHash::$hash,
            $crate::TagMode::$tag_mode,
        );)*
        /// Every legacy purpose this file declares.
        pub const LEGACY: &[$crate::LegacyPurpose] = &[$($name),*];
    };
}

/// Declares each area file and collects its purposes of both kinds.
macro_rules! areas {
    ($($area:ident),* $(,)?) => {
        $(pub mod $area;)*
        const PURPOSE_FILES: &[&[Purpose]] = &[$($area::ALL),*];
        const LEGACY_FILES: &[&[LegacyPurpose]] = &[$($area::LEGACY),*];
    };
}

areas! { affect, agent, agent_def, archive, artifact_hosting, blob, booking, broker, browser_library, calendar, channel_identity, claim, cluster, code, code_run, connector, dispatch_byoa, dreamer, engine_executor, federation, feedback, git_wire, identity, ids, inbox, learning, llm, mail_pack, memory, note, origin, outbound_intent_ledger, people, policy_model, receipt, restore, retrieval, runtime_hooks, saved_query, secret, self_heal, setting, skill, skill_attribution, skill_hub, skill_optimize, store, sync, task, testing, vault_import, vault_shape, voice, web_fetch, workspace_roster, world }
