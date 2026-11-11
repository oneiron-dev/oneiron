//! The side tables `skill_hub` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Marker (engine version string) that the built-in bootstrap skill set has been seeded. Key: ().
    SKILL_HUB_BOOTSTRAP_SEED: VaultMeta b"bootstrap_skills/seeded/v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each model pack's version a same-name update replaced, as its install receipt named it:
    /// the version the update's change notice names as `previous`, which the one-tap revert
    /// installs again once its bytes pass an install's checks (FIX 20192). One per pack name;
    /// the next same-name update replaces it and the pack's removal removes it. Key:
    /// string(pack name).
    LLM_MODEL_PACK_REPLACED: VaultMeta b"llm:model_pack_replaced:v1:" Named Admitted
        // Restore class: FIX 20192: a model pack's replaced version travels with the install
        // receipts a revert puts it back among.
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker (engine version string) that the built-in connector packs have been seeded. Key: ().
    SKILL_HUB_PACK_BUILTIN_SEED: VaultMeta b"pack.builtin.seeded.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Candidate knowledge-pack receipt. Key: lowercase hex content hash.
    SKILL_HUB_PACK_CANDIDATE: VaultMeta b"pack.candidate.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index from a claim predicate name to the pack name that owns it (exclusivity check). Key:
    /// string.
    SKILL_HUB_PACK_PREDICATE: VaultMeta b"pack.predicate.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One owner's guided setup of one exact pack source: custody refs, consent receipt refs and
    /// per-connection check results (OF-378). Key: pack name "/" hex content hash "/" principal
    /// digest.
    SKILL_HUB_PACK_SETUP: VaultMeta b"pack.setup.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Alias minted for one skill from a pack. Key: id16 + blake3(JSON hub ref).
    SKILL_HUB_PACK_SKILL_ALIAS: VaultMeta b"pack.skill-alias.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A bundled skill the owner's pack removal retired, and the pack that removed it; the pack's
    /// next install brings it back (OF-519). Key: id16.
    SKILL_HUB_PACK_SKILL_REMOVED: VaultMeta b"pack.skill-removed.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One pending Slack OAuth install awaiting its redirect (OF-519): the owner's proof snapshot,
    /// the install link's client id and redirect, and the custody the bot token takes. Key: the
    /// install state string.
    SKILL_HUB_PACK_SLACK_INSTALL: VaultMeta b"pack.slack-install.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Configured publisher provenance for a staged pack. Key: id16 + blake3(JSON hub ref).
    SKILL_HUB_PACK_SOURCE_ALIAS: VaultMeta b"pack.source-alias.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Append-only history of hub-admission receipts, keyed by receipt id. Key: string.
    SKILL_HUB_ADMISSION_HISTORY: VaultMeta b"skill_hub/admission-history/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest hub-admission receipt for one candidate entity. Key: id16.
    SKILL_HUB_ADMISSION_RECEIPT: VaultMeta b"skill_hub/admission-receipt/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Cached capability-surface projection for a hub-derived skill entity. Key: id16.
    SKILL_HUB_CAPABILITY: VaultMeta b"skill_hub/capability/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner switch (`0` off, `1` on) turning a dependency advisory hit into one owner ask on a
    /// ready marketplace fit; an absent row is on. Key: ().
    SKILL_HUB_MARKETPLACE_ADVISORY_ASK: VaultMeta b"skill_hub/marketplace-advisory-ask/v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner blocking rule (`0` off, `1` on) on one canonical marketplace content hash. Key: hash32.
    SKILL_HUB_MARKETPLACE_BLOCKED_HASH: VaultMeta b"skill_hub/marketplace-blocked-hash/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Revision (u64be) of the owner's code auto-install switch, bound into each change's consent.
    /// Key: ().
    SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL_REVISION: VaultMeta b"skill_hub/marketplace-code-auto-install-revision/v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner switch (`0` off, `1` on) for auto-installing code-bearing marketplace folders. Key: ().
    SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL: VaultMeta b"skill_hub/marketplace-code-auto-install/v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner setting (`0` rule fit, `1` owner-asked fit) choosing the fit an ordinary skill install
    /// runs; an absent row is the rule fit. Key: ().
    SKILL_HUB_MARKETPLACE_SKILL_FIT: VaultMeta b"skill_hub/marketplace-skill-fit/v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Origin marker for a hub-materialized skill (imported flag, optional forked-from parent id);
    /// survives deletion so it cannot be laundered by delete/recreate. Key: id16.
    SKILL_HUB_ORIGIN: VaultMeta b"skill_hub/origin/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Persisted hub package sidecar (custom MAGIC-framed binary envelope) for a skill entity. Key:
    /// id16.
    SKILL_HUB_PACKAGE: VaultMeta b"skill_hub/package/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One hub ref's sync policy and its seen/trusted revisions (ARCH-0053 §7). Key: id16 +
    /// string ref.
    SKILL_HUB_REF_SYNC: VaultMeta b"skill_hub/ref-sync/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker that a refinement holder's custody is permanently closed. Key: id16.
    SKILL_HUB_REFINEMENT_HOLDER_RETIRED: VaultMeta b"skill_hub/refinement-holder-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Fixed 48-byte carrier/hash binding recorded for a pending or materialized source holder. Key:
    /// id16.
    SKILL_HUB_SOURCE_BINDING: VaultMeta b"skill_hub/source-binding/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty-marker that a source holder's custody has been permanently retired. Key: id16.
    SKILL_HUB_SOURCE_RETIRED: VaultMeta b"skill_hub/source-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
