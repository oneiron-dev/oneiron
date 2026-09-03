//! Dreamer proactive-help × pack catalog (ONE-1707).
//!
//! ARCH-0067 §5: "the Dreamer may *suggest* packs (proposal rows on the board
//! and app surface; accept = the same gated install; disableable,
//! digest-not-nag)". This module is the analyze→propose half of that
//! sentence and nothing else.
//!
//! Four laws shape everything below.
//!
//! 1. **Suggesting is not installing.** [`run_plugin_suggestion_job`] ends the
//!    moment ONE-1706's Generated/Proposed claim exists. It performs zero hub
//!    import, zero skill activation, zero registry mutation, and zero package
//!    install. The post-consent executor — reached only through owner
//!    acceptance — does those, under that same approved claim. Rejection does
//!    none of them.
//! 2. **The catalog is a read-only local adapter, not a marketplace.**
//!    [`PackCatalog`] is an interface; [`LocalSkillHubPackCatalog`] reads the
//!    existing [`SkillHubAdapter`] discovery/fetch doors and writes nothing.
//!    OF-377 (a cloud pack store) remains an IDEA, and the trait is precisely
//!    what stops this ticket from pretending otherwise.
//! 3. **One key, one boundary form.** [`PluginSuggestionKey`] is `[u8; 32]`
//!    internally. Every persisted, surfaced, or deduped field carries the
//!    canonical lowercase 64-character hex `String` produced by a single
//!    `to_hex()` at the boundary. The private bytes are never serialized and
//!    there is no second textual encoding.
//! 4. **Digest, not nag.** Suppression is derived from the durable install
//!    claims themselves — not a timer, not a cadence key. An unchanged
//!    suggestion stays quiet in the next window *even after rejection*;
//!    changed evidence or changed package bytes produce a different digest,
//!    and therefore a different key, and are eligible again.
//!
//! The knob is read FIRST. When plugin suggestions are off, this module
//! returns [`PluginSuggestionDisposition::Disabled`] before the catalog is
//! consulted at all — no discovery, no fetch, no claim, no row.

use std::collections::BTreeSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::ClaimSource;
use crate::context_board::{
    PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload, PluginInstallOrigin,
    PluginInstallSource, PluginInstallTarget, PluginProposalRow, PluginResult, PluginSuggestionKey,
    SectionBindingResolver, SectionManifestEnvelope, decode_section_manifest,
    encode_section_manifest, propose_plugin_section_install_with_evidence, section_manifest_digest,
};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome,
};
use crate::entity_id::EntityId;
use crate::skill_hub::{HubPin, HubRef, SkillHubAdapter};
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteProvenance};

/// Payload attempt type carried on the EXISTING generic Dreamer queue kind.
///
/// A payload discriminator, not a new queue kind: a second kind would split
/// run-root Inbox grouping and duplicate the lease/retry/budget semantics the
/// Dreamer runner already owns.
pub const DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE: &str = "dreamer.plugin_suggest";

/// Conventional in-package path of a pack's typed section manifest.
///
/// Engine vocabulary, not product copy: a package that does not ship this
/// file simply contributes no section candidate.
pub const PACK_SECTION_MANIFEST_PATH: &str = "section_manifest.mp";

/// Domain separator for the suggestion key. Pinned: changing it renames every
/// suggestion and would un-suppress everything already answered.
const PLUGIN_SUGGESTION_KEY_DOMAIN: &[u8] = b"oneiron.plugin_suggestion.v1";

/// Bound on the install-claim scan the duplicate check performs.
const PLUGIN_SUGGESTION_ATTEMPT_INPUT_KEYS: [&str; 5] = [
    "pattern_key",
    "intent",
    "digest_window",
    "observed_at",
    "evidence_refs",
];

/// Write-envelope provenance keys that mark a Dreamer-run write.
///
/// These mirror `gate.rs`'s private reader over the SAME wire map. `gate.rs`
/// is READ-ONLY for this ticket, so it keeps its copy and this module owns
/// this one — the identical arrangement `task_verb` already uses.
const DREAMER_PROVENANCE_RUNNER_KEY: &str = "runner";
const DREAMER_PROVENANCE_RUN_ID_KEY: &str = "run_id";
const DREAMER_PROVENANCE_ATTEMPT_TYPE_KEY: &str = "attempt_type";

// ---------------------------------------------------------------------------
// §2 — the typed notice and job
// ---------------------------------------------------------------------------

/// One observed workflow pattern the Dreamer may act on.
///
/// TYPED, never raw conversation. `pattern_key` is a stable identifier for
/// the pattern (not prose), `summary` is owner-facing narration, and
/// `evidence_refs` are the entities that actually justify the observation.
/// Raw conversation text is never an install command: nothing in this module
/// parses `summary`, and the key is computed from `pattern_key` alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPatternNotice {
    pub pattern_key: String,
    pub summary: String,
    /// Entities the observation rests on. These become the claim's
    /// candidate evidence, which GATE-12's evidence floor requires of every
    /// Dreamer-authored claim: a suggestion that cites nothing is exactly
    /// what the floor exists to refuse.
    pub evidence_refs: Vec<EntityId>,
    pub observed_at: u64,
}

/// One suggestion job: a notice, the run that produced it, and the digest
/// window it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSuggestJob {
    pub run_id: String,
    pub digest_window: String,
    pub notice: WorkflowPatternNotice,
}

// ---------------------------------------------------------------------------
// §3 — the catalog interface and its local adapter
// ---------------------------------------------------------------------------

/// One pack the catalog offers for a notice, with EXACT package identity.
///
/// The manifest travels with the candidate so the proposal can be validated
/// against real fetched bytes before any claim opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackCandidate {
    pub hub_ref: HubRef,
    /// Preallocated destination for the skill row. Nothing is written here
    /// before consent — ONE-1706's payload carries it so the post-consent
    /// import has a ref to land at and a restart can re-find it.
    pub target_skill_ref: EntityId,
    pub pack_id: String,
    pub label: String,
    pub description: String,
    pub version: String,
    pub content_hash_hex: String,
    pub manifest: SectionManifestEnvelope,
}

/// Maps a workflow notice to deterministic pack candidates.
///
/// An INTERFACE over a local read-only source. It is deliberately not a
/// service, a database, a ranking engine, or a purchase flow: OF-377's cloud
/// pack store is an IDEA, and this trait is the seam that keeps this ticket
/// from shipping a pretend version of it.
pub trait PackCatalog {
    /// Returns the candidates for a notice, in deterministic order.
    ///
    /// # Errors
    ///
    /// Adapter/storage errors from the underlying read-only source.
    fn candidates(&self, notice: &WorkflowPatternNotice) -> PluginResult<Vec<PackCandidate>>;
}

/// The local adapter: discovery + exact fetch over an existing skill hub.
///
/// READ-ONLY by construction. It calls only [`SkillHubAdapter::discover`] and
/// [`SkillHubAdapter::fetch_package`], and imports nothing — the whole point
/// of ONE-1706's two-phase validation is that an uninstalled package can be
/// inspected byte-exactly before consent without a single byte being written.
pub struct LocalSkillHubPackCatalog<'a> {
    pub adapter: &'a dyn SkillHubAdapter,
}

impl PackCatalog for LocalSkillHubPackCatalog<'_> {
    fn candidates(&self, notice: &WorkflowPatternNotice) -> PluginResult<Vec<PackCandidate>> {
        let mut candidates = Vec::new();
        for entry in self.adapter.discover()? {
            // The pin is the exact content hash the index advertised, so the
            // fetch below cannot silently resolve to different bytes.
            let Ok(hub_ref) = HubRef::new(
                self.adapter.hub_id(),
                entry.ref_string.clone(),
                HubPin::ContentHash(entry.content_hash.to_hex()),
            ) else {
                continue;
            };
            let Ok(package) = self.adapter.fetch_package(&hub_ref) else {
                continue;
            };
            let Ok(content_hash) = package.content_hash() else {
                continue;
            };
            // A pack with no manifest, or one that does not strictly decode,
            // contributes nothing. It is skipped, never guessed at.
            let Some(file) = package
                .files
                .iter()
                .find(|file| file.path == PACK_SECTION_MANIFEST_PATH)
            else {
                continue;
            };
            let Ok(mut manifest) = decode_section_manifest(&file.content) else {
                continue;
            };
            // The match rule is TYPED, not prose: a notice names a workflow
            // pattern, and a pack declares the state family it serves. No
            // substring search over descriptions, and so no consumer copy in
            // engine code.
            if manifest.manifest.state_family.family != notice.pattern_key {
                continue;
            }
            // The pack supplies the RECIPE; the ENGINE supplies the IDENTITY.
            //
            // Two reasons, and both matter. A manifest shipped INSIDE the
            // package cannot state that package's own content hash — the
            // manifest file is part of the hashed tree, so the hash would
            // have to contain itself. And a pack trusted to declare its own
            // identity is no evidence of identity at all. So the exact
            // fetched bytes' hash and the record's own id/version are stamped
            // here, and ONE-1706's proposal validation then re-derives them
            // from the same package and refuses any disagreement.
            manifest.manifest.provenance.content_hash_hex = content_hash.to_hex();
            manifest.manifest.provenance.skill_id = package.record.skill_id.clone();
            manifest.manifest.provenance.skill_version = package.record.version.clone();
            candidates.push(PackCandidate {
                hub_ref,
                target_skill_ref: EntityId::now(),
                pack_id: manifest.manifest.provenance.pack_id.clone(),
                label: manifest.manifest.name.clone(),
                description: package.record.desc.clone(),
                version: package.record.version.clone(),
                content_hash_hex: content_hash.to_hex(),
                manifest,
            });
        }
        // Deterministic order regardless of how the adapter enumerated.
        candidates.sort_by(|left, right| {
            (&left.pack_id, &left.version).cmp(&(&right.pack_id, &right.version))
        });
        Ok(candidates)
    }
}

/// Catalog double for tests, gated behind the existing `test-support`
/// feature the self dev-dependency already enables.
///
/// `calls` is load-bearing, not decoration: it is how a test PROVES the knob
/// short-circuits before catalog access rather than merely discarding the
/// result.
#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct TestPackCatalog {
    pub entries: Vec<PackCandidate>,
    pub calls: std::cell::Cell<usize>,
}

#[cfg(feature = "test-support")]
impl PackCatalog for TestPackCatalog {
    fn candidates(&self, _notice: &WorkflowPatternNotice) -> PluginResult<Vec<PackCandidate>> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.entries.clone())
    }
}

// ---------------------------------------------------------------------------
// §4 — the one key
// ---------------------------------------------------------------------------

/// Computes the suggestion key over the evidence pattern, the exact package
/// identity, and the exact manifest digest.
///
/// Every field is LENGTH-PREFIXED before hashing so no two different tuples
/// can collide by concatenation (`"ab" + "c"` must not hash as `"a" + "bc"`).
/// Changing the observed pattern, the pack, its version, or one byte of the
/// manifest all produce a different key — which is exactly what makes
/// "unchanged stays quiet, changed becomes eligible" true rather than hoped
/// for.
///
/// # Errors
///
/// [`PluginSectionError::ManifestCodec`] when the candidate's manifest does
/// not canonically encode. The blueprint sketched an infallible signature;
/// the encode genuinely can fail, and returning the error is the only
/// spelling that neither panics nor invents a key from partial bytes.
pub fn plugin_suggestion_key(
    notice: &WorkflowPatternNotice,
    candidate: &PackCandidate,
) -> PluginResult<PluginSuggestionKey> {
    let manifest_bytes = encode_section_manifest(&candidate.manifest)?;
    let manifest_digest = section_manifest_digest(&manifest_bytes);

    let mut hasher = Sha256::new();
    hasher.update(PLUGIN_SUGGESTION_KEY_DOMAIN);
    for field in [
        notice.pattern_key.as_str(),
        candidate.pack_id.as_str(),
        candidate.version.as_str(),
    ] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(manifest_digest);
    Ok(PluginSuggestionKey::from_digest(hasher.finalize().into()))
}

// ---------------------------------------------------------------------------
// §5 — enqueue on the existing generic Dreamer queue
// ---------------------------------------------------------------------------

/// Enqueues one suggestion attempt on the EXISTING generic Dreamer queue
/// kind, deduped by the suggestion key.
///
/// The attempt's `dedupe_key` is the canonical hex of the suggestion key, so
/// two concurrent runs that reached the same conclusion collapse into one
/// attempt instead of racing to mint two claims about the same pack. No queue,
/// lease, retry, budget, or run-tree machinery is duplicated here — this is
/// one payload type on the runner's own door.
///
/// # Errors
///
/// Storage and queue errors from the Dreamer runner store.
pub fn enqueue_plugin_suggestion(
    store: &DreamerRunnerStore<'_>,
    job: &PluginSuggestJob,
    suggestion_key: &PluginSuggestionKey,
    now: u64,
) -> PluginResult<EnqueueDreamerAttemptOutcome> {
    Ok(store.enqueue(EnqueueDreamerAttempt {
        attempt_type: DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE.to_owned(),
        input: plugin_suggest_attempt_input(job),
        parent_attempt: None,
        // The single boundary conversion for THIS crossing.
        dedupe_key: Some(suggestion_key.to_hex()),
        run_id: Some(job.run_id.clone()),
        now,
    })?)
}

/// The attempt payload's typed input map.
///
/// `intent` is the key the Inbox run-brief reader already looks for, so the
/// owner's group card is headlined by the Dreamer's own words rather than a
/// generic label. The summary is DATA carried from the notice; no product
/// copy is authored here.
fn plugin_suggest_attempt_input(job: &PluginSuggestJob) -> Value {
    let [
        pattern_key,
        intent,
        digest_window,
        observed_at,
        evidence_refs,
    ] = PLUGIN_SUGGESTION_ATTEMPT_INPUT_KEYS;
    Value::Map(vec![
        (
            Value::from(pattern_key),
            Value::from(job.notice.pattern_key.as_str()),
        ),
        (
            Value::from(intent),
            Value::from(job.notice.summary.as_str()),
        ),
        (
            Value::from(digest_window),
            Value::from(job.digest_window.as_str()),
        ),
        (
            Value::from(observed_at),
            Value::from(job.notice.observed_at),
        ),
        (
            Value::from(evidence_refs),
            Value::Array(
                job.notice
                    .evidence_refs
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
    ])
}

// ---------------------------------------------------------------------------
// §6 — analyze → propose
// ---------------------------------------------------------------------------

/// What one suggestion job concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginSuggestionDisposition {
    /// The owner switched suggestions off. Returned BEFORE catalog access.
    Disabled,
    /// The catalog offered nothing for this pattern.
    NoMatch,
    /// This exact suggestion was already put to the owner. Suppressed
    /// whatever the owner decided — including rejection.
    SuppressedDuplicate {
        /// Canonical lowercase 64-character hex.
        suggestion_key: String,
    },
    /// One Generated/Proposed install claim now exists, awaiting consent.
    Proposed {
        /// Canonical lowercase 64-character hex.
        suggestion_key: String,
        install_claim_id: EntityId,
        board_row: PluginProposalRow,
    },
}

/// Runs one suggestion job: knob → catalog → dedupe → ONE proposed claim.
///
/// The function ENDS at the Proposed claim. It imports no package bytes,
/// activates no skill, touches no registry, and installs nothing. Owner
/// acceptance later drives ONE-1706's post-consent executor, which does the
/// checked import and the Candidate→Active admission under that same approved
/// claim — one consent covering install plus section admission, never two
/// prompts and never an autonomous install.
///
/// `source` is the read-only exact-byte source the proposal validation uses.
/// It is a separate parameter from `catalog` because they answer different
/// questions — "which packs suit this pattern" versus "what are this
/// package's exact bytes" — and because handing ONE-1706's door the same
/// unmodified `PluginInstallSource` it already takes is what keeps this a
/// reuse of the gated path rather than a second one.
///
/// # Errors
///
/// Storage errors, catalog errors, and any [`PluginSectionError`] the
/// ONE-1706 proposal door raises for a manifest that fails validation.
pub fn run_plugin_suggestion_job<C: PackCatalog + ?Sized>(
    vault: &Vault,
    catalog: &C,
    source: &dyn PluginInstallSource,
    job: &PluginSuggestJob,
    actor: WriteActor,
    bindings: &dyn SectionBindingResolver,
    now: u64,
) -> PluginResult<PluginSuggestionDisposition> {
    // The knob is read FIRST and short-circuits before anything observable:
    // no discovery, no fetch, no claim, no row. "Off" has to mean silent, not
    // "did the work then discarded it".
    if !vault.plugin_suggestions_enabled()? {
        return Ok(PluginSuggestionDisposition::Disabled);
    }

    let candidates = catalog.candidates(&job.notice)?;
    if candidates.is_empty() {
        return Ok(PluginSuggestionDisposition::NoMatch);
    }

    let already_asked = proposed_suggestion_keys(vault)?;
    let mut suppressed: Option<String> = None;

    for candidate in &candidates {
        // ONE conversion, at this boundary. The resulting String is what the
        // origin, the disposition, and the dedupe surface all carry.
        let suggestion_key = plugin_suggestion_key(&job.notice, candidate)?.to_hex();
        if already_asked.contains(&suggestion_key) {
            // Digest-not-nag: the owner has already seen this exact question.
            // Suppression is independent of the ANSWER — a rejected pack that
            // has not changed stays quiet rather than being asked again.
            suppressed.get_or_insert(suggestion_key);
            continue;
        }

        let origin = PluginInstallOrigin::DreamerSuggestion {
            run_id: job.run_id.clone(),
            suggestion_key: suggestion_key.clone(),
            digest_window: job.digest_window.clone(),
        };
        let proposal = propose_plugin_section_install_with_evidence(
            vault,
            actor,
            dreamer_suggestion_provenance(job)?,
            PluginInstallTarget::HubPackage {
                hub_ref: candidate.hub_ref.clone(),
                target_skill_ref: candidate.target_skill_ref,
            },
            &candidate.manifest,
            origin.clone(),
            source,
            bindings,
            Some(notice_evidence(&job.notice)),
            now,
        )?;

        return Ok(PluginSuggestionDisposition::Proposed {
            suggestion_key,
            install_claim_id: proposal.claim_id,
            board_row: PluginProposalRow {
                install_claim_id: proposal.claim_id,
                origin,
                pack_id: candidate.pack_id.clone(),
                section_id: candidate.manifest.manifest.section_id.clone(),
                label: candidate.label.clone(),
                awaiting_owner_consent: true,
            },
        });
    }

    Ok(
        suppressed.map_or(PluginSuggestionDisposition::NoMatch, |suggestion_key| {
            PluginSuggestionDisposition::SuppressedDuplicate { suggestion_key }
        }),
    )
}

/// Every suggestion key an install claim has ever carried.
///
/// Derived from the durable claims themselves, with NO status filter: an
/// approved, retracted, rejected, or still-pending claim all count as "the
/// owner has already been asked this". That is the whole of digest-not-nag —
/// there is no timer, no cadence key, and no separate suppression store to
/// fall out of sync with the claims.
fn proposed_suggestion_keys(vault: &Vault) -> PluginResult<BTreeSet<String>> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(crate::error::Error::from)?;
    let rows = vault.claims_with_predicate_in_txn(&rtxn, PREDICATE_PLUGIN_SECTION_INSTALL)?;
    drop(rtxn);

    let mut keys = BTreeSet::new();
    for (_, body) in rows {
        let Ok(payload) = PluginInstallClaimPayload::from_value(&body.value) else {
            continue;
        };
        if let PluginInstallOrigin::DreamerSuggestion { suggestion_key, .. } = payload.origin {
            keys.insert(suggestion_key);
        }
    }
    Ok(keys)
}

/// The Dreamer write provenance the pending-consent row groups on.
///
/// The exact keys `pending_consent_dreamer_run_id` reads: the Dreamer runner
/// marker and the exact run id, on an Agent-actor envelope stamping a
/// Generated/Proposed claim. Without them the proposal would land with no run
/// id and never reach the owner's Inbox group.
fn dreamer_suggestion_provenance(job: &PluginSuggestJob) -> PluginResult<WriteProvenance> {
    Ok(WriteProvenance::new(Value::Map(vec![
        (
            Value::from(DREAMER_PROVENANCE_RUNNER_KEY),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (
            Value::from(DREAMER_PROVENANCE_RUN_ID_KEY),
            Value::from(job.run_id.as_str()),
        ),
        (
            Value::from(DREAMER_PROVENANCE_ATTEMPT_TYPE_KEY),
            Value::from(DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE),
        ),
    ]))?)
}

/// The notice's observations as candidate evidence.
///
/// `chain` is empty because a suggestion descends from observations, not from
/// a consolidation lineage; `source_meet` is `Generated` because a suggestion
/// is exactly that — the Dreamer's own inference over those refs.
fn notice_evidence(notice: &WorkflowPatternNotice) -> Value {
    encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: notice.evidence_refs.clone(),
        chain: Vec::new(),
        source_meet: ClaimSource::Generated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_board::{
        AuthorityLaneRef, BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF,
        SECTION_MANIFEST_SCHEMA_VERSION, SectionId, SectionManifest, SectionManifestProvenance,
        SectionVerbRef, StateFamilyRef,
    };

    const PACK_HASH_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn hub_ref() -> HubRef {
        HubRef::new(
            EntityId::from_bytes([0x22; 16]).unwrap(),
            "demo-pack@1.0.0",
            HubPin::ContentHash(PACK_HASH_HEX.to_owned()),
        )
        .unwrap()
    }

    fn manifest(name: &str) -> SectionManifestEnvelope {
        SectionManifestEnvelope {
            schema_version: SECTION_MANIFEST_SCHEMA_VERSION,
            manifest: SectionManifest {
                section_id: SectionId("demo_rows".to_owned()),
                name: name.to_owned(),
                state_family: StateFamilyRef {
                    family: "demo.rows".to_owned(),
                    version: 1,
                },
                verbs: vec![SectionVerbRef("board.expand".to_owned())],
                authority_lane: AuthorityLaneRef("plugin.demo".to_owned()),
                budget_policy: BudgetPolicyRef(PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned()),
                provenance: SectionManifestProvenance {
                    pack_id: "demo-pack".to_owned(),
                    skill_id: "sk_demo".to_owned(),
                    skill_version: "1.0.0".to_owned(),
                    content_hash_hex: PACK_HASH_HEX.to_owned(),
                },
            },
        }
    }

    fn candidate(name: &str, version: &str) -> PackCandidate {
        PackCandidate {
            hub_ref: hub_ref(),
            target_skill_ref: EntityId::from_bytes([0x33; 16]).unwrap(),
            pack_id: "demo-pack".to_owned(),
            label: name.to_owned(),
            description: "demo".to_owned(),
            version: version.to_owned(),
            content_hash_hex: PACK_HASH_HEX.to_owned(),
            manifest: manifest(name),
        }
    }

    fn notice(pattern_key: &str) -> WorkflowPatternNotice {
        WorkflowPatternNotice {
            pattern_key: pattern_key.to_owned(),
            summary: "observed a repeated manual workflow".to_owned(),
            evidence_refs: vec![EntityId::from_bytes([0x44; 16]).unwrap()],
            observed_at: 1_000,
        }
    }

    #[test]
    fn suggestion_key_is_stable_and_canonical_at_the_boundary() {
        let key = plugin_suggestion_key(&notice("demo.rows"), &candidate("Demo", "1.0.0"))
            .expect("key computes");
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "the boundary form is canonical lowercase hex"
        );
        // Same inputs ⇒ same key: this is what suppression depends on.
        assert_eq!(
            plugin_suggestion_key(&notice("demo.rows"), &candidate("Demo", "1.0.0"))
                .expect("key recomputes"),
            key
        );
        // The private bytes round-trip through the boundary form and nothing
        // else — one internal representation, one textual encoding.
        assert_eq!(
            PluginSuggestionKey::parse_hex(&hex).expect("round trip"),
            key
        );
    }

    #[test]
    fn changed_pattern_pack_version_or_manifest_all_change_the_key() {
        let base = plugin_suggestion_key(&notice("demo.rows"), &candidate("Demo", "1.0.0"))
            .expect("base key");

        let other_pattern =
            plugin_suggestion_key(&notice("other.rows"), &candidate("Demo", "1.0.0"))
                .expect("pattern key");
        assert_ne!(base, other_pattern, "a changed pattern is eligible again");

        let other_version =
            plugin_suggestion_key(&notice("demo.rows"), &candidate("Demo", "2.0.0"))
                .expect("version key");
        assert_ne!(base, other_version, "a changed version is eligible again");

        // One byte of manifest difference (the display name) is enough.
        let other_manifest =
            plugin_suggestion_key(&notice("demo.rows"), &candidate("Demo2", "1.0.0"))
                .expect("manifest key");
        assert_ne!(
            base, other_manifest,
            "changed manifest bytes produce a new digest"
        );

        let mut pack_renamed = candidate("Demo", "1.0.0");
        pack_renamed.pack_id = "other-pack".to_owned();
        assert_ne!(
            base,
            plugin_suggestion_key(&notice("demo.rows"), &pack_renamed).expect("pack key"),
            "a different pack is a different suggestion"
        );
    }

    /// Length prefixing is what stops two different tuples from hashing the
    /// same way by concatenation.
    #[test]
    fn field_boundaries_cannot_be_shifted_between_fields() {
        let mut left = candidate("Demo", "1.0.0");
        left.pack_id = "ab".to_owned();
        left.version = "c".to_owned();
        let mut right = candidate("Demo", "1.0.0");
        right.pack_id = "a".to_owned();
        right.version = "bc".to_owned();
        assert_ne!(
            plugin_suggestion_key(&notice("demo.rows"), &left).expect("left"),
            plugin_suggestion_key(&notice("demo.rows"), &right).expect("right"),
        );
    }

    #[test]
    fn attempt_input_carries_the_run_brief_intent_key() {
        let job = PluginSuggestJob {
            run_id: "run_1".to_owned(),
            digest_window: "2026-08-19".to_owned(),
            notice: notice("demo.rows"),
        };
        let Value::Map(entries) = plugin_suggest_attempt_input(&job) else {
            panic!("attempt input is a map");
        };
        let intent = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("intent"))
            .map(|(_, value)| value.clone())
            .expect("the Inbox headline reads `intent`");
        assert_eq!(intent.as_str(), Some(job.notice.summary.as_str()));
    }

    #[test]
    fn dreamer_provenance_carries_the_runner_marker_and_exact_run_id() {
        let job = PluginSuggestJob {
            run_id: "run_7".to_owned(),
            digest_window: "2026-08-19".to_owned(),
            notice: notice("demo.rows"),
        };
        let provenance = dreamer_suggestion_provenance(&job).expect("provenance");
        let Value::Map(entries) = provenance.value() else {
            panic!("provenance is a map");
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned)
        };
        // Exactly the pair `pending_consent_dreamer_run_id` reads.
        assert_eq!(
            get("runner").as_deref(),
            Some(DREAMER_RUNNER_ATTEMPT_KIND),
            "the runner marker is what makes this a Dreamer-run write"
        );
        assert_eq!(get("run_id").as_deref(), Some("run_7"));
    }

    /// The local adapter surfaces only packs that both ship a strictly
    /// decodable manifest AND declare the state family the notice names. A
    /// manifest-less pack, an undecodable one, and an unrelated one are all
    /// SKIPPED — and discovery/fetch write nothing, so nothing is installed
    /// before consent.
    #[test]
    fn local_catalog_skips_invalid_and_unrelated_rows_and_imports_nothing() {
        use crate::claim::ClaimApprovalStatus;
        use crate::skill::{SkillLifecycle, SkillRecord};
        use crate::skill_hub::{
            HubFile, HubIndexEntry, HubPackage, SkillCapabilitySurface, SkillHubKind,
        };

        struct Hub {
            packages: Vec<(HubIndexEntry, HubPackage)>,
        }

        impl SkillHubAdapter for Hub {
            fn hub_id(&self) -> EntityId {
                EntityId::from_bytes([0x22; 16]).unwrap()
            }
            fn kind(&self) -> SkillHubKind {
                SkillHubKind::LocalDir
            }
            fn fetch_package(&self, hub_ref: &HubRef) -> crate::error::Result<HubPackage> {
                self.packages
                    .iter()
                    .find(|(entry, _)| entry.ref_string == hub_ref.ref_string)
                    .map(|(_, package)| package.clone())
                    .ok_or(crate::error::Error::EntityNotFound)
            }
            fn discover(&self) -> crate::error::Result<Vec<HubIndexEntry>> {
                Ok(self
                    .packages
                    .iter()
                    .map(|(entry, _)| entry.clone())
                    .collect())
            }
        }

        fn package(skill_id: &str, files: Vec<HubFile>) -> HubPackage {
            HubPackage::new(
                SkillRecord::new(
                    skill_id,
                    "pack",
                    "1.0.0",
                    ClaimApprovalStatus::Auto,
                    SkillLifecycle::Candidate,
                    ClaimSource::Imported,
                    0.5,
                    false,
                    true,
                    Vec::new(),
                    Value::Map(vec![(Value::from("hub"), Value::from("local"))]),
                ),
                files,
                SkillCapabilitySurface::default(),
            )
        }

        // The pack ships its RECIPE. Whatever identity it claims is
        // overwritten by the engine, so the shipped provenance is a
        // placeholder on purpose — a pack cannot vouch for itself.
        let mut shipped = manifest("Good");
        shipped.manifest.provenance.skill_id = "sk_lies".to_owned();
        shipped.manifest.provenance.skill_version = "9.9.9".to_owned();
        let good = package(
            "sk_good",
            vec![HubFile::new(
                PACK_SECTION_MANIFEST_PATH,
                encode_section_manifest(&shipped).unwrap(),
            )],
        );
        let good_hash = good.content_hash().unwrap();

        let bare = package(
            "sk_bare",
            vec![HubFile::new("SKILL.md", b"# no manifest".to_vec())],
        );
        let bare_hash = bare.content_hash().unwrap();
        let broken = package(
            "sk_broken",
            vec![HubFile::new(
                PACK_SECTION_MANIFEST_PATH,
                b"not messagepack".to_vec(),
            )],
        );
        let broken_hash = broken.content_hash().unwrap();

        let entry = |name: &str, hash, package: HubPackage| {
            (
                HubIndexEntry {
                    name: name.to_owned(),
                    description: "pack".to_owned(),
                    version: "1.0.0".to_owned(),
                    content_hash: hash,
                    ref_string: format!("{name}@1.0.0"),
                },
                package,
            )
        };
        let hub = Hub {
            packages: vec![
                entry("good", good_hash, good),
                entry("bare", bare_hash, bare),
                entry("broken", broken_hash, broken),
            ],
        };

        let catalog = LocalSkillHubPackCatalog { adapter: &hub };
        // The manifest declares `demo.rows`; only a notice naming that
        // pattern matches, and only the well-formed pack survives.
        let matched = catalog
            .candidates(&notice("demo.rows"))
            .expect("catalog reads");
        assert_eq!(
            matched.len(),
            1,
            "manifest-less and broken rows are skipped"
        );
        // The ENGINE's identity won, not the pack's claim.
        assert_eq!(matched[0].content_hash_hex, good_hash.to_hex());
        assert_eq!(
            matched[0].manifest.manifest.provenance.content_hash_hex,
            good_hash.to_hex()
        );
        assert_eq!(matched[0].manifest.manifest.provenance.skill_id, "sk_good");
        assert_eq!(
            matched[0].manifest.manifest.provenance.skill_version,
            "1.0.0"
        );

        assert!(
            catalog
                .candidates(&notice("unrelated.pattern"))
                .expect("catalog reads")
                .is_empty(),
            "a pack for another state family is not a candidate"
        );
    }

    #[test]
    fn notice_evidence_carries_every_observed_ref() {
        let observed = notice("demo.rows");
        let decoded = crate::dreamer_consolidation::decode_consolidation_evidence(
            &notice_evidence(&observed),
        )
        .expect("evidence decodes")
        .expect("evidence is an envelope");
        assert_eq!(decoded.refs, observed.evidence_refs);
        assert_eq!(decoded.source_meet, ClaimSource::Generated);
    }
}
