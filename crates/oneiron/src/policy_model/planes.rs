//! The two policy planes, the documents they enforce, and the rows they
//! contribute.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_id::bytes_to_hex_lower;
use crate::gate::{OwnerRowAction, PolicyManifestResolution};

use super::contract::PolicyOutputContract;
use super::pattern::PolicyPatternRule;
use super::request::PolicyClassifyRequest;
use super::verdict::PolicyClassifyDecision;

/// Category label an owner-plane ROW carries into the rubric. Owner rows are
/// free prose, so they share one label and are told apart by `row_ref` — which
/// is also the vocabulary the owner plane's policy document answers in.
pub(crate) const OWNER_POLICY_CATEGORY: &str = "owner_policy";
const HOSTED_LEGAL_CATEGORY_PREFIX: &str = "hosted_legal/";

/// Longest policy document the engine accepts, in bytes.
///
/// The reasoning-safeguard models this targets work best at roughly 400–600
/// tokens of policy and stay workable to around ten thousand; the bound here is
/// far above both, because it exists to keep a registration from carrying an
/// unbounded blob into storage, not to express a recommendation.
pub const POLICY_DOCUMENT_MAX_LEN: usize = 65_536;

/// Longest hosted-legal category label the engine accepts.
///
/// A SHAPE bound, not a vocabulary. The label is the host's own word for one
/// of its legal concerns and the engine has no opinion about which words are
/// meaningful — but the label rides into a gate reason code as written, so it
/// is bounded and tokenized on exactly the terms
/// [`POLICY_PATTERN_ID_MAX_LEN`] ids already are.
///
/// [`POLICY_PATTERN_ID_MAX_LEN`]: super::pattern::POLICY_PATTERN_ID_MAX_LEN
pub const POLICY_HOSTED_CATEGORY_MAX_LEN: usize = 64;

/// Most rows one hosted-legal policy may register.
///
/// A registration's rows are held in memory, re-read on every relay pass, and
/// rendered into the prompt the hosted model is shown, so their count is a
/// cost every pass pays. Until the rows replaced a fixed category enum the
/// shape itself capped them at four; nothing replaced that ceiling when the
/// enum went away, and a registration is a host-supplied blob.
///
/// Set to the owner plane's own rule ceiling
/// ([`POLICY_PATTERN_RULES_MAX`]) because the two hold the same kind of thing
/// — one plane's rules — and neither plane should be able to outgrow the
/// other by an order of magnitude. It is a flood stop, not a recommendation:
/// a legal policy with hundreds of distinct rows is already past what a model
/// can weigh in one pass. It REFUSES at registration rather than truncating,
/// because a silently shortened legal policy is the one failure this plane
/// exists to prevent.
///
/// [`POLICY_PATTERN_RULES_MAX`]: super::pattern::POLICY_PATTERN_RULES_MAX
pub const POLICY_HOSTED_ROWS_MAX: usize = super::pattern::POLICY_PATTERN_RULES_MAX;

/// Where a rule came from. These are the only two sources of authority in the
/// engine — there is no third, engine-authored plane underneath them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPlane {
    /// The vault owner's own rows, from the vault's policy manifest.
    OwnerPolicy,
    /// A hosted relay service's versioned legal policy.
    HostedLegal,
}

impl PolicyPlane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerPolicy => "owner_policy",
            Self::HostedLegal => "hosted_legal",
        }
    }
}

/// One row as it is shown to the classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRubricRow {
    pub row_ref: String,
    pub plane: PolicyPlane,
    pub category: String,
    pub action: PolicyClassifyDecision,
    pub text: String,
}

/// What a hosted legal row does when it fires. There is no `RouteToHelp` arm:
/// a hosted service enforcing its own legal duty withholds or annotates, and
/// help routing is a product decision that belongs to the vault owner's plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostedLegalAction {
    Warn,
    Block,
}

impl HostedLegalAction {
    #[must_use]
    pub const fn decision(self) -> PolicyClassifyDecision {
        match self {
            Self::Warn => PolicyClassifyDecision::Warn,
            Self::Block => PolicyClassifyDecision::Block,
        }
    }

    /// Ordering only, for picking the row that governs a categoryless answer.
    const fn severity(self) -> u8 {
        match self {
            Self::Warn => 0,
            Self::Block => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedLegalRow {
    pub row_ref: String,
    /// The host's own word for the concern this row covers.
    ///
    /// The engine ships NO category vocabulary. A hosted service's legal
    /// duties are whatever its jurisdiction and its counsel say they are, and
    /// a closed enum here would mean an engine release every time a host
    /// needed a concern the engine's authors had not thought of. Registration
    /// checks the label's SHAPE only — non-blank, within
    /// [`POLICY_HOSTED_CATEGORY_MAX_LEN`], ascii alphanumeric with `_`, `-` or
    /// `.` — because the label rides into a gate reason code as written.
    ///
    /// Several rows MAY share a label: two distinct legal concerns of one
    /// class are two rows, and telling them apart is what `row_ref` is for.
    /// When a model answer names a label carrying more than one row, the
    /// strictest of them governs, with registration order breaking ties.
    pub category: String,
    pub action: HostedLegalAction,
    pub text: String,
}

/// A hosted relay service's legal policy: the document it enforces, the rows a
/// verdict is routed through, the patterns it wants watched, and the published
/// version all of that is attributed to.
///
/// This is never read from the vault's own policy manifest — a vault cannot
/// name the jurisdiction it is relayed under, and a caller cannot invent one
/// per request. It reaches the relay bound to an attested service identity,
/// registered in the [`EdgeServiceRegistry`] alongside that identity.
///
/// # The document is the policy
///
/// `policy_document` is the substrate owner's own text, and it is sent to the
/// safeguard model AS THE SYSTEM MESSAGE, verbatim. The engine authors none of
/// it. The structure these models respond to is INSTRUCTIONS / DEFINITIONS /
/// VIOLATES / SAFE / EXAMPLES, with the output instruction stated at the top
/// AND repeated at the bottom, and the whole thing sized at roughly 400–600
/// tokens; that is guidance for whoever writes it, not something the engine
/// checks or supplies.
///
/// # What `policy_hash` covers
///
/// The registry DERIVES `policy_hash` at registration and replaces whatever the
/// caller set. It is a SHA-256 over, in order: the jurisdiction, the version,
/// the declared output contract, the policy document, every row
/// (`row_ref`, category, action, text) and every pattern rule (`id`, pattern,
/// category, role). It therefore covers the ENFORCED TEXT — a receipt that
/// attests this hash attests that this exact policy document was in force, and
/// changing one byte of the document produces a hash no earlier receipt can
/// match.
///
/// [`EdgeServiceRegistry`]: crate::policy_model::EdgeServiceRegistry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedLegalPolicy {
    pub jurisdiction: String,
    pub version: String,
    /// Derived by the registry. See the type doc for the exact coverage.
    pub policy_hash: String,
    pub docs_url: String,
    pub rows: Vec<HostedLegalRow>,
    /// The substrate owner's policy text, sent verbatim as the system message.
    pub policy_document: String,
    /// Which answer shape the document instructed the model to produce.
    /// Registration refuses a policy that does not declare one: the engine
    /// cannot read an answer whose shape nobody named.
    pub output_contract: Option<PolicyOutputContract>,
    /// Patterns the substrate owner wants watched. Empty by default — the
    /// engine ships none.
    pub pattern_rules: Vec<PolicyPatternRule>,
}

impl HostedLegalPolicy {
    /// The hash the registry will bind to this policy. Exposed so a caller can
    /// precompute or compare one without registering.
    #[must_use]
    pub fn derive_policy_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"oneiron.policy_model.hosted_legal.policy.v2");
        hash_field(&mut hasher, "jurisdiction", &self.jurisdiction);
        hash_field(&mut hasher, "version", &self.version);
        hash_field(
            &mut hasher,
            "output_contract",
            self.output_contract
                .map_or("none", PolicyOutputContract::as_str),
        );
        hash_field(&mut hasher, "policy_document", &self.policy_document);
        hash_len(&mut hasher, "rows", self.rows.len());
        for row in &self.rows {
            hash_field(&mut hasher, "row_ref", &row.row_ref);
            hash_field(&mut hasher, "row_category", &row.category);
            hash_field(&mut hasher, "row_action", row.action.decision().as_str());
            hash_field(&mut hasher, "row_text", &row.text);
        }
        hash_len(&mut hasher, "pattern_rules", self.pattern_rules.len());
        for rule in &self.pattern_rules {
            hash_field(&mut hasher, "rule_id", &rule.id);
            hash_field(&mut hasher, "rule_pattern", &rule.pattern);
            hash_field(&mut hasher, "rule_category", &rule.category);
            hash_field(&mut hasher, "rule_role", rule.role.as_str());
        }
        bytes_to_hex_lower(&hasher.finalize())
    }

    /// Whether `label` is a category this policy publishes — the check a
    /// pattern rule and a model answer are both held to.
    pub(crate) fn publishes_category(&self, label: &str) -> bool {
        self.row_for_category(label).is_some()
    }

    /// The row a category label routes to, or `None` when the label is not a
    /// hosted-legal category at all or the policy carries no row of it.
    ///
    /// Several rows may carry one label — two distinct legal concerns of the
    /// same class — so this resolves to the STRICTEST of them, with
    /// registration order breaking ties. Taking the first would let a later,
    /// stricter row be silently shadowed and never fire, which is the whole
    /// reason the plane used to refuse a duplicate category outright. The rule
    /// is the same one [`Self::strictest_row`] and the owner plane already
    /// apply when several rows could govern.
    pub(crate) fn row_for_category(&self, label: &str) -> Option<&HostedLegalRow> {
        let category = parse_hosted_category_label(label)?;
        strictest(self.rows.iter().filter(|row| row.category == category))
    }

    /// The row that governs a categoryless answer: the strictest row the
    /// policy registered, with registration order breaking ties. A
    /// [`PolicyOutputContract::Binary`] violation has no label to route on, so
    /// this is what it resolves to — and a policy with no rows cannot resolve
    /// one at all, which the caller treats as an unreadable answer.
    pub(crate) fn strictest_row(&self) -> Option<&HostedLegalRow> {
        strictest(self.rows.iter())
    }
}

/// The strictest row of `rows`, with the order they were registered in
/// breaking ties.
fn strictest<'a>(rows: impl Iterator<Item = &'a HostedLegalRow>) -> Option<&'a HostedLegalRow> {
    rows.reduce(|governing, row| {
        if row.action.severity() > governing.action.severity() {
            row
        } else {
            governing
        }
    })
}

/// The owner plane's rubric. Empty when the owner has not opted in — the
/// caller is expected to check [`PolicyManifestResolution::owner_policy_enabled`]
/// first and skip classification entirely, but an empty rubric is the honest
/// answer either way.
pub(crate) fn owner_rubric_rows(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Vec<PolicyRubricRow> {
    if !policy.owner_policy_enabled() {
        return Vec::new();
    }
    policy
        .active_owner_policy_rows(request.world_ref.as_deref())
        .into_iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::OwnerPolicy,
            // Owner rows share one plane label; the model answers in `row_ref`,
            // which is the only vocabulary that tells two owner rows apart.
            category: OWNER_POLICY_CATEGORY.to_owned(),
            action: owner_row_decision(row.action),
            text: row.text.clone(),
        })
        .collect()
}

/// The hosted legal plane's rubric.
pub(crate) fn hosted_rubric_rows(policy: &HostedLegalPolicy) -> Vec<PolicyRubricRow> {
    policy
        .rows
        .iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::HostedLegal,
            category: hosted_category_label(&row.category),
            action: row.action.decision(),
            text: row.text.clone(),
        })
        .collect()
}

/// The plane-qualified spelling of a hosted category. The prefix is what keeps
/// a hosted label and an owner `row_ref` from ever colliding in one namespace.
pub(crate) fn hosted_category_label(category: &str) -> String {
    format!("{HOSTED_LEGAL_CATEGORY_PREFIX}{category}")
}

/// The host's own label back out of its plane-qualified spelling, or `None`
/// when the string names no hosted category at all. The label itself is not
/// checked against a vocabulary here — the engine has none; whether the
/// POLICY publishes a row of it is
/// [`HostedLegalPolicy::publishes_category`]'s question.
pub(crate) fn parse_hosted_category_label(label: &str) -> Option<&str> {
    label.strip_prefix(HOSTED_LEGAL_CATEGORY_PREFIX)
}

const fn owner_row_decision(action: OwnerRowAction) -> PolicyClassifyDecision {
    match action {
        OwnerRowAction::Warn => PolicyClassifyDecision::Warn,
        OwnerRowAction::Block => PolicyClassifyDecision::Block,
        OwnerRowAction::RouteToHelp => PolicyClassifyDecision::RouteToHelp,
    }
}

/// Every length in the digest is encoded as a FIXED eight bytes.
///
/// `usize::to_be_bytes` is four bytes on a 32-bit target and eight on a 64-bit
/// one, so hashing it directly makes the policy hash architecture-dependent —
/// and the hash is what a receipt attests, so a 32-bit relay and a 64-bit
/// vault would never agree that they had seen the same policy and the
/// attestation would fail closed forever. `gate::hash_len` already casts for
/// the same reason.
fn hash_len_bytes(len: usize) -> [u8; 8] {
    (len as u64).to_be_bytes()
}

fn hash_field(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(hash_len_bytes(value.len()));
    hasher.update(value.as_bytes());
    hasher.update([0xff]);
}

fn hash_len(hasher: &mut Sha256, label: &str, len: usize) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(hash_len_bytes(len));
    hasher.update([0xff]);
}
