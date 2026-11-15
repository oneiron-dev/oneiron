//! K-proof (oracle) for PLAN-UC-04 stage 3.4a: the hosted legal policy hash keeps its bytes.
//!
//! `HostedLegalPolicy::derive_policy_hash` now starts its SHA-256 through the fingerprint
//! crate's K door (`purposes::policy_model::HOSTED_LEGAL_POLICY`). Its lowercase hex is the
//! policy's `policy_hash` in the relay registry, and every verdict read and attestation names
//! it and is compared with it, so it must give main's bytes for every policy. `base` below
//! holds main's lines at 5ead0741066f, copied by range (each range is named above its copy; the
//! generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing
//! from them only in indentation. The lines around the copies give the method body main's
//! name, through a trait this file declares.
//!
//! The known vector of `crates/oneiron/src/policy_model/tests/hosted_registration_relay.rs`
//! (`the_policy_hash_encodes_every_length_in_a_fixed_eight_bytes`) is checked here as well,
//! because that library test module does not build on main.
//!
//! `cargo test --locked -p oneiron-records --all-features --test fingerprint_keep_policy_hash`.

use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_policy_vocabulary::policy_model::contract::PolicyOutputContract;
use oneiron_policy_vocabulary::policy_model::pattern::{PolicyPatternRole, PolicyPatternRule};
use oneiron_records::policy_model::planes::{
    HostedLegalAction, HostedLegalBasis, HostedLegalBasisKind, HostedLegalPolicy, HostedLegalRow,
};

// Not formatted, so each copy stays line for line equal to main's. The copies keep main's
// `pub`, which this private module cannot export.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use oneiron_contracts::entity_id::bytes_to_hex_lower;
    use oneiron_policy_vocabulary::policy_model::contract::PolicyOutputContract;
    use oneiron_records::policy_model::planes::HostedLegalPolicy;
    use sha2::Digest;
    use sha2::Sha256;

    /// Main's policy hash, by main's method name.
    pub(crate) trait MainPolicyHash {
        fn derive_policy_hash(&self) -> String;
    }

    impl MainPolicyHash for HostedLegalPolicy {
        fn derive_policy_hash(&self) -> String {
    // main 5ead0741066f: crates/oneiron-records/src/policy_model/planes.rs:203-231
            let mut hasher = Sha256::new();
            hasher.update(b"oneiron.policy_model.hosted_legal.policy.v3");
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
                hash_field(&mut hasher, "row_basis_kind", row.basis.kind.as_str());
                hash_field(&mut hasher, "row_basis_subject", &row.basis.subject);
                hash_field(&mut hasher, "row_basis_reference", &row.basis.reference);
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
    }

    // main 5ead0741066f: crates/oneiron-records/src/policy_model/planes.rs:294-311
    pub fn hash_len_bytes(len: usize) -> [u8; 8] {
        (len as u64).to_be_bytes()
    }

    pub fn hash_field(hasher: &mut Sha256, label: &str, value: &str) {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(hash_len_bytes(value.len()));
        hasher.update(value.as_bytes());
        hasher.update([0xff]);
    }

    pub fn hash_len(hasher: &mut Sha256, label: &str, len: usize) {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(hash_len_bytes(len));
        hasher.update([0xff]);
    }
}

use base::MainPolicyHash as _;

/// Field values with the edges: empty, one byte, a NUL and `0xff`-looking text, unicode,
/// and a value longer than 255 bytes (its length needs two bytes of the u64).
fn texts() -> Vec<String> {
    vec![
        String::new(),
        "a".to_owned(),
        "row\0with-nul".to_owned(),
        "ÿ\u{ff}rule".to_owned(),
        "jurisdiction-日本".to_owned(),
        "x".repeat(300),
    ]
}

fn row(index: usize, action: HostedLegalAction, kind: HostedLegalBasisKind) -> HostedLegalRow {
    let texts = texts();
    let pick = |offset: usize| texts[(index + offset) % texts.len()].clone();
    HostedLegalRow {
        row_ref: pick(0),
        category: pick(1),
        action,
        text: pick(2),
        basis: HostedLegalBasis {
            kind,
            subject: pick(3),
            reference: pick(4),
        },
    }
}

fn rule(index: usize, role: PolicyPatternRole) -> PolicyPatternRule {
    let texts = texts();
    let pick = |offset: usize| texts[(index + offset) % texts.len()].clone();
    PolicyPatternRule::new(pick(5), pick(0), pick(1)).with_role(role)
}

fn row_lists() -> Vec<Vec<HostedLegalRow>> {
    let actions = [HostedLegalAction::Warn, HostedLegalAction::Block];
    let kinds = [
        HostedLegalBasisKind::Law,
        HostedLegalBasisKind::ProviderTerms,
        HostedLegalBasisKind::Capacity,
    ];
    let mut every = Vec::new();
    for (index, action) in actions.into_iter().enumerate() {
        for (offset, kind) in kinds.into_iter().enumerate() {
            every.push(row(index * kinds.len() + offset, action, kind));
        }
    }
    vec![Vec::new(), vec![every[0].clone()], every.clone(), every]
        .into_iter()
        .enumerate()
        .map(|(index, mut rows)| {
            if index == 3 {
                rows.reverse();
            }
            rows
        })
        .collect()
}

fn rule_lists() -> Vec<Vec<PolicyPatternRule>> {
    let roles = [
        PolicyPatternRole::Escalate,
        PolicyPatternRole::Decide,
        PolicyPatternRole::Log,
    ];
    let every: Vec<_> = roles
        .into_iter()
        .enumerate()
        .map(|(index, role)| rule(index, role))
        .collect();
    vec![Vec::new(), vec![every[1].clone()], every]
}

/// Every policy of the table: each text in each scalar field, each output contract and
/// none, and each row and rule list. `policy_hash` and `docs_url` are not hashed; they
/// carry text anyway.
fn policies() -> Vec<HostedLegalPolicy> {
    let contracts = [
        None,
        Some(PolicyOutputContract::Binary),
        Some(PolicyOutputContract::CategoryJson),
        Some(PolicyOutputContract::RationaleJson),
    ];
    let texts = texts();
    let mut policies = Vec::new();
    for (index, text) in texts.iter().enumerate() {
        for output_contract in contracts {
            for rows in row_lists() {
                for pattern_rules in rule_lists() {
                    policies.push(HostedLegalPolicy {
                        jurisdiction: text.clone(),
                        version: texts[(index + 1) % texts.len()].clone(),
                        policy_hash: "stale".to_owned(),
                        docs_url: "https://example.invalid/policy".to_owned(),
                        rows: rows.clone(),
                        policy_document: texts[(index + 2) % texts.len()].clone(),
                        output_contract,
                        pattern_rules,
                    });
                }
            }
        }
    }
    policies
}

#[test]
fn the_policy_purpose_keeps_main_s_tag() {
    let purpose = purposes::policy_model::HOSTED_LEGAL_POLICY;
    assert_eq!(purpose.hash(), LegacyHash::Sha256);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(purpose.tag(), "oneiron.policy_model.hosted_legal.policy.v3");
}

#[test]
fn the_policy_hash_keeps_its_bytes() {
    let policies = policies();
    assert_eq!(policies.len(), 6 * 4 * 4 * 3);
    for policy in &policies {
        let main = <HostedLegalPolicy as base::MainPolicyHash>::derive_policy_hash(policy);
        assert_eq!(policy.derive_policy_hash(), main, "{policy:?}");
        assert_eq!(main.len(), 64);
    }
}

#[test]
fn the_policy_hash_keeps_the_known_vector() {
    // `hosted_registration_relay.rs`'s fixture: `hosted_row` with the `Law` basis of
    // `test-jurisdiction` and `test-law-reference`.
    let policy = HostedLegalPolicy {
        jurisdiction: "test-jurisdiction".to_owned(),
        version: "2026-08-01".to_owned(),
        policy_hash: String::new(),
        docs_url: "https://example.invalid/hosted-policy".to_owned(),
        rows: vec![HostedLegalRow {
            row_ref: "hosted:ncii".to_owned(),
            category: "ncii".to_owned(),
            action: HostedLegalAction::Warn,
            text: "Flag intimate imagery shared without consent.".to_owned(),
            basis: HostedLegalBasis {
                kind: HostedLegalBasisKind::Law,
                subject: "test-jurisdiction".to_owned(),
                reference: "test-law-reference".to_owned(),
            },
        }],
        policy_document: "POLICY".to_owned(),
        output_contract: Some(PolicyOutputContract::Binary),
        pattern_rules: vec![PolicyPatternRule::new("p.one", "x", "hosted_legal/ncii")],
    };
    let known = "4e4df5d69b237d460e40bc05b87736f6d62b17b6c6f07f7488f8aaddb810dbc4";
    assert_eq!(policy.derive_policy_hash(), known);
    assert_eq!(
        <HostedLegalPolicy as base::MainPolicyHash>::derive_policy_hash(&policy),
        known
    );
}
