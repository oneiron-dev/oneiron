//! Hosted policy registration accountability, row-ref dedup, policy hashes, hosted relay plane.

use super::*;

#[test]
fn hosted_registration_rejects_a_policy_it_could_not_enforce() {
    let long_id = "x".repeat(POLICY_PATTERN_ID_MAX_LEN + 1);
    let long_pattern = "a".repeat(POLICY_PATTERN_MAX_LEN + 1);
    let too_many: Vec<PolicyPatternRule> = (0..=POLICY_PATTERN_RULES_MAX)
        .map(|index| escalate_rule(&format!("rule.{index}"), "(?i)bomb"))
        .collect();

    for (field, policy) in [
        (
            "docs_url",
            HostedLegalPolicy {
                docs_url: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "docs_url",
            HostedLegalPolicy {
                docs_url: "   ".to_owned(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "version",
            HostedLegalPolicy {
                version: "v".repeat(65),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "version",
            HostedLegalPolicy {
                version: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "jurisdiction",
            HostedLegalPolicy {
                jurisdiction: "j".repeat(1024),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "policy_document",
            HostedLegalPolicy {
                policy_document: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "policy_document",
            HostedLegalPolicy {
                policy_document: "d".repeat(POLICY_DOCUMENT_MAX_LEN + 1),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "output_contract",
            HostedLegalPolicy {
                output_contract: None,
                ..hosted_serious_crime_block()
            },
        ),
        (
            "pattern_rule_pattern",
            hosted_policy_with_rules(vec![escalate_rule("hosted.broken", "bomb(")]),
        ),
        (
            "pattern_rule_pattern",
            hosted_policy_with_rules(vec![escalate_rule("hosted.long", &long_pattern)]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("   ", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule(&long_id, "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("has a space", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![
                escalate_rule("hosted.same", "(?i)bomb"),
                escalate_rule("hosted.same", "(?i)build"),
            ]),
        ),
        (
            "pattern_rule_category",
            hosted_policy_with_rules(vec![PolicyPatternRule::new(
                "hosted.offplane",
                "(?i)bomb",
                "hosted_legal/ncii",
            )]),
        ),
        (
            "pattern_rule_category",
            hosted_policy_with_rules(vec![PolicyPatternRule::new(
                "hosted.owner",
                "(?i)bomb",
                "owner_policy",
            )]),
        ),
        ("pattern_rules", hosted_policy_with_rules(too_many)),
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, policy)
            .expect_err("an unenforceable hosted policy must be rejected at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid,
            "field: {field}"
        );
        assert!(format!("{err}").contains(field), "field: {field}");
        // The rejection is total: nothing partial was bound to the service.
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }
}

#[test]
fn a_hosted_policy_docs_url_must_be_https() {
    // `docs_url` becomes the link a notice hands the reader to go read the rule
    // they were judged under. A non-https scheme there is either not a document
    // at all, or one that can be rewritten between us and them.
    for docs_url in [
        "http://policy.example.test/hosted",
        "javascript:alert(1)",
        "data:text/html,<p>policy</p>",
        "policy.example.test/hosted",
        "ftp://policy.example.test/hosted",
        // A bare scheme passes a prefix check and points at nothing.
        "https://",
        "HTTPS://",
        "https://   ",
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                HostedLegalPolicy {
                    docs_url: docs_url.to_owned(),
                    ..hosted_serious_crime_block()
                },
            )
            .expect_err("a non-https docs_url must be rejected at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid,
            "docs_url: {docs_url:?}"
        );
        assert!(
            format!("{err}").contains("docs_url"),
            "docs_url: {docs_url:?}"
        );
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }

    // Schemes are case-insensitive, so the check is too.
    for docs_url in [HOSTED_DOCS_URL, "HTTPS://policy.example.test/hosted"] {
        let mut registry = fixture_edge_service_registry();
        registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                HostedLegalPolicy {
                    docs_url: docs_url.to_owned(),
                    ..hosted_serious_crime_block()
                },
            )
            .expect("an https docs_url registers");
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());
    }
}

#[test]
fn hosted_registration_rejects_a_row_that_carries_no_rule() {
    // The rows ARE the rubric. A blank `text` is handed to the model as the
    // rule it should judge against — and, worse, counts as coverage of its
    // category, so a blank row can be the reason a category is "covered". A
    // blank `row_ref` names nothing a reader could go and read.
    for (field, row) in [
        (
            "row_ref",
            hosted_row(
                "   ",
                "serious_crime",
                HostedLegalAction::Block,
                "Withhold credible facilitation of mass harm.",
            ),
        ),
        (
            "row_text",
            hosted_row(
                "hosted:serious-crime",
                "serious_crime",
                HostedLegalAction::Block,
                "   ",
            ),
        ),
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, hosted_policy(vec![row]))
            .expect_err("an unreadable row must be refused at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid
        );
        assert!(format!("{err}").contains(field), "unexpected error: {err}");
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }
}

#[test]
fn two_rows_of_one_category_are_legal_and_the_strictest_governs() -> Result<()> {
    // Two distinct legal concerns of one class are two rows. Registration
    // takes them, and the answer routes to the STRICTEST of them — so the
    // block written second is never shadowed by the warn written first, which
    // is the hole the old duplicate-category refusal was standing in front of.
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy(vec![
        hosted_row(
            "hosted:crime-warn",
            "serious_crime",
            HostedLegalAction::Warn,
            "Flag facilitation of mass harm.",
        ),
        hosted_row(
            "hosted:crime-block",
            "serious_crime",
            HostedLegalAction::Block,
            "Withhold facilitation of mass harm.",
        ),
    ]));
    let backend =
        static_backend(r#"{"violation":1,"policy_category":"hosted_legal/serious_crime"}"#);
    let budget = lease("two-rows-one-category");

    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::HostedLegal {
            category: "serious_crime".to_owned(),
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:crime-block".to_owned(),
        },
        "the strictest row of the label governs, and names itself",
    );
    Ok(())
}

#[test]
fn hosted_registration_rejects_two_rows_sharing_a_row_ref() {
    // With several rows per category legal, `row_ref` is what tells them
    // apart — in the rubric, in the notice a reader is pointed at, and in the
    // receipt. Duplicated, it names two rules at once, so it is refused where
    // every other unenforceable shape is: at registration.
    let mut registry = fixture_edge_service_registry();
    let err = registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(vec![
                hosted_row(
                    "hosted:crime",
                    "serious_crime",
                    HostedLegalAction::Warn,
                    "Flag facilitation of mass harm.",
                ),
                hosted_row(
                    "hosted:crime",
                    "ncii",
                    HostedLegalAction::Block,
                    "Withhold intimate imagery shared without consent.",
                ),
            ]),
        )
        .expect_err("two rows of one row_ref must be refused");
    assert!(
        format!("{err}").contains("row_ref"),
        "unexpected error: {err}"
    );
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
}

#[test]
fn a_hosted_policy_wider_than_the_row_bound_is_refused_at_registration() {
    // The row bound is a flood stop on a host-supplied blob, so the test that
    // matters is the pair: one OVER refuses, and exactly AT still registers.
    // Without the second half a bound is indistinguishable from a regression.
    let rows = |count: usize| {
        (0..count)
            .map(|index| {
                hosted_row(
                    &format!("hosted:row-{index}"),
                    "serious_crime",
                    HostedLegalAction::Block,
                    "Withhold facilitation of serious crime.",
                )
            })
            .collect::<Vec<_>>()
    };

    let mut registry = fixture_edge_service_registry();
    let err = registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(rows(POLICY_HOSTED_ROWS_MAX + 1)),
        )
        .expect_err("a policy past the row bound must be refused");
    assert!(format!("{err}").contains("rows"), "unexpected error: {err}");
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());

    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(rows(POLICY_HOSTED_ROWS_MAX)),
        )
        .expect("a policy exactly at the bound is a legal policy, not a flood");
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());
}

#[test]
fn hosted_registration_holds_a_category_label_to_its_shape_not_a_vocabulary() {
    // The engine has no list of acceptable concerns. What it does have is a
    // reason-code namespace the label rides into as written, so the label is
    // held to the same bound and charset a pattern rule id is.
    let over_long = "x".repeat(POLICY_HOSTED_CATEGORY_MAX_LEN + 1);
    for bad in ["", "   ", "serious crime", "serious/crime", &over_long] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                hosted_policy(vec![hosted_row(
                    "hosted:row",
                    bad,
                    HostedLegalAction::Block,
                    "Withhold facilitation of mass harm.",
                )]),
            )
            .expect_err("an unreceiptable category label must be refused");
        assert!(
            format!("{err}").contains("row_category"),
            "unexpected error for {bad:?}: {err}"
        );
    }

    // A label the engine's authors never imagined is fine, because that is the
    // whole point: the vocabulary belongs to the host.
    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(vec![hosted_row(
                "hosted:kk-2027",
                "kk-2027.disclosure",
                HostedLegalAction::Block,
                "Withhold undisclosed sponsored placement under KK-2027.",
            )]),
        )
        .expect("a well-shaped host label registers");
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());
}

#[test]
fn a_category_the_engine_never_shipped_enforces_and_receipts_end_to_end() -> Result<()> {
    // The BYO pin. Nothing about this label exists in the engine: the host
    // registered it, the model answered it, the verdict carries it, and the
    // ledger keys on it.
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy(vec![hosted_row(
        "hosted:kk-2027",
        "kk-2027.disclosure",
        HostedLegalAction::Block,
        "Withhold undisclosed sponsored placement under KK-2027.",
    )]));
    let backend =
        static_backend(r#"{"violation":1,"policy_category":"hosted_legal/kk-2027.disclosure"}"#);
    let budget = lease("byo-category");

    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert!(pass.must_halt_relay());
    assert_eq!(
        pass.boundary_verdict().expect("verdict").category,
        PolicyVerdictCategory::HostedLegal {
            category: "kk-2027.disclosure".to_owned(),
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:kk-2027".to_owned(),
        }
    );
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.policy_model.hosted_legal.kk-2027.disclosure")),
        "the host's own label is the reason code",
    );
    Ok(())
}

#[test]
fn owner_rows_sharing_a_row_ref_are_dropped_rather_than_shadowed() -> Result<()> {
    // Same hole on the owner plane: resolution finds the first row of a ref,
    // so a second one with a stricter action would never fire. The manifest
    // drops the rows instead, and a plane that is ON says so rather than
    // enforcing half a policy. One ref under two WORLDS is a different shape
    // and stays legal — that is the scoped override, pinned by
    // `active_owner_rows_resolve_scoped_world_override`.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x39),
        &enabled_owner_manifest(vec![
            owner_row_with_action("owner:spoilers", "Warn about spoilers.", "warn"),
            owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
        ]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.owner_policy_rows_dropped());
    drop(rtxn);

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
        .expect_err("an enabled plane must not classify against shadowed rows");
    assert!(
        format!("{err}").contains("owner_policy_rows"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn owner_rows_sharing_a_row_ref_across_manifests_are_dropped_too() -> Result<()> {
    // The same shadowing, assembled across two manifest entities instead of
    // inside one. Resolution CONCATENATES every manifest's rows and then
    // first-matches over the result, so each manifest is individually well
    // formed and the block still never fires. Splitting a policy in two must
    // not buy a rule that silently swallows another.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3a),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Warn about spoilers.",
            "warn",
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3b),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Block spoilers.",
            "block",
        )]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.owner_policy_rows_dropped());
    assert!(policy.active_owner_policy_rows(None).is_empty());
    drop(rtxn);

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
        .expect_err("an enabled plane must not classify against shadowed rows");
    assert!(
        format!("{err}").contains("owner_policy_rows"),
        "unexpected error: {err}"
    );
    Ok(())
}

/// A DISABLED row cannot shadow the live row that replaced it.
///
/// The cross-manifest duplicate check drops the whole resolved table when two
/// rows claim one `(row_ref, world_ref)` pair, which is right for two rows
/// that could be in force together. It counted inactive rows too — so keeping
/// a historical row around, switched off, beside the live row that replaced it
/// took the owner plane down entirely: an enabled plane refusing to classify
/// over an ambiguity that never existed, since `active_owner_policy_rows`
/// filters on `active` before it resolves anything.
#[test]
fn a_disabled_row_does_not_shadow_the_live_row_that_replaced_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &enabled_owner_manifest(vec![inactive_owner_row(
            "owner:spoilers",
            "Warn about spoilers.",
            "warn",
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3d),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Block spoilers.",
            "block",
        )]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        !policy.owner_policy_rows_dropped(),
        "one live row and one disabled one are not an ambiguity"
    );
    assert_eq!(
        policy.active_owner_policy_rows(None).len(),
        1,
        "the live row is the sole candidate, and it survives"
    );
    Ok(())
}

#[test]
fn one_row_ref_under_two_worlds_survives_a_manifest_split() -> Result<()> {
    // The scoped override is the shape the PAIR key exists to protect, and it
    // is just as legal split across manifests as it is inside one. Keying on
    // the ref alone would turn a legitimate world-scoped policy into dropped
    // rows the moment its author filed the two worlds separately.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Warn about spoilers.",
            "warn",
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3d),
        &enabled_owner_manifest(vec![scoped_owner_row(
            "owner:spoilers",
            "Block spoilers at work.",
            "work",
        )]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(!policy.owner_policy_rows_dropped());
    assert_eq!(policy.active_owner_policy_rows(Some("work")).len(), 1);
    Ok(())
}

#[test]
fn the_policy_hash_encodes_every_length_in_a_fixed_eight_bytes() {
    // A KNOWN VECTOR, and the reason for it: lengths ride into the digest as
    // big-endian `u64`, never as a bare `usize`. A `usize` is four bytes on a
    // 32-bit target and eight on a 64-bit one, so hashing it directly would
    // make the policy hash depend on the word size of whoever computed it —
    // and the hash is what a receipt attests, so a 32-bit relay would never
    // agree with a 64-bit vault that they had seen the same policy, and the
    // attestation would fail closed forever. This literal is what a conforming
    // implementation produces on EVERY architecture.
    let policy = HostedLegalPolicy {
        jurisdiction: "test-jurisdiction".to_owned(),
        version: "2026-08-01".to_owned(),
        policy_hash: String::new(),
        docs_url: HOSTED_DOCS_URL.to_owned(),
        rows: vec![hosted_row(
            "hosted:ncii",
            "ncii",
            HostedLegalAction::Warn,
            "Flag intimate imagery shared without consent.",
        )],
        policy_document: "POLICY".to_owned(),
        output_contract: Some(PolicyOutputContract::Binary),
        pattern_rules: vec![PolicyPatternRule::new("p.one", "x", "hosted_legal/ncii")],
    };
    assert_eq!(
        policy.derive_policy_hash(),
        "4e4df5d69b237d460e40bc05b87736f6d62b17b6c6f07f7488f8aaddb810dbc4"
    );
}

#[test]
fn the_registered_hash_covers_the_policy_document() {
    // The attestation is only worth something if it names the enforced TEXT.
    // Amend one byte of the document and every earlier receipt stops being
    // evidence about the policy now in force.
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let original = registered_policy(&registry);
    assert_ne!(
        original.policy_hash, "sha256:fixture-not-derived",
        "the registry derives the hash rather than trusting the caller"
    );
    assert_eq!(original.policy_hash, original.derive_policy_hash());

    let amended_registry = hosted_edge_registry(HostedLegalPolicy {
        policy_document: format!("{HOSTED_DOCUMENT}."),
        ..hosted_serious_crime_block()
    });
    let amended = registered_policy(&amended_registry);
    assert_eq!(amended.version, original.version);
    assert_ne!(
        amended.policy_hash, original.policy_hash,
        "one byte of the document must move the hash"
    );

    // A receipt attesting the original does not attest the amendment.
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let receipt = PolicyClassifyVerdict::clean_allow(
        binding,
        &PolicyModelConfig::default(),
        PolicyPlane::OwnerPolicy,
    )
    .attesting_hosted_plane(&original, &PolicyModelConfig::default(), &answered_pass());
    assert!(receipt.attests_hosted_plane(&original, &PolicyModelConfig::default()));
    assert!(!receipt.attests_hosted_plane(&amended, &PolicyModelConfig::default()));
}

#[test]
fn the_registered_hash_covers_the_rows_and_the_rules() {
    let base = registered_policy(&hosted_edge_registry(hosted_serious_crime_block()));
    let rowed = registered_policy(&hosted_edge_registry(HostedLegalPolicy {
        rows: vec![hosted_row(
            "hosted:serious-crime",
            "serious_crime",
            HostedLegalAction::Warn,
            "Withhold credible facilitation of serious violence or mass harm.",
        )],
        ..hosted_serious_crime_block()
    }));
    let ruled = registered_policy(&hosted_edge_registry(hosted_policy_with_rules(vec![
        escalate_rule("hosted.bomb", "(?i)bomb"),
    ])));
    let rerolled = registered_policy(&hosted_edge_registry(hosted_policy_with_rules(vec![
        decide_rule("hosted.bomb", "(?i)bomb"),
    ])));

    assert_ne!(base.policy_hash, rowed.policy_hash);
    assert_ne!(base.policy_hash, ruled.policy_hash);
    assert_ne!(
        ruled.policy_hash, rerolled.policy_hash,
        "changing a rule's role changes what is enforced"
    );
}

#[test]
fn hosted_legal_policy_binds_to_a_registered_service_identity() {
    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, hosted_serious_crime_block())
        .expect("registering a policy on a known service succeeds");

    let bound = registry
        .hosted_legal_policy(HOSTED_EDGE_IDENTITY)
        .expect("the registered policy is reachable by identity");
    assert_eq!(bound.jurisdiction, HOSTED_JURISDICTION);
    assert_eq!(bound.version, HOSTED_VERSION);

    // A service with no policy has none, and an unregistered name can never
    // carry one — jurisdiction authority does not float free of an identity.
    assert!(
        registry
            .hosted_legal_policy("connector-edge:push-relay")
            .is_none()
    );
    let err = registry
        .register_hosted_legal_policy("totally-unknown-edge", hosted_serious_crime_block())
        .expect_err("a policy needs a registered service behind it");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity
    );
}

#[test]
fn hosted_relay_runs_the_hosted_legal_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = blocking_backend();
    let budget = lease("hosted-runs");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert!(pass.ran_relay_classify());
    let verdict = pass.boundary_verdict().expect("hosted relay runs a pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::HostedLegal {
            category: "serious_crime".to_owned(),
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:serious-crime".to_owned(),
        }
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn hosted_relay_without_a_policy_classifies_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = CountingPolicyBackend::clean();
    let budget = lease("no-policy");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::NoPolicyInPlay));
    assert!(!pass.must_halt_relay());
    assert!(gate_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn hosted_warn_relays_the_content_and_does_not_halt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        rows: vec![hosted_row(
            "hosted:serious-crime",
            "serious_crime",
            HostedLegalAction::Warn,
            "Flag credible facilitation of serious violence.",
        )],
        ..hosted_serious_crime_block()
    };
    let backend = blocking_backend();
    let budget = lease("hosted-warn");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Warn
    );
    assert!(!pass.must_halt_relay());

    // A warn still carries an enforcement signal, so it is receipted.
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_boundary_warn");
    Ok(())
}

#[test]
fn hosted_notices_are_attributed_to_the_hosted_service() -> Result<()> {
    for action in [HostedLegalAction::Warn, HostedLegalAction::Block] {
        let (_tmp, vault) = temp_vault();
        let policy = HostedLegalPolicy {
            rows: vec![hosted_row(
                "hosted:serious-crime",
                "serious_crime",
                action,
                "Serious-crime facilitation.",
            )],
            ..hosted_serious_crime_block()
        };
        let backend = blocking_backend();
        let budget = lease("hosted-notice");
        relay_pass(
            &vault,
            BOMB_CONTENT,
            &hosted_edge_registry(policy),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;

        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1);
        let fields = &receipts[0].fields;
        assert_eq!(
            fields.get("system_notice_policy_plane").map(String::as_str),
            Some(PolicyPlane::HostedLegal.as_str())
        );
        assert_eq!(
            fields
                .get("system_notice_policy_version")
                .map(String::as_str),
            Some(HOSTED_VERSION)
        );
        assert_eq!(
            fields.get("system_notice_docs_url").map(String::as_str),
            Some(HOSTED_DOCS_URL)
        );
        let body = fields.get("system_notice").expect("notice body");
        assert!(body.contains(HOSTED_JURISDICTION), "body: {body}");
        // The vault owner did not write this rule and is not blamed for it.
        assert!(!body.contains("your policy"), "body: {body}");
        assert!(has_trace(
            &receipts[0],
            "gate.policy_model.plane.hosted_legal"
        ));
    }
    Ok(())
}

#[test]
fn the_hosted_document_is_what_reaches_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = RecordingPolicyBackend::new(r#"{"violation":0,"policy_category":null}"#);
    let budget = lease("hosted-document");
    relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        backend.seen_system.lock().expect("system").as_deref(),
        Some(HOSTED_DOCUMENT),
        "the system message is the substrate owner's document, verbatim"
    );
    assert_eq!(
        backend.seen_user.lock().expect("user").as_deref(),
        Some(CLEAN_CONTENT),
        "the user message is the candidate, verbatim — the engine adds no words"
    );
    Ok(())
}

#[test]
fn byo_path_never_evaluates_hosted_legal_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A policy that WOULD block this content, on a path that never reaches us.
    let backend = CountingPolicyBackend::clean();
    let budget = lease("byo");
    let pass = block_on(vault.relay_boundary_pass(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &byo_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    assert_eq!(pass, RelayBoundaryPass::NotRelayedByUs);
    assert_eq!(backend.calls(), 0);
    assert!(!pass.ran_relay_classify());
    assert!(pass.boundary_verdict().is_none());
    assert!(!pass.must_halt_relay());

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_not_relayed");
    assert!(has_trace(&receipts[0], "gate.relay.classify.skipped"));
    // No hosted-legal verdict was reached, so no hosted notice exists.
    assert!(!receipts[0].fields.contains_key("system_notice"));
    Ok(())
}

#[test]
fn owner_rows_are_never_evaluated_at_the_relay() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x50), &spoiler_manifest("block"))?;

    // The vault-egress classify DOES fire the owner rule.
    let vault_side = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(
        vault_side.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );

    // The relay pass never assembles the owner plane.
    let backend = clean_backend();
    let budget = lease("relay-owner-blind");
    let pass = relay_pass(
        &vault,
        "This reply contains spoilers.",
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    let verdict = pass.boundary_verdict().expect("hosted relay runs a pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn relay_block_writes_audit_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = blocking_backend();
    let budget = lease("relay-block-receipt");
    let pass = block_on(
        vault.relay_boundary_pass(
            PolicyClassifyRequest::outbound_content(BOMB_CONTENT)
                .with_caller_ref("relay:hosted-connector"),
            &hosted_witness(),
            &hosted_edge_registry(hosted_serious_crime_block()),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
            &EMPTY_VAULT_SIDE_VERDICTS,
        ),
    )?;
    assert!(pass.must_halt_relay());

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.outcome, "relay_boundary_block");
    for expected in [
        "gate.relay.trust_domain.local_via_hosted_connector",
        "gate.relay.classifier_mode.classify_all",
        "gate.relay.classify.ran",
        "gate.relay.resolution.model_decided",
        "gate.policy_model.block",
        "gate.policy_model.hosted_legal.serious_crime",
    ] {
        assert!(has_trace(receipt, expected), "missing trace {expected}");
    }
    Ok(())
}

#[test]
fn a_model_examined_clean_allow_writes_no_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = clean_backend();
    let budget = lease("clean-allow");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(pass.degraded().is_none());
    assert!(
        gate_receipts(&vault)?.is_empty(),
        "the one pass with nothing to say writes nothing"
    );
    Ok(())
}

#[test]
fn relay_pass_fails_closed_on_a_malformed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x52), b"not a policy manifest")?;

    let backend = clean_backend();
    let budget = lease("malformed");
    let err = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )
    .expect_err("a malformed manifest must fail the relay pass closed");
    assert!(
        format!("{err}").contains("malformed"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn a_max_length_jurisdiction_still_produces_a_receiptable_notice() -> Result<()> {
    // The jurisdiction bound is derived from the ledger's notice-body bound,
    // and that bound is paid for whichever hosted template is LONGEST — the
    // warn one. Checking only the shorter block template would leave the case
    // the arithmetic is actually about untested, so both run here with the
    // longest jurisdiction the registry accepts.
    let longest = "j".repeat(HOSTED_LEGAL_JURISDICTION_MAX_LEN);
    for (action, halts) in [
        (HostedLegalAction::Warn, false),
        (HostedLegalAction::Block, true),
    ] {
        let (_tmp, vault) = temp_vault();
        let policy = HostedLegalPolicy {
            jurisdiction: longest.clone(),
            rows: vec![hosted_row(
                "hosted:serious-crime",
                "serious_crime",
                action,
                "Withhold credible facilitation of serious violence or mass harm.",
            )],
            ..hosted_serious_crime_block()
        };
        let backend = blocking_backend();
        let budget = lease("longest-jurisdiction");
        let pass = relay_pass(
            &vault,
            BOMB_CONTENT,
            &hosted_edge_registry(policy),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
        assert_eq!(pass.must_halt_relay(), halts, "action: {action:?}");

        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1, "action: {action:?}");
        assert!(
            receipts[0]
                .fields
                .get("system_notice")
                .expect("notice body")
                .contains(&longest),
            "action: {action:?}"
        );
    }
    Ok(())
}
