//! DEC-0006 unified consent-mode conformance.
//!
//! Each of the nine named tests below asserts ONE invariant from the DEC-0006
//! invariant table MECHANICALLY — the table is exact, not illustrative, so a
//! test that only exercises the happy path is not conformance. Adapter tests
//! then prove the four pre-existing grant shapes fold through without a byte,
//! status, or codec change, and that no type byte is allocated.

use super::*;

use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::genui::{ConsentConfirmOutcome, ConsentScopeEscalator};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn at(seconds: u64) -> TimeRange {
    TimeRange {
        start: seconds,
        end: seconds,
    }
}

/// Opens a vault whose owner is a real store-truth PERSON, and returns the
/// authenticated-owner handle every minting door requires.
fn owner_vault() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x51);
    vault
        .put_entity(&owner_id, ENTITY_TYPE_PERSON, at(1), 1, b"owner")
        .expect("seed owner person");
    let owner = vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");
    (dir, vault, owner)
}

fn action_bound(actor: &str, class: &str, selectors: &[&str]) -> GrantBound {
    GrantBound::action(
        ActorBound::new(actor).expect("actor bound"),
        ActionClass::new(class).expect("action class"),
        ActionEnvelope::new(selectors.iter().map(|s| (*s).to_owned())).expect("action envelope"),
    )
    .expect("action bound")
}

fn disclosure_bound(audience: &[&str], class: &str, selectors: &[&str]) -> GrantBound {
    GrantBound::disclosure(
        AudienceBound::new(audience.iter().map(|s| (*s).to_owned())).expect("audience bound"),
        DisclosureClass::new(class).expect("disclosure class"),
        DisclosureEnvelope::new(selectors.iter().map(|s| (*s).to_owned()))
            .expect("disclosure envelope"),
    )
    .expect("disclosure bound")
}

/// The quiet, local, fully-undoable case: effect-reversible.
fn reversible_facts() -> EffectFacts {
    EffectFacts::new("claim.put").expect("facts")
}

/// An outbound send: irreversible IN EFFECT even though the ledger records it.
fn irreversible_send_facts() -> EffectFacts {
    EffectFacts::new("channel.send")
        .expect("facts")
        .with_external_observers(true)
}

// ---------------------------------------------------------------------------
// 1 · Reversibility-primary
// ---------------------------------------------------------------------------

/// `1 · Reversibility-primary` — "An effect-reversible op runs automatically —
/// undo is the net. Only ops that are irreversible-in-effect enter the ask
/// lane. 'Reversible' means effect-reversible, not merely ledger-appendable:
/// an outbound send or a deploy is irreversible-in-effect even though the
/// ledger records it."
#[test]
fn consent_reversible_effect_auto_irreversible_asks() {
    // An effect-reversible op runs automatically with no grant at all.
    let reversible = ComposedEffect::new(reversible_facts())
        .with_action_requirement(action_bound("agent-a", "claim.put", &["world:home"]))
        .expect("action requirement");
    assert_eq!(
        evaluate_consent(&reversible, None, &[]),
        ConsentDecision::Auto,
        "an effect-reversible op must run automatically — undo is the net"
    );

    // An outbound send is irreversible IN EFFECT and enters the ask lane, even
    // though it is perfectly ledger-appendable. This is the whole point of the
    // invariant: "appendable" is not "reversible".
    let send = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("action requirement");
    assert_eq!(
        evaluate_consent(&send, None, &[]),
        ConsentDecision::Ask,
        "an outbound send is irreversible-in-effect and must reach the ask"
    );
    assert_eq!(
        classify_composed_effect(send.facts()).expect("classify"),
        ReversibilityClass::Irreversible
    );

    // A deploy is the other named case.
    let deploy = ComposedEffect::new(
        EffectFacts::new("repo.deploy")
            .expect("facts")
            .with_publish_trigger(true),
    )
    .with_action_requirement(action_bound("agent-a", "deploy", &["repo:oneiron"]))
    .expect("action requirement");
    assert_eq!(evaluate_consent(&deploy, None, &[]), ConsentDecision::Ask);

    // And a ledger-appendable-but-locally-undoable write is NOT pushed to ask
    // merely because it was recorded.
    assert_eq!(
        classify_composed_effect(&reversible_facts()).expect("classify"),
        ReversibilityClass::Reversible
    );
}

// ---------------------------------------------------------------------------
// 2 · Two grant types, one receipt
// ---------------------------------------------------------------------------

/// `2 · Two grant types, one receipt` — "approve_once(effect_digest)
/// authorizes this op, now. create_standing_grant(bound) is a deliberate
/// 'remember' — created ONLY by the authenticated owner, NEVER inferred from a
/// preference, a claim, a transcript line, or a guard hunch. Both live under
/// one receipt and one UX. Every manual confirm — INCLUDING a scope-exceed
/// escalation — offers exactly three outcomes: approve once (the default),
/// approve-and-stop-asking, or deny. Approve-and-stop-asking is the in-moment
/// path into create_standing_grant: it flips that one grant row (the ARCH-0072
/// slate row) to auto under the SAME owner stamp, audit-visible and revocable
/// from the registry. It stays an authenticated owner act bounded to that row
/// — never an inference."
#[test]
fn consent_lifetime_types_share_one_receipt_enum_owner_only_standing() {
    let (_dir, vault, owner) = owner_vault();

    // Both lifetimes land in the SAME receipt enum, and both in its `Approved`
    // arm — distinguished only by the `grant` arm.
    let digest = ComposedEffect::new(irreversible_send_facts()).digest();
    let once = vault.approve_once(&owner, digest).expect("approve once");
    let bound = action_bound("agent-a", "send", &["channel:email"]);
    let standing = vault
        .create_standing_grant(&owner, bound.clone())
        .expect("create standing grant");
    assert!(matches!(
        once,
        ConsentReceipt::Approved {
            grant: ConsentGrant::ApproveOnce(_),
            ..
        }
    ));
    assert!(matches!(
        standing,
        ConsentReceipt::Approved {
            grant: ConsentGrant::Standing(_),
            ..
        }
    ));

    // approve_once authorizes THIS op, now — and no other op.
    let this_op = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    let other_op = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:sms"]))
        .expect("requirement");
    let this_digest = this_op.digest();
    assert_eq!(
        evaluate_consent(&this_op, Some(&this_digest), &[]),
        ConsentDecision::Auto
    );
    assert_eq!(
        evaluate_consent(&other_op, Some(&this_digest), &[]),
        ConsentDecision::Ask,
        "an approve-once receipt must not cover a different op"
    );

    // Standing minting is OWNER-ONLY, enforced by the type system: a
    // `ConsentProposal` (all a guard can produce) carries no owner stamp and
    // there is no conversion from it into an `AuthenticatedOwner`. The runtime
    // half is that unauthenticated principals never get an owner handle at all.
    let unauth = vault.authenticate_owner(
        owner.actor(),
        "principal:owner",
        false,
        GateDecisionId::now(),
    );
    assert_eq!(
        unauth.expect_err("unauthenticated principal").kind(),
        ErrorKind::ConsentOwnerNotAuthenticated
    );
    // Nor does naming a non-person entity as the "owner" work.
    let not_a_person = entity(0x62);
    assert_eq!(
        vault
            .authenticate_owner(not_a_person, "principal:owner", true, GateDecisionId::now())
            .expect_err("non-person actor")
            .kind(),
        ErrorKind::ConsentOwnerNotAuthenticated
    );

    // Approve-and-stop-asking flips exactly ONE row to auto under the SAME
    // owner stamp, and that row is registry-revocable.
    let row = vault
        .consent_grant(&bound.digest().to_hex())
        .expect("read row")
        .expect("row exists");
    assert_eq!(row.owner_stamp.actor, owner.actor());
    assert_eq!(row.owner_stamp.principal_ref, owner.principal_ref());
    assert!(row.is_active());
    let registry = vault
        .consent_registry(ConsentRegistryQuery::new(16, false))
        .expect("registry");
    assert_eq!(
        registry.rows.len(),
        1,
        "exactly one row was flipped to auto"
    );
    assert_eq!(
        registry.rows[0].revoke_action.command,
        CONSENT_REVOKE_COMMAND
    );
}

// ---------------------------------------------------------------------------
// 3 · A grant is a bound, not a verb
// ---------------------------------------------------------------------------

/// `3 · A grant is a bound, not a verb` — "A standing grant is BOUND:
/// (actor/audience × class × envelope). Reuse inside the bound is auto — no
/// re-nag. Anything that exceeds the bound is a fresh ask. Widening the bound
/// is its own decision, never a side effect of reuse. Approve-and-stop-asking
/// at a scope-exceed escalation IS that own decision — an explicit owner act
/// on the exceeding op, never inferred from the reuse that triggered it
/// (ARCH-0072)."
#[test]
fn consent_bound_reuse_exceed_and_widen_are_distinct() {
    let (_dir, vault, owner) = owner_vault();

    let granted = action_bound("agent-a", "send", &["channel:email", "channel:sms"]);
    vault
        .create_standing_grant(&owner, granted.clone())
        .expect("mint");
    let grants = vault
        .active_standing_consent_grants()
        .expect("active grants");

    // REUSE INSIDE THE BOUND IS AUTO — no re-nag.
    let inside = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    assert_eq!(
        evaluate_consent(&inside, None, &grants),
        ConsentDecision::Auto
    );

    // EXCEEDING THE BOUND IS A FRESH ASK, on every axis independently.
    let wider_envelope = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:slack"]))
        .expect("requirement");
    let other_actor = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-b", "send", &["channel:email"]))
        .expect("requirement");
    let other_class = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "deploy", &["channel:email"]))
        .expect("requirement");
    for exceeding in [&wider_envelope, &other_actor, &other_class] {
        assert_eq!(
            evaluate_consent(exceeding, None, &grants),
            ConsentDecision::Ask,
            "an op that exceeds the bound must be a fresh ask"
        );
    }

    // A raw verb ALONE never constitutes a bound: the class matches, but with
    // no covering subject the candidate is still outside.
    assert!(!granted.contains(&action_bound("agent-zzz", "send", &["channel:email"])));

    // WIDENING IS ITS OWN DECISION: reuse did not mutate the bound, and the
    // wider grant is a SEPARATE row with its own receipt and its own stamp.
    let row = vault
        .consent_grant(&granted.digest().to_hex())
        .expect("read")
        .expect("row");
    assert_eq!(
        row.grant.bound(),
        &granted,
        "reuse must never mutate a stored bound"
    );
    let widened = action_bound(
        "agent-a",
        "send",
        &["channel:email", "channel:sms", "channel:slack"],
    );
    let widen_receipt = vault
        .create_standing_grant(&owner, widened.clone())
        .expect("widen");
    assert!(matches!(widen_receipt, ConsentReceipt::Approved { .. }));
    assert_ne!(
        widened.digest(),
        granted.digest(),
        "a wider bound is a different row, not an edit of the old one"
    );
    let registry = vault
        .consent_registry(ConsentRegistryQuery::new(16, false))
        .expect("registry");
    assert_eq!(
        registry.rows.len(),
        2,
        "widening mints a new row; the original survives untouched"
    );

    // Narrowing/revocation is immediate.
    vault
        .revoke_consent_grant(&owner, &granted.digest().to_hex())
        .expect("revoke");
    let after = vault
        .active_standing_consent_grants()
        .expect("active grants");
    assert!(
        !after.iter().any(|grant| grant.bound() == &granted),
        "a revoked bound must stop authorizing immediately"
    );
}

// ---------------------------------------------------------------------------
// 4 · Disclosure and action are disjoint types
// ---------------------------------------------------------------------------

/// `4 · Disclosure and action are disjoint types` — "Disclosure-grants (data →
/// audience) are typed DISJOINT from action-grants (actor → verb → target),
/// even under the shared UX. A mixed op — a channel_send of private content —
/// must satisfy BOTH gates, not either."
#[test]
fn consent_mixed_operation_requires_disclosure_and_action() {
    let disclosure = disclosure_bound(&["contact:doctor"], "health", &["entity:vitals"]);
    let action = action_bound("agent-a", "send", &["channel:email"]);

    // A mixed op — a channel_send of private content.
    let mixed = ComposedEffect::new(irreversible_send_facts())
        .with_disclosure_requirement(disclosure.clone())
        .expect("disclosure requirement")
        .with_action_requirement(action.clone())
        .expect("action requirement");
    assert!(mixed.is_mixed());

    let disclosure_only = [StandingConsentGrant::from_bound(disclosure.clone()).expect("grant")];
    let action_only = [StandingConsentGrant::from_bound(action.clone()).expect("grant")];
    let both = [
        StandingConsentGrant::from_bound(disclosure.clone()).expect("grant"),
        StandingConsentGrant::from_bound(action.clone()).expect("grant"),
    ];

    // EITHER is not enough — this is the AND, not an OR.
    assert_eq!(
        evaluate_consent(&mixed, None, &disclosure_only),
        ConsentDecision::Ask,
        "a disclosure grant alone must not authorize a mixed op"
    );
    assert_eq!(
        evaluate_consent(&mixed, None, &action_only),
        ConsentDecision::Ask,
        "an action grant alone must not authorize a mixed op"
    );
    assert_eq!(
        evaluate_consent(&mixed, None, &both),
        ConsentDecision::Auto,
        "both conjuncts covered authorizes the mixed op"
    );

    // The two types are DISJOINT: a crossed triple cannot even be built, so a
    // caller cannot reinterpret one domain as the other.
    let crossed = GrantBound::new(
        BoundSubject::Audience(AudienceBound::singleton("contact:doctor").expect("audience")),
        BoundClass::Action(ActionClass::new("send").expect("class")),
        BoundEnvelope::Action(ActionEnvelope::new(["channel:email".to_owned()]).expect("envelope")),
    );
    assert_eq!(
        crossed.expect_err("crossed triple").kind(),
        ErrorKind::InvalidConsentBound
    );

    // And the wrappers refuse a bound from the other domain.
    assert_eq!(
        DisclosureGrant::new(action.clone())
            .expect_err("action bound in a disclosure grant")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
    assert_eq!(
        ActionGrant::new(disclosure.clone())
            .expect_err("disclosure bound in an action grant")
            .kind(),
        ErrorKind::InvalidConsentBound
    );

    // A cross-domain bound never contains one from the other domain, so a
    // disclosure grant can never silently satisfy an action requirement.
    assert!(!disclosure.contains(&action));
    assert!(!action.contains(&disclosure));

    // The requirement setters are typed too.
    assert_eq!(
        ComposedEffect::new(irreversible_send_facts())
            .with_disclosure_requirement(action)
            .expect_err("action bound as a disclosure requirement")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
    assert_eq!(
        ComposedEffect::new(irreversible_send_facts())
            .with_action_requirement(disclosure)
            .expect_err("disclosure bound as an action requirement")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
}

// ---------------------------------------------------------------------------
// 5 · The guard offers, never grants
// ---------------------------------------------------------------------------

/// A guard that proposes with maximum confidence. Even at `1.0` it authorizes
/// nothing — confidence may change the OFFER, never authority.
struct AlwaysCertainGuard {
    bound: GrantBound,
}

impl ConsentGuard for AlwaysCertainGuard {
    fn propose(&self, _facts: &EffectFacts) -> ConsentProposal {
        ConsentProposal {
            effect_digest: self.bound.digest(),
            suggested_bound: self.bound.clone(),
            confidence: 1.0,
        }
    }
}

/// `5 · The guard offers, never grants` — "The small model may propose
/// 'remember this?' and may raise or lower confidence. It never authorizes.
/// Authorization is remembered state the authenticated owner granted once.
/// Inference is not authority. The ARCH-0072 admission slate IS this invariant
/// rather than an exception to it: the model drafts the rows and is bound by
/// the drafter-only floor that forces destructive, paying, and outward-sending
/// tools to draft confirm-first (the owner may override any row), and the
/// owner's single tap is the only authorization."
///
/// The compile-fail half of this assertion is the API SHAPE, asserted by the
/// companion `consent_guard_api_has_no_proposal_to_grant_path` test below:
/// there is no `From<ConsentProposal> for ConsentGrant`, no guard-reachable
/// persistence function, and no proposal field treated as an owner stamp.
#[test]
fn consent_guard_proposes_never_grants() {
    let (_dir, vault, owner) = owner_vault();
    let bound = action_bound("agent-a", "send", &["channel:email"]);
    let guard = AlwaysCertainGuard {
        bound: bound.clone(),
    };

    let proposal = guard.propose(&irreversible_send_facts());
    assert!((proposal.confidence - 1.0).abs() < f32::EPSILON);
    assert_eq!(proposal.suggested_bound, bound);

    // The proposal exists, at maximum confidence — and the op still ASKS,
    // because inference is not authority.
    let effect = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(bound)
        .expect("requirement");
    let grants = vault
        .active_standing_consent_grants()
        .expect("active grants");
    assert!(
        grants.is_empty(),
        "a guard proposal must never have created a grant row"
    );
    assert_eq!(
        evaluate_consent(&effect, None, &grants),
        ConsentDecision::Ask,
        "a maximally-confident proposal authorizes nothing"
    );

    // Only the owner's act creates authority — the single tap.
    vault
        .create_standing_grant(&owner, proposal.suggested_bound)
        .expect("owner taps");
    let grants = vault
        .active_standing_consent_grants()
        .expect("active grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(
        evaluate_consent(&effect, None, &grants),
        ConsentDecision::Auto
    );
}

/// The API-shape half of invariant 5. `create_standing_grant` takes an
/// `&AuthenticatedOwner`, whose fields are private and whose only constructor
/// is `Vault::authenticate_owner` — so the following does not compile, and the
/// invariant is a type fact rather than a convention:
///
/// ```compile_fail
/// use oneiron::consent::{AuthenticatedOwner, ConsentProposal};
/// // `AuthenticatedOwner` has private fields: a guard cannot fabricate one
/// // from its proposal, and there is no `From<ConsentProposal>` for it or for
/// // `ConsentGrant`.
/// fn launder(proposal: ConsentProposal) -> AuthenticatedOwner {
///     AuthenticatedOwner {
///         actor: proposal.effect_digest,
///         principal_ref: String::new(),
///         decision_id: todo!(),
///     }
/// }
/// ```
#[test]
fn consent_guard_api_has_no_proposal_to_grant_path() {
    // A `ConsentProposal` carries exactly three fields, none of which is an
    // owner stamp: a digest, a suggested bound, and a confidence.
    let proposal = ConsentProposal {
        effect_digest: EffectDigest::from_bytes([7_u8; 32]),
        suggested_bound: action_bound("agent-a", "send", &["channel:email"]),
        confidence: 0.99,
    };
    // Confidence is the only knob a guard may turn, and turning it changes
    // neither the bound the owner would stamp nor the op it names.
    let lowered = ConsentProposal {
        confidence: 0.01,
        ..proposal.clone()
    };
    assert_eq!(lowered.suggested_bound, proposal.suggested_bound);
    assert_eq!(lowered.effect_digest, proposal.effect_digest);
}

// ---------------------------------------------------------------------------
// 6 · Reversibility classification is host-owned, biased-permissive
// ---------------------------------------------------------------------------

/// `6 · Reversibility classification is host-owned, biased-permissive` —
/// "Generated code, connector labels, and the guard cannot self-declare
/// 'reversible.' The host classifies the composed effect — hooks,
/// publish/deploy triggers, external observers, undo fidelity and window,
/// cumulative blast radius. Unknown-and-irreversible-and-catastrophe-shaped
/// resolves to ask; everything else is biased toward auto."
#[test]
fn consent_reversibility_is_host_classified_biased_permissive() {
    // Every named host axis independently forces Irreversible.
    let axes: [(&str, EffectFacts); 5] = [
        (
            "hooks",
            EffectFacts::new("claim.put")
                .expect("facts")
                .with_hooks(true),
        ),
        (
            "publish/deploy trigger",
            EffectFacts::new("repo.deploy")
                .expect("facts")
                .with_publish_trigger(true),
        ),
        (
            "external observers",
            EffectFacts::new("channel.send")
                .expect("facts")
                .with_external_observers(true),
        ),
        (
            "undo fidelity",
            EffectFacts::new("claim.put")
                .expect("facts")
                .with_undo_fidelity(UndoFidelity::None),
        ),
        (
            "cumulative blast radius",
            EffectFacts::new("claim.put")
                .expect("facts")
                .with_blast_radius(BULK_BLAST_RADIUS_FLOOR),
        ),
    ];
    for (axis, facts) in axes {
        assert_eq!(
            classify_composed_effect(&facts).expect("classify"),
            ReversibilityClass::Irreversible,
            "host axis {axis} must force Irreversible"
        );
    }

    // BIASED-PERMISSIVE: an unknown sub-axis with no irreversible and no
    // catastrophe evidence stays auto-eligible.
    let unknown = EffectFacts::new("claim.put")
        .expect("facts")
        .with_undo_fidelity(UndoFidelity::Unknown);
    assert_eq!(
        classify_composed_effect(&unknown).expect("classify"),
        ReversibilityClass::Unknown
    );
    let effect = ComposedEffect::new(unknown)
        .with_action_requirement(action_bound("agent-a", "claim.put", &["world:home"]))
        .expect("requirement");
    assert_eq!(
        evaluate_consent(&effect, None, &[]),
        ConsentDecision::Auto,
        "unknown WITHOUT irreversible/catastrophe evidence biases to auto"
    );

    // Unknown-AND-irreversible-shaped resolves to ask...
    let unknown_and_irreversible = EffectFacts::new("channel.send")
        .expect("facts")
        .with_undo_fidelity(UndoFidelity::Unknown)
        .with_external_observers(true);
    assert_eq!(
        classify_composed_effect(&unknown_and_irreversible).expect("classify"),
        ReversibilityClass::Irreversible
    );
    // ...and so does unknown-AND-catastrophe-shaped.
    let unknown_and_catastrophe = EffectFacts::new("authority.widen")
        .expect("facts")
        .with_undo_fidelity(UndoFidelity::Unknown)
        .with_catastrophe(CatastropheClass::WidenOwnAuthority);
    assert_eq!(
        classify_composed_effect(&unknown_and_catastrophe).expect("classify"),
        ReversibilityClass::Irreversible
    );

    // The facts a caller may supply contain NO reversibility verdict: the only
    // undo input is the host's own finding, and the classifier — not the
    // caller — maps it. A connector claiming "reversible" has nowhere to say so.
    let facts = irreversible_send_facts();
    assert_eq!(
        classify_composed_effect(&facts).expect("classify"),
        ReversibilityClass::Irreversible,
        "a caller cannot self-declare an outbound send reversible"
    );
}

// ---------------------------------------------------------------------------
// 7 · A small closed catastrophe floor
// ---------------------------------------------------------------------------

/// `7 · A small closed catastrophe floor` — "A short, versioned, engine-owned,
/// non-rememberable set is gated at ANY trust level — even an all-yes owner.
/// It is the only always-gate. Members: widen own authority · key / recovery ·
/// vault-wide destruction · security-control disable · mass secret-export."
#[test]
fn consent_catastrophe_floor_is_closed_any_trust_non_rememberable() {
    // EXACT version and set equality — the set is CLOSED, so this asserts
    // membership, order, and length, not merely "contains".
    assert_eq!(CATASTROPHE_FLOOR_VERSION, 1);
    assert_eq!(
        CATASTROPHE_FLOOR_V1,
        [
            CatastropheClass::WidenOwnAuthority,
            CatastropheClass::KeyRecovery,
            CatastropheClass::VaultWideDestruction,
            CatastropheClass::SecurityControlDisable,
            CatastropheClass::MassSecretExport,
        ]
    );
    assert_eq!(CATASTROPHE_FLOOR_V1.len(), 5);
    assert_eq!(
        CATASTROPHE_FLOOR_V1.map(CatastropheClass::as_str),
        [
            "widen_own_authority",
            "key_recovery",
            "vault_wide_destruction",
            "security_control_disable",
            "mass_secret_export",
        ]
    );

    let (_dir, vault, owner) = owner_vault();

    for catastrophe in CATASTROPHE_FLOOR_V1 {
        // GATED AT ANY TRUST LEVEL — even with a covering standing grant AND a
        // matching approve-once receipt in hand, which is the strongest
        // "all-yes owner" state the system can be in.
        let bound = action_bound("agent-a", catastrophe.as_str(), &["scope:all"]);
        let effect = ComposedEffect::new(
            EffectFacts::new("authority.op")
                .expect("facts")
                .with_catastrophe(catastrophe),
        )
        .with_action_requirement(bound.clone())
        .expect("requirement");
        let covering = [StandingConsentGrant::from_bound(bound.clone()).expect("grant")];
        let digest = effect.digest();
        assert_eq!(
            evaluate_consent(&effect, Some(&digest), &covering),
            ConsentDecision::Ask,
            "{} must ask even with a covering grant and an exact receipt",
            catastrophe.as_str()
        );

        // NON-REMEMBERABLE — rejected from standing-grant minting outright.
        assert_eq!(
            vault
                .create_standing_grant(&owner, bound)
                .expect_err("catastrophe bound")
                .kind(),
            ErrorKind::ConsentCatastropheNotRememberable,
            "{} must be rejected from standing-grant minting",
            catastrophe.as_str()
        );
    }

    // It is the ONLY always-gate: an ordinary irreversible op with a covering
    // grant runs, so the floor is not just "irreversible ops always ask".
    let ordinary = action_bound("agent-a", "send", &["channel:email"]);
    let effect = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(ordinary.clone())
        .expect("requirement");
    let covering = [StandingConsentGrant::from_bound(ordinary).expect("grant")];
    assert_eq!(
        evaluate_consent(&effect, None, &covering),
        ConsentDecision::Auto
    );

    // Round-trips through the pinned strings, so a receipt naming a floor
    // member is machine-readable and no member string drifts.
    for catastrophe in CATASTROPHE_FLOOR_V1 {
        assert_eq!(
            CatastropheClass::parse(catastrophe.as_str()),
            Some(catastrophe)
        );
    }
    assert_eq!(CatastropheClass::parse("not_a_member"), None);
}

// ---------------------------------------------------------------------------
// 8 · Fail-safe flips by domain
// ---------------------------------------------------------------------------

/// `8 · Fail-safe flips by domain` — "Disclosure fails safe by HIDING; writes
/// fail safe by ASKING. The safe direction is domain-specific, not a single
/// global default."
#[test]
fn consent_fail_safe_hides_disclosure_and_asks_writes() {
    // The domain-level statement of the invariant.
    assert_eq!(
        ConsentDomain::Disclosure.fail_safe(),
        ConsentDecision::Hide,
        "disclosure fails safe by hiding"
    );
    assert_eq!(
        ConsentDomain::Action.fail_safe(),
        ConsentDecision::Ask,
        "writes fail safe by asking"
    );
    assert_ne!(
        ConsentDomain::Disclosure.fail_safe(),
        ConsentDomain::Action.fail_safe(),
        "the safe direction is domain-specific, not one global default"
    );

    // An uncovered irreversible DISCLOSURE hides.
    let disclosure = ComposedEffect::new(
        EffectFacts::new("disclosure.share")
            .expect("facts")
            .with_external_observers(true),
    )
    .with_disclosure_requirement(disclosure_bound(
        &["contact:stranger"],
        "health",
        &["entity:vitals"],
    ))
    .expect("requirement");
    assert_eq!(
        evaluate_consent(&disclosure, None, &[]),
        ConsentDecision::Hide
    );

    // An uncovered irreversible WRITE asks.
    let write = ComposedEffect::new(irreversible_send_facts())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    assert_eq!(evaluate_consent(&write, None, &[]), ConsentDecision::Ask);

    // A MIXED op writes, so it asks rather than silently hiding the write half.
    let mixed = ComposedEffect::new(irreversible_send_facts())
        .with_disclosure_requirement(disclosure_bound(
            &["contact:stranger"],
            "health",
            &["entity:vitals"],
        ))
        .expect("requirement")
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    assert_eq!(evaluate_consent(&mixed, None, &[]), ConsentDecision::Ask);

    // MALFORMED/ABSENT required write facts take the same domain fail-safe
    // rather than a fabricated verdict.
    let mut malformed_facts = irreversible_send_facts();
    malformed_facts.operation_kind = String::new();
    assert_eq!(
        classify_composed_effect(&malformed_facts)
            .expect_err("malformed facts")
            .kind(),
        ErrorKind::InvalidConsentEffectFacts
    );
    let malformed_write = ComposedEffect::new(malformed_facts.clone())
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    assert_eq!(
        evaluate_consent(&malformed_write, None, &[]),
        ConsentDecision::Ask
    );
    let malformed_disclosure = ComposedEffect::new(malformed_facts)
        .with_disclosure_requirement(disclosure_bound(
            &["contact:stranger"],
            "health",
            &["entity:vitals"],
        ))
        .expect("requirement");
    assert_eq!(
        evaluate_consent(&malformed_disclosure, None, &[]),
        ConsentDecision::Hide
    );

    // A revoked (or malformed) disclosure scope remains HIDE at the adapter
    // too: it yields no bound at all rather than a permissive one.
    let revoked = DisclosureScope {
        status: DisclosureScopeStatus::Revoked,
        ..DisclosureScope::task_scoped("purpose", vec![entity(0x71)], 5).expect("scope")
    };
    assert_eq!(
        disclosure_grant_from_disclosure_scope(&revoked, "contact:doctor", "health")
            .expect_err("revoked scope")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
}

// ---------------------------------------------------------------------------
// 9 · Exactly two human surfaces
// ---------------------------------------------------------------------------

/// `9 · Exactly two human surfaces` — "(a) The in-moment ask, raised only when
/// genuinely uncertain. (b) A 'who-can-see-what / what-can-run' registry to
/// review and one-tap revoke. No duration pickers (once vs standing only; the
/// registry replaces expiry-guessing). No sensitivity-tagging settings (tiers
/// are inferred and drive auto). At connector add the ARCH-0072 admission
/// slate is surface (a) in batch form, and the grants it mints live in surface
/// (b) afterwards — no third surface and no settings screen. The invariant-2
/// confirm trio adds no duration option; the no-duration-picker rule above is
/// unchanged. The reverse flip (auto back to confirm-first) lives on the
/// registry surface."
#[test]
fn consent_has_only_ask_and_registry_surfaces_no_duration_picker() {
    let (_dir, vault, owner) = owner_vault();

    // SURFACE (a) — the in-moment ask. Every emitted action id maps into the
    // confirm TRIO and nothing else, so the ask offers exactly three outcomes
    // no matter how many bound-naming escalators a surface renders.
    assert_eq!(
        ConsentConfirmOutcome::trio(),
        [
            ConsentConfirmOutcome::ApproveOnce,
            ConsentConfirmOutcome::ApproveAndStopAsking,
            ConsentConfirmOutcome::Deny,
        ]
    );
    assert_eq!(
        ConsentConfirmOutcome::trio().first().copied(),
        Some(ConsentConfirmOutcome::ApproveOnce),
        "approve once is the default"
    );

    // The emitted ids: approve-once, deny, and one bound-naming
    // approve-and-stop-asking id per escalator — plus the BATCH form, which is
    // surface (a) in batch form (the ARCH-0072 slate), never a third surface.
    let mut emitted = vec![
        crate::genui::CONSENT_ACTION_APPROVE_ONCE.to_owned(),
        crate::genui::CONSENT_ACTION_DECLINE.to_owned(),
        crate::genui::CONSENT_BUNDLE_ACTION_DECLINE.to_owned(),
    ];
    emitted.extend(ConsentScopeEscalator::all().iter().map(|scope| {
        format!(
            "{}{}",
            crate::genui::CONSENT_ACTION_ESCALATE_PREFIX,
            scope.as_str()
        )
    }));
    emitted.push(format!(
        "{}{}",
        crate::genui::CONSENT_BUNDLE_ACTION_ID_PREFIX,
        crate::genui::BundleApprovalScope::BriefVerbClass.as_str()
    ));

    for action_id in &emitted {
        let outcome = ConsentConfirmOutcome::from_action_id(action_id)
            .unwrap_or_else(|| panic!("ask action id {action_id} must map into the confirm trio"));
        assert!(
            ConsentConfirmOutcome::trio().contains(&outcome),
            "{action_id} mapped outside the trio"
        );
        // NO DURATION PICKER anywhere on the ask.
        assert!(
            !crate::genui::consent_action_id_offers_duration(action_id),
            "ask action id {action_id} must not offer a duration option"
        );
    }

    // Approve-and-stop-asking is REACHABLE (it is the in-moment path into
    // create_standing_grant) and each of its ids names ONE bound.
    assert!(
        emitted.iter().any(|action_id| {
            ConsentConfirmOutcome::from_action_id(action_id)
                == Some(ConsentConfirmOutcome::ApproveAndStopAsking)
        }),
        "the trio's stop-asking outcome must be offered"
    );

    // SURFACE (b) — the registry: review + ONE-TAP REVOKE, for BOTH domains.
    let action = action_bound("agent-a", "send", &["channel:email"]);
    let disclosure = disclosure_bound(&["contact:doctor"], "health", &["entity:vitals"]);
    vault
        .create_standing_grant(&owner, action)
        .expect("mint action");
    vault
        .create_standing_grant(&owner, disclosure)
        .expect("mint disclosure");
    let registry = vault
        .consent_registry(ConsentRegistryQuery::new(16, false))
        .expect("registry");
    assert_eq!(registry.rows.len(), 2);
    assert!(
        registry
            .rows
            .iter()
            .any(|row| row.domain == ConsentDomain::Disclosure),
        "the registry is who-can-see-what..."
    );
    assert!(
        registry
            .rows
            .iter()
            .any(|row| row.domain == ConsentDomain::Action),
        "...AND what-can-run — one place for both kinds"
    );
    for row in &registry.rows {
        assert_eq!(row.revoke_action.command, CONSENT_REVOKE_COMMAND);
        assert_eq!(row.revoke_action.grant_ref, row.grant_ref);
    }

    // The one tap actually revokes.
    let revoked = vault
        .revoke_consent_grant(&owner, &registry.rows[0].revoke_action.grant_ref)
        .expect("one-tap revoke");
    assert!(matches!(revoked, ConsentReceipt::Revoked { .. }));
    assert_eq!(
        vault
            .consent_registry(ConsentRegistryQuery::new(16, false))
            .expect("registry")
            .rows
            .len(),
        1
    );

    // NO DURATION/EXPIRY FIELD on a bound or a registry row: the persisted key
    // set is closed and carries none. The ARCH-0071 delegation duration is a
    // mint-time field on the DELEGATION record, which lives outside this
    // module — nothing here duplicates it or turns it into an ask option.
    assert_eq!(
        CONSENT_GRANT_BODY_KEYS,
        [
            "schema_version",
            "domain",
            "subject",
            "class",
            "envelope",
            "status",
            "owner_stamp",
            "created_at",
        ]
    );
    for key in CONSENT_GRANT_BODY_KEYS {
        for banned in ["expires", "expiry", "duration", "ttl", "until"] {
            assert!(
                !key.contains(banned),
                "consent row key {key} must not carry a lifetime field"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Adapters — fold, never migrate
// ---------------------------------------------------------------------------

/// Every pre-existing grant shape projects into the new bound WITHOUT
/// rewriting its bytes, status vocabulary, or codec.
#[test]
fn consent_adapters_fold_existing_shapes_without_rewriting_them() {
    // AccessGrant → DisclosureGrant.
    let access = crate::access_grant::AccessGrant::companion_profile_read(
        entity(0x51),
        entity(0xB1),
        entity(0xC1),
        42,
    );
    let before = crate::access_grant::encode_access_grant_body(&access).expect("encode");
    let projected = disclosure_grant_from_access_grant(&access).expect("project");
    assert_eq!(projected.bound().domain(), ConsentDomain::Disclosure);
    assert_eq!(
        projected.bound().class().as_str(),
        access.capability.as_str(),
        "the capability becomes the disclosure class"
    );
    assert!(access_grant_projection_is_active(&access));
    let after = crate::access_grant::encode_access_grant_body(&access).expect("encode");
    assert_eq!(
        before, after,
        "projection must not rewrite the source bytes"
    );
    assert_eq!(
        crate::access_grant::decode_access_grant_body(&after).expect("decode"),
        access,
        "the source codec still round-trips unchanged"
    );

    // StandingOutboundGrant scope → ActionGrant, across every blind scope dial.
    let scopes = [
        StandingOutboundGrantScope::Contact {
            contact_ref: "contact:alice".to_owned(),
        },
        StandingOutboundGrantScope::VerbClass {
            verb_class: "send".to_owned(),
        },
        StandingOutboundGrantScope::Channel {
            channel: "email".to_owned(),
        },
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: "brief:q3".to_owned(),
            verb_class: "send".to_owned(),
        },
    ];
    for scope in scopes {
        let dial_before = scope.dial_label();
        let (class, selectors, _) = outbound_scope_axes(&scope);
        assert!(!class.is_empty() && !selectors.is_empty());
        assert_eq!(
            scope.dial_label(),
            dial_before,
            "projection must not change the source scope's dial vocabulary"
        );
    }

    // PolicyScopedGrant → ActionGrant. `receipt_required` may only RESTRICT.
    let policy_grant = PolicyScopedGrant {
        actor_class: Some("agent".to_owned()),
        actor_ref: Some("agent-a".to_owned()),
        effector: "external:send".to_owned(),
        scope: None,
        budget: None,
        receipt_required: true,
    };
    let projected = action_grant_from_policy_scoped_grant(&policy_grant).expect("project");
    assert_eq!(projected.bound().domain(), ConsentDomain::Action);
    assert_eq!(projected.bound().class().as_str(), "external:send");
    let BoundEnvelope::Action(envelope) = projected.bound().envelope() else {
        panic!("action bound must carry an action envelope");
    };
    assert!(
        envelope.receipt_required(),
        "receipt_required rides the envelope as an obligation"
    );
    // A grant naming no actor names no subject, so it cannot become a bound —
    // `receipt_required` can never conjure authority.
    let subjectless = PolicyScopedGrant {
        actor_ref: None,
        ..policy_grant
    };
    assert_eq!(
        action_grant_from_policy_scoped_grant(&subjectless)
            .expect_err("no subject")
            .kind(),
        ErrorKind::InvalidConsentBound
    );

    // DisclosureScope → DisclosureGrant.
    let scope = DisclosureScope::task_scoped("q3 planning", vec![entity(0x71)], 5).expect("scope");
    let before = crate::disclosure::encode_disclosure_scope_body(&scope).expect("encode");
    let projected = disclosure_grant_from_disclosure_scope(&scope, "contact:doctor", "health")
        .expect("project");
    assert_eq!(projected.bound().domain(), ConsentDomain::Disclosure);
    let after = crate::disclosure::encode_disclosure_scope_body(&scope).expect("encode");
    assert_eq!(
        before, after,
        "projection must not rewrite the source bytes"
    );
    assert_eq!(
        crate::disclosure::decode_disclosure_scope_body(&after).expect("decode"),
        scope
    );
}

/// The consent contract allocates NO entity type and NO type byte: its rows
/// live under a `vault_meta` prefix owned by this module.
#[test]
fn consent_allocates_no_entity_type_or_type_byte() {
    assert_eq!(CONSENT_GRANT_KEY_PREFIX, b"consent.grant.v1:");
    let (_dir, vault, owner) = owner_vault();
    let bound = action_bound("agent-a", "send", &["channel:email"]);
    vault
        .create_standing_grant(&owner, bound.clone())
        .expect("mint");

    // The row is reachable only through the vault_meta prefix — a generic
    // entity read finds nothing, because no entity was created.
    let grant_ref = bound.digest().to_hex();
    assert!(vault.consent_grant(&grant_ref).expect("read").is_some());
    let stray = EntityId::from_hex(&grant_ref[..32]).expect("hex");
    assert!(
        vault.get(&stray).expect("get entity").is_none(),
        "no entity record is minted for a consent grant"
    );
}

// ---------------------------------------------------------------------------
// Codec + containment unit coverage
// ---------------------------------------------------------------------------

#[test]
fn consent_grant_row_round_trips_and_rejects_malformed_bodies() {
    let owner_stamp = ConsentOwnerStamp {
        actor: entity(0x51),
        principal_ref: "principal:owner".to_owned(),
        decision_id: GateDecisionId::now(),
    };
    for bound in [
        action_bound("agent-a", "send", &["channel:email"]),
        disclosure_bound(&["contact:doctor"], "health", &["entity:vitals"]),
    ] {
        let row = ConsentGrantRow {
            grant: StandingConsentGrant::from_bound(bound).expect("grant"),
            status: ConsentGrantStatus::Active,
            owner_stamp: owner_stamp.clone(),
            created_at: 99,
        };
        let bytes = encode_consent_grant_row(&row).expect("encode");
        assert_eq!(decode_consent_grant_row(&bytes).expect("decode"), row);

        // Trailing bytes and a truncated body are both rejected fail-closed.
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            decode_consent_grant_row(&trailing)
                .expect_err("trailing bytes")
                .kind(),
            ErrorKind::InvalidConsentGrantRow
        );
        assert_eq!(
            decode_consent_grant_row(&bytes[..bytes.len() - 1])
                .expect_err("truncated")
                .kind(),
            ErrorKind::InvalidConsentGrantRow
        );
    }

    // A row whose stored subject kind disagrees with its stored domain is a
    // crossed triple ON DISK: rejected, never reinterpreted.
    let crossed = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CONSENT_GRANT_SCHEMA_VERSION),
        ),
        (Value::from(KEY_DOMAIN), Value::from(DOMAIN_ACTION)),
        (
            Value::from(KEY_SUBJECT),
            Value::Map(vec![
                (
                    Value::from(SUBJECT_KEYS[0]),
                    Value::from(SUBJECT_KIND_AUDIENCE),
                ),
                (
                    Value::from(SUBJECT_KEYS[1]),
                    Value::Array(vec![Value::from("contact:doctor")]),
                ),
            ]),
        ),
        (Value::from(KEY_CLASS), Value::from("send")),
        (
            Value::from(KEY_ENVELOPE),
            Value::Map(vec![
                (
                    Value::from(ENVELOPE_KEYS[0]),
                    Value::Array(vec![Value::from("channel:email")]),
                ),
                (Value::from(ENVELOPE_KEYS[1]), Value::Nil),
                (Value::from(ENVELOPE_KEYS[2]), Value::Nil),
                (Value::from(ENVELOPE_KEYS[3]), Value::from(false)),
            ]),
        ),
        (Value::from(KEY_STATUS), Value::from("active")),
        (
            Value::from(KEY_OWNER_STAMP),
            Value::Map(vec![
                (
                    Value::from(OWNER_STAMP_KEYS[0]),
                    Value::from(entity(0x51).to_hex()),
                ),
                (
                    Value::from(OWNER_STAMP_KEYS[1]),
                    Value::from("principal:owner"),
                ),
                (
                    Value::from(OWNER_STAMP_KEYS[2]),
                    Value::from(GateDecisionId::now().to_hex()),
                ),
            ]),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(1_u64)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &crossed).expect("encode");
    assert_eq!(
        decode_consent_grant_row(&bytes)
            .expect_err("crossed triple on disk")
            .kind(),
        ErrorKind::InvalidConsentGrantRow
    );
}

#[test]
fn consent_bound_containment_is_deterministic_and_monotone() {
    let wide = action_bound("agent-a", "send", &["channel:email", "channel:sms"]);
    let narrow = action_bound("agent-a", "send", &["channel:email"]);

    // Reflexive and monotone: wide ⊇ narrow, and never the reverse.
    assert!(wide.contains(&wide));
    assert!(wide.contains(&narrow));
    assert!(!narrow.contains(&wide));

    // Deterministic: selector ORDER at construction changes neither the answer
    // nor the digest.
    let reordered = action_bound("agent-a", "send", &["channel:sms", "channel:email"]);
    assert_eq!(wide, reordered);
    assert_eq!(wide.digest(), reordered.digest());
    assert!(reordered.contains(&narrow));

    // A class-pinned subject does not cover an unpinned (wider) candidate.
    let class_pinned = GrantBound::action(
        ActorBound::new("agent-a")
            .expect("actor")
            .with_actor_class("agent")
            .expect("class"),
        ActionClass::new("send").expect("class"),
        ActionEnvelope::new(["channel:email".to_owned()]).expect("envelope"),
    )
    .expect("bound");
    assert!(!class_pinned.contains(&narrow));
    assert!(narrow.contains(&class_pinned));

    // A target-pinned envelope does not cover an unpinned candidate, and a
    // budget cap is respected.
    let targeted = GrantBound::action(
        ActorBound::new("agent-a").expect("actor"),
        ActionClass::new("send").expect("class"),
        ActionEnvelope::new(["channel:email".to_owned()])
            .expect("envelope")
            .with_target("contact:alice")
            .expect("target")
            .with_budget(10),
    )
    .expect("bound");
    assert!(!targeted.contains(&narrow));
    let under_budget = GrantBound::action(
        ActorBound::new("agent-a").expect("actor"),
        ActionClass::new("send").expect("class"),
        ActionEnvelope::new(["channel:email".to_owned()])
            .expect("envelope")
            .with_target("contact:alice")
            .expect("target")
            .with_budget(5),
    )
    .expect("bound");
    assert!(targeted.contains(&under_budget));

    // An empty envelope is not a bound.
    assert_eq!(
        ActionEnvelope::new(Vec::new())
            .expect_err("empty envelope")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
    // Nor is an empty audience.
    assert_eq!(
        AudienceBound::new(Vec::new())
            .expect_err("empty audience")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
}

#[test]
fn consent_effect_digests_are_engine_computed_and_collision_resistant() {
    // Field boundaries are length-prefixed, so shifting a boundary changes the
    // digest instead of colliding.
    let left = action_bound("agent-a", "send", &["ab", "c"]);
    let right = action_bound("agent-a", "send", &["a", "bc"]);
    assert_ne!(left.digest(), right.digest());

    // The effect digest covers the facts AND both requirements.
    let base = ComposedEffect::new(irreversible_send_facts());
    let with_action = base
        .clone()
        .with_action_requirement(action_bound("agent-a", "send", &["channel:email"]))
        .expect("requirement");
    let with_both = with_action
        .clone()
        .with_disclosure_requirement(disclosure_bound(
            &["contact:doctor"],
            "health",
            &["entity:vitals"],
        ))
        .expect("requirement");
    assert_ne!(base.digest(), with_action.digest());
    assert_ne!(with_action.digest(), with_both.digest());

    // Bound and effect digests use separate domains, so a bound digest can
    // never be replayed as an effect digest.
    let bound = action_bound("agent-a", "send", &["channel:email"]);
    assert_ne!(
        bound.digest(),
        ComposedEffect::new(irreversible_send_facts()).digest()
    );
}

#[test]
fn consent_receipts_project_into_the_gate_receipt_family() {
    let (_dir, vault, owner) = owner_vault();
    let bound = action_bound("agent-a", "send", &["channel:email"]);
    let grant_ref = bound.digest().to_hex();

    // Standing creation: `grant_ref` joins the row, `diff_handle` is the bound
    // digest, and the reason code sits in the pinned `gate.` namespace.
    let created = vault
        .create_standing_grant(&owner, bound.clone())
        .expect("mint");
    assert_eq!(created.grant_ref().as_deref(), Some(grant_ref.as_str()));
    assert_eq!(created.diff_handle(), bound.digest().as_bytes().to_vec());
    assert_eq!(created.reason_code(), CONSENT_REASON_STANDING_CREATED);

    // Quiet in-bound reuse joins the same row via `grant_ref` plus the exact
    // effect digest.
    let effect_digest = ComposedEffect::new(irreversible_send_facts()).digest();
    let used = vault
        .record_standing_grant_use(&grant_ref, effect_digest)
        .expect("use");
    assert_eq!(used.grant_ref().as_deref(), Some(grant_ref.as_str()));
    assert_eq!(used.diff_handle(), effect_digest.as_bytes().to_vec());
    assert_eq!(used.reason_code(), CONSENT_REASON_STANDING_USED);

    // Approve-once and denial carry the op digest and no grant join.
    let once = vault.approve_once(&owner, effect_digest).expect("once");
    assert_eq!(once.grant_ref(), None);
    assert_eq!(once.reason_code(), CONSENT_REASON_APPROVE_ONCE);
    let denied = vault.deny_consent(&owner, effect_digest).expect("deny");
    assert_eq!(denied.grant_ref(), None);
    assert_eq!(denied.reason_code(), CONSENT_REASON_DENIED);
    assert_eq!(denied.gate_outcome(), "denied");

    // Every reason code is in the `gate.` namespace the ledger pins.
    for reason in [
        CONSENT_REASON_APPROVE_ONCE,
        CONSENT_REASON_STANDING_CREATED,
        CONSENT_REASON_STANDING_USED,
        CONSENT_REASON_DENIED,
        CONSENT_REASON_REVOKED,
    ] {
        assert!(
            reason.starts_with("gate."),
            "{reason} must be gate-namespaced"
        );
    }

    // Revocation is immediate: a revoked row cannot record further use.
    vault
        .revoke_consent_grant(&owner, &grant_ref)
        .expect("revoke");
    assert_eq!(
        vault
            .record_standing_grant_use(&grant_ref, effect_digest)
            .expect_err("revoked row")
            .kind(),
        ErrorKind::ConsentGrantRevoked
    );
    assert_eq!(
        vault
            .record_standing_grant_use("not-a-row", effect_digest)
            .expect_err("missing row")
            .kind(),
        ErrorKind::ConsentGrantNotFound
    );
}

#[test]
fn consent_rows_carry_no_credential_or_posture_fields() {
    // A static check over the pinned key set: no key names key material, a
    // bearer token, a credential, or a hosting posture.
    for key in CONSENT_GRANT_BODY_KEYS {
        for banned in [
            "key",
            "secret",
            "token",
            "bearer",
            "credential",
            "password",
            "posture",
            "hosted",
        ] {
            assert!(
                !key.contains(banned),
                "consent row key {key} must not carry {banned} material"
            );
        }
    }
    // The owner stamp holds REFERENCES only.
    for key in OWNER_STAMP_KEYS {
        assert!(
            key.ends_with("_ref") || key == "actor" || key == "decision_id",
            "owner stamp key {key} must be a reference, not material"
        );
    }
}

#[test]
fn consent_settle_bound_shape_is_action_domain_and_target_exact() {
    // The settle arming target's bound: an actor + `artifact.settle` + the
    // exact brief target. Asserted here as a shape so `edit_settle.rs` and
    // this contract cannot drift apart.
    let actor = crate::write_envelope::WriteActor::new(entity(0x51), EdgeActorClass::Human);
    let bound = GrantBound::action(
        ActorBound::new(actor.entity_ref().to_hex()).expect("actor"),
        ActionClass::new("artifact.settle").expect("class"),
        ActionEnvelope::new(["brief:q3".to_owned()])
            .expect("envelope")
            .with_target("brief:q3")
            .expect("target"),
    )
    .expect("bound");
    assert_eq!(bound.domain(), ConsentDomain::Action);

    // A disclosure grant never authorizes a settle.
    let disclosure = disclosure_bound(&["contact:doctor"], "health", &["entity:vitals"]);
    assert!(!disclosure.contains(&bound));

    // Nor does a wider-target assumption: a settle grant for one brief does
    // not cover another.
    let other_brief = GrantBound::action(
        ActorBound::new(actor.entity_ref().to_hex()).expect("actor"),
        ActionClass::new("artifact.settle").expect("class"),
        ActionEnvelope::new(["brief:q4".to_owned()])
            .expect("envelope")
            .with_target("brief:q4")
            .expect("target"),
    )
    .expect("bound");
    assert!(!bound.contains(&other_brief));

    // And another actor's settle grant does not cover this actor's settle.
    let other_actor = GrantBound::action(
        ActorBound::new(entity(0x62).to_hex()).expect("actor"),
        ActionClass::new("artifact.settle").expect("class"),
        ActionEnvelope::new(["brief:q3".to_owned()])
            .expect("envelope")
            .with_target("brief:q3")
            .expect("target"),
    )
    .expect("bound");
    assert!(!other_actor.contains(&bound));
}
