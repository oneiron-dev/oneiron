use super::*;
use crate::Vault;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, SelfHeldShape,
};
use crate::channel_identity_selection::{
    ChannelIdentityCandidate, ChannelIdentityFace, ChannelIdentitySelectionQuery,
    RelationshipContext, compile_channel_identity_selection, resolve_channel_identity_selection,
};
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::test_util::{entity, open_test_vault_with};
use core::assert_matches;

const OBSERVED_AT: u64 = 1_800_000_000;

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

/// Creates a live `ChannelIdentity` record so passports have a legal subject.
fn seed_identity(vault: &Vault, id: EntityId, address: &str) {
    let identity = ChannelIdentity::requested(
        "email",
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x51)),
        OBSERVED_AT,
    );
    vault
        .create_channel_identity(&id, &identity)
        .expect("seed channel identity");
}

fn mid(raw: &str) -> CanonicalMessageId {
    canonical_message_id(raw).expect("canonical message id")
}

fn input(identity_ref: EntityId, message_id: &str, observed_at: u64) -> ThreadPassportInput {
    ThreadPassportInput::new(identity_ref, entity(0xA9), mid(message_id), observed_at)
}

fn active_passport_count(vault: &Vault) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    active_passport_rows(vault, &rtxn)
        .expect("passport rows")
        .len()
}

// ─── canonicalization ───────────────────────────────────────────────────

#[test]
fn message_id_case_is_preserved() {
    // Outer whitespace and one <...> pair come off; case survives untouched.
    assert_eq!(
        mid("  <AbC.DeF@Example.COM>  ").as_str(),
        "AbC.DeF@Example.COM"
    );
    assert_eq!(mid("AbC.DeF@Example.COM").as_str(), "AbC.DeF@Example.COM");
    // Only ONE pair is unwrapped, and a residual bracket is then refused.
    assert_matches!(
        canonical_message_id("<<a@b>>").map(CanonicalMessageId::into_string),
        Err(err) if err.kind() == ErrorKind::InvalidClaimBody
    );

    // Case-distinct ids stay distinct all the way through thread minting.
    assert_ne!(mid("A@b.com"), mid("a@b.com"));
    assert_ne!(
        mid("A@b.com").minted_thread_ref(),
        mid("a@b.com").minted_thread_ref()
    );
    assert!(
        mid("A@b.com")
            .minted_thread_ref()
            .starts_with(THREAD_REF_PREFIX)
    );
    // Deterministic: the same token always mints the same ref.
    assert_eq!(
        mid("A@b.com").minted_thread_ref(),
        mid("  <A@b.com> ").minted_thread_ref()
    );

    for rejected in [
        "",
        "   ",
        "<>",
        "a b@c.com",
        "a\tb@c.com",
        "a\nb@c.com",
        "a\u{0}b@c.com",
        "a<b@c.com",
    ] {
        assert_matches!(
            canonical_message_id(rejected),
            Err(err) if err.kind() == ErrorKind::InvalidClaimBody,
            "{rejected:?} must be refused"
        );
    }

    // The 998-byte cap is measured on the CANONICAL form.
    let longest = format!("{}@x", "a".repeat(MAX_MESSAGE_ID_BYTES - 2));
    assert_eq!(longest.len(), MAX_MESSAGE_ID_BYTES);
    assert_eq!(mid(&format!("  <{longest}>  ")).as_str(), longest);
    assert_matches!(
        canonical_message_id(&format!("{longest}x")),
        Err(err) if err.kind() == ErrorKind::InvalidClaimBody
    );
}

#[test]
fn reference_lists_dedupe_without_reordering() {
    let list = canonical_message_id_list(&["<c@x>", " <a@x> ", "c@x", "<b@x>", "a@x"])
        .expect("canonical list");
    assert_eq!(
        list.iter()
            .map(CanonicalMessageId::as_str)
            .collect::<Vec<_>>(),
        ["c@x", "a@x", "b@x"]
    );

    // In-Reply-To normalizes through the same function and dedupes against
    // References without disturbing provider order.
    let chain = input(entity(0x61), "<m@x>", OBSERVED_AT)
        .with_references(list)
        .with_in_reply_to(mid("<c@x>"));
    assert_eq!(
        chain
            .reference_chain()
            .into_iter()
            .map(CanonicalMessageId::as_str)
            .collect::<Vec<_>>(),
        ["c@x", "a@x", "b@x"]
    );

    // A malformed entry fails the whole list rather than being dropped.
    assert_matches!(
        canonical_message_id_list(&["<a@x>", "b b@x"]),
        Err(err) if err.kind() == ErrorKind::InvalidClaimBody
    );
}

// ─── threading physics ──────────────────────────────────────────────────

#[test]
fn references_join_existing_thread() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    let root = vault
        .record_thread_passport(input(identity, "<root@x>", OBSERVED_AT))
        .expect("root passport");
    assert_eq!(root.canonical_thread_ref, mid("root@x").minted_thread_ref());
    assert!(root.aliased_thread_refs.is_empty());

    // In-Reply-To alone joins.
    let reply = vault
        .record_thread_passport(
            input(identity, "<reply@x>", OBSERVED_AT + 1).with_in_reply_to(mid("<root@x>")),
        )
        .expect("reply passport");
    assert_eq!(reply.canonical_thread_ref, root.canonical_thread_ref);
    assert!(reply.aliased_thread_refs.is_empty());

    // References alone joins, including a reference the vault has never seen.
    let third = vault
        .record_thread_passport(
            input(identity, "<third@x>", OBSERVED_AT + 2)
                .with_references(vec![mid("<unknown@x>"), mid("<root@x>")]),
        )
        .expect("third passport");
    assert_eq!(third.canonical_thread_ref, root.canonical_thread_ref);

    // A message referencing nothing known mints its OWN thread.
    let orphan = vault
        .record_thread_passport(
            input(identity, "<orphan@x>", OBSERVED_AT + 3).with_references(vec![mid("<nobody@x>")]),
        )
        .expect("orphan passport");
    assert_eq!(
        orphan.canonical_thread_ref,
        mid("orphan@x").minted_thread_ref()
    );
    assert_ne!(orphan.canonical_thread_ref, root.canonical_thread_ref);

    let members = vault
        .thread_passports(&root.canonical_thread_ref)
        .expect("thread passports");
    assert_eq!(
        members
            .iter()
            .map(|passport| passport.message_id.as_str())
            .collect::<Vec<_>>(),
        ["root@x", "reply@x", "third@x"]
    );
}

#[test]
fn bridge_roots_converges_order_independently() {
    // Two independent roots, then one message referencing both. The surviving
    // thread must be the lexicographically smallest ref in EITHER arrival
    // order, with alias rows carrying every other root onto it.
    let canonical_for = |reversed: bool| -> (String, Vec<String>, String, String) {
        let (_dir, vault) = test_vault();
        let identity = entity(0x61);
        seed_identity(&vault, identity, "agent@example.com");

        let first = if reversed { "<beta@x>" } else { "<alpha@x>" };
        let second = if reversed { "<alpha@x>" } else { "<beta@x>" };
        let head = vault
            .record_thread_passport(input(identity, first, OBSERVED_AT))
            .expect("first root");
        let tail = vault
            .record_thread_passport(input(identity, second, OBSERVED_AT + 1))
            .expect("second root");
        assert_ne!(head.canonical_thread_ref, tail.canonical_thread_ref);

        let bridge = vault
            .record_thread_passport(
                input(identity, "<bridge@x>", OBSERVED_AT + 2)
                    .with_references(vec![mid(second), mid(first)]),
            )
            .expect("bridge passport");

        // Every root now READS as the survivor.
        let alpha = vault
            .canonical_thread_ref(&mid("alpha@x").minted_thread_ref())
            .expect("alpha canonical");
        let beta = vault
            .canonical_thread_ref(&mid("beta@x").minted_thread_ref())
            .expect("beta canonical");
        assert_eq!(alpha, bridge.canonical_thread_ref);
        assert_eq!(beta, bridge.canonical_thread_ref);
        assert_eq!(
            vault
                .thread_passports(&bridge.canonical_thread_ref)
                .expect("converged members")
                .len(),
            3
        );
        (
            bridge.canonical_thread_ref,
            bridge.aliased_thread_refs,
            alpha,
            beta,
        )
    };

    let forward = canonical_for(false);
    let backward = canonical_for(true);
    assert_eq!(forward, backward);

    let smallest = std::cmp::min(
        mid("alpha@x").minted_thread_ref(),
        mid("beta@x").minted_thread_ref(),
    );
    let largest = std::cmp::max(
        mid("alpha@x").minted_thread_ref(),
        mid("beta@x").minted_thread_ref(),
    );
    assert_eq!(forward.0, smallest);
    assert_eq!(forward.1, vec![largest]);
}

#[test]
fn bridging_a_third_root_keeps_reads_at_one_fixed_point() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    let mut roots = Vec::new();
    for (index, raw) in ["<r1@x>", "<r2@x>", "<r3@x>"].into_iter().enumerate() {
        let observed = OBSERVED_AT + u64::try_from(index).expect("small index");
        roots.push(
            vault
                .record_thread_passport(input(identity, raw, observed))
                .expect("root passport")
                .canonical_thread_ref,
        );
    }

    // Bridge r1+r2, then a second bridge pulling r3 in as well.
    vault
        .record_thread_passport(
            input(identity, "<b1@x>", OBSERVED_AT + 10)
                .with_references(vec![mid("<r1@x>"), mid("<r2@x>")]),
        )
        .expect("first bridge");
    let second = vault
        .record_thread_passport(
            input(identity, "<b2@x>", OBSERVED_AT + 11)
                .with_references(vec![mid("<r2@x>"), mid("<r3@x>")]),
        )
        .expect("second bridge");

    let mut sorted = roots.clone();
    sorted.sort();
    assert_eq!(second.canonical_thread_ref, sorted[0]);
    for root in &roots {
        assert_eq!(
            vault.canonical_thread_ref(root).expect("canonical"),
            sorted[0],
            "every root must reach the one fixed point"
        );
    }
    assert_eq!(
        vault
            .thread_passports(&sorted[2])
            .expect("members via an aliased ref")
            .len(),
        5
    );
}

#[test]
fn passport_replay_is_idempotent() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    let first = vault
        .record_thread_passport(input(identity, "<root@x>", OBSERVED_AT))
        .expect("first landing");
    assert_eq!(active_passport_count(&vault), 1);

    // The exact same provider event, replayed.
    let replay = vault
        .record_thread_passport(input(identity, " <root@x> ", OBSERVED_AT))
        .expect("replay");
    assert_eq!(replay, first);
    assert_eq!(active_passport_count(&vault), 1);

    // A replay carrying a DIFFERENT mask still returns the stored row: the
    // active passport is never restamped and never duplicated.
    let flipped = vault
        .record_thread_passport(
            ThreadPassportInput::new(identity, entity(0xB9), mid("<root@x>"), OBSERVED_AT + 5)
                .with_facet(entity(0xC9)),
        )
        .expect("replay with another mask");
    assert_eq!(flipped.passport, first.passport);
    assert_eq!(active_passport_count(&vault), 1);

    assert_eq!(
        vault
            .thread_passport(&identity, &mid("root@x"))
            .expect("read back"),
        Some(first.passport.clone())
    );

    // A replay after convergence reports where the row reads TODAY while the
    // stored ref stays the evidence it was written as.
    vault
        .record_thread_passport(input(identity, "<other@x>", OBSERVED_AT + 6))
        .expect("second root");
    vault
        .record_thread_passport(
            input(identity, "<bridge@x>", OBSERVED_AT + 7)
                .with_references(vec![mid("<root@x>"), mid("<other@x>")]),
        )
        .expect("bridge");
    let after = vault
        .record_thread_passport(input(identity, "<root@x>", OBSERVED_AT))
        .expect("replay after convergence");
    assert_eq!(after.passport.thread_ref, first.passport.thread_ref);
    assert_eq!(
        after.canonical_thread_ref,
        std::cmp::min(
            mid("root@x").minted_thread_ref(),
            mid("other@x").minted_thread_ref()
        )
    );
    assert!(after.aliased_thread_refs.is_empty());
}

#[test]
fn passport_requires_a_live_channel_identity_subject() {
    let (_dir, vault) = test_vault();
    assert_matches!(
        vault.record_thread_passport(input(entity(0x61), "<root@x>", OBSERVED_AT)),
        Err(err) if err.kind() == ErrorKind::EntityNotFound
    );

    // An entity that exists but is not a ChannelIdentity is refused too: a
    // passport may only be filed against a real identity record.
    let stranger = crate::comm::resolve_or_create_comm_party(&vault, "someone@example.com")
        .expect("seed a non-identity entity");
    assert_matches!(
        vault.record_thread_passport(input(stranger, "<root@x>", OBSERVED_AT)),
        Err(Error::InvalidEntityType(_))
    );
    assert_eq!(active_passport_count(&vault), 0);
}

// ─── sticky mask ────────────────────────────────────────────────────────

#[test]
fn sticky_identity_and_facet() {
    let (_dir, vault) = test_vault();
    let first_identity = entity(0x61);
    let second_identity = entity(0x62);
    seed_identity(&vault, first_identity, "one@example.com");
    seed_identity(&vault, second_identity, "two@example.com");

    let thread_ref = mid("root@x").minted_thread_ref();
    assert_eq!(
        vault
            .sticky_thread_mask(&thread_ref, None)
            .expect("unpinned thread"),
        StickyMaskDecision::Unset
    );

    let pinned = ThreadMask::new(first_identity, entity(0xA9)).with_facet(entity(0xF1));
    let landing = vault
        .record_thread_passport(
            ThreadPassportInput::new(first_identity, entity(0xA9), mid("<root@x>"), OBSERVED_AT)
                .with_facet(entity(0xF1)),
        )
        .expect("first passport");
    assert_eq!(landing.passport.mask, pinned);

    // The composer builds the upstream selection pin out of the mask and the
    // CANONICAL ref this module resolved; the actor stays behind.
    let pin = landing
        .passport
        .mask
        .thread_pin(landing.canonical_thread_ref.as_str());
    assert_eq!(pin.thread_ref, thread_ref);
    assert_eq!(pin.identity_ref, first_identity);
    assert_eq!(pin.facet_ref, Some(entity(0xF1)));

    assert_eq!(
        vault.sticky_thread_mask(&thread_ref, None).expect("keep"),
        StickyMaskDecision::Keep(pinned)
    );
    assert_eq!(
        vault
            .sticky_thread_mask(&thread_ref, Some(pinned))
            .expect("agreeing request"),
        StickyMaskDecision::Keep(pinned)
    );

    // A different identity, a different actor, and a different facet are each
    // a conflict — never a silent flip.
    for requested in [
        ThreadMask::new(second_identity, entity(0xA9)).with_facet(entity(0xF1)),
        ThreadMask::new(first_identity, entity(0xB9)).with_facet(entity(0xF1)),
        ThreadMask::new(first_identity, entity(0xA9)).with_facet(entity(0xF2)),
        ThreadMask::new(first_identity, entity(0xA9)),
    ] {
        assert_eq!(
            vault
                .sticky_thread_mask(&thread_ref, Some(requested))
                .expect("conflicting request"),
            StickyMaskDecision::Conflict { pinned, requested }
        );
    }

    // A later message from ANOTHER identity joins the thread but does not
    // move the pin, and the pin follows the thread across convergence.
    vault
        .record_thread_passport(
            ThreadPassportInput::new(
                second_identity,
                entity(0xB9),
                mid("<reply@x>"),
                OBSERVED_AT + 1,
            )
            .with_in_reply_to(mid("<root@x>")),
        )
        .expect("second identity joins");
    assert_eq!(
        vault
            .sticky_thread_mask(&thread_ref, None)
            .expect("still pinned"),
        StickyMaskDecision::Keep(pinned)
    );
    assert_eq!(
        vault
            .sticky_thread_mask(&mid("reply@x").minted_thread_ref(), None)
            .expect("unrelated ref is its own thread"),
        StickyMaskDecision::Unset
    );
}

#[test]
fn sticky_mask_pins_on_the_earliest_passport_after_convergence() {
    let (_dir, vault) = test_vault();
    let early_identity = entity(0x61);
    let late_identity = entity(0x62);
    seed_identity(&vault, early_identity, "one@example.com");
    seed_identity(&vault, late_identity, "two@example.com");

    // "zzz" mints the larger ref, so convergence keeps "aaa"'s thread — but
    // the PIN must follow the earliest observation, not the surviving ref.
    let late = vault
        .record_thread_passport(ThreadPassportInput::new(
            late_identity,
            entity(0xB9),
            mid("<aaa@x>"),
            OBSERVED_AT + 100,
        ))
        .expect("late root");
    let early = vault
        .record_thread_passport(ThreadPassportInput::new(
            early_identity,
            entity(0xA9),
            mid("<zzz@x>"),
            OBSERVED_AT,
        ))
        .expect("early root");
    let bridge = vault
        .record_thread_passport(
            input(early_identity, "<bridge@x>", OBSERVED_AT + 200)
                .with_references(vec![mid("<aaa@x>"), mid("<zzz@x>")]),
        )
        .expect("bridge");

    assert_eq!(
        bridge.canonical_thread_ref,
        std::cmp::min(
            late.canonical_thread_ref,
            early.canonical_thread_ref.clone()
        )
    );
    assert_eq!(
        vault
            .sticky_thread_mask(&bridge.canonical_thread_ref, None)
            .expect("pinned mask"),
        StickyMaskDecision::Keep(ThreadMask::new(early_identity, entity(0xA9)))
    );
    // Reading through the aliased-away ref answers identically.
    assert_eq!(
        vault
            .sticky_thread_mask(&early.canonical_thread_ref, None)
            .expect("pinned mask via alias"),
        StickyMaskDecision::Keep(ThreadMask::new(early_identity, entity(0xA9)))
    );
}

// ─── selection hand-off ─────────────────────────────────────────────────

#[test]
fn thread_pin_carries_the_canonical_ref_into_selection() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    // Two roots then a bridge, so the ref the composer must pin is the
    // SURVIVOR rather than the ref the first passport was written as.
    let root = vault
        .record_thread_passport(
            ThreadPassportInput::new(identity, entity(0xA9), mid("<alpha@x>"), OBSERVED_AT)
                .with_facet(entity(0xF1)),
        )
        .expect("alpha root");
    vault
        .record_thread_passport(input(identity, "<beta@x>", OBSERVED_AT + 1))
        .expect("beta root");
    vault
        .record_thread_passport(
            input(identity, "<bridge@x>", OBSERVED_AT + 2)
                .with_references(vec![mid("<alpha@x>"), mid("<beta@x>")]),
        )
        .expect("bridge");

    let canonical = vault
        .canonical_thread_ref(&root.passport.thread_ref)
        .expect("canonical ref");
    let StickyMaskDecision::Keep(pinned) = vault
        .sticky_thread_mask(&canonical, None)
        .expect("sticky mask")
    else {
        panic!("the thread wears its earliest passport's mask");
    };
    let pin = pinned.thread_pin(canonical.as_str());
    assert_eq!(pin.thread_ref, canonical);
    assert_eq!(pin.identity_ref, identity);
    assert_eq!(pin.facet_ref, Some(entity(0xF1)));
    // The actor rides the mask, never the pin: selection does not see it.
    assert_eq!(pinned.actor_ref, entity(0xA9));

    // Upstream selection law takes the pin BORROWED and honours it verbatim,
    // ahead of every compiled row — so a minted `mail:v1:` ref must be a legal
    // pin token, not merely a String.
    let compiled = compile_channel_identity_selection(None).expect("compiled defaults");
    let candidates = vec![ChannelIdentityCandidate {
        identity_ref: identity,
        shape: ChannelIdentityShape::DedicatedAddress,
        face: ChannelIdentityFace::AgentNamedAddress,
        active: true,
    }];
    let decision = resolve_channel_identity_selection(
        &compiled,
        ChannelIdentitySelectionQuery {
            relationship: RelationshipContext::WorkDeal,
            applicable_scopes: &[],
            candidates: &candidates,
            thread_pin: Some(&pin),
        },
    )
    .expect("the minted thread ref is a legal selection pin");
    assert!(decision.used_thread_pin);
    assert_eq!(decision.identity_ref, identity);
    assert_eq!(decision.facet_ref, Some(entity(0xF1)));
    assert_eq!(decision.rule_id, None);
}

// ─── alias corruption ───────────────────────────────────────────────────

/// Writes a raw alias row, bypassing the typed door so a corrupt graph can be
/// staged. Production code has no path that produces these.
fn write_raw_alias(vault: &Vault, identity_ref: EntityId, from: &str, to: &str) {
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_ALIAS,
        ClaimSubject::Entity(identity_ref),
        encode_alias_value(identity_ref, from, to, OBSERVED_AT),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    vault
        .with_write_txn(|wtxn| {
            vault.put_claim_in_txn(
                wtxn,
                &EntityId::now(),
                &body,
                TimeRange {
                    start: OBSERVED_AT,
                    end: OBSERVED_AT,
                },
                OBSERVED_AT,
            )
        })
        .expect("raw alias write");
}

#[test]
fn alias_cycle_rejected() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    let root = vault
        .record_thread_passport(input(identity, "<root@x>", OBSERVED_AT))
        .expect("root passport");
    let looped = root.canonical_thread_ref;
    write_raw_alias(&vault, identity, &looped, "mail:v1:bb");
    write_raw_alias(&vault, identity, "mail:v1:bb", &looped);

    // Every read door refuses; none of them loops.
    assert_matches!(
        vault.canonical_thread_ref(&looped),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    assert_matches!(
        vault.sticky_thread_mask("mail:v1:bb", None),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    assert_matches!(
        vault.thread_passports(&looped),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    // Writing refuses too, as soon as a reference reaches the cycle.
    assert_matches!(
        vault.record_thread_passport(
            input(identity, "<later@x>", OBSERVED_AT + 1).with_in_reply_to(mid("<root@x>"))
        ),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    // Replaying the trapped message refuses rather than answering a thread it
    // cannot resolve.
    assert_matches!(
        vault.record_thread_passport(input(identity, "<root@x>", OBSERVED_AT)),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    // A message that never touches the cycle is unaffected: corruption fails
    // the reads that depend on it, not the whole module.
    let untouched = vault
        .record_thread_passport(input(identity, "<elsewhere@x>", OBSERVED_AT + 2))
        .expect("an unrelated thread still lands");
    assert_eq!(
        untouched.canonical_thread_ref,
        mid("elsewhere@x").minted_thread_ref()
    );

    // A self-alias is the degenerate cycle and fails the same way.
    let (_dir2, other) = test_vault();
    seed_identity(&other, identity, "agent@example.com");
    write_raw_alias(&other, identity, "mail:v1:cc", "mail:v1:cc");
    assert_matches!(
        other.canonical_thread_ref("mail:v1:cc"),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
}

#[test]
fn overlong_alias_chain_and_forks_are_rejected() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    // An acyclic chain one hop past the bound still fails typed.
    for hop in 0..=MAX_THREAD_ALIAS_HOPS {
        write_raw_alias(
            &vault,
            identity,
            &format!("mail:v1:h{hop:04}"),
            &format!("mail:v1:h{:04}", hop + 1),
        );
    }
    assert_matches!(
        vault.canonical_thread_ref("mail:v1:h0000"),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );
    // A short chain inside the bound still resolves to its fixed point.
    assert_eq!(
        vault
            .canonical_thread_ref(&format!("mail:v1:h{MAX_THREAD_ALIAS_HOPS:04}"))
            .expect("tail resolves"),
        format!("mail:v1:h{:04}", MAX_THREAD_ALIAS_HOPS + 1)
    );

    let (_dir2, forked) = test_vault();
    seed_identity(&forked, identity, "agent@example.com");
    write_raw_alias(&forked, identity, "mail:v1:aa", "mail:v1:bb");
    write_raw_alias(&forked, identity, "mail:v1:aa", "mail:v1:cc");
    assert_matches!(
        forked.canonical_thread_ref("mail:v1:aa"),
        Err(err) if err.kind() == ErrorKind::CorruptedIndex
    );

    // A duplicated, AGREEING alias row is not a fork.
    let (_dir3, duplicated) = test_vault();
    seed_identity(&duplicated, identity, "agent@example.com");
    write_raw_alias(&duplicated, identity, "mail:v1:aa", "mail:v1:bb");
    write_raw_alias(&duplicated, identity, "mail:v1:aa", "mail:v1:bb");
    assert_eq!(
        duplicated
            .canonical_thread_ref("mail:v1:aa")
            .expect("agreeing duplicate resolves"),
        "mail:v1:bb"
    );
}

#[test]
fn read_doors_reject_malformed_thread_refs() {
    let (_dir, vault) = test_vault();
    for rejected in ["", "mail:v1: aa", "mail:v1:\u{0}aa"] {
        assert_matches!(
            vault.canonical_thread_ref(rejected),
            Err(err) if err.kind() == ErrorKind::InvalidClaimBody
        );
    }
    assert_matches!(
        vault.canonical_thread_ref(&"x".repeat(MAX_THREAD_REF_BYTES + 1)),
        Err(err) if err.kind() == ErrorKind::InvalidClaimBody
    );
    // An unknown ref is its own fixed point.
    assert_eq!(
        vault
            .canonical_thread_ref("mail:v1:unknown")
            .expect("unknown ref"),
        "mail:v1:unknown"
    );
}

// ─── comm hand-off ──────────────────────────────────────────────────────

#[test]
fn thread_membership_joins_the_canonical_thread_through_comm() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");

    let root = vault
        .record_thread_passport(input(identity, "<alpha@x>", OBSERVED_AT))
        .expect("alpha root");
    let other = vault
        .record_thread_passport(input(identity, "<beta@x>", OBSERVED_AT + 1))
        .expect("beta root");
    let bridge = vault
        .record_thread_passport(
            input(identity, "<bridge@x>", OBSERVED_AT + 2)
                .with_references(vec![mid("<alpha@x>"), mid("<beta@x>")]),
        )
        .expect("bridge");

    // Joining through an aliased-away ref lands on the survivor, and comm
    // keeps ownership of the membership claim itself.
    let aliased = if root.canonical_thread_ref == bridge.canonical_thread_ref {
        other.canonical_thread_ref
    } else {
        root.canonical_thread_ref
    };
    let party = "counterparty@example.com";
    vault
        .join_thread_party(&aliased, party, true, OBSERVED_AT + 3)
        .expect("join through the alias");
    crate::comm::run_comm_projector(&vault).expect("project comm events");

    assert_eq!(
        crate::comm::count_active_thread_member_claims(&vault, &bridge.canonical_thread_ref, party)
            .expect("membership on the survivor"),
        1
    );
    assert_eq!(
        crate::comm::count_active_thread_member_claims(&vault, &aliased, party)
            .expect("no membership on the aliased-away root"),
        0
    );
}

// ─── cross-identity first writes ────────────────────────────────────────

#[test]
fn second_identity_first_write_lands_on_the_survivor() {
    // Identity A converges two roots. Identity B then sees the SAME provider
    // event that made one of them — a first write for B, so the replay arm
    // never fires — carrying no references at all. B must land on the
    // survivor: the ref it takes away is the pin token (contract A3), and a
    // converged-away name there would strand every reply.
    let (_dir, vault) = test_vault();
    let first_identity = entity(0x61);
    let second_identity = entity(0x62);
    seed_identity(&vault, first_identity, "one@example.com");
    seed_identity(&vault, second_identity, "two@example.com");

    vault
        .record_thread_passport(input(first_identity, "<aaa@x>", OBSERVED_AT))
        .expect("aaa root");
    vault
        .record_thread_passport(input(first_identity, "<zzz@x>", OBSERVED_AT + 1))
        .expect("zzz root");
    let bridge = vault
        .record_thread_passport(
            input(first_identity, "<bridge@x>", OBSERVED_AT + 2)
                .with_references(vec![mid("<aaa@x>"), mid("<zzz@x>")]),
        )
        .expect("bridge");
    let survivor = bridge.canonical_thread_ref;

    // Whichever root lost the lexicographic contest is the one B replays.
    let converged_away = if mid("aaa@x").minted_thread_ref() == survivor {
        "<zzz@x>"
    } else {
        "<aaa@x>"
    };
    let second = vault
        .record_thread_passport(ThreadPassportInput::new(
            second_identity,
            entity(0xB9),
            mid(converged_away),
            OBSERVED_AT + 20,
        ))
        .expect("second identity first-writes the converged-away Message-ID");

    assert_eq!(second.canonical_thread_ref, survivor);
    assert_ne!(survivor, mid(converged_away).minted_thread_ref());
    // Stored as resolved, not as the dead name, and a join rather than a
    // convergence: nothing new was aliased.
    assert_eq!(second.passport.thread_ref, survivor);
    assert!(second.aliased_thread_refs.is_empty());

    // The ref handed back is a fixed point, so the pin the composer builds out
    // of it is already canonical.
    assert_eq!(
        vault
            .canonical_thread_ref(&second.canonical_thread_ref)
            .expect("canonical ref"),
        second.canonical_thread_ref
    );
    let pin = second
        .passport
        .mask
        .thread_pin(second.canonical_thread_ref.as_str());
    assert_eq!(
        vault
            .canonical_thread_ref(&pin.thread_ref)
            .expect("pin token"),
        pin.thread_ref
    );

    // One thread, four rows, and the pin still wears the earliest mask.
    assert_eq!(active_passport_count(&vault), 4);
    assert_eq!(vault.thread_passports(&survivor).expect("members").len(), 4);
    assert_eq!(
        vault
            .sticky_thread_mask(&survivor, None)
            .expect("still pinned"),
        StickyMaskDecision::Keep(ThreadMask::new(first_identity, entity(0xA9)))
    );
}

#[test]
fn second_identity_first_write_reuses_the_thread_a_message_already_joined() {
    // A landed <child@x> on its parent's thread, so <child@x>'s OWN minted ref
    // was never the thread. Identity B first-writing <child@x> without
    // headers must reuse the parent thread instead of minting a parallel
    // mail:v1: hash for mail this vault has already threaded.
    let (_dir, vault) = test_vault();
    let first_identity = entity(0x61);
    let second_identity = entity(0x62);
    seed_identity(&vault, first_identity, "one@example.com");
    seed_identity(&vault, second_identity, "two@example.com");

    let parent = vault
        .record_thread_passport(input(first_identity, "<parent@x>", OBSERVED_AT))
        .expect("parent root");
    let child = vault
        .record_thread_passport(
            input(first_identity, "<child@x>", OBSERVED_AT + 1).with_in_reply_to(mid("<parent@x>")),
        )
        .expect("child joins the parent thread");
    assert_eq!(child.canonical_thread_ref, parent.canonical_thread_ref);

    let second = vault
        .record_thread_passport(ThreadPassportInput::new(
            second_identity,
            entity(0xB9),
            mid("<child@x>"),
            OBSERVED_AT + 20,
        ))
        .expect("second identity first-writes the child Message-ID");

    assert_eq!(second.canonical_thread_ref, parent.canonical_thread_ref);
    assert_eq!(second.passport.thread_ref, parent.canonical_thread_ref);
    assert_ne!(
        second.canonical_thread_ref,
        mid("child@x").minted_thread_ref()
    );
    assert!(second.aliased_thread_refs.is_empty());

    // The unused minted name stays an unaliased stranger with no members:
    // joining a known thread is not the same as converging two of them.
    assert_eq!(
        vault
            .canonical_thread_ref(&mid("child@x").minted_thread_ref())
            .expect("unused minted ref"),
        mid("child@x").minted_thread_ref()
    );
    assert!(
        vault
            .thread_passports(&mid("child@x").minted_thread_ref())
            .expect("no parallel thread")
            .is_empty()
    );

    assert_eq!(active_passport_count(&vault), 3);
    assert_eq!(
        vault
            .thread_passports(&parent.canonical_thread_ref)
            .expect("members")
            .len(),
        3
    );
    assert_eq!(
        vault
            .sticky_thread_mask(&parent.canonical_thread_ref, None)
            .expect("still pinned"),
        StickyMaskDecision::Keep(ThreadMask::new(first_identity, entity(0xA9)))
    );
}
