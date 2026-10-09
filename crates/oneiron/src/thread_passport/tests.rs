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

// ─── threading physics ──────────────────────────────────────────────────

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

#[test]
fn long_evidenced_alias_chains_converge_without_an_availability_cliff() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let mut messages: Vec<_> = (0..MAX_THREAD_ALIAS_HOPS + 2)
        .map(|n| mid(&format!("root-{n}@x")))
        .collect();
    messages.sort_by_key(CanonicalMessageId::minted_thread_ref);
    for message in &messages {
        vault
            .record_thread_passport(ThreadPassportInput::new(
                identity,
                entity(0xA9),
                message.clone(),
                OBSERVED_AT,
            ))
            .unwrap();
    }
    for pair in messages.windows(2).rev() {
        vault
            .record_thread_passport(
                input(identity, &format!("bridge-{}", pair[0]), OBSERVED_AT + 1)
                    .with_references(pair.to_vec()),
            )
            .unwrap();
    }
    for message in &messages {
        assert_eq!(
            vault
                .canonical_thread_ref(&message.minted_thread_ref())
                .unwrap(),
            messages[0].minted_thread_ref()
        );
    }
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

#[path = "regressions.rs"]
mod regressions;
