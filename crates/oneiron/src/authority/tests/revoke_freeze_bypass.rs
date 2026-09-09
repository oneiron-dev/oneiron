//! Pending-widen freeze with RevokeActor emergency bypass.

use super::support::*;
use super::*;

/// The pending-widen freeze that a `RevokeActor` builds its fixture from: a
/// two-key roster, a live human binding, and a cosigned `EnrollDevice` that is
/// still inside its veto delay, so `state.pending_widens` is non-empty for every
/// entry that follows.
struct PendingWidenFreeze {
    fixture: BindFixture,
    entries: Vec<AuthorityLogEntry>,
    first_seen: BTreeMap<AuthorityEntryHash, u64>,
    widen_hash: AuthorityEntryHash,
    bind_hash: AuthorityEntryHash,
    now_secs: u64,
}

/// Builds the freeze. `long_ago` first-seen times keep genesis/enroll/bind out of
/// the delay; the widen is first seen at `now`, which is what pins it pending.
fn pending_widen_freeze(seed: u8) -> PendingWidenFreeze {
    let fixture = bind_fixture(seed);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();

    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let widen = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&ed_key(seed.wrapping_add(4))),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
        },
        103,
    );
    let widen_hash = authority_entry_hash(&widen).unwrap();

    let now_secs = 10_000_000;
    let mut first_seen = BTreeMap::new();
    for hash in [genesis_hash, enroll_hash, bind_hash] {
        first_seen.insert(hash, 1);
    }
    first_seen.insert(widen_hash, now_secs);

    PendingWidenFreeze {
        entries: vec![fixture.genesis.clone(), fixture.enroll.clone(), bind, widen],
        fixture,
        first_seen,
        widen_hash,
        bind_hash,
        now_secs,
    }
}

/// fix-leg 11 P1-1: a `RevokeActor` must NOT wait behind an unrelated pending
/// widen — a revocation is the operator's emergency brake.
///
/// A pending widen freezes the log: `fold_entry_state` returned `Waiting` for
/// every entry that followed one, so a revocation filed while any enrollment sat
/// inside its veto window did not take effect until that enrollment matured. The
/// consequences run the wrong way on every axis. The revocation is the response
/// to a compromise, so the window it is deferred across is exactly the window the
/// compromised key keeps every owner verb — up to
/// `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`. And the delay is ATTACKER-CHOSEN: the
/// compromised key can cosign a delayable widen of its own and thereby extend the
/// life of its own authority, re-arming the freeze each time one matures.
///
/// Folding the revocation early is sound because a revocation cannot widen: it
/// only raises a per-key watermark, so an early fold strictly REMOVES authority.
/// Nothing about the pending widen changes — it still matures on its own clock,
/// which the last assertion pins.
///
/// MUTATION PROBE: restore the unconditional deferral (drop the
/// `op_applies_despite_pending_widen` term at the `pending_widens.is_empty()`
/// guard) and this test fails — the revocation folds Waiting and the binding
/// stays Active.
#[test]
fn revoke_actor_applies_immediately_despite_an_unrelated_pending_widen() {
    let freeze = pending_widen_freeze(240);
    let key = freeze.fixture.owner_key.clone();
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        revoke_actor_op(&key, 5),
        104,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    // Baseline: with no revocation the binding authorizes, so the assertions
    // below pin the revocation's effect and not a broken fixture.
    let before =
        fold_authority_log_with_seen_times(&freeze.entries, &freeze.first_seen, freeze.now_secs);
    assert!(
        before.pending_widens.contains_key(&freeze.widen_hash),
        "fixture: the widen must start inside its veto delay"
    );
    assert!(
        actor_binding_is_active(&before, &freeze.fixture.actor, "human"),
        "fixture: the binding must authorize before the revocation"
    );

    let mut entries = freeze.entries.clone();
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(revoke_hash, freeze.now_secs);
    let after = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        after.issues.is_empty(),
        "the revocation must fold cleanly: {:?}",
        after.issues
    );
    assert!(
        after.valid_entries.contains(&revoke_hash),
        "the revocation must fold VALID, not park as Waiting behind the widen"
    );
    assert_eq!(
        folded_status(&after, &key),
        Some(ActorBindingStatus::Revoked),
        "the revocation must kill the binding NOW"
    );
    assert!(
        !actor_binding_is_active(&after, &freeze.fixture.actor, "human"),
        "a revoked actor must lose its authority immediately, not when an \
         unrelated enrollment matures"
    );
    // The widen keeps its OWN clock: the revocation neither matures nor vetoes it.
    assert!(
        after.pending_widens.contains_key(&freeze.widen_hash),
        "the pending widen must still mature on its own clock"
    );
    assert_eq!(
        after.pending_widens[&freeze.widen_hash], before.pending_widens[&freeze.widen_hash],
        "the revocation must not disturb the pending widen's delay bookkeeping"
    );
}

/// The other half of the same ruling: GRANTS still wait.
///
/// `RevokeActor` skips the freeze because withdrawing consent is unconditional.
/// `BindActor` and `RebindActor` do the opposite — they hand an actor authority —
/// so they keep the deferral: folding a grant against a roster the pending widen
/// may still change is exactly what the freeze exists to prevent. Pinned so a
/// future edit cannot widen the exemption from "the withdrawal" to "the actor
/// ops".
///
/// MUTATION PROBE: make `op_applies_despite_pending_widen` return true for the
/// bind arms and this test fails.
#[test]
fn bind_and_rebind_still_defer_behind_a_pending_widen() {
    for (label, op, seq) in [
        (
            "rebind",
            rebind_op(
                &pending_widen_freeze(244).fixture.owner_key,
                scope_entity(0x71),
                "human",
                2,
            ),
            4_u64,
        ),
        (
            "bind",
            bind_op(
                &pending_widen_freeze(244).fixture.agent_key,
                scope_entity(0x72),
                "agent",
                1,
            ),
            4,
        ),
    ] {
        let freeze = pending_widen_freeze(244);
        let entry = cosigned_entry(&freeze.fixture, vec![freeze.widen_hash], seq, op, 104);
        let entry_hash = authority_entry_hash(&entry).unwrap();
        let mut entries = freeze.entries.clone();
        entries.push(entry);
        let mut first_seen = freeze.first_seen.clone();
        first_seen.insert(entry_hash, freeze.now_secs);

        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);
        assert!(
            fold.pending_widens.contains_key(&freeze.widen_hash),
            "{label}: fixture — the widen must still be pending"
        );
        assert!(
            !fold.valid_entries.contains(&entry_hash),
            "{label}: a GRANT must stay deferred behind the pending widen"
        );
        // The pre-existing binding is untouched: the deferred grant changed nothing.
        assert!(
            actor_binding_is_active(&fold, &freeze.fixture.actor, "human"),
            "{label}: the deferred grant must leave the existing binding alone"
        );
        assert!(
            fold.valid_entries.contains(&freeze.bind_hash),
            "{label}: the pre-widen bind must remain valid"
        );
    }
}

/// fix-leg 12 P1: the freeze exemption must survive the ANCESTRY hurdle — a
/// revoked key cannot stall its own revocation by parenting it on a grant the
/// key itself froze.
///
/// fix-leg 11 exempted `RevokeActor` from the pending-widen freeze, but the
/// exemption sits BELOW the parent-ancestry resolution: a parent with no folded
/// state returns `Waiting` before any op-specific rule runs. The compromised key
/// C turns that ordering into a stall lever. C files a grant of its own as a
/// child of an unrelated pending widen; by fix-11's own (correct) ruling that
/// grant defers. The operator's `RevokeActor` naming the deferred grant as its
/// parent then inherits the wait, and C keeps every owner verb its binding
/// carries until the widen matures — up to `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`
/// on the compromised key's own forging. That is the exact live bug fix-11
/// shipped against, re-entered one level up.
///
/// Note what C needs to build the lever: only the ability to author a
/// `BindActor`, which asks for ordinary authority consent and never inspects the
/// signer's own actor binding. A key already stripped down to veto-only can
/// still do it, so "C cannot mature its own widen" does not close the hole —
/// the stall is the veto WINDOW, not the widen.
///
/// MUTATION PROBE: drop the `RevokeActor` arm from
/// `unstick_stalled_revocation` (or restore the unconditional
/// `return EntryFold::Waiting` for an unresolved parent) and this test fails —
/// the revocation lands in `issues` as `InvalidAncestry` and the binding stays
/// Active.
#[test]
fn revoke_actor_folds_past_a_grant_frozen_in_its_own_ancestry() {
    let freeze = pending_widen_freeze(248);
    let key = freeze.fixture.owner_key.clone();

    // C's stall lever: C's OWN grant, filed under the pending widen so the
    // freeze parks it. `bind_and_rebind_still_defer_behind_a_pending_widen`
    // pins that this entry cannot fold while the widen is pending.
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x73), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    // The operator's emergency brake, parented on that deferred grant.
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![stall_hash],
        5,
        revoke_actor_op(&key, 5),
        105,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(revoke_hash, freeze.now_secs);
    let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        fold.valid_entries.contains(&revoke_hash),
        "the revocation must fold past a parent frozen behind an unrelated widen"
    );
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked),
        "withdrawal of consent must take effect NOW, not when the widen matures"
    );
    assert!(
        !actor_binding_is_active(&fold, &freeze.fixture.actor, "human"),
        "a revoked actor must not keep owner authority because it parented the \
         revocation on a grant it froze itself"
    );
    // The exemption stays exactly one op wide: the GRANT keeps waiting, and the
    // widen keeps its own clock.
    assert!(
        !fold.valid_entries.contains(&stall_hash),
        "the deferred grant must NOT be dragged past the freeze with the revocation"
    );
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "the pending widen must still mature on its own clock"
    );
}

/// fix-leg 13 P1: the freeze classifier must mirror the fold's own rule, which
/// reads the MERGED parent state — not each branch in isolation.
///
/// fix-12's `entry_is_frozen_by_pending_widen` asked whether EVERY parent
/// branch resolves to a state carrying a pending widen. The fold does not work
/// that way. `fold_entry_state` merges all parents first and then freezes on
/// `!state.pending_widens.is_empty()`, so ONE widen-bearing branch is enough to
/// park the entry. A grant parented on `[widen, ordinary_ready_entry]` is
/// therefore Waiting in the fold and "not frozen" to the classifier — the two
/// disagree, and the disagreement is what the attacker gets to pick.
///
/// C only has to add a second, entirely innocuous parent to its stall grant to
/// re-open the exact hole fix-12 closed: the child `RevokeActor` asks the
/// bypass to step over that grant, the classifier says the parent is not frozen,
/// `nearest_unfrozen_ancestor_state` refuses the whole walk, and the revocation
/// falls out as `InvalidAncestry` while the compromised key keeps every owner
/// verb for the widen's full veto window. Multi-parent entries are ordinary in
/// this log — the merge loop above exists for them — so this is not an exotic
/// shape, it is the same lever with one more edge drawn.
///
/// MUTATION PROBE: restore the per-branch `all()` shape in
/// `entry_is_frozen_by_pending_widen` (classify from each parent's own nearest
/// ancestor state instead of their merge) and this test fails — the revocation
/// lands in `issues` as `InvalidAncestry` and the binding stays Active.
#[test]
fn revoke_actor_folds_past_a_grant_frozen_through_only_one_of_its_parents() {
    let freeze = pending_widen_freeze(220);
    let key = freeze.fixture.owner_key.clone();

    // The mixed parentage: the pending widen AND an ordinary, already-folded
    // sibling that carries no widen at all. `bind_hash` is the plain
    // Genesis -> Enroll -> Bind chain entry the fixture folds first.
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash, freeze.bind_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x77), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![stall_hash],
        5,
        revoke_actor_op(&key, 5),
        105,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(revoke_hash, freeze.now_secs);
    let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    // Fixture: the mixed-parent grant really is frozen, and the sibling branch
    // really did fold clean — that pairing is the whole point of the row.
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "fixture: the widen must still be pending"
    );
    assert!(
        fold.valid_entries.contains(&freeze.bind_hash),
        "fixture: the second parent must be an ordinary FOLDED entry with no widen"
    );
    assert!(
        !fold.valid_entries.contains(&stall_hash),
        "fixture: one widen-bearing parent must be enough to freeze the grant"
    );

    assert!(
        fold.valid_entries.contains(&revoke_hash),
        "the revocation must fold past a parent the fold froze through ONE of its \
         parents: a branch with no widen must not veto the freeze classification"
    );
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked),
        "withdrawal of consent must take effect NOW, not when the widen matures"
    );
    assert!(
        !actor_binding_is_active(&fold, &freeze.fixture.actor, "human"),
        "adding one innocuous second parent to the stall grant must not buy the \
         compromised key another veto window of owner authority"
    );
    // The narrowings hold: the grant itself is not dragged along, and the widen
    // keeps its own clock.
    assert!(
        !fold.valid_entries.contains(&stall_hash),
        "the deferred grant must NOT be dragged past the freeze with the revocation"
    );
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "the pending widen must still mature on its own clock"
    );
}

/// The second fix-12 narrowing: the bypass steps over a FROZEN parent, never an
/// invalid one.
///
/// "Resolve against the nearest ready ancestor" is only sound while the skipped
/// entries are ones the fold is deliberately holding. An entry the fold REJECTED
/// is a different animal: nothing above it was ever validated, and walking past
/// it would let a revocation fold over ancestry the vault refused. The
/// revocation is removal-only, so this is not a privilege escalation — but it
/// would silently admit an entry whose parent is not part of the log's valid
/// history, which is a fold-integrity break the wider machinery (permutation
/// invariance, `valid_entries` as the authority of record) relies on not
/// happening.
///
/// Here the revocation's parent is a double-`BindActor`, rejected with
/// `BindingExists`. No pending widen is involved at all, so the revocation must
/// simply fail its ancestry as it always did.
///
/// MUTATION PROBE: relax `nearest_unfrozen_ancestor_state` to walk past any
/// unfolded ancestor (drop the `pending` / `entry_is_frozen_by_pending_widen`
/// terms) and this test fails — the revocation folds valid on top of a rejected
/// parent.
#[test]
fn the_bypass_does_not_walk_past_a_rejected_parent() {
    let fixture = bind_fixture(228);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();

    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    // Rejected: a live binding already exists on this key.
    let double_bind = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        bind_op(&key, scope_entity(0x76), "human", 5),
        103,
    );
    let double_bind_hash = authority_entry_hash(&double_bind).unwrap();
    let revoke = cosigned_entry(
        &fixture,
        vec![double_bind_hash],
        4,
        revoke_actor_op(&key, 5),
        104,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let entries = vec![
        fixture.genesis.clone(),
        fixture.enroll,
        bind,
        double_bind.clone(),
        revoke,
    ];
    let fold = fold_authority_log_without_seen_time_delay(&entries);

    assert_eq!(
        binding_rejection(&fold, &double_bind),
        Some(ActorBindingRejection::BindingExists),
        "fixture: the parent must be REJECTED, not merely deferred"
    );
    assert!(
        !fold.valid_entries.contains(&revoke_hash),
        "the bypass must not carry a revocation over a parent the fold rejected: \
         only a parent frozen by a pending widen may be stepped over"
    );
}

/// The `RevokeActor`-only gate on the fix-12 bypass, probed where it actually
/// bites: `VetoPendingWiden`.
///
/// Most ops are held back a second time by the freeze check inside
/// `fold_entry_state`, so opening the bypass to them changes nothing
/// observable. A veto is the exception — `fold_entry_state` resolves it BEFORE
/// the freeze, since a veto's whole job is to kill a pending widen. So a veto
/// is the one op that would really travel through an ancestry bypass, and it is
/// the one that must not: a veto folded against a state from before the frozen
/// entry is a veto evaluated against a roster the vault has not settled, decided
/// on `has_veto_authority_consent` from stale ancestry.
///
/// Here C parents a veto of the widen on its own frozen grant. The veto must
/// stay stuck. It carries the same shape as the revocation that DOES get
/// through in the test above, so what separates them is only the op gate.
///
/// MUTATION PROBE: drop the `matches!(entry.op, AuthorityOp::RevokeActor {..})`
/// guard from `revocation_bypass_states` and this test fails — the veto folds
/// valid and the pending widen dies without ever being weighed against a
/// settled roster.
#[test]
fn a_veto_may_not_ride_the_revocation_ancestry_bypass() {
    let freeze = pending_widen_freeze(236);
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x75), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    let veto = veto_entry(
        freeze.fixture.vault_id,
        &stall,
        &freeze.fixture.owner,
        freeze.widen_hash,
        5,
    );
    let veto_hash = authority_entry_hash(&veto).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(veto);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(veto_hash, freeze.now_secs);
    let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        !fold.valid_entries.contains(&veto_hash),
        "a veto must NOT travel the revocation bypass: it is resolved before the \
         freeze check, so an ancestry bypass would let it kill a widen from a \
         roster the fold has not settled"
    );
    assert!(
        !fold.vetoed_widens.contains(&freeze.widen_hash),
        "the widen must not be vetoed by an entry that never folded"
    );
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "the widen must still be pending on its own clock"
    );
}

/// The other half of the fix-12 ruling: a revocation folded past the freeze must
/// stay in force once the widen it bypassed matures.
///
/// The bypass resolves the revocation against an ancestry state that predates
/// the frozen grant, so the obvious failure mode is a stranded watermark: the
/// widen matures, the grant folds for real, the revocation re-folds on the
/// now-available parent, and some ordering loses the raised
/// `actor_binding_revocations` entry. Merge is monotone by max, so this should
/// fall out — pinned so it stays true.
#[test]
fn revocation_folded_past_a_freeze_survives_the_widen_maturing() {
    let freeze = pending_widen_freeze(252);
    let key = freeze.fixture.owner_key.clone();
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x74), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![stall_hash],
        5,
        revoke_actor_op(&key, 5),
        105,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(revoke_hash, freeze.now_secs);

    // Same log, one clock apart: frozen, then matured.
    let matured_at = freeze.now_secs + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    let after = fold_authority_log_with_seen_times(&entries, &first_seen, matured_at);
    assert!(
        !after.pending_widens.contains_key(&freeze.widen_hash),
        "fixture: the widen must have matured at the later reading"
    );
    assert!(
        after.valid_entries.contains(&stall_hash),
        "fixture: the grant must fold once the freeze lifts"
    );
    assert!(
        after.valid_entries.contains(&revoke_hash),
        "the revocation must still fold once its parent is available for real"
    );
    assert_eq!(
        folded_status(&after, &key),
        Some(ActorBindingStatus::Revoked),
        "the revocation's watermark must survive the widen maturing"
    );
    assert!(
        !actor_binding_is_active(&after, &freeze.fixture.actor, "human"),
        "a matured widen must not resurrect the revoked actor's authority"
    );
}

/// fix-leg 11 P1-2: a matured ENROLLMENT must survive a restart under a
/// rolled-back wall clock, which is what makes the write fold's floor
/// persistence load-bearing in the GRANT direction.
///
/// `readonly_fold_backward_wall_clock_skew_keeps_elapsed_rotation_applied`
/// already pins the revoke direction: a matured `RotateKey` must stay applied, or
/// the retired key's owner binding comes back. That test cannot catch a
/// regression in the other direction, because a lost floor pushes a rotation back
/// INTO `pending_widens`, which for a rotation is the fail-OPEN outcome its
/// assertions are built around.
///
/// The grant direction fails the opposite way and needs its own row. An
/// `EnrollDevice` matured on this vault's monotonic clock authorizes its child
/// bind; if the floor is not persisted, a restart drops the process-local clock,
/// the fold falls back to a wall clock sitting far BELOW the observation, and the
/// enrollment reverts to pending — so a legitimately matured owner enrollment
/// silently loses its authority. That is fail-CLOSED but wrong, and it is
/// indistinguishable from the feature simply not working: the operator waited out
/// the veto window, and a reboot took it back.
///
/// MUTATION PROBE: drop the floor `put` from `Vault::authority_fold`'s write txn
/// and this test fails at the post-reopen assertions.
#[test]
fn matured_enrollment_survives_a_restart_under_a_rolled_back_wall_clock() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Park the authority clock far ahead of real Unix time, so every later
    // observation is written from a future reading and `unix_seconds_now()` is
    // the BACKWARD-skewed clock a reopen would otherwise trust.
    let domain = vault.store.authority_clock_domain;
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    assert!(authority_observation_secs_for_domain(domain, 0, future) >= future);

    let owner = ed_key(231);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(231, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(232);
    let second_key = authority_key_from_ed(&second);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 232,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x67);
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let before = vault.authority_fold().unwrap();
    assert!(
        before.pending_widens.contains_key(&enroll_hash),
        "the enrollment starts inside its veto delay"
    );
    assert!(
        !actor_binding_is_active(&before, &actor, "human"),
        "its child bind must not authorize while the enrollment is pending"
    );

    // Run the local monotonic clock past the delay, then let a WRITE fold record
    // the observation — this is the commit whose floor must outlive the process.
    let matured_at = future + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert!(authority_observation_secs_for_domain(domain, matured_at, 0) >= matured_at);
    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&enroll_hash),
        "the enrollment must mature once the local clock passes its delay"
    );
    assert!(
        actor_binding_is_active(&full, &actor, "human"),
        "the matured enrollment must authorize its child bind"
    );

    // Restart. The process-local clock dies with the vault, so the rolled-back
    // wall clock is the only other candidate reading — the persisted floor is
    // the sole thing keeping the enrollment matured.
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let rtxn = reopened.store.env.read_txn().unwrap();
    let after_reopen = reopened.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !after_reopen.pending_widens.contains_key(&enroll_hash),
        "a restart under a rolled-back wall clock must not un-mature the \
         enrollment — the persisted floor is what carries the observation across"
    );
    assert!(
        actor_binding_is_active(&after_reopen, &actor, "human"),
        "a legitimately matured owner enrollment must keep authorizing its child \
         bind across a restart"
    );
}
