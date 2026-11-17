//! Regression pins for four pass 28 review fixes that had no test (FIX
//! [PASS28-REVIEW-FIX-TESTS-NEED-DOORS], [R3E-FAMILYLESS-DEBT-NEEDS-DOORS]).
//!
//! - #8845 P1-2 (R1 986a4738, `authority/world_refold.rs`): a grant act folded again above a
//!   crossed main-log row folds before the rows crossed above it, so a later giving on the
//!   same Grant replaces it instead of standing beside it unordered.
//! - #8846 P1-1 (R2a, the same refold path for the general grant act): an end of the wrong
//!   family above a crossed row, whose Grant an owner's mint below it gives, ends nothing.
//! - #8855 P1-1 (R3c fccaa1a3, `federation/grant_standing.rs`): a row a counted act names
//!   stands only on its line's family, so a counted Connect guest's row overwritten with the
//!   owner's own-device shape stands for nothing.
//! - #8982 P2-1 (R3e 2a8027c0, `federation/grant_ending.rs`): a debt on a line two branches
//!   named in two families waits; no act of one family ends it, and clearing it would drop
//!   the taking back from the record.
//!
//! The grant acts on chosen parents are signed by a machine the owner admitted, whose install
//! key the test holds; the collisions are the losing federation confirmation of
//! `grant_review_dropped_end.rs`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test grant_review_fix_pins`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerKeyEnrollment,
    authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::grant_ending::put_own_device_shaped_row;
use oneiron::test_doors::grant_standing::{grant_line, grant_row_verbs, standing_grant_act};
use oneiron::test_doors::owed_grant_end::{
    carry_owed_grant_ends, grant_end_owed, replay_peer_soft_delete,
};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    GRANT_ACT_SEEN, GrantActChange, GrantActRecord, GrantDecider, GrantFamily, OwnerAct,
};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A peer vault id no vault here opens.
const UNOPENED_PEER: AuthorityVaultId = [0xbd; 32];

/// A rooted vault as a host starts one: the owner bound under the host root and this install
/// profiled, so it carries the owner's acts.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        issuer,
        owner,
        proof,
        vault_id,
    }
}

/// A machine the owner admitted, and its install key, which the test holds: it carries grant
/// acts on whatever parents the test names.
fn admit_machine(rooted: &Rooted) -> (EntityId, SigningKey) {
    let signing = SigningKey::from_bytes(&[0xA1; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &rooted.vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine");
    assert!(folded.is_mine(None), "the admitted machine is the owner's");
    (machine, signing)
}

/// The owner enrols `signing` as an owner key held on `machine`, through the public owner key
/// enrollment door; returns the enrollment's entry, the one head the log then has.
fn enrol_owner_key(rooted: &Rooted, machine: EntityId, signing: &SigningKey) -> AuthorityEntryHash {
    let authority = ActAuthority::Owner(rooted.proof.clone(), ActSurface::ThisInstall);
    let public_key = signing.verifying_key().to_bytes();
    let challenge = rooted
        .vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the enrollment's challenge");
    rooted
        .vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: signing.sign(&challenge).to_bytes().to_vec(),
            },
            &rooted.issuer,
        )
        .expect("the owner enrols the key")
        .entry
}

/// `op` signed by `signing` at `seq` on `parents`.
fn row_signed_by(
    rooted: &Rooted,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

/// Puts `row` through the public put door; `what` names it in the failure message.
fn store(rooted: &Rooted, row: &AuthorityLogEntry, what: &str) {
    if let Err(error) = rooted.vault.put_authority_log_entry(row, AT, 1) {
        let issues = rooted.vault.authority_fold().map(|fold| fold.issues);
        panic!(
            "setup: {what} is stored: {:?}; issues {issues:?}",
            error.kind()
        );
    }
}

/// A federation confirmation with `confirm_id` and `nonce`.
fn confirmation(confirm_id: [u8; 32], nonce: [u8; 16]) -> AuthorityOp {
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: [0x77; 32],
        epoch: 1,
        nonce,
    })
}

/// The first confirmation `signing` signs with `confirm_id` at `seq` on `parents` whose hash is
/// below `below`. Its nonce starts 0xC0, which no other row's nonce here does, so it collides
/// only through `confirm_id`.
fn colliding_below(
    rooted: &Rooted,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    confirm_id: [u8; 32],
    below: AuthorityEntryHash,
) -> AuthorityLogEntry {
    (0..=u64::MAX)
        .map(|counter| {
            let mut nonce = [0xC0; 16];
            nonce[8..].copy_from_slice(&counter.to_be_bytes());
            row_signed_by(
                rooted,
                signing,
                seq,
                parents.clone(),
                confirmation(confirm_id, nonce),
            )
        })
        .find(|row| hash_of(row) < below)
        .expect("a nonce whose confirmation hashes below the one it collides with")
}

/// The owner's general grant act on the member line of `subject`, carried by `machine`.
fn member_grant_act(
    rooted: &Rooted,
    machine: EntityId,
    subject: EntityId,
    change: GrantActChange,
) -> AuthorityOp {
    let act = OwnerAct::by_owner(
        rooted.owner,
        change.act_kind(),
        subject,
        ActSurface::ThisInstall,
        GRANT_ACT_SEEN,
    );
    AuthorityOp::GrantAct(GrantActRecord {
        decider: GrantDecider::Person(act),
        machine,
        subject,
        family: GrantFamily::SharedMember,
        change,
    })
}

/// What the fold says of `grant`: the act of the one giving that counts, and whether a counted
/// act ended it; `None` when no counted act names it.
fn line(rooted: &Rooted, grant: EntityId) -> Option<(Option<AuthorityEntryHash>, bool)> {
    grant_line(&rooted.vault, grant).expect("the grant line")
}

/// The owner's agent Grant for a fresh agent, minted through the public door: its id and the
/// mint's act.
fn mint_agent_grant(rooted: &Rooted, name: &str) -> (EntityId, AuthorityEntryHash) {
    let agent = rooted
        .vault
        .ensure_agent_principal(name)
        .expect("a named agent principal");
    mint_agent_grant_after_principal(rooted, agent)
}

fn mint_agent_grant_after_principal(
    rooted: &Rooted,
    agent: EntityId,
) -> (EntityId, AuthorityEntryHash) {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &rooted.vault,
        &rooted.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the agent a Grant");
    assert!(minted.grant.confers, "setup: the minted Grant is live");
    (minted.grant.grant_ref, unhex(&minted.act_ref))
}

/// The entry hash an act reference names (its hex).
fn unhex(text: &str) -> AuthorityEntryHash {
    assert_eq!(
        text.len(),
        64,
        "an act reference is 32 bytes of hex: {text}"
    );
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex act ref");
    }
    bytes
}

/// #8845 P1-2. The owner key K's confirmation C sits on the head P; the admitted machine gives
/// G at A on C, K's unrelated confirmation X sits on A, and the machine gives G new terms at B
/// on X. K's colliding confirmation on P hashes below C, so settlement drops C and every row
/// above it; A and B are folded again with C and X crossed. B must still replace A: built
/// without A, X's stand-in would leave B beside A, unordered, and G would stand on neither.
#[test]
fn a_giving_folded_again_above_a_crossed_row_is_replaced_by_the_later_giving() {
    let rooted = rooted();
    let (machine, carrier) = admit_machine(&rooted);
    let owner_key = SigningKey::from_bytes(&[0x4B; 32]);
    let head = enrol_owner_key(&rooted, machine, &owner_key);
    let grant = EntityId::now();
    let confirm_id = [0x31; 32];
    let confirmed = row_signed_by(
        &rooted,
        &owner_key,
        1,
        vec![head],
        confirmation(confirm_id, [0x01; 16]),
    );
    store(&rooted, &confirmed, "C");
    let first = row_signed_by(
        &rooted,
        &carrier,
        1,
        vec![hash_of(&confirmed)],
        member_grant_act(
            &rooted,
            machine,
            grant,
            GrantActChange::Give { terms: [0x11; 32] },
        ),
    );
    store(&rooted, &first, "the first giving A");
    let unrelated = row_signed_by(
        &rooted,
        &owner_key,
        2,
        vec![hash_of(&first)],
        confirmation([0x32; 32], [0x02; 16]),
    );
    store(&rooted, &unrelated, "the unrelated confirmation X");
    let later = row_signed_by(
        &rooted,
        &carrier,
        2,
        vec![hash_of(&unrelated)],
        member_grant_act(
            &rooted,
            machine,
            grant,
            GrantActChange::Give { terms: [0x22; 32] },
        ),
    );
    store(&rooted, &later, "the later giving B");
    assert_eq!(
        line(&rooted, grant),
        Some((Some(hash_of(&later)), false)),
        "setup: before the collision the later giving replaces the first"
    );

    let collision = colliding_below(
        &rooted,
        &owner_key,
        3,
        vec![head],
        confirm_id,
        hash_of(&confirmed),
    );
    store(&rooted, &collision, "the colliding confirmation");
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        fold.valid_entries.contains(&hash_of(&collision))
            && !fold.valid_entries.contains(&hash_of(&confirmed)),
        "setup: the lower-hash confirmation wins the collision; issues {:?}",
        fold.issues
    );
    assert_eq!(
        line(&rooted, grant),
        Some((Some(hash_of(&later)), false)),
        "a giving folded again above a crossed row must be replaced by the later giving on its \
         Grant; issues {:?}",
        fold.issues
    );
}

/// #8846 P1-1. K's confirmation C sits on the head P; the owner mints G for an agent at A on C
/// (the mint door names every head), K's unrelated confirmation J sits on A, and the admitted
/// machine signs a member-family end of G at E on J. K's colliding confirmation on P drops C
/// and every row above it; A and E are folded again. A is E's ancestor, so E, an end of
/// another family than G's line, must end nothing, and G stands on A.
#[test]
fn a_wrong_family_end_folded_again_above_a_crossed_row_ends_nothing() {
    let rooted = rooted();
    let (machine, carrier) = admit_machine(&rooted);
    let owner_key = SigningKey::from_bytes(&[0x4B; 32]);
    let agent = rooted
        .vault
        .ensure_agent_principal("refold-wrong-family-end-agent")
        .expect("a named agent principal");
    let head = enrol_owner_key(&rooted, machine, &owner_key);
    let confirm_id = [0x31; 32];
    let confirmed = row_signed_by(
        &rooted,
        &owner_key,
        1,
        vec![head],
        confirmation(confirm_id, [0x01; 16]),
    );
    store(&rooted, &confirmed, "C");
    let (grant, mint) = mint_agent_grant_after_principal(&rooted, agent);
    let unrelated = row_signed_by(
        &rooted,
        &owner_key,
        2,
        vec![mint],
        confirmation([0x32; 32], [0x02; 16]),
    );
    store(&rooted, &unrelated, "the unrelated confirmation J");
    let end = row_signed_by(
        &rooted,
        &carrier,
        1,
        vec![hash_of(&unrelated)],
        member_grant_act(&rooted, machine, grant, GrantActChange::End),
    );
    store(&rooted, &end, "the member-family end E");
    let now = rooted.vault.now_recorded_at();
    assert_eq!(
        line(&rooted, grant),
        Some((Some(mint), false)),
        "setup: before the collision an end of another family ends nothing"
    );
    assert_eq!(
        standing_grant_act(&rooted.vault, grant, now).expect("standing read"),
        Some(mint),
        "setup: before the collision the minted row stands on the owner's mint"
    );

    let collision = colliding_below(
        &rooted,
        &owner_key,
        3,
        vec![head],
        confirm_id,
        hash_of(&confirmed),
    );
    store(&rooted, &collision, "the colliding confirmation");
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        fold.valid_entries.contains(&hash_of(&collision))
            && !fold.valid_entries.contains(&hash_of(&confirmed)),
        "setup: the lower-hash confirmation wins the collision; issues {:?}",
        fold.issues
    );
    let now = rooted.vault.now_recorded_at();
    assert_eq!(
        line(&rooted, grant),
        Some((Some(mint), false)),
        "an end of another family folded again above a crossed row must end nothing; issues \
         {:?}",
        fold.issues
    );
    assert_eq!(
        standing_grant_act(&rooted.vault, grant, now).expect("standing read"),
        Some(mint),
        "the owner's agent Grant must still stand on his mint"
    );
}

/// A Connect slice over one named WORLD: read and propose, public claims.
fn connect_scope(world: EntityId) -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(world)])),
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        audience: ScopeAxis::Some(BTreeSet::from([ScopeId(
            oneiron::claim::default_project_id(),
        )])),
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "propose".to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
    }
}

/// #8855 P1-1. The owner's Connect mint gives a guest Grant by its counted act; the row at its
/// id is then overwritten with the owner's own-device shape, which the derived read stands
/// while its holder is a live Owner. A row a counted act names stands only on its line's
/// family, so the overwritten row confers nothing at the readers' row read (the check-in
/// chain's among them). Guard: the same shape at an id no act names stands.
#[test]
fn a_counted_guest_row_overwritten_with_the_own_device_shape_stands_for_nothing() {
    let rooted = rooted();
    let now = rooted.vault.now_recorded_at();
    let world = rooted
        .vault
        .create_world(&rooted.proof, "Connect guest overwritten", now)
        .expect("a named WORLD");
    let minted = rooted
        .vault
        .mint_connect_grant(
            &rooted.proof,
            UNOPENED_PEER,
            connect_scope(world),
            Some(now + 30 * 24 * 3_600),
            None,
        )
        .expect("the owner's Connect guest Grant");
    let grant = minted.grant;
    assert!(
        matches!(line(&rooted, grant), Some((Some(_), false))),
        "setup: the Connect mint gives its Grant by a counted act"
    );
    let unacted = EntityId::now();
    put_own_device_shaped_row(&rooted.vault, unacted, rooted.owner)
        .expect("an own-device row at an id no act names");
    assert!(
        grant_row_verbs(&rooted.vault, unacted)
            .expect("the row read")
            .is_some(),
        "guard: the owner's own-device row that no act names stands"
    );

    put_own_device_shaped_row(&rooted.vault, grant, rooted.owner)
        .expect("the guest row is overwritten with the own-device shape");
    assert_eq!(
        grant_row_verbs(&rooted.vault, grant).expect("the row read"),
        None,
        "a counted guest row overwritten with the own-device shape must stand for nothing"
    );
}

/// #8982 P2-1. The owner mints G for an agent on his line; the admitted machine gives G as a
/// member row on a branch that never saw the mint, so the fold holds G's line in two families
/// and G stands on neither. A peer's soft delete of G's row owes G's end here. No act of one
/// family can end that line, so the carry pass must leave the debt owed: clearing it with no
/// act would drop the taking back from the record while no end counts.
#[test]
fn a_debt_on_a_line_two_families_name_waits_through_the_carry_pass() {
    let rooted = rooted();
    let (machine, carrier) = admit_machine(&rooted);
    let owner_key = SigningKey::from_bytes(&[0x4B; 32]);
    let head = enrol_owner_key(&rooted, machine, &owner_key);
    let (grant, _mint) = mint_agent_grant(&rooted, "two-family-debt-agent");
    let side = row_signed_by(
        &rooted,
        &carrier,
        1,
        vec![head],
        member_grant_act(
            &rooted,
            machine,
            grant,
            GrantActChange::Give { terms: [0x33; 32] },
        ),
    );
    store(&rooted, &side, "the member-family giving on a side branch");
    assert_eq!(
        line(&rooted, grant),
        Some((None, false)),
        "setup: two branches name G in two families, so its line has no giving and no end"
    );

    replay_peer_soft_delete(&rooted.vault, grant).expect("the peer's soft delete replays");
    assert!(
        grant_end_owed(&rooted.vault, grant).expect("the debt read"),
        "setup: the peer's delete owes G's end here"
    );
    carry_owed_grant_ends(&rooted.vault);
    assert!(
        grant_end_owed(&rooted.vault, grant).expect("the debt read"),
        "a debt on a line two families name must wait through the carry pass"
    );
    assert_eq!(
        line(&rooted, grant),
        Some((None, false)),
        "no act of one family ends a line two families name"
    );
}
