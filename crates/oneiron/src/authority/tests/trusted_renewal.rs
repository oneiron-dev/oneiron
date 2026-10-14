//! World privacy P6b: a stale trusted roster revision is renewed by exactly
//! the copies the trusted chain itself accepts (contract §4, roster trust per
//! revision). Two owner-held keys sign one profile of a machine, and only the
//! loser's later copy is still within its stale-roster window (Sol code-R2
//! S2-F1, code-R3 S3-F2, code-R4 S4-F1).
use super::machine_identity::request_for;
use super::owner_anchor::{YOURS, pin, profile, publish, rekeyed, signed};
use super::support::{
    RosterChain, authority_key_from_ed, cosign_ed, device, ed_key, genesis_entry,
};
use super::*;

/// Owner-held keys A and B sign one `role` profile of machine M on sibling
/// branches; one of them (the winner) speaks for the trusted roster revision,
/// and the other's (the loser's) copy is first seen later. A sibling branch
/// enrols the loser again as `again` says, and a handoff joins them, so it
/// retires both.
struct TwoCopies {
    id: AuthorityVaultId,
    machine: SigningKey,
    request: MachineEnrolmentRequest,
    winner: AuthorityEntryHash,
    handoff: AuthorityLogEntry,
    entries: Vec<AuthorityLogEntry>,
    first_seen: BTreeMap<AuthorityEntryHash, u64>,
}

/// Past the winner's stale-roster deadline, before the loser's.
const PAST: u64 = 120 + DEFAULT_STALE_ROSTER_WINDOW_SECS;

fn two_copies(role: MachineRole, again: impl Fn(AuthorityKey) -> DeviceAuthority) -> TwoCopies {
    let (root_key, next) = (ed_key(180), ed_key(183));
    let genesis = genesis_entry(180, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let ordinary = |key: &SigningKey| {
        device(
            authority_key_from_ed(key),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        )
    };
    let (a, b) = (ed_key(181), ed_key(182));
    let enrol_a = signed(
        id,
        &[&genesis],
        &root_key,
        1,
        AuthorityOp::EnrollDevice {
            device: ordinary(&a),
        },
    );
    let enrol_b = cosign_ed(
        signed(
            id,
            &[&enrol_a],
            &root_key,
            2,
            AuthorityOp::EnrollDevice {
                device: ordinary(&b),
            },
        ),
        &root_key,
        &a,
    );
    let machine = ed_key(184);
    let request = request_for(id, EntityId::now(), &machine);
    let op = profile(&request, role, 1);
    let copy_a = signed(id, &[&enrol_b], &a, 1, op.clone());
    let copy_b = signed(id, &[&enrol_b], &b, 1, op);
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let ((winner, winner_copy), (loser, loser_copy)) = if hash(&copy_a) < hash(&copy_b) {
        ((&a, &copy_a), (&b, &copy_b))
    } else {
        ((&b, &copy_b), (&a, &copy_a))
    };
    let sibling = signed(
        id,
        &[&genesis],
        &root_key,
        3,
        AuthorityOp::EnrollDevice {
            device: again(authority_key_from_ed(loser)),
        },
    );
    let handoff = cosign_ed(
        signed(
            id,
            &[winner_copy, loser_copy, &sibling],
            &root_key,
            4,
            AuthorityOp::ReRoot {
                new_device: ordinary(&next),
            },
        ),
        &root_key,
        winner,
    );
    let mut first_seen: BTreeMap<_, _> = [&genesis, &enrol_a, &enrol_b, winner_copy, &sibling]
        .into_iter()
        .map(|entry| (hash(entry), 100))
        .collect();
    first_seen.insert(hash(loser_copy), 150);
    first_seen.insert(hash(&handoff), 200);
    let winning = hash(winner_copy);
    TwoCopies {
        id,
        machine,
        request,
        winner: winning,
        entries: vec![
            genesis,
            enrol_a,
            enrol_b,
            copy_a,
            copy_b,
            sibling,
            handoff.clone(),
        ],
        handoff,
        first_seen,
    }
}

impl TwoCopies {
    fn fold_at(&self, now: u64, posture: crate::HostingPrivacyPosture) -> AuthorityFold {
        let fold = fold_authority_log_for_posture(
            &self.entries,
            &self.first_seen,
            now,
            &BTreeMap::new(),
            posture,
        );
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&self.handoff).unwrap())
        );
        fold
    }

    fn trusted_revision(&self, fold: &AuthorityFold) -> MachineRevision {
        let folded = fold.machine(self.request.machine).unwrap();
        folded.roster_trusted.clone().unwrap()
    }
}

/// On a hosted log the sibling branch enrols the loser for the cloud, so
/// custody reaches it on the merged history. Past the winner's deadline the
/// loser's copy renews nothing in the trusted chain: an unpinned install no
/// longer counts M mine (S2-F1). Fails before: any valid roster copy renewed
/// it.
#[test]
fn a_copy_custody_reached_never_renews_a_trusted_mark() {
    let log = two_copies(YOURS, |key| {
        device(
            key,
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
        )
    });
    let hosted = crate::HostingPrivacyPosture::Hosted;
    let fold = log.fold_at(100, hosted);
    assert_eq!(log.trusted_revision(&fold).entry, log.winner);
    assert!(fold.machine(log.request.machine).unwrap().is_mine(None));
    let past = log.fold_at(PAST, hosted);
    assert!(log.trusted_revision(&past).stale);
    let folded = past.machine(log.request.machine).unwrap();
    assert!(!folded.roster_chain().stale);
    assert!(!folded.is_mine(None));
}

/// On a self-host log the sibling branch enrols the loser as an agent
/// instead. The merged roster strips its consent, but no custody reaches it,
/// so the trusted chain still accepts its copy, and that copy renews the
/// trusted revision past the winner's deadline (S3-F2). Fails before: the
/// renewal judged the signer's merged roles.
#[test]
fn a_copy_the_trusted_chain_accepts_renews_its_mark() {
    let log = two_copies(YOURS, |key| {
        device(key, ROLE_AGENT, AuthorityTier::Software)
    });
    let self_host = crate::HostingPrivacyPosture::SelfHostLocal;
    let fold = log.fold_at(100, self_host);
    assert!(fold.machine(log.request.machine).unwrap().is_mine(None));
    let past = log.fold_at(PAST, self_host);
    let trusted = log.trusted_revision(&past);
    assert_eq!(trusted.entry, log.winner);
    assert!(!trusted.stale);
    assert!(past.machine(log.request.machine).unwrap().is_mine(None));
}

/// The two copies are a hosted-node profile on a self-host log, and the
/// owner's anchor marks M as theirs with the same machine key and a fresh
/// encryption key. The loser's node copy renews the trusted revision past the
/// winner's deadline, so the two live trusted chains still disagree on M's
/// keys and M is not mine under the pin (S4-F1). Fails before: only owned
/// copies renewed, so the node revision went stale and the anchor's keys
/// stood alone.
#[test]
fn a_node_copy_the_trusted_chain_accepts_renews_its_revision() {
    let mut log = two_copies(MachineRole::HostedNode, |key| {
        device(key, ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software)
    });
    let (root, anchor, published) = publish(log.id, &log.handoff);
    let rekeyed = rekeyed(log.id, &log.request, &log.machine);
    let mark = signed(
        log.id,
        &[&published],
        &anchor,
        2,
        profile(&rekeyed, YOURS, 1),
    );
    for entry in [published, mark] {
        log.first_seen
            .insert(authority_entry_hash(&entry).unwrap(), 100);
        log.entries.push(entry);
    }
    let past = log.fold_at(PAST, crate::HostingPrivacyPosture::SelfHostLocal);
    let trusted = log.trusted_revision(&past);
    assert_eq!(trusted.profile.role, MachineRole::HostedNode);
    assert!(!trusted.stale);
    let folded = past.machine(log.request.machine).unwrap();
    assert!(folded.admits(&MachineAdmitter::Anchor(root.anchor_key)));
    assert!(folded.trusted(Some(&pin(&root))).is_none());
}
