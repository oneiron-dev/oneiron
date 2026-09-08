//! Peer roster derivation from relayed entries.

use super::support::*;
use super::*;

/// A synthetic peer vault under the HOST-KEY premise.
///
/// Its genesis device is owner/admin at a LAWFUL attestation tier — canon never
/// stamps a host-root genesis `ROLE_CLOUD`/`CloudCustodial`, and the standing
/// admission guards would refuse to mint one (see
/// `peer_consent_predicate_ignores_cloud_markings_the_local_one_keeps`).
///
/// Chain: genesis(host) → enroll(admin) → enroll(agent) → enroll(spare) →
/// revoke(spare). Everything past the second device carries the peer cosign the
/// quorum rule demands once two devices are active.
struct PeerLogFixture {
    host_key: AuthorityKey,
    admin_key: AuthorityKey,
    agent_key: AuthorityKey,
    revoked_key: AuthorityKey,
    outsider: SigningKey,
    vault_id: AuthorityVaultId,
    genesis: AuthorityLogEntry,
    entries: Vec<AuthorityLogEntry>,
}

fn peer_log_fixture(seed: u8) -> PeerLogFixture {
    let host = ed_key(seed);
    let admin = ed_key(seed.wrapping_add(1));
    let agent = ed_key(seed.wrapping_add(2));
    let spare = ed_key(seed.wrapping_add(3));
    let outsider = ed_key(seed.wrapping_add(4));
    let host_key = authority_key_from_ed(&host);

    let genesis = genesis_entry(seed, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();

    let enroll_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &host,
        EnrollSpec {
            seed: seed.wrapping_add(1),
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_agent = cosigned_enroll(
        vault_id,
        &enroll_admin,
        &host,
        &admin,
        &agent,
        ROLE_AGENT,
        2,
        3,
    );
    let enroll_spare = cosigned_enroll(
        vault_id,
        &enroll_agent,
        &host,
        &admin,
        &spare,
        ROLE_OWNER | ROLE_ADMIN,
        3,
        4,
    );
    let revoke_spare = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            4,
            vec![authority_entry_hash(&enroll_spare).unwrap()],
            AuthorityOp::RevokeDevice {
                revoked_key: authority_key_from_ed(&spare),
            },
            host_key.clone(),
            5,
        ),
        &host,
        &admin,
    );

    PeerLogFixture {
        host_key,
        admin_key: authority_key_from_ed(&admin),
        agent_key: authority_key_from_ed(&agent),
        revoked_key: authority_key_from_ed(&spare),
        outsider,
        vault_id,
        entries: vec![
            genesis.clone(),
            enroll_admin,
            enroll_agent,
            enroll_spare,
            revoke_spare,
        ],
        genesis,
    }
}

#[allow(clippy::too_many_arguments)]
fn cosigned_enroll(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
    enrolled: &SigningKey,
    roles: u16,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    cosign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(enrolled),
                    roles,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(signer),
            ts,
        ),
        signer,
        cosigner,
    )
}

fn peer_roster_consent_keys(fold: &AuthorityFold) -> BTreeSet<AuthorityKey> {
    crate::federation::peer_consent_roots(fold)
}

#[test]
fn peer_fold_derives_the_host_root_roster_from_relayed_entries() {
    let fixture = peer_log_fixture(180);
    let fold = fold_peer_authority_log(&fixture.entries);

    assert_eq!(
        fold.vault_id,
        Some(fixture.vault_id),
        "the peer fold roots at the peer's own classic-Genesis vault id"
    );
    let roots = peer_roster_consent_keys(&fold);
    assert!(
        roots.contains(&fixture.host_key),
        "under host-root the peer HOST genesis key IS a consent root"
    );
    assert!(roots.contains(&fixture.admin_key));
    assert!(
        !roots.contains(&fixture.agent_key),
        "an agent-role peer device is not a consent root"
    );
    assert!(
        !roots.contains(&fixture.revoked_key),
        "a revoked peer device is not a consent root"
    );
}

#[test]
fn peer_consent_predicate_ignores_cloud_markings_the_local_one_keeps() {
    let key = authority_key_from_ed(&ed_key(181));
    let cloud_marked_owner = FoldedDevice {
        key: key.clone(),
        tier: AuthorityTier::CloudCustodial,
        roles: ROLE_OWNER | ROLE_CLOUD,
        revoked: false,
    };
    assert!(
        folded_peer_device_is_consent_root(&cloud_marked_owner),
        "the peer arm ignores ROLE_CLOUD/CloudCustodial: owner-or-admin and \
         not-revoked is the whole test"
    );
    assert!(
        !folded_device_can_authority_consent(&cloud_marked_owner),
        "the LOCAL arm is unchanged and still excludes cloud-marked devices"
    );

    // ...and the divergence stays a forward-compatibility seam, not a live
    // behaviour split: the standing admission guards refuse to MINT that shape
    // at all (ONE-1410 item 16 — `validate_shape` rides both encode and decode,
    // so lifting them would be engine-wide).
    assert!(
        device(
            key.clone(),
            ROLE_OWNER | ROLE_CLOUD,
            AuthorityTier::Software
        )
        .validate()
        .is_err()
    );
    assert!(
        device(key.clone(), ROLE_OWNER, AuthorityTier::CloudCustodial)
            .validate()
            .is_err()
    );

    // Both arms agree on every shape that CAN reach a fold.
    for (roles, tier, expected) in [
        (ROLE_OWNER, AuthorityTier::Software, true),
        (ROLE_ADMIN, AuthorityTier::Hardware, true),
        (ROLE_AGENT, AuthorityTier::Software, false),
        (ROLE_CLOUD, AuthorityTier::CloudCustodial, false),
    ] {
        let folded = FoldedDevice {
            key: key.clone(),
            tier,
            roles,
            revoked: false,
        };
        assert_eq!(folded_peer_device_is_consent_root(&folded), expected);
        assert_eq!(folded_device_can_authority_consent(&folded), expected);
        let revoked = FoldedDevice {
            revoked: true,
            ..folded
        };
        assert!(!folded_peer_device_is_consent_root(&revoked));
        assert!(!folded_device_can_authority_consent(&revoked));
    }
}

#[test]
fn peer_entries_bind_only_the_authority_transcript_domain() {
    // Fixture copy of the sync-only `sync::lease::LEASE_POP_DOMAIN`. The law
    // under test is base-mode (a foreign transcript domain never widens the
    // peer roster) and needs only SOME foreign domain, so the seed is local
    // and this test runs in every feature configuration. If sync ever remints
    // its constant the bytes here merely stop mirroring it; the law is unmoved.
    const LEASE_POP_DOMAIN: &[u8] = b"oneiron/lease-pop/v1";

    assert_eq!(
        AUTHORITY_TRANSCRIPT_DOMAIN, b"oneiron/authority/v1",
        "the peer fold reuses the EXISTING authority domain; no second \
         constant is minted for peer rosters"
    );
    assert_ne!(AUTHORITY_TRANSCRIPT_DOMAIN, LEASE_POP_DOMAIN);

    let fixture = peer_log_fixture(182);
    let host_signing = ed_key(182);
    for domain in [
        LEASE_POP_DOMAIN,
        FEDERATION_PACT_DOMAIN,
        b"oneiron/authority/v2".as_slice(),
        b"".as_slice(),
    ] {
        // Byte-identical entry, byte-identical transcript BODY — only the
        // domain prefix the signature commits to differs.
        let mut enroll = fixture.entries[1].clone();
        let mut transcript = domain.to_vec();
        transcript.extend_from_slice(
            &encode_value(&transcript_value_with_genesis_delay(&enroll, true)).unwrap(),
        );
        enroll.signer.signature = host_signing.sign(&transcript).to_bytes().to_vec();

        let hash = authority_entry_hash(&enroll).unwrap();
        let fold = fold_peer_authority_log(&[fixture.genesis.clone(), enroll]);
        assert!(
            fold.issues
                .contains(&AuthorityFoldIssue::InvalidEntry(hash)),
            "a signature over {domain:?} is an INVALID entry, not a roster widen"
        );
        assert!(
            !fold.roster.contains_key(&fixture.admin_key),
            "a non-authority-domain signature must never enrol a peer device"
        );
    }
}

#[test]
fn peer_roster_is_permutation_invariant() {
    let fixture = peer_log_fixture(184);
    let canonical = fold_peer_authority_log(&fixture.entries);
    assert!(!canonical.roster.is_empty());

    let len = fixture.entries.len();
    for rotation in 0..len {
        let mut permuted = fixture.entries.clone();
        permuted.rotate_left(rotation);
        assert_eq!(
            fold_peer_authority_log(&permuted).roster,
            canonical.roster,
            "relay-chosen arrival order must not move the peer roster"
        );
    }
    let mut reversed = fixture.entries;
    reversed.reverse();
    assert_eq!(fold_peer_authority_log(&reversed).roster, canonical.roster);
}

#[test]
fn withheld_peer_entries_cannot_mint_a_key_or_unrevoke_one() {
    let fixture = peer_log_fixture(185);
    let full = fold_peer_authority_log(&fixture.entries);
    let revoke_hash = authority_entry_hash(fixture.entries.last().unwrap()).unwrap();

    // The log is a chain, so its ancestry-closed subsets are exactly its
    // prefixes.
    for length in 1..=fixture.entries.len() {
        let subset = &fixture.entries[..length];
        let fold = fold_peer_authority_log(subset);
        for key in fold.roster.keys() {
            assert!(
                full.roster.contains_key(key),
                "withholding entries must never CREATE a never-enrolled key"
            );
        }
        if fold.valid_entries.contains(&revoke_hash) {
            assert!(
                fold.roster[&fixture.revoked_key].revoked,
                "no withheld suffix can widen a key back past its revocation"
            );
            assert!(!peer_roster_consent_keys(&fold).contains(&fixture.revoked_key));
        }
    }
}

#[test]
fn forged_peer_entry_signed_off_roster_never_enters_the_peer_roster() {
    let fixture = peer_log_fixture(186);
    let forged_device = authority_key_from_ed(&ed_key(200));
    let forged = sign_ed(
        unsigned_entry(
            Some(fixture.vault_id),
            9,
            vec![authority_entry_hash(&fixture.genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(
                    forged_device.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&fixture.outsider),
            9,
        ),
        &fixture.outsider,
    );

    let mut entries = fixture.entries.clone();
    entries.push(forged);
    let fold = fold_peer_authority_log(&entries);

    assert!(
        !fold.roster.contains_key(&forged_device),
        "an entry signed by a key the peer roster never held cannot enrol anyone"
    );
    assert!(
        !fold
            .roster
            .contains_key(&authority_key_from_ed(&fixture.outsider))
    );
    assert_eq!(
        fold.roster,
        fold_peer_authority_log(&fixture.entries).roster,
        "the forgery leaves the derived roster byte-identical"
    );
}

#[test]
fn peer_fold_uses_no_local_seen_times_so_peer_widens_never_pend() {
    let fixture = peer_log_fixture(188);
    let peer = fold_peer_authority_log(&fixture.entries);
    assert!(
        peer.pending_widens.is_empty(),
        "a peer's widen is not a LOCAL observation and must never pend"
    );
    assert!(peer_roster_consent_keys(&peer).contains(&fixture.admin_key));

    // The SAME entries through the local seen-time fold do pend — which is
    // exactly the local state a peer must not be able to force.
    let local = fold_authority_log(&fixture.entries);
    assert!(
        !local.pending_widens.is_empty(),
        "fixture must actually carry a delayable widen for this contrast to bite"
    );
}
