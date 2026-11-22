//! Retired-key evidence names only this vault's rows (census L7-13,
//! identity.md "Open, Engine's follow-up" under the saved fork alarm).
//!
//! A key a handoff retired here may also be enrolled in a second vault, where
//! it signs that vault's rows rightly. A peer that replays those genuine rows
//! into this vault is refused, as before, and now plants no evidence record
//! and no alarm. Before the fix the append door recorded each such row, up to
//! the record's bound, and raised the retired key's alarm on a row this vault
//! never held. This vault's own row signed by the retired key still records
//! and raises the alarm (the control). The signed import compares the vault
//! first, so it records nothing either way.
//!
//! A refused row's signer is recorded only by a fence the vault held before
//! the write, or by a handoff it signed that the judging fold holds closed:
//! a key only an arriving handoff fences, that signed no handoff, is refused
//! with no record and no alarm until that handoff lands, and its next late
//! row then records without naming a handoff it did not sign.

use std::collections::BTreeSet;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityHandoffAlarm,
    AuthorityHandoffEquivocation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT,
    ROLE_CLOUD, ROLE_OWNER, authority_entry_hash, authority_transcript,
    encode_authority_log_entry_body, genesis_vault_id,
};
#[cfg(all(oneiron_test_support, feature = "sync"))]
use oneiron::test_doors::replicated_authority_batch::commit_replicated_authority_rows;
use oneiron::{ErrorKind, TimeRange, Vault, VaultConfig};

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent: Option<&AuthorityLogEntry>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parent
            .map(|parent| vec![authority_entry_hash(parent).expect("parent hash")])
            .unwrap_or_default(),
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
        overlay_seed: None,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// A vault's genesis, rooted on `root`; `nonce` tells two vaults of one key apart.
fn genesis(root: &SigningKey, nonce: u8) -> AuthorityLogEntry {
    signed(
        None,
        0,
        None,
        AuthorityOp::Genesis {
            device: device(key_of(root), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [nonce; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        root,
    )
}

/// `signer` enrols the agent key `enrolled` on `parent`.
fn enrollment(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    enrolled: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        Some(vault_id),
        seq,
        Some(parent),
        AuthorityOp::EnrollDevice {
            device: device(key_of(enrolled), ROLE_AGENT | ROLE_CLOUD),
        },
        signer,
    )
}

/// `signer` enrols the agent-only key `enrolled` on `parent`: the one
/// `EnrollDevice` shape the vault door's fold counts.
fn agent_only_enrollment(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    enrolled: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        Some(vault_id),
        seq,
        Some(parent),
        AuthorityOp::EnrollDevice {
            device: device(key_of(enrolled), ROLE_AGENT),
        },
        signer,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn put(vault: &Vault, entry: &AuthorityLogEntry) -> oneiron::Result<()> {
    vault
        .put_authority_log_entry(entry, TimeRange { start: 2, end: 2 }, 2)
        .map(|_| ())
}

/// This vault (root `old`, handed off to `next`) and a second vault rooted on
/// the same `old` key, which holds a genuine row `old` signed there.
struct TwoVaults {
    _dirs: [tempfile::TempDir; 2],
    here: Vault,
    old: SigningKey,
    here_genesis: AuthorityLogEntry,
    handoff: AuthorityLogEntry,
    elsewhere_genesis: AuthorityLogEntry,
    elsewhere_row: AuthorityLogEntry,
}

fn two_vaults() -> TwoVaults {
    let old = SigningKey::from_bytes(&[171; 32]);
    let next = SigningKey::from_bytes(&[172; 32]);
    let agent = SigningKey::from_bytes(&[173; 32]);

    let (here_dir, here) = open_vault();
    let here_genesis = genesis(&old, 181);
    let here_id = genesis_vault_id(&here_genesis).expect("vault id here");
    put(&here, &here_genesis).expect("genesis here");
    let handoff = signed(
        Some(here_id),
        1,
        Some(&here_genesis),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&next), ROLE_OWNER | ROLE_ADMIN),
        },
        &old,
    );
    here.apply_signed_re_root(&handoff).expect("handoff here");
    let fold = here.authority_fold().expect("fold here");
    assert!(
        fold.roster
            .get(&key_of(&next))
            .is_some_and(|device| !device.revoked),
        "the handoff installs the successor here"
    );
    assert!(
        fold.retired_keys.contains(&key_of(&old)),
        "the handoff retires the old root here"
    );

    let (elsewhere_dir, elsewhere) = open_vault();
    let elsewhere_genesis = genesis(&old, 182);
    let elsewhere_id = genesis_vault_id(&elsewhere_genesis).expect("vault id elsewhere");
    assert_ne!(here_id, elsewhere_id, "two vaults");
    put(&elsewhere, &elsewhere_genesis).expect("genesis elsewhere");
    let elsewhere_row = enrollment(elsewhere_id, &elsewhere_genesis, &old, 1, &agent);
    put(&elsewhere, &elsewhere_row).expect("the old key signs rightly in its own vault");

    TwoVaults {
        _dirs: [here_dir, elsewhere_dir],
        here,
        old,
        here_genesis,
        handoff,
        elsewhere_genesis,
        elsewhere_row,
    }
}

/// The saved alarms once one is saved: its writer runs after the refusing
/// transaction ends. The wait is 1,000 polls of 20 ms, a count and no clock
/// read; with no alarm after them the answer is empty.
fn saved_alarms(vault: &Vault) -> Vec<AuthorityHandoffAlarm> {
    for _ in 0..1000 {
        let alarms = vault.authority_handoff_alarms().expect("alarms");
        if !alarms.is_empty() {
            return alarms;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Vec::new()
}

/// Fails when an alarm appears within `window`, polling every 20 ms. The
/// alarm's writer is a thread with no completion signal, so absence rests on
/// this bounded window; the in-memory records are the exact check. The window
/// is counted in polls, with no clock read.
fn no_alarm_for(vault: &Vault, window: Duration) {
    let poll = Duration::from_millis(20);
    for _ in 0..=window.as_millis() / poll.as_millis() {
        assert!(
            vault
                .authority_handoff_alarms()
                .expect("the alarms read")
                .is_empty(),
            "no alarm is saved for a fence the vault never held"
        );
        std::thread::sleep(poll);
    }
}

#[test]
fn another_vaults_row_signed_by_a_retired_key_adds_no_evidence() {
    let vaults = two_vaults();
    let here = &vaults.here;

    assert!(
        put(here, &vaults.elsewhere_row).is_err(),
        "a row of another vault is refused here"
    );
    assert!(
        put(here, &vaults.elsewhere_row).is_err(),
        "and refused again on a replay"
    );
    assert_eq!(
        here.authority_handoff_equivocations(),
        Vec::new(),
        "another vault's genuine row is no evidence of a fork here"
    );

    // Control: the same act, by the same retired key, on this vault's own
    // history is refused and recorded with the handoff the key signed.
    let here_id = genesis_vault_id(&vaults.here_genesis).expect("vault id here");
    let agent = SigningKey::from_bytes(&[174; 32]);
    let own_row = enrollment(here_id, &vaults.here_genesis, &vaults.old, 2, &agent);
    assert!(
        put(here, &own_row).is_err(),
        "the retired key signs nothing new here"
    );
    let own_hash = authority_entry_hash(&own_row).expect("own row hash");
    assert_eq!(
        here.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: key_of(&vaults.old),
            handoffs: BTreeSet::from([authority_entry_hash(&vaults.handoff).expect("handoff")]),
            refused: own_hash,
        }]
    );
    let alarms = saved_alarms(here);
    assert_eq!(alarms.len(), 1, "one alarm for the one retired key");
    assert_eq!(
        alarms[0].refused,
        hex(&own_hash),
        "the alarm names this vault's refused row"
    );
}

#[test]
fn a_signed_import_of_another_vaults_rows_adds_no_evidence() {
    let vaults = two_vaults();
    let here = &vaults.here;
    let row = encode_authority_log_entry_body(&vaults.elsewhere_row).expect("row body");
    let genesis = encode_authority_log_entry_body(&vaults.elsewhere_genesis).expect("genesis body");

    assert!(
        here.import_signed_authority_history(std::slice::from_ref(&row))
            .is_err(),
        "a row of another vault does not import"
    );
    assert!(
        here.import_signed_authority_history(&[genesis, row])
            .is_err(),
        "nor does that vault's history"
    );
    assert_eq!(here.authority_handoff_equivocations(), Vec::new());
    assert_eq!(here.authority_handoff_alarms().expect("alarms"), Vec::new());
}

#[test]
fn a_revocation_after_a_handoff_records_evidence_only_for_the_handoff_key() {
    let old = SigningKey::from_bytes(&[175; 32]);
    let next = SigningKey::from_bytes(&[176; 32]);
    let revoked = SigningKey::from_bytes(&[177; 32]);
    let agent = SigningKey::from_bytes(&[178; 32]);
    let (_dir, vault) = open_vault();
    let genesis = genesis(&old, 183);
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    put(&vault, &genesis).expect("genesis");
    let handoff = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&next), ROLE_OWNER | ROLE_ADMIN),
        },
        &old,
    );
    vault.apply_signed_re_root(&handoff).expect("handoff");
    let admission = signed(
        Some(vault_id),
        1,
        Some(&handoff),
        AuthorityOp::EnrollDevice {
            device: device(key_of(&revoked), ROLE_AGENT),
        },
        &next,
    );
    put(&vault, &admission).expect("the successor enrolls a new key");
    let before_revocation = vault.authority_fold().expect("fold before revocation");
    assert!(
        before_revocation
            .roster
            .get(&key_of(&revoked))
            .is_some_and(|device| !device.revoked)
    );
    let mut late = signed(
        Some(vault_id),
        1,
        Some(&admission),
        AuthorityOp::EnrollDevice {
            device: device(key_of(&agent), ROLE_AGENT),
        },
        &revoked,
    );
    // The agent signs the row; the successor's cosign supplies consent.
    let cosigner = key_of(&next);
    late.cosigns.push(AuthoritySignature {
        suite: cosigner.suite(),
        public_key: cosigner,
        signature: vec![0; 64],
    });
    let transcript = authority_transcript(&late).expect("cosigned transcript");
    late.signer.signature = revoked.sign(&transcript).to_bytes().to_vec();
    late.cosigns[0].signature = next.sign(&transcript).to_bytes().to_vec();
    let revocation = signed(
        Some(vault_id),
        2,
        Some(&admission),
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&revoked),
        },
        &next,
    );
    put(&vault, &revocation).expect("the successor revokes the new key");
    let fold = vault.authority_fold().expect("fold after revocation");
    let handoff_hash = authority_entry_hash(&handoff).expect("handoff hash");
    assert!(fold.valid_entries.contains(&handoff_hash));
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&revocation).expect("revocation hash"))
    );
    assert_eq!(
        fold.retired_keys,
        BTreeSet::from([key_of(&old), key_of(&revoked)])
    );

    let error = put(&vault, &late).expect_err("the door refuses the revoked agent's row");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    assert!(vault.authority_handoff_equivocations().is_empty());

    let old_row = signed(
        Some(vault_id),
        2,
        Some(&genesis),
        AuthorityOp::EnrollDevice {
            device: device(key_of(&agent), ROLE_AGENT),
        },
        &old,
    );
    let error = put(&vault, &old_row).expect_err("the door refuses the old root's row");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: key_of(&old),
            handoffs: BTreeSet::from([handoff_hash]),
            refused: authority_entry_hash(&old_row).expect("refused row hash"),
        }]
    );
    assert_eq!(vault.authority_handoff_equivocations_dropped(), 0);
}

#[test]
fn a_revoked_keys_row_refused_beside_an_arriving_handoff_adds_no_evidence_until_the_handoff_lands()
{
    let owner = SigningKey::from_bytes(&[191; 32]);
    let peer = SigningKey::from_bytes(&[192; 32]);
    let agent = SigningKey::from_bytes(&[193; 32]);
    let next = SigningKey::from_bytes(&[194; 32]);
    let (_dir, vault) = open_vault();
    let genesis = genesis(&owner, 201);
    let vault_id = genesis_vault_id(&genesis).expect("FIXTURE: the genesis names its vault");
    put(&vault, &genesis).expect("FIXTURE: the genesis lands");
    // The peer is admitted as an agent alone, so the fold holds it live, and
    // a second admission of the same key with the admin role and no cloud
    // role makes the import's never-applied filter vouch for its row; the
    // helper's cloud role would do neither. A non-agent EnrollDevice never
    // counts in the fold: the vault door refuses it as a retired device-key
    // op. The peer still signs its row alone.
    let admission = agent_only_enrollment(vault_id, &genesis, &owner, 1, &peer);
    put(&vault, &admission).expect("FIXTURE: the owner enrols the peer");
    let admitter = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        AuthorityOp::EnrollDevice {
            device: device(key_of(&peer), ROLE_AGENT | ROLE_ADMIN),
        },
        &owner,
    );
    put(&vault, &admitter).expect("FIXTURE: the same key gains the filter's vouch");
    let fold = vault
        .authority_fold()
        .expect("FIXTURE: the fold reads after admission");
    assert!(
        fold.roster
            .get(&key_of(&peer))
            .is_some_and(|device| !device.revoked && device.roles == ROLE_AGENT),
        "FIXTURE: the peer stands live as an agent"
    );
    let withheld = enrollment(vault_id, &admission, &peer, 1, &agent);
    let revocation = signed(
        Some(vault_id),
        2,
        Some(&admission),
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&peer),
        },
        &owner,
    );
    put(&vault, &revocation).expect("FIXTURE: the owner revokes the peer");
    let fold = vault.authority_fold().expect("FIXTURE: the fold reads");
    assert!(
        fold.retired_keys.contains(&key_of(&peer)),
        "FIXTURE: the revocation retires the peer"
    );
    assert!(
        vault.authority_handoff_equivocations().is_empty(),
        "FIXTURE: the fixture plants no record"
    );
    assert!(
        vault
            .authority_handoff_alarms()
            .expect("FIXTURE: the alarms read")
            .is_empty(),
        "FIXTURE: the fixture raises no alarm"
    );
    let handoff = signed(
        Some(vault_id),
        3,
        Some(&revocation),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&next), ROLE_OWNER | ROLE_ADMIN),
        },
        &owner,
    );
    let before = vault
        .export_signed_authority_history()
        .expect("FIXTURE: the history exports");
    assert_eq!(
        before.len(),
        4,
        "FIXTURE: only the stored fixture rows are held"
    );
    let withheld_body =
        encode_authority_log_entry_body(&withheld).expect("FIXTURE: the withheld row encodes");
    let handoff_body =
        encode_authority_log_entry_body(&handoff).expect("FIXTURE: the handoff encodes");
    let error = vault
        .import_signed_authority_history(&[withheld_body, handoff_body])
        .expect_err("the import beside the arriving handoff is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history exports after the refusal"),
        before,
        "the refused import writes nothing"
    );
    assert!(
        vault.authority_handoff_equivocations().is_empty(),
        "a fence only the refused write brings records no signer"
    );
    assert_eq!(
        vault.authority_handoff_equivocations_dropped(),
        0,
        "nothing is dropped when nothing records"
    );
    no_alarm_for(&vault, Duration::from_millis(500));

    vault
        .apply_signed_re_root(&handoff)
        .expect("FIXTURE: the handoff lands alone");
    let fold = vault
        .authority_fold()
        .expect("FIXTURE: the fold reads after the handoff");
    assert!(
        fold.roster
            .get(&key_of(&next))
            .is_some_and(|device| !device.revoked),
        "FIXTURE: the handoff installs its successor live"
    );

    let error = put(&vault, &withheld).expect_err("the revoked peer signs nothing new");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    let withheld_hash = authority_entry_hash(&withheld).expect("the withheld row hashes");
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: key_of(&peer),
            handoffs: BTreeSet::new(),
            refused: withheld_hash,
        }],
        "the late row records once the fence is held, naming no handoff the peer did not sign"
    );
    let alarms = saved_alarms(&vault);
    assert_eq!(alarms.len(), 1, "one alarm for the one retired key");
    let peer_pub = peer.verifying_key().to_bytes();
    assert_eq!(
        alarms[0].signer,
        format!("ed25519:{}", hex(&peer_pub)),
        "the alarm names the retired peer"
    );
    assert_eq!(
        alarms[0].refused,
        hex(&withheld_hash),
        "the alarm names this vault's refused row"
    );
    assert!(alarms[0].handoffs.is_empty(), "the peer signed no handoff");
}

#[cfg(all(oneiron_test_support, feature = "sync"))]
#[test]
fn a_live_keys_row_refused_beside_the_handoff_that_fences_it_adds_no_evidence_until_the_handoff_lands()
 {
    let owner = SigningKey::from_bytes(&[195; 32]);
    let peer = SigningKey::from_bytes(&[196; 32]);
    let agent = SigningKey::from_bytes(&[197; 32]);
    let next = SigningKey::from_bytes(&[198; 32]);
    let (_dir, vault) = open_vault();
    let genesis = genesis(&owner, 202);
    let vault_id = genesis_vault_id(&genesis).expect("FIXTURE: the genesis names its vault");
    put(&vault, &genesis).expect("FIXTURE: the genesis lands");
    let admission = agent_only_enrollment(vault_id, &genesis, &owner, 1, &peer);
    put(&vault, &admission).expect("FIXTURE: the owner enrols the peer");
    let fold = vault.authority_fold().expect("FIXTURE: the fold reads");
    assert!(
        fold.roster
            .get(&key_of(&peer))
            .is_some_and(|device| !device.revoked),
        "FIXTURE: the peer stands live"
    );
    assert!(
        !fold.retired_keys.contains(&key_of(&peer)),
        "FIXTURE: no fence holds the peer yet"
    );
    let withheld = enrollment(vault_id, &admission, &peer, 1, &agent);
    let handoff = signed(
        Some(vault_id),
        2,
        Some(&admission),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&next), ROLE_OWNER | ROLE_ADMIN),
        },
        &owner,
    );
    let before = vault
        .export_signed_authority_history()
        .expect("FIXTURE: the history exports");
    assert_eq!(
        before.len(),
        2,
        "FIXTURE: only the stored fixture rows are held"
    );
    let error = commit_replicated_authority_rows(&vault, &[handoff.clone(), withheld.clone()])
        .expect_err("the batch beside the fencing handoff is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history exports after the refusal"),
        before,
        "the refused batch writes nothing"
    );
    assert!(
        vault.authority_handoff_equivocations().is_empty(),
        "a fence only the refused write brings records no signer"
    );
    assert_eq!(
        vault.authority_handoff_equivocations_dropped(),
        0,
        "nothing is dropped when nothing records"
    );
    no_alarm_for(&vault, Duration::from_millis(500));

    vault
        .apply_signed_re_root(&handoff)
        .expect("FIXTURE: the handoff lands alone");
    let fold = vault
        .authority_fold()
        .expect("FIXTURE: the fold reads after the handoff");
    assert!(
        fold.roster
            .get(&key_of(&next))
            .is_some_and(|device| !device.revoked),
        "FIXTURE: the handoff installs its successor live"
    );

    let error = put(&vault, &withheld).expect_err("the fenced peer signs nothing new");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    let withheld_hash = authority_entry_hash(&withheld).expect("the withheld row hashes");
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: key_of(&peer),
            handoffs: BTreeSet::new(),
            refused: withheld_hash,
        }],
        "the late row records once the fence is held, naming no handoff the peer did not sign"
    );
    let alarms = saved_alarms(&vault);
    assert_eq!(alarms.len(), 1, "one alarm for the one fenced key");
    let peer_pub = peer.verifying_key().to_bytes();
    assert_eq!(
        alarms[0].signer,
        format!("ed25519:{}", hex(&peer_pub)),
        "the alarm names the fenced peer"
    );
    assert_eq!(
        alarms[0].refused,
        hex(&withheld_hash),
        "the alarm names this vault's refused row"
    );
    assert!(alarms[0].handoffs.is_empty(), "the peer signed no handoff");
}

#[cfg(all(oneiron_test_support, feature = "sync"))]
#[test]
fn sibling_handoffs_of_one_root_in_one_refused_batch_record_the_root_and_name_no_handoff() {
    let root = SigningKey::from_bytes(&[203; 32]);
    let first_next = SigningKey::from_bytes(&[204; 32]);
    let second_next = SigningKey::from_bytes(&[205; 32]);
    let (_dir, vault) = open_vault();
    let genesis = genesis(&root, 206);
    let vault_id = genesis_vault_id(&genesis).expect("FIXTURE: the genesis names its vault");
    put(&vault, &genesis).expect("FIXTURE: the genesis lands");
    let first = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&first_next), ROLE_OWNER | ROLE_ADMIN),
        },
        &root,
    );
    let second = signed(
        Some(vault_id),
        2,
        Some(&genesis),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&second_next), ROLE_OWNER | ROLE_ADMIN),
        },
        &root,
    );
    let before = vault
        .export_signed_authority_history()
        .expect("FIXTURE: the history exports");
    assert_eq!(
        before.len(),
        1,
        "FIXTURE: only the stored fixture rows are held"
    );
    let error = commit_replicated_authority_rows(&vault, &[first.clone(), second.clone()])
        .expect_err("the batch of sibling handoffs is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidAuthorityLogBody);
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history exports after the refusal"),
        before,
        "the refused batch writes nothing"
    );
    let second_hash = authority_entry_hash(&second).expect("the second handoff hashes");
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: key_of(&root),
            handoffs: BTreeSet::new(),
            refused: second_hash,
        }],
        "the root signed the judging fold's closed handoff, which rolls back unnamed"
    );
    let alarms = saved_alarms(&vault);
    assert_eq!(alarms.len(), 1, "one alarm for the one retired key");
    let root_pub = root.verifying_key().to_bytes();
    assert_eq!(
        alarms[0].signer,
        format!("ed25519:{}", hex(&root_pub)),
        "the alarm names the retired root"
    );
    assert_eq!(
        alarms[0].refused,
        hex(&second_hash),
        "the alarm names this vault's refused row"
    );
    assert!(
        alarms[0].handoffs.is_empty(),
        "the alarm names no handoff the refused batch rolled back"
    );
}
