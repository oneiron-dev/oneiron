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

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityHandoffAlarm,
    AuthorityHandoffEquivocation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT,
    ROLE_CLOUD, ROLE_OWNER, authority_entry_hash, authority_transcript,
    encode_authority_log_entry_body, genesis_vault_id,
};
use oneiron::{TimeRange, Vault, VaultConfig};

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
/// transaction ends.
fn saved_alarms(vault: &Vault) -> Vec<AuthorityHandoffAlarm> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let alarms = vault.authority_handoff_alarms().expect("alarms");
        if !alarms.is_empty() || Instant::now() > deadline {
            return alarms;
        }
        std::thread::sleep(Duration::from_millis(20));
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
