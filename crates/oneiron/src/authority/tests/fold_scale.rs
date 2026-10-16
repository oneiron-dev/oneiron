//! The fold's measured cost on a long log: the table behind the memory
//! floor's coefficients and the headroom rows' defaults (rule 5, H72).
//!
//! Run one shape per process, on Linux, so the peak is this fold's:
//! `ONEIRON_FOLD_SCALE=agents:2000 cargo nextest run -p oneiron --lib
//! --run-ignored only -E 'test(=authority::tests::fold_scale::measure)'
//! --no-capture`. Shapes: `agents:<n>` (each agent enrolled, then bound, in
//! one chain of the owner's rows), `chain:<n>` (n confirms in one chain),
//! `star:<n>` (n confirms, each under genesis alone).
use super::support::*;
use super::*;

fn agent_key(n: usize) -> SigningKey {
    let mut seed = [0xA6; 32];
    seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

fn confirm_op(n: usize) -> AuthorityOp {
    let mut confirm_id = [0xC0; 32];
    confirm_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    let mut nonce = [0xC0; 16];
    nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: [77; 32],
        epoch: 1,
        nonce,
    })
}

/// `owner`'s row `op` under `parents`, cosigned by `cosigner`.
fn owner_row(
    vault_id: AuthorityVaultId,
    owner: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    cosigner: Option<&SigningKey>,
) -> AuthorityLogEntry {
    let mut entry = unsigned_entry(
        Some(vault_id),
        seq,
        parents,
        op,
        authority_key_from_ed(owner),
        3,
    );
    if let Some(key) = cosigner {
        entry.cosigns.push(AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: authority_key_from_ed(key),
            signature: vec![0; 64],
        });
    }
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = owner.sign(&transcript).to_bytes().to_vec();
    if let Some(key) = cosigner {
        entry.cosigns[0].signature = key.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// The log of `shape`: genesis, then the owner's rows.
pub(super) fn scale_log(shape: &str, rows: usize) -> Vec<AuthorityLogEntry> {
    let owner = ed_key(91);
    let genesis = genesis_entry(91, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let root = authority_entry_hash(&genesis).unwrap();
    let mut entries = vec![genesis];
    let mut parent = root;
    for n in 0..rows {
        let seq = n as u64 + 1;
        let entry = match shape {
            "agents" if n % 2 == 0 => owner_row(
                vault_id,
                &owner,
                seq,
                vec![parent],
                AuthorityOp::EnrollDevice {
                    device: device(
                        authority_key_from_ed(&agent_key(n / 2)),
                        ROLE_AGENT,
                        AuthorityTier::Software,
                    ),
                },
                None,
            ),
            "agents" => {
                let mut actor = [0x71; 16];
                actor[8..].copy_from_slice(&(n as u64).to_be_bytes());
                owner_row(
                    vault_id,
                    &owner,
                    seq,
                    vec![parent],
                    AuthorityOp::BindActor {
                        authority_key: authority_key_from_ed(&agent_key(n / 2)),
                        actor_ref: EntityId::from_bytes(actor).unwrap(),
                        actor_class: "system".into(),
                        epoch: 1,
                    },
                    Some(&agent_key(n / 2)),
                )
            }
            "chain" => owner_row(vault_id, &owner, seq, vec![parent], confirm_op(n), None),
            "star" => owner_row(vault_id, &owner, seq, vec![root], confirm_op(n), None),
            other => panic!("unknown shape {other}"),
        };
        parent = authority_entry_hash(&entry).unwrap();
        entries.push(entry);
    }
    entries
}

/// The vault door's fold of `entries` under no memory floor.
pub(super) fn vault_fold(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 1))
        .collect();
    let observations = AuthorityLocalObservations {
        sequence_floors: BTreeMap::new(),
        vouched: BTreeSet::new(),
        unvouched: false,
        policy: AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(u64::MAX),
            ..AuthorityObservationPolicy::default()
        },
    };
    fold_authority_log_with_local_observations_and_posture(
        entries,
        &first_seen,
        2,
        &BTreeMap::new(),
        &observations,
        crate::HostingPrivacyPosture::default(),
    )
}

fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Measurement: one fold of `ONEIRON_FOLD_SCALE`'s log, its peak resident
/// bytes over the process's before it, its time, and its ancestor pairs.
#[test]
#[ignore = "measurement: run one shape per process on Linux, see the module doc"]
fn measure() {
    let spec = std::env::var("ONEIRON_FOLD_SCALE").unwrap_or_else(|_| "agents:512".into());
    let (shape, rows) = spec.split_once(':').unwrap();
    let rows: usize = rows.parse().unwrap();
    let entries = scale_log(shape, rows);
    // Resets the peak where the host allows it; building the log is small
    // beside the fold either way.
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let base = status_kib("VmRSS:");
    let started = Instant::now();
    let fold = vault_fold(&entries);
    let secs = started.elapsed().as_secs_f64();
    let peak = (status_kib("VmHWM:") - base) * 1024;
    let n = entries.len() as u64;
    let pairs = match shape {
        "star" => n - 1,
        _ => n * (n - 1) / 2,
    };
    eprintln!(
        "FOLD-SCALE shape={shape} rows={n} valid={} pairs={pairs} counted_pairs={} peak_bytes={peak} \
         bytes_per_pair={} bytes_per_row={} secs={secs:.3}",
        fold.valid_entries.len(),
        fold.counted_ancestor_pairs,
        peak / pairs.max(1),
        peak / n,
    );
}
