//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2f2: the owner's own
//! import of an export secret supplement carries the owner key's proof on
//! its import mark. Past its owner reserve, install B lands only the owner's
//! work (`authority/log_budget.rs`), and the `ExportSupplementImported` mark
//! install A signs in the import's writer reaches B signed by A's install
//! key. Since #9892 the fold takes one owner key's proof beside that
//! signature; here the import door's proof of the owner, revalidated in the
//! import's writer as his own write, makes the mark, and the install join it
//! names when A's frontier is wider than one entry names, carry it
//! (`Vault::owner_act_proof_signer`).
//!
//! Before B takes A's history, the owner marks A his, admits a second
//! machine on A (the flooder), registers a portable secret on A (A holds
//! it), exports the whole vault once for the secret's archive row, and
//! records an export secret request for it with A as recipient (test door
//! `holder_export_requests`, as an owner export's audit write records one
//! for a secret it met unopened). B then takes A's history and is flooded
//! until its door holds a row at the reserve (`owner_reserve/two_installs.rs`).
//! The owner imports the supplement on A (`Vault::import_secret_supplement`;
//! A holds the same record, so the import is `Unchanged` and marks the
//! request), and B imports what A wrote since.
//!
//! Red at the base (#9955 head 3f6417b2, an import mark is carried
//! unproven): A's mark, and the join before it, carry no proof, so the first
//! and fourth tests fail. The controls, the import on an A that holds no
//! owner key and the import by a proof bound to a request's slip, carry the
//! mark unproven and it waits at B on both.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_import_mark`.

#![cfg(oneiron_test_support)]

use std::io::{Cursor, Read as _};

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, MachineOwnership, MachineRole,
    OpenedSecretSupplement, SecretSupplementImport, VerifiedSlip, authority_entry_hash,
};
use oneiron::batch::export::ArchiveSecretCustody;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::ExportOptions;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::settings::ReadDestination;
use oneiron::test_doors::holder_export_requests::record_export_secret_request;
use oneiron::{EntityId, ErrorKind, Vault};
use oneiron_authority::authority::{FrontierJoinFamily, MAX_PARENTS};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Flooder, Rooted, Second, admit_flooder, flood_row, heads_of_a, hold_owner_key, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, the_row_a_wrote,
    written_since,
};

/// How many concurrent heads the flooder signs on A: one more than one
/// entry names, so the mark on A joins them first.
const WIDE_HEADS: u64 = MAX_PARENTS as u64 + 1;

/// When the owner registers the secret.
const CUSTODY_AT: u64 = 1_780_000_000;

/// The portable secret the owner registers on A.
const SECRET: &str = "owner-reserve-import-mark";

/// What A holds before B takes its history: the flooder, the owner's export
/// secret request, and the archive row of its secret that the owner's
/// export carried, the supplement the owner imports.
struct Prepared {
    flooder: Flooder,
    request: AuthorityEntryHash,
    row: ArchiveSecretCustody,
}

/// The owner marks A his, admits the flooder, registers a portable secret
/// on A, exports the whole vault for that secret's archive row, and records
/// the export secret request for it, its sealed copy for A.
fn prepare(rooted: &Rooted) -> Prepared {
    let machine_of_a = rooted
        .vault
        .local_machine()
        .expect("FIXTURE: A's machine")
        .expect("FIXTURE: A has a machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            machine_of_a,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner marks A yours");
    let flooder = admit_flooder(rooted);
    // Registered after A is the owner's, so the value is portable.
    let registered = rooted
        .vault
        .register_secret_as_owner(
            &rooted.proof,
            &OwnerSecretRegistration {
                name: SECRET,
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"owner-reserve-import-mark-value",
            },
            CUSTODY_AT,
        )
        .expect("FIXTURE: the owner registers a portable secret on A");
    let row = archived_row(rooted, registered.secret_id);
    let request = record_export_secret_request(
        &rooted.vault,
        &rooted.proof,
        registered.secret_id,
        registered.rotation_generation,
        machine_of_a,
    )
    .expect("FIXTURE: the owner's export secret request, A its holder and recipient");
    Prepared {
        flooder,
        request,
        row,
    }
}

/// The archive row of `secret`, with its value, from the owner's
/// whole-vault export on A, on this device.
fn archived_row(rooted: &Rooted, secret: EntityId) -> ArchiveSecretCustody {
    let (export, _) = rooted
        .vault
        .export_with_authenticated_owner_listing(
            &ExportOptions::default(),
            &rooted.proof,
            ActSurface::ThisInstall,
            ReadDestination::on_device(),
        )
        .expect("FIXTURE: the owner exports the whole vault on A");
    let mut zip = zip::ZipArchive::new(Cursor::new(export.archive.as_slice()))
        .expect("FIXTURE: the archive opens as a zip");
    let mut rows = String::new();
    zip.by_name("records/secret_custody.jsonl")
        .expect("FIXTURE: the archive carries custody records")
        .read_to_string(&mut rows)
        .expect("FIXTURE: the custody records read");
    let row = rows
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str::<ArchiveSecretCustody>(line).expect("FIXTURE: a custody row")
        })
        .find(|row| row.id == secret.to_hex())
        .expect("FIXTURE: the export carries the secret's row");
    assert!(
        row.body.is_some(),
        "FIXTURE: the export carries the secret's value"
    );
    row
}

/// The owner imports the supplement on A by `proof`: A holds the same
/// record, so the import is unchanged and marks the request.
fn owner_imports_on_a(rooted: &Rooted, proof: &AuthenticatedOwner, prepared: &Prepared) {
    let imported = rooted
        .vault
        .import_secret_supplement(
            proof,
            ActSurface::ThisInstall,
            &OpenedSecretSupplement {
                request: prepared.request,
                row: prepared.row.clone(),
            },
        )
        .expect("the owner imports the supplement on A");
    assert_eq!(
        imported,
        SecretSupplementImport::Unchanged,
        "FIXTURE: A holds the same record already"
    );
}

fn is_import_mark(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::ExportSupplementImported(_))
}

/// B imports `rows`, what A wrote since B took its history, and counts the
/// mark `hash`; A signed `entry` with one owner key's proof beside its
/// install key.
fn b_lands_the_proven_mark(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the import mark with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
        .expect("B lands the import mark A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the import mark"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// A carried the mark `entry` unproven, and B's door holds it at its
/// reserve (`AuthorityLogFull`), as before.
fn b_holds_the_unproven_mark(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert!(
        entry.cosigns.is_empty(),
        "A carries the import mark unproven: {} cosigns",
        entry.cosigns.len()
    );
    let import = second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new());
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven import mark at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
}

/// A fresh slip id from two entity ids.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

/// The owner's own verified human slip, cut from the host root with a fresh
/// id and verified on its binding, as a transport verifies the slip a
/// request arrives with.
fn owners_verified_slip(vault: &Vault, owner: EntityId) -> VerifiedSlip {
    let issuer = oneiron::test_support::test_host_issuer();
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("FIXTURE: the owner's own slip");
    let challenge = b"authority-log-owner-reserve-import-mark";
    let binding = issuer
        .binding_proof(&slip, challenge)
        .expect("FIXTURE: the binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .expect("FIXTURE: the slip verifies")
}

/// The owner imports the supplement on A, where A holds an owner key: the
/// import mark carries the proof, and B, past its owner reserve, lands it.
#[test]
fn the_owners_import_mark_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    owner_imports_on_a(&rooted, &rooted.proof, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_import_mark);
    b_lands_the_proven_mark(&second, &rows, &entry, hash);
}

/// The same import on an A that holds no owner key: A carries the mark
/// unproven, and it waits at B's door, as before.
#[test]
fn the_owners_import_mark_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let prepared = prepare(&rooted);
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    owner_imports_on_a(&rooted, &rooted.proof, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_import_mark);
    b_holds_the_unproven_mark(&second, &rows, &entry, hash);
}

/// The same import on an A that holds an owner key, by the owner's proof
/// bound to the owner's own slip as its request's slip
/// (`Vault::bind_request_credential`): that slip is read for its liveness
/// alone, so the mark is carried unproven and waits at B's door.
#[test]
fn the_owners_import_by_a_request_bound_proof_marks_unproven_and_waits_past_this_installs_reserve()
{
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    let request_bound = rooted
        .vault
        .bind_request_credential(
            rooted.proof.clone(),
            owners_verified_slip(&rooted.vault, rooted.owner),
        )
        .expect("FIXTURE: the request's slip binds to the owner's proof");
    owner_imports_on_a(&rooted, &request_bound, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_import_mark);
    b_holds_the_unproven_mark(&second, &rows, &entry, hash);
}

/// The flooder signs one more concurrent head on A than one entry names,
/// each its own world edit on its admission, and B takes them, below its
/// reserve. The owner then imports on A, where A holds an owner key: A joins
/// the wide frontier first, and the join carries the mark's proof, so B,
/// past its reserve, lands the join and the mark on it.
#[test]
fn the_owners_import_mark_past_a_wide_frontier_lands_with_its_join_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    let flooder = &prepared.flooder;
    let mut last = flooder.admission;
    for seq in 1..=WIDE_HEADS {
        let row = flood_row(&rooted, flooder, EntityId::now(), seq, flooder.admission);
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("FIXTURE: A stores the flooder's concurrent world edit");
        last = authority_entry_hash(&row).expect("hash");
    }
    let heads = heads_of_a(&rooted).len();
    assert!(
        heads > MAX_PARENTS,
        "FIXTURE: A's frontier is wider than one entry names: {heads} heads"
    );
    let second = second_install_at_its_reserve_from(&rooted, flooder, (last, WIDE_HEADS + 1));
    owner_imports_on_a(&rooted, &rooted.proof, &prepared);
    let written = written_since(&rooted, &second);
    let joins: Vec<&AuthorityLogEntry> = written
        .iter()
        .map(|(_, entry)| entry)
        .filter(|entry| {
            matches!(&entry.op, AuthorityOp::FrontierJoin(join)
                if matches!(join.family, FrontierJoinFamily::Install(_)))
        })
        .collect();
    let [join] = joins.as_slice() else {
        panic!("A joined its wide frontier once before the import mark: {joins:?}");
    };
    assert!(
        join.parent_hashes.len() > MAX_PARENTS && join.cosigns.len() == 1,
        "A's join names every head and carries the owner key's proof: {} parents, {} cosigns",
        join.parent_hashes.len(),
        join.cosigns.len()
    );
    let join_hash = authority_entry_hash(join).expect("hash");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_import_mark);
    assert_eq!(
        entry.parent_hashes,
        vec![join_hash],
        "the import mark names the join alone"
    );
    b_lands_the_proven_mark(&second, &rows, &entry, hash);
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "B's fold counts the join"
    );
}
