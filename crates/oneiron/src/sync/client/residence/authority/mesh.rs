//! The home's host-signed mesh bindings, read each sync round whatever this
//! machine's residence (`residence.authority.mesh`,
//! MESH-AUTHORITY-REPLICATION). No window carries a binding or the MACHINE
//! address it binds, and a joined machine holds no host issuer to sign its
//! own. Each binding a live owner host of this machine's fold signed lands
//! as signed ([`Vault::import_mesh_authority_rows`]), so a node here proves
//! the peers the owner bound on the home.
//!
//! A round reads at most [`MAX_PAGES`] pages, from where the last round
//! stopped, so every binding lands however many the home holds
//! (REVIEW-10536 P1). A binding past one page comes by reference, and this
//! machine reads its signed row a part at a time
//! (`residence.authority.mesh.part`, MESH-AUTHORITY-ROW-PARTS), checks the
//! joined row's length and content hash ([`MeshAuthorityRowJoin`]) and
//! imports it alone, in MACHINE order among the page's other rows, before it
//! reads the next: a round holds at most one joined row (REVIEW-10560 P1). A
//! row that does not join, as when the home signed it again while this
//! machine read it, or whose part read fails, as when a long row cannot
//! cross a slow link inside one call's deadline, stays out alone until the
//! scan comes back to it; the page's other rows land and the scan goes on,
//! over a socket opened again after a failed read (REVIEW-10560 round 2).

use std::sync::{Mutex, PoisonError};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{MAX_PAGES, ResidenceRpc, refused, residence_budgets, storage};
use crate::authority::{
    MESH_AUTHORITY_PAGE_MAX, MeshAuthorityPart, MeshAuthorityRow, MeshAuthorityRowJoin,
    MeshAuthorityRowRef,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

/// One binding as the home serves it, each part in base64.
#[derive(Deserialize)]
struct MeshAuthorityRowReply {
    machine: String,
    authority: String,
    address: String,
    /// The address was served without its direct addresses, to fit the page.
    #[serde(default)]
    bare: bool,
}

/// A binding the home names by reference, its signed row read in parts: its
/// length, its content hash as `blake3:<hex>` and its address in base64.
#[derive(Deserialize)]
struct MeshAuthorityRowRefReply {
    machine: String,
    total: u64,
    digest: String,
    address: String,
    #[serde(default)]
    bare: bool,
}

/// One part of a signed row the home holds, and the row's whole length.
#[derive(Deserialize)]
struct MeshAuthorityPartReply {
    total: u64,
    part: String,
}

/// The home's answer to one mesh bindings ask: the page's rows, those it
/// names by reference (none from a home older than MESH-AUTHORITY-ROW-PARTS),
/// and the MACHINE the next page starts after while there is one.
#[derive(Deserialize)]
struct MeshAuthorityReply {
    rows: Vec<MeshAuthorityRowReply>,
    #[serde(default)]
    parted: Vec<MeshAuthorityRowRefReply>,
    #[serde(default)]
    next: Option<String>,
}

/// Reads the home's mesh bindings for one round and imports each page. The
/// round starts after the MACHINE `cursor` holds, or at the first binding
/// when it holds none. Each page this machine committed moves `cursor` past
/// it, so a round that stops early, or a reconnect, goes on from there; it
/// holds `None` once the scan reached the home's last binding. Returns how
/// many bindings were written here.
///
/// # Errors
///
/// A member lane; the home is offline, serves no such method (a home older
/// than MESH-AUTHORITY-REPLICATION) or answers a page this machine refuses;
/// a socket that does not open again after a failed part read; storage
/// errors. Pages committed before the error stay committed.
pub(crate) async fn catch_up_mesh_authority(
    vault: &Vault,
    config: &SyncClientConfig,
    cursor: &Mutex<Option<EntityId>>,
) -> Result<usize, TransportError> {
    if config.member_lane {
        return Err(refused());
    }
    let budgets = residence_budgets(vault)?;
    let Some(rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::home_offline());
    };
    let mut home = HomeParts {
        vault,
        config,
        rpc,
        failed: false,
    };
    let mut after = *cursor.lock().unwrap_or_else(PoisonError::into_inner);
    let mut written = 0;
    for _ in 0..MAX_PAGES {
        home.reopen_after_failure().await?;
        let reply = home
            .rpc
            .request(
                "residence.authority.mesh",
                json!({ "after": after.as_ref().map(EntityId::to_hex) }),
            )
            .await?;
        let reply: MeshAuthorityReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let (rows, parted, next) = decoded_page(reply, after)?;
        written += import_page(rows, parted, &mut home, |rows| imported(vault, rows)).await?;
        after = next;
        *cursor.lock().unwrap_or_else(PoisonError::into_inner) = after;
        if after.is_none() {
            break;
        }
    }
    Ok(written)
}

/// Imports `rows`, some of one page's bindings, through
/// [`Vault::import_mesh_authority_rows`]. Returns how many were written here.
fn imported(vault: &Vault, rows: Vec<MeshAuthorityRow>) -> Result<usize, TransportError> {
    let import = vault.import_mesh_authority_rows(rows).map_err(storage)?;
    if !import.refused.is_empty() {
        tracing::warn!(
            refused = import.refused.len(),
            "the home served mesh bindings this machine refused"
        );
    }
    Ok(import.written.len())
}

/// Where the rows a page names by reference are read from, a part at a time.
trait MeshAuthorityPartSource {
    /// The part of the signed row of `machine` from `offset`, with the row's
    /// whole length; `None` when the source serves none there. A read that
    /// failed leaves the source to open again
    /// ([`Self::reopen_after_failure`]).
    async fn part(
        &mut self,
        machine: EntityId,
        offset: u64,
    ) -> Result<Option<MeshAuthorityPart>, TransportError>;

    /// Opens the source again when a part read failed since it was opened,
    /// so the page's other rows can still be read; nothing when none did.
    async fn reopen_after_failure(&mut self) -> Result<(), TransportError>;
}

/// The home over this round's socket, which the round opens again after a
/// part read failed: a call that timed out can still be answered later on
/// its socket, under its own id, so that socket takes no other call.
struct HomeParts<'a> {
    vault: &'a Vault,
    config: &'a SyncClientConfig,
    rpc: ResidenceRpc,
    /// A part read failed on `rpc` since it was opened.
    failed: bool,
}

/// The home's parts (`residence.authority.mesh.part`). Its refusal is
/// `None`: the home refuses a binding it no longer serves and an offset at or
/// past the row's end, as when it signed the row again shorter. A reply this
/// machine cannot read leaves the socket as it was.
impl MeshAuthorityPartSource for HomeParts<'_> {
    async fn part(
        &mut self,
        machine: EntityId,
        offset: u64,
    ) -> Result<Option<MeshAuthorityPart>, TransportError> {
        let reply = match self
            .rpc
            .call(
                "residence.authority.mesh.part",
                json!({ "machine": machine.to_hex(), "offset": offset }),
            )
            .await
        {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => return Ok(None),
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let reply: MeshAuthorityPartReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        Ok(Some(MeshAuthorityPart {
            total: reply.total,
            part,
        }))
    }

    async fn reopen_after_failure(&mut self) -> Result<(), TransportError> {
        if !self.failed {
            return Ok(());
        }
        let budgets = residence_budgets(self.vault)?;
        let Some(rpc) = ResidenceRpc::connect(self.vault, self.config, budgets).await? else {
            return Err(TransportError::home_offline());
        };
        self.rpc = rpc;
        self.failed = false;
        Ok(())
    }
}

/// Imports one page through `import`: the rows it carries whole and, in
/// MACHINE order among them, each row it names by reference, read from
/// `parts` and imported alone before the next is read, so the page holds at
/// most one joined row (REVIEW-10560 P1). A row that does not join stays out
/// alone, logged, and the rest of the page lands (REVIEW-10560 P1): one past
/// the longest row this machine joins, one the home signed again or no
/// longer serves since the page named it, and one whose part read failed or
/// that this machine refuses (REVIEW-10560 round 2), which the next scan
/// reads again. After a failed read, `parts` opens again before the next
/// row's parts are read. Returns how many bindings `import` wrote.
///
/// # Errors
///
/// A source that does not open again after a failed part read; what
/// `import` returns. Rows imported before the error stay imported.
async fn import_page(
    rows: Vec<MeshAuthorityRow>,
    parted: Vec<MeshAuthorityRowRef>,
    parts: &mut impl MeshAuthorityPartSource,
    mut import: impl FnMut(Vec<MeshAuthorityRow>) -> Result<usize, TransportError>,
) -> Result<usize, TransportError> {
    let mut written = 0;
    let mut whole = rows.into_iter().peekable();
    for reference in parted {
        let before: Vec<MeshAuthorityRow> =
            std::iter::from_fn(|| whole.next_if(|row| row.machine < reference.machine)).collect();
        if !before.is_empty() {
            written += import(before)?;
        }
        let machine = reference.machine;
        let Some(join) = MeshAuthorityRowJoin::start(reference) else {
            tracing::warn!(
                machine = %machine.to_hex(),
                "the home named a mesh binding longer than this machine joins; it stays out"
            );
            continue;
        };
        parts.reopen_after_failure().await?;
        match joined_row(parts, join).await {
            Ok(Some(row)) => written += import(vec![row])?,
            Ok(None) => tracing::warn!(
                machine = %machine.to_hex(),
                "a mesh binding changed on the home while this machine read it; it stays out until the scan reads it again"
            ),
            Err(error) => tracing::warn!(
                machine = %machine.to_hex(),
                %error,
                "a part of a mesh binding was not read; it stays out until the scan reads it again"
            ),
        }
    }
    let rest: Vec<MeshAuthorityRow> = whole.collect();
    if !rest.is_empty() {
        written += import(rest)?;
    }
    Ok(written)
}

/// The row `join` names, read from `parts` a part at a time and checked
/// against the length and content hash its page named; `None` when it does
/// not join: no part where one should be, a part that does not continue it,
/// or a joined row the page did not name (the home signed it again, or no
/// longer serves it, since the page named it).
///
/// # Errors
///
/// A part read that failed or that this machine refuses.
async fn joined_row(
    parts: &mut impl MeshAuthorityPartSource,
    mut join: MeshAuthorityRowJoin,
) -> Result<Option<MeshAuthorityRow>, TransportError> {
    while !join.is_whole() {
        let Some(part) = parts.part(join.machine(), join.offset()).await? else {
            return Ok(None);
        };
        if !join.take(part) {
            return Ok(None);
        }
    }
    Ok(join.finish())
}

/// A page's rows, those it names by reference and where the next page
/// starts, checked: at most [`MESH_AUTHORITY_PAGE_MAX`] bindings, each list
/// in MACHINE order past `after`, no MACHINE in both, and a next page that
/// starts past them all, so no answer can turn the scan back.
fn decoded_page(
    reply: MeshAuthorityReply,
    after: Option<EntityId>,
) -> Result<
    (
        Vec<MeshAuthorityRow>,
        Vec<MeshAuthorityRowRef>,
        Option<EntityId>,
    ),
    TransportError,
> {
    if reply.rows.len() + reply.parted.len() > MESH_AUTHORITY_PAGE_MAX {
        return Err(refused());
    }
    let decode = |encoded: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| refused())
    };
    // Each MACHINE past `after` and the one before it in its list.
    let ordered = |floor: &mut Option<EntityId>, hex: &str| -> Result<EntityId, TransportError> {
        let machine = EntityId::from_hex(hex).map_err(|_| refused())?;
        if floor.is_some_and(|floor| machine <= floor) {
            return Err(refused());
        }
        *floor = Some(machine);
        Ok(machine)
    };
    let mut rows: Vec<MeshAuthorityRow> = Vec::with_capacity(reply.rows.len());
    let mut floor = after;
    for row in &reply.rows {
        rows.push(MeshAuthorityRow {
            machine: ordered(&mut floor, &row.machine)?,
            authority: decode(&row.authority)?,
            address: decode(&row.address)?,
            bare: row.bare,
        });
    }
    let mut parted: Vec<MeshAuthorityRowRef> = Vec::with_capacity(reply.parted.len());
    let mut floor = after;
    for reference in &reply.parted {
        let machine = ordered(&mut floor, &reference.machine)?;
        if rows.iter().any(|row| row.machine == machine) {
            return Err(refused());
        }
        parted.push(MeshAuthorityRowRef {
            machine,
            total: reference.total,
            digest: MeshAuthorityRowRef::digest_from_text(&reference.digest).ok_or_else(refused)?,
            address: decode(&reference.address)?,
            bare: reference.bare,
        });
    }
    let next = reply
        .next
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| refused())?;
    let last = rows
        .last()
        .map(|row| row.machine)
        .max(parted.last().map(|reference| reference.machine));
    if let Some(next) = next
        && (after.is_some_and(|after| next <= after) || last.is_some_and(|last| next < last))
    {
        return Err(refused());
    }
    Ok((rows, parted, next))
}

#[cfg(test)]
mod tests {
    //! MESH-AUTHORITY-ROW-PARTS: a page names its bindings whole and by
    //! reference, and the machine refuses one that names a MACHINE twice or
    //! turns its scan back. It imports each row it joins before it reads the
    //! next, and a row that does not join, or whose part read fails, holds
    //! back no other (REVIEW-10560 P1, round 2).

    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    use oneiron_contracts::fingerprint::ContentHash;

    use super::*;

    /// Three MACHINE ids, in order.
    fn machines() -> [EntityId; 3] {
        let mut machines = [EntityId::now(), EntityId::now(), EntityId::now()];
        machines.sort();
        machines
    }

    /// A page with `rows` carried whole, `parted` named by reference, and
    /// the next page after `next`.
    fn reply(rows: &[EntityId], parted: &[EntityId], next: Option<EntityId>) -> MeshAuthorityReply {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        serde_json::from_value(json!({
            "rows": rows
                .iter()
                .map(|machine| json!({
                    "machine": machine.to_hex(),
                    "authority": encode(b"row"),
                    "address": encode(b"address"),
                }))
                .collect::<Vec<_>>(),
            "parted": parted
                .iter()
                .map(|machine| json!({
                    "machine": machine.to_hex(),
                    "total": 3,
                    "digest": format!("blake3:{}", "01".repeat(32)),
                    "address": encode(b"address"),
                }))
                .collect::<Vec<_>>(),
            "next": next.as_ref().map(EntityId::to_hex),
        }))
        .unwrap()
    }

    #[test]
    fn a_page_names_its_bindings_whole_and_by_reference() {
        let [a, b, c] = machines();
        let (rows, parted, next) = decoded_page(reply(&[a, c], &[b], Some(c)), None).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.machine).collect::<Vec<_>>(),
            vec![a, c]
        );
        assert_eq!(
            parted,
            vec![MeshAuthorityRowRef {
                machine: b,
                total: 3,
                digest: [1; 32],
                address: b"address".to_vec(),
                bare: false,
            }]
        );
        assert_eq!(next, Some(c));

        let older: MeshAuthorityReply =
            serde_json::from_value(json!({ "rows": [], "next": null })).unwrap();
        let (rows, parted, next) = decoded_page(older, None).unwrap();
        assert!(
            rows.is_empty() && parted.is_empty() && next.is_none(),
            "a home older than MESH-AUTHORITY-ROW-PARTS names none by reference"
        );
    }

    #[test]
    fn a_page_that_names_a_machine_twice_or_turns_the_scan_back_is_refused() {
        let [a, b, c] = machines();
        assert!(
            decoded_page(reply(&[a, b], &[b], None), None).is_err(),
            "one MACHINE whole and by reference"
        );
        assert!(
            decoded_page(reply(&[a], &[c], Some(b)), None).is_err(),
            "a next page that starts before the last reference"
        );
        assert!(
            decoded_page(reply(&[], &[c, b], None), None).is_err(),
            "references out of order"
        );
        assert!(
            decoded_page(reply(&[], &[a], None), Some(a)).is_err(),
            "a reference at or before where the page starts"
        );
        let mut other_hash = reply(&[], &[a], None);
        other_hash.parted[0].digest = format!("sha256:{}", "01".repeat(32));
        assert!(
            decoded_page(other_hash, None).is_err(),
            "a content hash of another name"
        );
    }

    /// What a page import did, in order: one part read of a MACHINE's row
    /// from an offset, one opening of the home again, or one import of the
    /// MACHINEs it was given.
    #[derive(Debug, PartialEq, Eq)]
    enum Step {
        Part(EntityId, u64),
        Reopen,
        Import(Vec<EntityId>),
    }

    /// A home that serves each MACHINE's signed row in `signed` four bytes a
    /// part, fails each part read of a MACHINE in `failing`, and logs each
    /// read and each opening again in `steps`; when `reopen_fails`, it does
    /// not open again.
    struct Home<'a> {
        signed: BTreeMap<EntityId, Vec<u8>>,
        failing: BTreeSet<EntityId>,
        reopen_fails: bool,
        failed: bool,
        steps: &'a RefCell<Vec<Step>>,
    }

    impl MeshAuthorityPartSource for Home<'_> {
        async fn part(
            &mut self,
            machine: EntityId,
            offset: u64,
        ) -> Result<Option<MeshAuthorityPart>, TransportError> {
            assert!(
                !self.failed,
                "a part read on a socket that a failed read left unusable"
            );
            self.steps.borrow_mut().push(Step::Part(machine, offset));
            if self.failing.contains(&machine) {
                self.failed = true;
                return Err(TransportError::home_offline());
            }
            let Some(row) = self.signed.get(&machine) else {
                return Ok(None);
            };
            let rest = &row[usize::try_from(offset).unwrap().min(row.len())..];
            Ok((!rest.is_empty()).then(|| MeshAuthorityPart {
                total: row.len() as u64,
                part: rest[..rest.len().min(4)].to_vec(),
            }))
        }

        async fn reopen_after_failure(&mut self) -> Result<(), TransportError> {
            if !self.failed {
                return Ok(());
            }
            self.steps.borrow_mut().push(Step::Reopen);
            if self.reopen_fails {
                return Err(TransportError::home_offline());
            }
            self.failed = false;
            Ok(())
        }
    }

    /// A binding of `machine` a page carries whole.
    fn whole(machine: EntityId) -> MeshAuthorityRow {
        MeshAuthorityRow {
            machine,
            authority: b"row".to_vec(),
            address: b"address".to_vec(),
            bare: false,
        }
    }

    /// The reference a page names for `authority`, the signed row of
    /// `machine`.
    fn named(machine: EntityId, authority: &[u8]) -> MeshAuthorityRowRef {
        MeshAuthorityRowRef {
            machine,
            total: authority.len() as u64,
            digest: ContentHash::of(authority).into_bytes(),
            address: b"address".to_vec(),
            bare: false,
        }
    }

    /// [`import_page`] of `rows` and `parted`, read from a home that serves
    /// `signed`, each import writing every row it is given: what it returned
    /// and the steps it took.
    async fn imported_page(
        rows: Vec<MeshAuthorityRow>,
        parted: Vec<MeshAuthorityRowRef>,
        signed: BTreeMap<EntityId, Vec<u8>>,
    ) -> (Option<usize>, Vec<Step>) {
        imported_page_failing(rows, parted, signed, &[], false).await
    }

    /// [`imported_page`] from a home whose part reads of each MACHINE in
    /// `failing` fail, and which does not open again when `reopen_fails`.
    async fn imported_page_failing(
        rows: Vec<MeshAuthorityRow>,
        parted: Vec<MeshAuthorityRowRef>,
        signed: BTreeMap<EntityId, Vec<u8>>,
        failing: &[EntityId],
        reopen_fails: bool,
    ) -> (Option<usize>, Vec<Step>) {
        let steps = RefCell::new(Vec::new());
        let mut home = Home {
            signed,
            failing: failing.iter().copied().collect(),
            reopen_fails,
            failed: false,
            steps: &steps,
        };
        let written = import_page(rows, parted, &mut home, |rows| {
            steps
                .borrow_mut()
                .push(Step::Import(rows.iter().map(|row| row.machine).collect()));
            Ok(rows.len())
        })
        .await;
        (written.ok(), steps.into_inner())
    }

    /// A binding the home signs again, or no longer serves, while this
    /// machine reads it stays out alone: the page's other rows land and the
    /// round goes on, so a binding that keeps changing never holds back
    /// another (REVIEW-10560 P1).
    #[tokio::test]
    async fn a_binding_that_changes_while_it_is_read_stays_out_and_the_rest_of_the_page_lands() {
        let [a, b, _] = machines();
        let signed = b"the signed row the page named".to_vec();
        let reference = named(a, &signed);
        let mut longer = signed.clone();
        longer.push(0);
        let mut other_bytes = signed.clone();
        other_bytes[0] ^= 1;
        for (case, signed_again) in [
            ("signed again, longer", Some(longer)),
            ("signed again, other bytes of its length", Some(other_bytes)),
            ("no longer served", None),
        ] {
            let served = signed_again.into_iter().map(|row| (a, row)).collect();
            let (written, steps) =
                imported_page(vec![whole(b)], vec![reference.clone()], served).await;
            assert_eq!(written, Some(1), "{case}: the page goes on: {steps:?}");
            assert_eq!(
                steps
                    .iter()
                    .filter(|step| matches!(step, Step::Import(_)))
                    .collect::<Vec<_>>(),
                vec![&Step::Import(vec![b])],
                "{case}: only the binding carried whole lands"
            );
        }

        let (written, steps) = imported_page(
            vec![whole(b)],
            vec![reference],
            BTreeMap::from([(a, signed)]),
        )
        .await;
        assert_eq!(written, Some(2), "control: the row the page named joins");
        assert!(
            steps
                .iter()
                .any(|step| matches!(step, Step::Import(imported) if imported.contains(&a))),
            "control: {steps:?}"
        );
    }

    /// Each row a page names by reference is imported alone, in MACHINE
    /// order among the rows the page carries whole, before the next is read:
    /// a round holds at most one joined row, however many a page names
    /// (REVIEW-10560 P1).
    #[tokio::test]
    async fn each_row_named_by_reference_is_imported_before_the_next_is_read() {
        let [a, b, c] = machines();
        let row_a = b"the row of a".to_vec();
        let row_c = b"row c".to_vec();
        let (written, steps) = imported_page(
            vec![whole(b)],
            vec![named(a, &row_a), named(c, &row_c)],
            BTreeMap::from([(a, row_a), (c, row_c)]),
        )
        .await;
        assert_eq!(written, Some(3));
        assert_eq!(
            steps,
            vec![
                Step::Part(a, 0),
                Step::Part(a, 4),
                Step::Part(a, 8),
                Step::Import(vec![a]),
                Step::Import(vec![b]),
                Step::Part(c, 0),
                Step::Part(c, 4),
                Step::Import(vec![c]),
            ]
        );
    }

    /// A part read that fails, as when a long row cannot cross a slow link
    /// inside one call's deadline, keeps out only its own binding: the
    /// page's other rows land, the next row's parts read over a socket
    /// opened again, and a socket that does not open again ends the round
    /// with the rows before it in (REVIEW-10560 round 2).
    #[tokio::test]
    async fn a_failed_part_read_keeps_out_only_its_binding_and_the_page_goes_on() {
        let [a, b, c] = machines();
        let row_a = b"a row too long for the link".to_vec();
        let row_c = b"row c".to_vec();
        let signed = BTreeMap::from([(a, row_a.clone()), (c, row_c.clone())]);
        let parted = || vec![named(a, &row_a), named(c, &row_c)];

        let (written, steps) =
            imported_page_failing(vec![whole(b)], parted(), signed.clone(), &[a], false).await;
        assert_eq!(written, Some(2), "{steps:?}");
        assert_eq!(
            steps,
            vec![
                Step::Part(a, 0),
                Step::Import(vec![b]),
                Step::Reopen,
                Step::Part(c, 0),
                Step::Part(c, 4),
                Step::Import(vec![c]),
            ]
        );

        // The review's page: the row whose part does not arrive, then a small
        // binding carried whole.
        let (written, steps) = imported_page_failing(
            vec![whole(b)],
            vec![named(a, &row_a)],
            signed.clone(),
            &[a],
            false,
        )
        .await;
        assert_eq!(written, Some(1), "{steps:?}");
        assert_eq!(steps, vec![Step::Part(a, 0), Step::Import(vec![b])]);

        let (written, steps) =
            imported_page_failing(vec![whole(b)], parted(), signed, &[a], true).await;
        assert_eq!(
            written, None,
            "a socket that does not open again ends the round"
        );
        assert_eq!(
            steps,
            vec![Step::Part(a, 0), Step::Import(vec![b]), Step::Reopen]
        );
    }
}
