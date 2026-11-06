//! A reviewed proposal whose file carries lifted secret handles lands as
//! a NEW resolved proposal (FIX 2938, Engine ruling 10-20): the handles
//! are detected in the reviewed bytes, resolved through custody under the
//! repo-landing binding, and a successor carrying the resolved bytes —
//! its own id, snapshot and operation hash, linked back by `resolves` —
//! is what lands, while the original goes terminal `Superseded` and never
//! lands at all. Resolving in place at land time would change every
//! byte-derived binding the review made.

use super::*;
use crate::codebase::entity_id_from_hash_material;

mod rereview;

/// The effector a landing reads secret values under: the owner binds a
/// record's `read` scope to it at the bind door, and an unbound record
/// refuses the landing with its typed binding error.
pub(crate) const REPO_LANDING_EFFECTOR: &str = "repo:landing";

/// The domain of a resolved successor's derived id: one original has at
/// most one successor, found again by deriving it.
const RESOLVED_SUCCESSOR_DOMAIN: &[u8] = b"oneiron:repo-proposal-resolved-successor:v1";

/// The mask's text form of a handle, as it stands in reviewed content.
const HANDLE_OPEN: &[u8] = b"[secret ";

/// The detector kind a resolved successor's mask facts carry (L04 11:52):
/// custody-bound substitution, never a scan-pattern hit.
const RESOLVED_HANDLE_DETECTOR: &str = "gate.secret_scan.resolved_handle";

/// The successor minted for `original`, if one stands: its derived id's
/// row, verified to resolve this original.
pub(super) fn successor_of(vault: &Vault, original: EntityId) -> Result<Option<EntityId>> {
    let id = successor_id(original)?;
    Ok(vault
        .repo_proposal(id)?
        .filter(|row| row.resolves == Some(original))
        .map(|_| id))
}

fn successor_id(original: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(RESOLVED_SUCCESSOR_DOMAIN, &[original.as_bytes()])
}

/// The `[secret scN]` spans `content` carries: each span's byte range and
/// its text, validated as a handle. A bracketed span that names no handle
/// is the file's own prose and carries nothing.
fn handle_spans(content: &[u8]) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(open) = find(&content[at..], HANDLE_OPEN) {
        let start = at + open;
        let Some(close) = find(&content[start..], b"]") else {
            break;
        };
        let end = start + close + 1;
        if let Ok(text) = std::str::from_utf8(&content[start..end])
            && crate::secret_custody::parse_secret_handle(text).is_ok()
        {
            spans.push((start, end, text.to_owned()));
            at = end;
        } else {
            // An invalid span may wrap a valid one (`[secret note [secret sc1]`);
            // step past only the opener so nested spans are still detected.
            at = start + HANDLE_OPEN.len();
        }
    }
    spans
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Whether any file the row carries holds a handle span: what a merge
/// stack refuses outright, as its tested tree already binds the reviewed
/// bytes and no successor can join it after the fact.
pub(crate) fn refuse_handle_bearing_row(row: &RepoProposal) -> Result<()> {
    if row
        .files
        .iter()
        .filter_map(|file| file.content.as_deref())
        .any(|content| !handle_spans(content).is_empty())
    {
        return Err(invalid(
            "a handle-bearing proposal resolves and lands alone, never in its merge stack",
        ));
    }
    Ok(())
}

/// The successor an Approved standalone `row` lands as, when its file
/// carries handles: resolved through custody, custody-admitted like any
/// write, minted Approved with the original's critiques exactly when it
/// is the original with each handle replaced by its bound value, and the
/// original superseded in the same writer. `None` when the file carries
/// no handle and the row lands as itself.
///
/// # Errors
///
/// The typed custody refusal of an unbound, unknown or revoked handle, a
/// snapshot withhold on the resolved bytes, or storage errors: the
/// original stays Approved and unconsumed on every one.
pub(super) fn resolved_successor(
    vault: &Vault,
    row: &RepoProposal,
) -> Result<Option<RepoProposal>> {
    // Already resolved (FIX 2938 retry/idempotence): a successor's values land as
    // bytes, even when a value carries handle syntax.
    if row.resolves.is_some() {
        return Ok(None);
    }
    let (path, content) = row.ordinary_file()?;
    let spans = handle_spans(content);
    if spans.is_empty() {
        return Ok(None);
    }
    let path = path.to_owned();
    let values = spans_values(vault, &spans)?;
    // The ordinary proposal bound (submit.rs): substitution must not mint an
    // over-limit successor. Checked arithmetic over ascending non-overlapping spans.
    let mut resolved_len = content.len();
    for (start, end, text) in &spans {
        let value_len = values
            .iter()
            .find(|known| &known.0 == text)
            .expect("every span resolved above")
            .1
            .len();
        resolved_len = resolved_len
            .checked_sub(end - start)
            .and_then(|len| len.checked_add(value_len))
            .ok_or(invalid(
                "proposal requires bounded content and review lenses",
            ))?;
    }
    // FIX 12563: the cap binds the final resolved length, not each prefix of it:
    // an at-limit file whose first replacement grows and whose later replacement
    // shrinks more still fits, and the checked arithmetic above already holds.
    if resolved_len > 32 * 1024 * 1024 {
        return Err(invalid(
            "proposal requires bounded content and review lenses",
        ));
    }
    let resolved = substitute(content, &spans, &values);
    // Round-4 P1: the resolved bytes are new content under a new hash, so
    // the successor's mask facts name them here, before the bytes move.
    let raw_blake3 = *blake3::hash(&resolved).as_bytes();
    let blob_oid = git_blob_oid(&resolved)?;
    let resolved_ranges = resolved_span_ranges(&spans, &values)?;
    // The original's review carries only onto the proposal it actually
    // judged: the successor must re-redact to the original byte for byte
    // (Engine ruling on FIX 2938 F4).
    if reredact(&resolved, &values)? != content {
        return Err(invalid(
            "the resolved bytes are not the reviewed operation with its handles replaced",
        ));
    }
    // Round-6 (review P1 kimi:168): the landing document is text: a
    // non-UTF-8 resolution can never complete its landing, so refuse with
    // the document door's own typed refusal before the mint writer opens,
    // with the original still Approved and no successor minted.
    std::str::from_utf8(&resolved)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    let repo = RepoRef::parse(&row.repo)?;
    let repo_root = resolve_mutable_repo_root(&repo)?;
    let snapshot = stored_snapshot(vault, row.pre_action_fork_hash)?;
    admit_custody(
        &SnapshotCustody::of(vault, &repo_root)?,
        &snapshot,
        &path,
        &resolved,
        &row.message,
    )?;
    let mut successor = row.clone();
    successor.id = successor_id(row.id)?;
    successor.files = vec![RepoProposedFile::ordinary(path.clone(), resolved)];
    successor.status = RepoProposalStatus::Approved;
    successor.resolves = Some(row.id);
    successor.settlement = None;
    successor.queue_review = None;
    successor.operation_seq = None;
    successor.created_at = now_millis() / 1000;
    validate_conflict(vault, &successor, &repo_root)?;
    let encoded = SNAPSHOT.encode_value(&snapshot)?;
    let mut txn = vault.store.env.write_txn()?;
    let mut original = PROPOSAL
        .get(&vault.store, &txn, &row.id)?
        .ok_or(Error::EntityNotFound)?;
    if original.status != RepoProposalStatus::Approved || original.operation_seq.is_some() {
        return Err(invalid("proposal already consumed"));
    }
    // A critic erasure committing between the first read and this writer must not
    // ride into the successor as erased refs again: the successor clones both
    // critique collections, so refuse when either changed.
    if original.critiques != row.critiques || original.policy_critiques != row.policy_critiques {
        return Err(invalid(
            "proposal critiques changed while resolving handles; submit a fresh proposal",
        ));
    }
    // Round-7 (review P1 sol-1): `spans_values` read under a read txn that
    // is gone by now, so an owner revoke or repo:landing unbind committing
    // in between would mint the cached plaintext and Supersede the
    // original. Re-read every handle's live grant and unchanged value and
    // custody in this mint writer before persisting: the original stays
    // Approved on every refusal.
    {
        let mut seen: Vec<&str> = Vec::new();
        for (_, _, text) in spans.iter() {
            if seen.iter().any(|held| *held == text.as_str()) {
                continue;
            }
            seen.push(text.as_str());
            let (_, id) = crate::secret_custody::handle_record_in_txn(&vault.store, &txn, text)?;
            let live = vault
                .get_secret_value_in_txn(&txn, &id, REPO_LANDING_EFFECTOR)?
                .ok_or(Error::EntityNotFound)?;
            let known = values
                .iter()
                .find(|known| &known.0 == text)
                .expect("every span resolved above");
            if id != known.2 || live != known.1 {
                return Err(invalid(
                    "a handle's binding changed while resolving handles; submit a fresh proposal",
                ));
            }
        }
    }
    if PROPOSAL.get(&vault.store, &txn, &successor.id)?.is_none() {
        super::persist::PreparedRepoProposal::new(successor.clone(), encoded)?
            .persist_in_txn(vault, &mut txn)?;
        // Round-4 P1 (L04 11:52): one secret-mark fact per substituted span,
        // same writer txn, naming the resolved coords under the new hash —
        // masked reads already join by hash and need no change.
        let marked_at = crate::ports::recorded_at_in_txn(&vault.store, &mut txn)?;
        let store_identity = landing_store_identity(&repo);
        let store_id = crate::origin::lfs::lfs_repo_id(&store_identity)?;
        for ((_, _, text), (start, end)) in spans.iter().zip(resolved_ranges.iter()) {
            let (_, _, custody, handle) = values
                .iter()
                .find(|known| &known.0 == text)
                .expect("every span resolved above");
            let mark = crate::origin::secret_marks::RepoSecretMark {
                schema_version: crate::origin::secret_marks::RepoSecretMark::SCHEMA,
                operation_id: successor.id,
                store_id,
                store_identity: store_identity.clone(),
                source: crate::origin::secret_marks::RepoSecretSource::Quarantine,
                blob_oid: blob_oid.clone(),
                raw_blake3,
                path: Some(path.clone()),
                detector_kind: RESOLVED_HANDLE_DETECTOR.to_owned(),
                content_kind: crate::receive_scan::ReceiveBlobKind::Text,
                placement: crate::origin::secret_marks::RepoSecretPlacement::Span {
                    member: Vec::new(),
                    start: *start,
                    end: *end,
                    custody: *custody,
                    handle: handle.clone(),
                },
                marked_at,
            };
            crate::origin::secret_marks::put_repo_secret_mark_in_txn(vault, &mut txn, &mark)?;
        }
        // Round-5 (review P1 sol-1): document views (blame/diff) mask lifted
        // keys only through the content-hash mask row, which never reads
        // repo.secret_mark: project the same resolved spans there, so a
        // non-owner never reads the substituted values in clear.
        let mut masked =
            crate::secret_custody::masked_file_in_txn(&vault.store, &txn, &raw_blake3)?.unwrap_or(
                crate::secret_custody::MaskedFile {
                    band: crate::secret_custody::MASKED_FILE_BAND,
                    keys: Vec::new(),
                    masked_at: marked_at,
                    members: Vec::new(),
                },
            );
        for ((_, _, text), (start, end)) in spans.iter().zip(resolved_ranges.iter()) {
            let (_, _, custody, _) = values
                .iter()
                .find(|known| &known.0 == text)
                .expect("every span resolved above");
            // Round-7 (review P1 sol-2): `unite` keeps the marks already
            // held and drops a new span on any overlap (FIX 2781), so a
            // pre-existing mark covering only an interior part of a
            // substituted value would silently drop the whole span and
            // blame/diff reads would expose the outer bytes. Project only
            // the fragments outside held spans; each carries this
            // substitution's custody while held spans stay as they are.
            let held: Vec<(u64, u64)> =
                masked.keys.iter().map(|key| (key.start, key.end)).collect();
            let mut fragments: Vec<(u64, u64)> = vec![(*start, *end)];
            for span in &held {
                let mut kept = Vec::new();
                for (from, to) in fragments {
                    if to <= span.0 || span.1 <= from {
                        kept.push((from, to));
                    } else {
                        if from < span.0 {
                            kept.push((from, span.0));
                        }
                        if span.1 < to {
                            kept.push((span.1, to));
                        }
                    }
                }
                fragments = kept;
            }
            for (from, to) in fragments {
                masked.unite(
                    &[],
                    crate::file_secret_marks::KeySpan {
                        start: from,
                        end: to,
                        custody: *custody,
                        reason: RESOLVED_HANDLE_DETECTOR.to_owned(),
                    },
                );
            }
        }
        crate::secret_custody::put_masked_file_in_txn(
            &vault.store,
            &mut txn,
            &raw_blake3,
            &masked,
        )?;
        // Round-5 (review P1 sol-2): index copies already derived from these
        // bytes refresh under the new marks here, as the receive path does;
        // new bytes have no copies and the call no-ops.
        crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
            vault,
            &mut txn,
            &[raw_blake3],
        )?;
    }
    original.status = RepoProposalStatus::Superseded;
    store(vault, &mut txn, &original)?;
    txn.commit()?;
    Ok(Some(successor))
}

/// Each distinct span's bound value, read once per handle, with its
/// custody record and canonical handle: the successor's mask facts name
/// the resolved spans (round-4 P1).
fn spans_values(
    vault: &Vault,
    spans: &[(usize, usize, String)],
) -> Result<Vec<(String, Vec<u8>, EntityId, String)>> {
    let mut values: Vec<(String, Vec<u8>, EntityId, String)> = Vec::new();
    let txn = vault.store.env.read_txn()?;
    for (_, _, text) in spans {
        if values.iter().any(|(known, _, _, _)| known == text) {
            continue;
        }
        let (handle, id) = crate::secret_custody::handle_record_in_txn(&vault.store, &txn, text)?;
        let value = vault
            .get_secret_value_in_txn(&txn, &id, REPO_LANDING_EFFECTOR)?
            .ok_or(Error::EntityNotFound)?;
        values.push((text.clone(), value, id, handle));
    }
    Ok(values)
}

/// Round-6 (review P1 sol:110): replay the mint-time custody admission for
/// an unconsumed resolved successor on the retry path, on the caller's open
/// transaction: every recorded handle is read again through custody under
/// the repo:landing binding, so a secret or binding withdrawn after the
/// mint refuses typed instead of landing the successor's cached plaintext.
/// A consumed successor (its operation already applied) needs no replay.
pub(crate) fn revalidate_resolved_successor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    successor: &RepoProposal,
) -> Result<()> {
    if successor.operation_seq.is_some() {
        return Ok(());
    }
    let Some(original_id) = successor.resolves else {
        return Ok(());
    };
    let original = vault
        .repo_proposal(original_id)?
        .ok_or(Error::EntityNotFound)?;
    let (_, content) = original.ordinary_file()?;
    let mut seen: Vec<String> = Vec::new();
    for (_, _, text) in handle_spans(content) {
        if seen.iter().any(|held| held == &text) {
            continue;
        }
        let (_, id) = crate::secret_custody::handle_record_in_txn(&vault.store, txn, &text)?;
        vault
            .get_secret_value_in_txn(txn, &id, REPO_LANDING_EFFECTOR)?
            .ok_or(Error::EntityNotFound)?;
        seen.push(text);
    }
    Ok(())
}

/// `content` with each span replaced by its handle's bound value.
fn substitute(
    content: &[u8],
    spans: &[(usize, usize, String)],
    values: &[(String, Vec<u8>, EntityId, String)],
) -> Vec<u8> {
    let mut resolved = Vec::with_capacity(content.len());
    let mut at = 0;
    for (start, end, text) in spans {
        resolved.extend_from_slice(&content[at..*start]);
        let value = &values
            .iter()
            .find(|known| &known.0 == text)
            .expect("every span resolved above")
            .1;
        resolved.extend_from_slice(value);
        at = *end;
    }
    resolved.extend_from_slice(&content[at..]);
    resolved
}

/// Each substituted span's byte range in the resolved bytes (round-4 P1):
/// the mask facts name resolved coords, so masked reads join the
/// successor's new hash. Mirrors `substitute`'s walk.
fn resolved_span_ranges(
    spans: &[(usize, usize, String)],
    values: &[(String, Vec<u8>, EntityId, String)],
) -> Result<Vec<(u64, u64)>> {
    let mut ranges = Vec::with_capacity(spans.len());
    let mut at = 0usize;
    let mut resolved = 0u64;
    for (start, end, text) in spans {
        let value_len = values
            .iter()
            .find(|known| &known.0 == text)
            .expect("every span resolved above")
            .1
            .len();
        resolved = resolved
            .checked_add((start - at) as u64)
            .and_then(|pos| pos.checked_add(value_len as u64))
            .ok_or(Error::ArithmeticOverflow(
                "a resolved successor's mask spans",
            ))?;
        ranges.push((resolved - value_len as u64, resolved));
        at = *end;
    }
    Ok(ranges)
}

/// The git blob OID `bytes` hash to (L04 11:52): sha1 over the blob header
/// plus the bytes, computed and never written — deterministic, so it
/// matches the object if the bytes later land in git.
fn git_blob_oid(bytes: &[u8]) -> Result<crate::git_wire::GitOid> {
    let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    let oid = hasher
        .try_finalize()
        .map_err(|_| Error::CorruptedIndex("resolved bytes blob hash"))?;
    Ok(crate::git_wire::GitOid::parse_hex(oid.to_string())?)
}

/// The store a landing belongs to (L04 11:52): the landing RepoRef with its
/// commit pin stripped — no canonical object-store identity exists at
/// landing, and never the full RepoRef (it changes every push).
fn landing_store_identity(repo: &RepoRef) -> String {
    match repo {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { owner, repo, .. } => format!("github:{owner}/{repo}"),
    }
}

/// Pushes `chunk` unless the re-redaction already exceeds the ordinary proposal
/// bound: handles inserted by earlier passes must not compound without a bound
/// (a few dozen distinct handle spellings with short bound values would otherwise
/// grow each pass over the preceding handles). Overflow refuses the review carry.
fn push_bounded(out: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let end = out
        .len()
        .checked_add(chunk.len())
        .filter(|len| *len <= 32 * 1024 * 1024);
    match end {
        Some(_) => {
            out.extend_from_slice(chunk);
            Ok(())
        }
        None => Err(invalid(
            "the resolved bytes are not the reviewed operation with its handles replaced",
        )),
    }
}

/// The inverse substitution, for the review-carry proof: each bound value
/// back to its span. An empty value proves nothing and is left, which the
/// caller's byte equality then refuses.
fn reredact(resolved: &[u8], values: &[(String, Vec<u8>, EntityId, String)]) -> Result<Vec<u8>> {
    let mut out = resolved.to_vec();
    for (text, value, _, _) in values {
        if value.is_empty() {
            continue;
        }
        let mut replaced = Vec::with_capacity(out.len());
        let mut at = 0;
        while let Some(hit) = find(&out[at..], value) {
            push_bounded(&mut replaced, &out[at..at + hit])?;
            push_bounded(&mut replaced, text.as_bytes())?;
            at += hit + value.len();
        }
        push_bounded(&mut replaced, &out[at..])?;
        out = replaced;
    }
    Ok(out)
}

/// The stored pre-action snapshot `fork` names, its hash proven.
fn stored_snapshot(vault: &Vault, fork: RepoForkHash) -> Result<StoredRepoSnapshot> {
    let txn = vault.store.env.read_txn()?;
    let snapshot = SNAPSHOT
        .get(&vault.store, &txn, &repo_mutation_snapshot_key(fork))?
        .ok_or(Error::EntityNotFound)?;
    if *blake3::hash(&SNAPSHOT.encode_value(&snapshot)?).as_bytes() != fork {
        return Err(Error::CorruptedIndex("reviewed fork hash mismatch"));
    }
    Ok(snapshot)
}
