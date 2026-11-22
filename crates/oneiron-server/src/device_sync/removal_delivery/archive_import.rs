//! Writing delivered removal archives beside the credential file and taking
//! them into the vault, kept ones again at each start.
use super::*;

/// Writes `delivery` of the session answer `answer` under `archives` as
/// `<receipt>.<version>.json`, once it checks: this person's, under a
/// well-formed receipt id, its archive the bytes the digest says, decoded
/// into a spool file of `vault`'s own as it is checked. The file is the
/// copy's JSON as the answer carries it, copied from the answer's file
/// whole before it takes its name, and only its owner may read it; one
/// already written stays as it is. Answers the file's path and the copy.
pub(super) fn store(
    vault: &oneiron::Vault,
    archives: &Path,
    person: oneiron::EntityId,
    answer: &mut std::fs::File,
    delivery: Delivery,
) -> anyhow::Result<(PathBuf, RemovalExportFile)> {
    let copy = &delivery.copy;
    anyhow::ensure!(
        oneiron::EntityId::from_hex(&copy.member).is_ok_and(|member| member == person),
        "a removal archive for another person"
    );
    let receipt = oneiron::EntityId::from_hex(&copy.receipt_id)?;
    let (archive, digest) =
        copy_json::decode_archive(answer, delivery.archive, vault.archive_spool_file()?)?;
    anyhow::ensure!(
        digest == copy.export.digest,
        "a removal archive whose bytes are not its digest's"
    );
    std::fs::create_dir_all(archives)?;
    owner_only(archives, 0o700)?;
    let path = archives.join(format!("{}.{}.json", receipt.to_hex(), delivery.version));
    if !path.exists() {
        let part = path.with_extension("json.part");
        {
            let mut file = std::fs::File::create(&part)?;
            owner_only(&part, 0o600)?;
            copy_json::copy_span(answer, delivery.json, &mut file)?;
            file.sync_all()?;
        }
        std::fs::rename(&part, &path)?;
    }
    Ok((path, RemovalExportFile::received(delivery.copy, archive)))
}

/// Takes `copy`, the archive written at `path` beside the credential for
/// `person`, into `vault` (FIX 11197), and logs what came of it by its
/// receipt; its caller holds the import's admission (FIX 11796). One that
/// does not import stays on disk as written, and the next start tries it
/// again. Once its import has committed, by this call or an earlier one, its
/// file goes ([`remove_imported`]).
pub(super) fn import(
    vault: &oneiron::Vault,
    person: oneiron::EntityId,
    copy: &mut RemovalExportFile,
    path: &Path,
) {
    match vault.import_removal_archive(person, copy) {
        Ok(Some(records)) => tracing::info!(
            receipt = %copy.receipt_id(),
            version = copy.delivered_at(),
            records,
            "removal archive imported"
        ),
        Ok(None) => tracing::debug!(
            receipt = %copy.receipt_id(),
            version = copy.delivered_at(),
            "removal archive imported before"
        ),
        Err(error) => {
            tracing::warn!(
                receipt = %copy.receipt_id(),
                version = copy.delivered_at(),
                %error,
                "removal archive kept on disk, not imported"
            );
            return;
        }
    }
    remove_imported(path, copy.receipt_id(), copy.delivered_at());
}

/// Takes into `vault` each archive kept under `archives` that it has not
/// taken in yet: one an earlier import refused or never reached. Each is
/// logged as [`import`] logs it; a sweep that cannot run is logged once and
/// leaves every file as it is. Each import holds an admission `admit`
/// grants; one skipped while frozen stays for the sweep after the thaw.
pub(super) async fn import_kept(
    vault: &Arc<oneiron::Vault>,
    admit: &HousekeepingAdmission,
    credential_file: &Path,
    archives: &Path,
) {
    let (vault, admit) = (Arc::clone(vault), Arc::clone(admit));
    let (credential_file, archives) = (credential_file.to_owned(), archives.to_owned());
    let swept = tokio::task::spawn_blocking(move || {
        import_dir(&vault, &admit, &credential_file, &archives)
    })
    .await;
    match swept {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            error = %format!("{error:#}"),
            "kept removal archives not imported"
        ),
        Err(error) => tracing::warn!(%error, "kept removal archive import task"),
    }
}
