//! Export and import commands for a stopped vault.
//! Keeps archive streaming and batch consent in their existing order.
//! Vault access, file creation, and common output stay in the parent.

use super::{
    ExportArgs, ImportCommand, Path, Read, Seek, Serialize, emit, imports, io, local_owner,
    note_imports, open_stopped_vault, open_vault, resolve_serve_config, write_new_file,
};

#[derive(Serialize)]
struct Exported<'a> {
    file: &'a Path,
    format: String,
    bytes: u64,
}

pub fn export(args: ExportArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/core/facade/vault.export")?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    // The owner's own `vault.export`, so its verb hooks run around it
    // (ARCH-0080 §3). The export's own owner check comes first, so a hook
    // never fires on an export it refuses.
    let memory = vault.memory(owner, oneiron::edge::EdgeActorClass::Human);
    memory
        .admit_export(None)
        .map_err(|error| anyhow::anyhow!("export failed: {error}"))?;
    let secrets_recipient = args
        .secrets_recipient
        .as_deref()
        .map(|id| {
            oneiron::EntityId::from_hex(id)
                .map_err(|error| anyhow::anyhow!("--secrets-recipient {id}: {error}"))
        })
        .transpose()?;
    let options = oneiron::memory::ExportOptions {
        format: Some(args.format),
        include_secrets: Some(args.include_secrets),
        delivery: None,
        secrets_recipient,
    };
    // The archive is written to a file as it is built (FIX 2766), never held
    // whole: to `--out`, or to a spool under the vault's own staging
    // directory that is then copied to stdout. The verb hooks see the
    // export's receipt, not its bytes.
    let run = |file: &mut std::fs::File| {
        oneiron::task_verb::verb_hook_boundary::typed_row(
            &memory,
            "vault.export",
            options.clone(),
            |input| memory.export_to(&input, &mut *file),
        )
    };
    let Some(out) = args.out else {
        let mut spool = vault
            .archive_spool_file()
            .map_err(|error| anyhow::anyhow!("export failed: {error}"))?;
        run(&mut spool).map_err(|error| anyhow::anyhow!("export failed: {error}"))?;
        spool.seek(io::SeekFrom::Start(0))?;
        io::copy(&mut spool, &mut io::stdout().lock())?;
        return Ok(());
    };
    let mut exported = None;
    write_new_file(&out, |file| {
        let receipt =
            run(file).map_err(|error| io::Error::other(format!("export failed: {error}")))?;
        file.sync_all()?;
        exported = Some(receipt);
        Ok(())
    })?;
    let exported = exported.ok_or_else(|| anyhow::anyhow!("export failed: no receipt"))?;
    emit(&Exported {
        file: &out,
        format: exported.format,
        bytes: exported.bytes,
    })
}

/// A batch file: imported claims, or the notes `import notes` wrote.
enum Batch {
    Claims(imports::ImportBatch),
    Notes(note_imports::NoteBatch),
}

fn read_batch(source: &str) -> anyhow::Result<Batch> {
    let raw = if source == "-" {
        let mut raw = String::new();
        io::stdin().read_to_string(&mut raw)?;
        raw
    } else {
        std::fs::read_to_string(source)
            .map_err(|error| anyhow::anyhow!("read batch {source}: {error}"))?
    };
    // A saved `import preview` output works as is: take its `batch`. A notes
    // batch holds a folder's text, so it is moved, never copied.
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    drop(raw);
    let batch = if value.get("batch").is_some() {
        value["batch"].take()
    } else {
        value
    };
    let read = if batch.get("notes").is_some() {
        serde_json::from_value(batch).map(Batch::Notes)
    } else {
        serde_json::from_value(batch).map(Batch::Claims)
    };
    read.map_err(|error| anyhow::anyhow!("batch JSON: {error}"))
}

#[derive(Serialize)]
struct ImportedArchive {
    inserted_entities: usize,
    unchanged_entities: usize,
    omitted_entities: usize,
    archived_receipt_sources: usize,
    imported_results: usize,
    withheld_results: usize,
    restored_secrets: usize,
    unchanged_secrets: usize,
    /// Secrets the archive carried that a revoke here ended: not restored.
    skipped_revoked_secrets: usize,
    /// Archived `regenerates` links whose restored MESSAGE pair does not
    /// prove what the stream proved: left out, not restored.
    skipped_unproven_regenerates_edges: usize,
    /// Secrets the archive carried as handles only: re-enter each one.
    missing_secrets: Vec<String>,
    /// Secrets the archive could not carry even as a handle, by id: each
    /// comes as its export secret supplement (FIX 12066).
    owed_secrets: Vec<String>,
    embedding_setup: ImportedEmbeddingSetup,
}

/// What the archive's embedding setup did (OF-370): descriptors only, so a
/// stopped vault's media vectors wait for `serve` or the host's own backfill.
#[derive(Serialize)]
struct ImportedEmbeddingSetup {
    /// [`EMBEDDING_SETUP_IMPORTED`] when the archive carried any setup.
    status: Option<&'static str>,
    declared_spaces: Vec<String>,
    unchanged_spaces: Vec<String>,
    /// Spaces this vault declares otherwise under the same id; its own stay.
    conflicted_spaces: Vec<String>,
    bound_slots: Vec<oneiron::embed::InputKind>,
    unchanged_slots: Vec<oneiron::embed::InputKind>,
    /// Slots this vault binds otherwise, or cannot bind as the archive did;
    /// its own stay.
    conflicted_slots: Vec<oneiron::embed::InputKind>,
    /// Setup the export withheld as credential-shaped: spaces by count.
    withheld_spaces: u64,
    withheld_slots: Vec<oneiron::embed::InputKind>,
}

/// The archive import's embedding setup status: the setup came in, its
/// vectors did not.
const EMBEDDING_SETUP_IMPORTED: &str = "setup imported; vectors pending recompute";

/// Re-imports a whole-vault archive through the vault's import doors.
fn import_archive(args: crate::cli::ImportArchiveArgs) -> anyhow::Result<()> {
    // The archive is read member by member from its file (FIX 2766), never
    // whole.
    let file = std::fs::File::open(&args.path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", args.path.display()))?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(&config, "stop `serve` to import an archive")?;
    let receipt = vault
        .import_whole_vault_archive_from(io::BufReader::new(file))
        .map_err(|error| anyhow::anyhow!("archive import failed: {error}"))?;
    let setup = receipt.embedding_setup;
    let status = setup
        .vectors_pending_recompute()
        .then_some(EMBEDDING_SETUP_IMPORTED);
    emit(&ImportedArchive {
        inserted_entities: receipt.inserted_entities,
        unchanged_entities: receipt.unchanged_entities,
        omitted_entities: receipt.omitted_entities,
        archived_receipt_sources: receipt.archived_receipt_sources,
        imported_results: receipt.imported_results,
        withheld_results: receipt.withheld_results,
        restored_secrets: receipt.restored_secrets,
        unchanged_secrets: receipt.unchanged_secrets,
        skipped_revoked_secrets: receipt.skipped_revoked_secrets,
        skipped_unproven_regenerates_edges: receipt.skipped_unproven_regenerates_edges,
        missing_secrets: receipt
            .missing_secrets
            .into_iter()
            .map(|secret| secret.name)
            .collect(),
        owed_secrets: receipt
            .owed_secrets
            .iter()
            .map(|secret| secret.to_hex())
            .collect(),
        embedding_setup: ImportedEmbeddingSetup {
            status,
            declared_spaces: setup.declared_spaces,
            unchanged_spaces: setup.unchanged_spaces,
            conflicted_spaces: setup.conflicted_spaces,
            bound_slots: setup.bound_slots,
            unchanged_slots: setup.unchanged_slots,
            conflicted_slots: setup.conflicted_slots,
            withheld_spaces: setup.withheld.spaces,
            withheld_slots: setup.withheld.slots,
        },
    })
}

pub fn import(command: ImportCommand) -> anyhow::Result<()> {
    use oneiron::ingest::history::HistorySource;
    // A batch decision: preview, or approve / decline with the digest.
    let (batch, digest, serve) = match command {
        ImportCommand::Chatgpt(args) => {
            return super::history_import::import_history(HistorySource::Chatgpt, *args);
        }
        ImportCommand::Claude(args) => {
            return super::history_import::import_history(HistorySource::Claude, *args);
        }
        ImportCommand::ClaudeCode(args) => {
            return super::history_import::import_history(HistorySource::ClaudeCode, *args);
        }
        ImportCommand::Codex(args) => {
            return super::history_import::import_history(HistorySource::Codex, *args);
        }
        ImportCommand::HookTranscript(args) => {
            return super::history_import::import_history(HistorySource::HookTranscript, *args);
        }
        ImportCommand::Notes(args) => return super::history_import::notes::import_notes(*args),
        ImportCommand::Archive(args) => return import_archive(*args),
        ImportCommand::Folder(command) => {
            return super::history_import::notes::folder::import_folder(command);
        }
        ImportCommand::Preview(args) => (args.batch, None, args.serve),
        ImportCommand::Approve(args) => (args.batch, Some((true, args.digest)), args.serve),
        ImportCommand::Decline(args) => (args.batch, Some((false, args.digest)), args.serve),
    };
    let config = resolve_serve_config(&serve)?;
    let vault = open_vault(&config, "POST /v1/owner/imports/<preview|approve|decline>")?;
    let owner = local_owner(&vault)?;
    match (read_batch(&batch)?, digest) {
        (Batch::Claims(batch), None) => emit(&imports::preview(&vault, &owner, batch)?),
        (Batch::Claims(batch), Some((true, digest))) => {
            emit(&imports::approve(&vault, &owner, &batch, &digest)?)
        }
        (Batch::Claims(batch), Some((false, digest))) => {
            emit(&imports::decline(&vault, &owner, &batch, &digest)?)
        }
        (Batch::Notes(batch), None) => emit(&note_imports::preview(&vault, &owner, batch)?),
        (Batch::Notes(batch), Some((true, digest))) => {
            emit(&note_imports::approve(&vault, &owner, batch, &digest)?)
        }
        (Batch::Notes(batch), Some((false, digest))) => {
            emit(&note_imports::decline(&vault, &owner, batch, &digest)?)
        }
    }
}
