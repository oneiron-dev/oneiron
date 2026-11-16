//! `oneiron import slack <zip | folder> --members <map.json>`: a Slack
//! workspace export, imported into a stopped vault (ARCH-0027
//! #import-audience; the owner's IMPORT-IDENTITY and IMPORT-PUBLIC rulings
//! of 15 Nov 00:43).
//!
//! The owner confirms the member map once per import: `--propose-members
//! <out.json>` lands nothing and writes the map the vault proposes
//! ([`oneiron::Vault::propose_history_members`]) to a new file only the owner
//! reads, which the owner checks and passes to `--members`. `oneiron import
//! slack members set <workspace> <member> <person | contact>` maps one member
//! later ([`oneiron::Vault::set_history_member`]).
//!
//! This is the host's half. It reads the export's JSON files (a zip through
//! the archive pre-check, ARCH-0027 #archive-precheck; a folder without
//! following a link) and the owner's member map, and hands both to the
//! engine: [`oneiron::ingest::history::slack::decode`] decodes the export,
//! and each conversation lands bound to the members Slack shares it with
//! whom the map gives a vault person, and to the owner. Every other member
//! is a contact: its name and words are kept, and it reads nothing. A
//! workspace where no member is mapped reads to the owner alone, and the
//! run says so on stderr. Every TURN the import births is born under the
//! workspace's own facet, named after it ([`oneiron::Vault::history_import_facet`];
//! Engine ruling L2-18-WORKSPACE-FACET-CARRIER = A). The output is the
//! import's JSON document of counts, with the workspace's member counts and
//! its facet beside it.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use oneiron::EntityId;
use oneiron::ingest::archive_precheck::{self, EntryReader, SkippedEntry};
use oneiron::ingest::history::slack::{
    self, SlackExport, SlackExportFile, SlackMemberCounts, SlackMemberMap, SlackMemberMapping,
    SlackWorkspace, USERS_FILE,
};
use oneiron::ingest::history::{HistoryImportReport, HistorySharing, HistorySource};
use serde::Serialize;

use super::{
    ExportBounds, Files, ImportOutcome, MAX_UNZIPPED_EXPORT_BYTES, Totals, crossed_decoded,
    earliest_first, landed_review, open_vault, own_second, progress, read_text, text_of,
};
use crate::cli::{
    ImportSlackArgs, ImportSlackCommand, ImportSlackMemberMapArgs, ImportSlackMemberSetArgs,
    ImportSlackMembersCommand, ImportSlackSubcommand,
};
use crate::config::{ServeConfig, resolve_serve_config};
use crate::files_intake::ImportWarning;

const SOURCE: HistorySource = HistorySource::Slack;

/// The `members set` value that makes a member a contact again.
const CONTACT: &str = "contact";

/// What the export's file name says before the date range Slack appends.
const EXPORT_NAME_TAIL: &str = " Slack export";

/// The workspace, in counts: no names.
#[derive(Serialize)]
struct Workspace<'a> {
    name: &'a str,
    /// The key `members set` names the workspace by: its Slack team id.
    key: &'a str,
    #[serde(flatten)]
    members: SlackMemberCounts,
    /// No member is mapped to a vault person, so every conversation reads to
    /// the owner alone.
    owner_only: bool,
    /// The FACET the import's TURNs are born under, in hex; absent when the
    /// owner stands for no live person to wear one.
    #[serde(skip_serializing_if = "Option::is_none")]
    facet: Option<String>,
}

#[derive(Serialize)]
struct SlackOutcome<'a> {
    workspace: Workspace<'a>,
    #[serde(flatten)]
    import: ImportOutcome<'a>,
}

/// The workspace a proposed map is for, in counts: no names.
#[derive(Serialize)]
struct ProposedWorkspace<'a> {
    name: &'a str,
    key: &'a str,
    /// The members the map proposes as a vault person (`matched`) or as
    /// contacts, the owner's own member left out.
    #[serde(flatten)]
    members: SlackMemberCounts,
}

/// What `--propose-members` did.
#[derive(Serialize)]
struct ProposalOutcome<'a> {
    workspace: ProposedWorkspace<'a>,
    /// The file the proposed map was written to.
    proposal: &'a Path,
    seconds: f64,
}

/// What `members set` did.
#[derive(Serialize)]
struct MemberSetOutcome<'a> {
    workspace: &'a str,
    member: &'a str,
    /// The member's PERSON in hex; none for a contact.
    person: Option<String>,
    /// The workspace's conversations the member is in, whose readers were
    /// set again.
    conversations: u32,
}

/// `oneiron import slack ...`: an import, a proposed member map, or
/// `members set`.
pub(in crate::commands) fn import_slack(command: ImportSlackCommand) -> anyhow::Result<()> {
    match command.command {
        Some(ImportSlackSubcommand::Members(ImportSlackMembersCommand::Set(args))) => {
            set_member(*args)
        }
        None => import_export(command.import),
    }
}

/// The export a run reads, decoded.
struct DecodedExport {
    path: PathBuf,
    /// The name the owner knows the workspace by.
    name: String,
    files: Files,
    decoded: SlackWorkspace,
}

/// `oneiron import slack <path> (--members <map.json> | --propose-members
/// <out.json>) [--workspace <name>]`.
fn import_export(args: ImportSlackArgs) -> anyhow::Result<()> {
    let ImportSlackArgs {
        path,
        map,
        workspace,
        serve,
    } = args;
    let ImportSlackMemberMapArgs {
        members,
        propose_members,
    } = map;
    let path = path.ok_or_else(|| anyhow::anyhow!("give the export: its zip or its folder"))?;
    let config = resolve_serve_config(&serve)?;
    let started = Instant::now();
    let map = members.as_deref().map(read_member_map).transpose()?;
    if let Some(out) = &propose_members {
        anyhow::ensure!(
            !out.exists(),
            "{} exists; the proposed map goes to a new file",
            out.display()
        );
    }
    let name = workspace.unwrap_or_else(|| workspace_name(&path));
    let (files, export) = read_export(&path, &name, &ExportBounds::for_config(&config)?)?;
    let decoded =
        slack::decode(&export).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    drop(export);
    let decoded_export = DecodedExport {
        path,
        name,
        files,
        decoded,
    };
    match (members.zip(map), propose_members) {
        (Some((members, map)), _) => land_export(&config, decoded_export, &members, &map, started),
        (None, Some(out)) => propose(&config, &decoded_export, &out, started),
        (None, None) => anyhow::bail!("give --members or --propose-members"),
    }
}

/// The owner's member map in the file `members`.
fn read_member_map(members: &Path) -> anyhow::Result<SlackMemberMap> {
    let file = File::open(members)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", members.display()))?;
    slack::parse_member_map(&read_text(file, members)?)
        .map_err(|error| anyhow::anyhow!("{}: {error}", members.display()))
}

/// `--members <map>`: lands the export, each conversation bound to the
/// members `map` maps, its TURNs born under the workspace's facet.
fn land_export(
    config: &ServeConfig,
    export: DecodedExport,
    members: &Path,
    map: &SlackMemberMap,
    started: Instant,
) -> anyhow::Result<()> {
    let DecodedExport {
        path,
        name,
        mut files,
        mut decoded,
    } = export;
    let counts = decoded
        .map_members(map)
        .map_err(|error| anyhow::anyhow!("{}: {error}", members.display()))?;
    let roster = decoded.mapped_members(map);
    earliest_first(&mut decoded.conversations);
    files.passed = decoded.passed.len();
    files.decoded.add(&decoded.conversations);
    progress(&format!(
        "read {} file(s): {} conversation(s) of {} member(s)",
        files.read,
        decoded.conversations.len(),
        decoded.members.len()
    ));

    let vault = open_vault(config)?;
    let owner = crate::owner::local_owner(&vault)?;
    let imported_at = own_second(&vault)?;
    // The member table first: a contact keeps its name from the import that
    // first names it, and `members set` finds each conversation's members.
    let containers: Vec<&HistorySharing> = decoded
        .conversations
        .iter()
        .filter_map(|conversation| conversation.sharing.as_ref())
        .collect();
    vault
        .import_history_members(&owner, SOURCE, &decoded.key, &roster, &containers)
        .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
    let facet = vault
        .history_import_facet(&owner, &name, imported_at)
        .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
    let mut totals = Totals::default();
    let mut reports: Vec<HistoryImportReport> = Vec::with_capacity(decoded.conversations.len());
    for (done, conversation) in decoded.conversations.iter().enumerate() {
        let report = vault
            .import_history_in_facet(&owner, SOURCE, conversation, imported_at, facet)
            .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
        totals.add(&report);
        reports.push(report);
        if (done + 1) % 100 == 0 {
            progress(&format!(
                "{} of {} conversations",
                done + 1,
                decoded.conversations.len()
            ));
        }
    }
    let review = landed_review(&vault, SOURCE, &totals, imported_at)?;
    files
        .warnings
        .extend(crossed_decoded(&vault, files.decoded));
    let owner_only = counts.matched == 0;
    let outcome = SlackOutcome {
        workspace: Workspace {
            name: &name,
            key: &decoded.key,
            members: counts,
            owner_only,
            facet: facet.map(|facet| facet.to_hex()),
        },
        import: ImportOutcome {
            source: SOURCE.source_id(),
            path: &path,
            dry_run: false,
            files: &files,
            warnings: &files.warnings,
            totals,
            ledger: vault.history_import_ledger_len(SOURCE)?,
            review,
            seconds: started.elapsed().as_secs_f64(),
            conversations: reports,
        },
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &outcome)?;
    writeln!(stdout)?;
    progress(&member_line(&name, counts));
    if let Some(review) = &outcome.import.review {
        progress(&format!(
            "claims the Dreamer extracts from this import wait for your review: \
             `oneiron runs show {}`",
            review.run_id
        ));
    }
    Ok(())
}

/// `--propose-members <out>`: the member map the vault proposes for the
/// decoded workspace, written to the new file `out` that only the owner
/// reads. Nothing lands. The output is counts only.
fn propose(
    config: &ServeConfig,
    export: &DecodedExport,
    out: &Path,
    started: Instant,
) -> anyhow::Result<()> {
    let DecodedExport { name, decoded, .. } = export;
    let vault = open_vault(config)?;
    let owner = crate::owner::local_owner(&vault)?;
    let proposals = vault
        .propose_history_members(&owner, SOURCE, &decoded.key, &decoded.member_addresses())
        .map_err(|error| anyhow::anyhow!("proposal stopped: {error}"))?;
    let map = slack::proposed_map(&proposals);
    let document = decoded.member_map_document(&map);
    crate::commands::owner::write_new_file(out, |file| {
        let mut writer = io::BufWriter::new(&mut *file);
        serde_json::to_writer_pretty(&mut writer, &document).map_err(io::Error::other)?;
        writeln!(writer)?;
        writer.flush()?;
        drop(writer);
        file.sync_all()
    })?;
    let counts = decoded.member_counts(&map);
    let outcome = ProposalOutcome {
        workspace: ProposedWorkspace {
            name,
            key: &decoded.key,
            members: counts,
        },
        proposal: out,
        seconds: started.elapsed().as_secs_f64(),
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &outcome)?;
    writeln!(stdout)?;
    let own = if map
        .values()
        .any(|mapping| *mapping == SlackMemberMapping::Owner)
    {
        String::new()
    } else {
        format!(", set your own member to \"{}\"", slack::OWNER_MAPPING)
    };
    progress(&format!(
        "{name}: {} of {} member(s) proposed as a vault person; check {}{own}, then import \
         with --members {}",
        counts.matched,
        counts.members,
        out.display(),
        out.display()
    ));
    Ok(())
}

/// `oneiron import slack members set <workspace> <member> <person | contact>`.
fn set_member(args: ImportSlackMemberSetArgs) -> anyhow::Result<()> {
    let ImportSlackMemberSetArgs {
        workspace,
        member,
        person,
        serve,
    } = args;
    let person = if person == CONTACT {
        None
    } else {
        Some(EntityId::from_hex(&person).map_err(|_| {
            anyhow::anyhow!("{person} is neither a person's id in hex nor `{CONTACT}`")
        })?)
    };
    let config = resolve_serve_config(&serve)?;
    let vault = open_vault(&config)?;
    let owner = crate::owner::local_owner(&vault)?;
    let at = own_second(&vault)?;
    let conversations = vault
        .set_history_member(&owner, SOURCE, &workspace, &member, person, at)
        .map_err(|error| anyhow::anyhow!("members set stopped: {error}"))?;
    let outcome = MemberSetOutcome {
        workspace: &workspace,
        member: &member,
        person: person.map(|person| person.to_hex()),
        conversations,
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &outcome)?;
    writeln!(stdout)?;
    Ok(())
}

/// The run's one line on the workspace's members, in the owner's words: for
/// a workspace with no match, "Antevon: 0 of 7 matched, kept as contacts,
/// owner-only".
fn member_line(name: &str, counts: SlackMemberCounts) -> String {
    let SlackMemberCounts {
        members,
        matched,
        contacts,
    } = counts;
    if matched == 0 {
        format!("{name}: 0 of {members} matched, kept as contacts, owner-only")
    } else {
        format!("{name}: {matched} of {members} matched, {contacts} kept as contacts")
    }
}

/// The workspace's name from the export's path: its file or folder name, up
/// to the " Slack export" Slack puts before the date range.
fn workspace_name(path: &Path) -> String {
    let stem = if path.is_dir() {
        path.file_name()
    } else {
        path.file_stem()
    };
    let stem = stem
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = stem
        .find(EXPORT_NAME_TAIL)
        .map_or(stem.as_str(), |end| &stem[..end])
        .trim();
    if name.is_empty() {
        SOURCE.source_id().to_owned()
    } else {
        name.to_owned()
    }
}

/// Every JSON file of the export at `path`, a zip or a folder, by its path
/// under the export's own folder.
fn read_export(
    path: &Path,
    name: &str,
    bounds: &ExportBounds,
) -> anyhow::Result<(Files, SlackExport)> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    let (files, skipped) = if metadata.is_dir() {
        (read_folder(path)?, Vec::new())
    } else {
        anyhow::ensure!(
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("zip")),
            "{} is not a Slack export: give its zip or the unzipped folder",
            path.display()
        );
        read_zip(path, bounds)?
    };
    let read = Files {
        read: files.len(),
        warnings: skipped
            .into_iter()
            .map(|skip| ImportWarning::ArchiveEntrySkipped {
                name: skip.name,
                reason: skip.reason.as_str(),
            })
            .collect(),
        ..Files::default()
    };
    Ok((
        read,
        SlackExport {
            workspace: name.to_owned(),
            files,
        },
    ))
}

/// A path under the export's folder as the decoder names it: plain names
/// joined by `/`.
fn export_path(relative: &Path) -> Option<String> {
    let names: Option<Vec<&str>> = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    names
        .filter(|names| !names.is_empty())
        .map(|names| names.join("/"))
}

/// Every JSON entry under the zip's export folder (the one holding the
/// shallowest `users.json`), read through the archive pre-check, and the
/// entries the pre-check skipped and listed. The reads together are bound
/// by the room under `[import] storage_cap_bytes`, each by the codec's bound.
fn read_zip(
    path: &Path,
    bounds: &ExportBounds,
) -> anyhow::Result<(Vec<SlackExportFile>, Vec<SkippedEntry>)> {
    let file =
        File::open(path).map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    let mut archive = archive_precheck::check_archive(file, bounds.archive)
        .map_err(|refusal| bounds.refused(path, refusal))?;
    let root = archive
        .entries()
        .iter()
        .filter(|entry| {
            !entry.directory
                && entry
                    .path
                    .file_name()
                    .is_some_and(|name| name == USERS_FILE)
        })
        .min_by_key(|entry| entry.path.components().count())
        .and_then(|entry| entry.path.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("{} holds no {USERS_FILE}", path.display()))?;
    let wanted: Vec<(usize, String)> = archive
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !entry.directory
                && entry
                    .path
                    .extension()
                    .is_some_and(|extension| extension == "json")
        })
        .filter_map(|(at, entry)| {
            let relative = entry.path.strip_prefix(&root).ok()?;
            export_path(relative).map(|shown| (at, shown))
        })
        .collect();
    let mut room = bounds.room;
    let mut files = Vec::with_capacity(wanted.len());
    for (at, shown) in wanted {
        let bound = room.map_or(MAX_UNZIPPED_EXPORT_BYTES, |left| {
            left.min(MAX_UNZIPPED_EXPORT_BYTES)
        });
        let bytes = archive
            .read_entry(at, EntryReader::Json, bound)
            .map_err(|refusal| bounds.refused(path, refusal))?;
        room = room.map(|left| left.saturating_sub(bytes.len() as u64));
        files.push(SlackExportFile {
            path: shown,
            text: text_of(bytes),
        });
    }
    Ok((files, archive.into_skipped()))
}

/// Every JSON file under the export's folder, never through a link.
#[cfg(unix)]
fn read_folder(root: &Path) -> anyhow::Result<Vec<SlackExportFile>> {
    let mut files = Vec::new();
    crate::files_intake::confined::walk_json(root, &mut |shown: &Path, file: File| {
        let Some(relative) = shown.strip_prefix(root).ok().and_then(export_path) else {
            return Ok(());
        };
        files.push(SlackExportFile {
            path: relative,
            text: read_text(file, shown)?,
        });
        Ok(())
    })?;
    Ok(files)
}

#[cfg(not(unix))]
fn read_folder(root: &Path) -> anyhow::Result<Vec<SlackExportFile>> {
    anyhow::bail!(
        "importing a folder ({}) needs a unix host; give the export's zip",
        root.display()
    )
}
