//! One remediation's plan (FIX 7608 slice 6), built in one read of the
//! marks: the files its bundle writes or removes, each with its action,
//! the env names it gives, and each key it leaves unresolved.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use heed::RoTxn;

use super::env::{RepoEnvEntry, RepoEnvFileKind};
use super::text::{assigned_name, fallback_name, line_before, literal_bounds, toml_string};
use super::{
    CommitFile, RepoSecretReferenceRenderer, RepoSecretRemediationAction, RepoSecretUnresolved,
    RepoSecretUnresolvedReason, dotenv_value_lifts, repo_env_entries, repo_env_file,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_manifest::SECRET_MANIFEST_PATH;
use crate::origin::secret_marks::{RepoBlobMarks, RepoMarkFacts, RepoSecretPlacement};
use crate::repo_mutation::snapshot::SnapshotCustody;
use crate::secret_manifest::{SECRET_MANIFEST_SCHEMA_VERSION, parse_secret_manifest};

/// The example file the names of moved literals go into.
const ROOT_EXAMPLE_PATH: &str = ".env.example";

/// The ignore file a remediation extends.
const IGNORE_PATH: &str = ".gitignore";

/// One file the bundle writes (`Some`) or removes (`None`), the action it
/// is, and the custody records whose keys it moves.
pub(super) struct Staged {
    pub(super) content: Option<Vec<u8>>,
    pub(super) action: RepoSecretRemediationAction,
    custody: Vec<EntityId>,
}

/// One secret's manifest entry: its custody record's name and class, and
/// its env name.
struct Declaration {
    record: String,
    class: &'static str,
    env_name: String,
}

/// The current secret manifest, as the remediation found it.
enum Manifest {
    Absent,
    Text(String),
    Unreadable,
}

/// The env names a remediation gives: one per custody record, each taken
/// once in the manifest.
#[derive(Default)]
struct Names {
    by_custody: BTreeMap<EntityId, String>,
    taken: BTreeSet<String>,
    /// Each manifest entry's custody name and env name, as declared.
    declared: BTreeMap<String, Option<String>>,
}

impl Names {
    /// The env name of `custody`, whose record is named `record`: the one it
    /// already has, the manifest's, or `wanted` with the first free suffix.
    fn name(&mut self, custody: EntityId, record: &str, wanted: &str) -> String {
        if let Some(name) = self.by_custody.get(&custody) {
            return name.clone();
        }
        let name = match self.declared.get(record) {
            Some(Some(declared)) => declared.clone(),
            _ => {
                let mut name = wanted.to_owned();
                let mut suffix = 2_u32;
                while self.taken.contains(&name) {
                    name = format!("{wanted}_{suffix}");
                    suffix += 1;
                }
                name
            }
        };
        self.taken.insert(name.clone());
        self.by_custody.insert(custody, name.clone());
        name
    }
}

/// One remediation's plan, built in one read of the marks.
#[derive(Default)]
pub(super) struct Plan {
    pub(super) files: BTreeMap<String, Staged>,
    pub(super) unresolved: Vec<RepoSecretUnresolved>,
    /// The current files holding marked keys, which the link names.
    pub(super) marked: Vec<String>,
    names: Names,
    declared: BTreeMap<EntityId, Declaration>,
    /// The names each example file gains, by its path.
    examples: BTreeMap<String, BTreeSet<String>>,
    /// The removed dotenv files' paths, which the ignore file gains.
    ignored: BTreeSet<String>,
}

impl Plan {
    /// Plans the remediation of `files`, the current HEAD's, against the
    /// readable `facts` in `txn`.
    pub(super) fn build(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        facts: &RepoMarkFacts,
        custody: &SnapshotCustody,
        files: &BTreeMap<String, CommitFile>,
    ) -> Result<()> {
        let manifest = self.read_manifest(files);
        // Dotenv files first: their names are the ones programs read.
        for (path, file) in files {
            if let Some(kind) = repo_env_file(path) {
                let marks = facts.for_hash(blake3::hash(&file.content).as_bytes());
                self.dotenv(vault, txn, custody, path, &file.content, kind, &marks)?;
            }
        }
        for (path, file) in files {
            if repo_env_file(path).is_none() {
                let marks = facts.for_hash(blake3::hash(&file.content).as_bytes());
                if !marks.is_empty() {
                    self.code(vault, txn, custody, path, &file.content, &marks)?;
                }
            }
        }
        if self.files.is_empty() {
            return Ok(());
        }
        self.write_examples(files);
        self.write_ignore(files);
        self.write_manifest(manifest);
        Ok(())
    }

    fn unresolved(
        &mut self,
        path: &str,
        reason: RepoSecretUnresolvedReason,
        custody: Option<EntityId>,
    ) {
        self.unresolved.push(RepoSecretUnresolved {
            path: path.to_owned(),
            reason,
            custody,
        });
    }

    fn read_manifest(&mut self, files: &BTreeMap<String, CommitFile>) -> Manifest {
        let Some(file) = files.get(SECRET_MANIFEST_PATH) else {
            return Manifest::Absent;
        };
        let parsed = std::str::from_utf8(&file.content)
            .ok()
            .and_then(|text| Some((text, parse_secret_manifest(text).ok()?)));
        let Some((text, manifest)) = parsed else {
            self.unresolved(
                SECRET_MANIFEST_PATH,
                RepoSecretUnresolvedReason::ManifestUnreadable,
                None,
            );
            return Manifest::Unreadable;
        };
        for entry in manifest.secrets {
            if let Some(env_name) = &entry.env_name {
                self.names.taken.insert(env_name.clone());
            }
            self.names.declared.insert(entry.name, entry.env_name);
        }
        Manifest::Text(text.to_owned())
    }

    /// The custody record `custody` names and its class, or an unresolved
    /// action at `path` when it does not read.
    fn record(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        path: &str,
        custody: EntityId,
    ) -> Result<Option<(String, &'static str)>> {
        let record =
            crate::secret_custody::read_secret_custody_meta_in_txn(&vault.store, txn, &custody)?
                .map(|record| (record.name.clone(), record.class.as_str()));
        if record.is_none() {
            self.unresolved(
                path,
                RepoSecretUnresolvedReason::NoCustodyRecord,
                Some(custody),
            );
        }
        Ok(record)
    }

    fn declare(&mut self, custody: EntityId, record: String, class: &'static str, env_name: &str) {
        self.declared.entry(custody).or_insert(Declaration {
            record,
            class,
            env_name: env_name.to_owned(),
        });
    }

    /// A dotenv file: a live one is removed and each value it lifts is
    /// declared; an example's marked values are blanked.
    #[allow(clippy::too_many_arguments)]
    fn dotenv(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        custody: &SnapshotCustody,
        path: &str,
        content: &[u8],
        kind: RepoEnvFileKind,
        marks: &RepoBlobMarks,
    ) -> Result<()> {
        let entries = repo_env_entries(content);
        let spans = top_level_spans(marks)?;
        let held = |entry: &RepoEnvEntry| {
            spans
                .iter()
                .find(|(span, _)| span.start < entry.value.end && entry.value.start < span.end)
                .map(|(_, id)| *id)
        };
        if !marks.is_empty() {
            self.marked.push(path.to_owned());
        }
        match kind {
            RepoEnvFileKind::Live => {
                let lifted: Vec<&RepoEnvEntry> = entries
                    .iter()
                    .filter(|entry| {
                        content
                            .get(entry.value.clone())
                            .is_some_and(dotenv_value_lifts)
                    })
                    .collect();
                if lifted.is_empty() && marks.is_empty() {
                    return Ok(());
                }
                let mut moved = Vec::new();
                for entry in lifted {
                    let Some(id) = held(entry) else {
                        self.unresolved(path, RepoSecretUnresolvedReason::NotInCustody, None);
                        continue;
                    };
                    if let Some((record, class)) = self.record(vault, txn, path, id)? {
                        let env_name = self.names.name(id, &record, &entry.name);
                        self.declare(id, record, class, &env_name);
                        moved.push(id);
                    }
                }
                let example = example_beside(path);
                let names = self.examples.entry(example).or_default();
                names.extend(entries.iter().map(|entry| entry.name.clone()));
                self.ignored.insert(path.to_owned());
                self.files.insert(
                    path.to_owned(),
                    Staged {
                        content: None,
                        action: RepoSecretRemediationAction::RemoveDotenv {
                            path: path.to_owned(),
                        },
                        custody: moved,
                    },
                );
            }
            RepoEnvFileKind::Example => {
                if marks.is_empty() {
                    return Ok(());
                }
                if marks.opaque() {
                    self.unresolved(path, RepoSecretUnresolvedReason::Opaque, None);
                    return Ok(());
                }
                let mut blanked = content.to_vec();
                let mut moved = Vec::new();
                for entry in entries.iter().rev() {
                    if let Some(id) = held(entry) {
                        blanked.drain(entry.value.clone());
                        moved.push(id);
                    }
                }
                if moved.is_empty() {
                    return Ok(());
                }
                if custody.withholds(path, &blanked).is_some() {
                    for id in moved {
                        self.unresolved(path, RepoSecretUnresolvedReason::StillSecret, Some(id));
                    }
                    return Ok(());
                }
                self.files.insert(
                    path.to_owned(),
                    Staged {
                        content: Some(blanked),
                        action: RepoSecretRemediationAction::WriteExample {
                            path: path.to_owned(),
                            names: Vec::new(),
                        },
                        custody: moved,
                    },
                );
            }
        }
        Ok(())
    }

    /// A code file whose bytes a mark names: each marked literal becomes a
    /// reference, from the end so earlier offsets hold.
    fn code(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        custody: &SnapshotCustody,
        path: &str,
        content: &[u8],
        marks: &RepoBlobMarks,
    ) -> Result<()> {
        self.marked.push(path.to_owned());
        if marks.opaque() {
            self.unresolved(path, RepoSecretUnresolvedReason::Opaque, None);
            return Ok(());
        }
        for mark in marks.marks() {
            if let RepoSecretPlacement::Span {
                member,
                custody: id,
                ..
            } = &mark.placement
                && !member.is_empty()
            {
                self.unresolved(path, RepoSecretUnresolvedReason::ContainerMember, Some(*id));
            }
        }
        let handles = handles_of(marks);
        let mut edited = content.to_vec();
        let mut env_names = BTreeSet::new();
        let mut moved = Vec::new();
        let mut floor = content.len();
        for (span, id) in top_level_spans(marks)?.into_iter().rev() {
            let Some(literal) = literal_bounds(content, &span).filter(|lit| lit.end <= floor)
            else {
                self.unresolved(path, RepoSecretUnresolvedReason::NotOneLiteral, Some(id));
                continue;
            };
            let Some((record, class)) = self.record(vault, txn, path, id)? else {
                continue;
            };
            let before = line_before(content, literal.start);
            let wanted = assigned_name(before)
                .unwrap_or_else(|| fallback_name(handles.get(&id).map(String::as_str)));
            let env_name = self.names.name(id, &record, &wanted);
            let Some(reference) =
                RepoSecretReferenceRenderer::reference(path, content, before, &env_name)
            else {
                self.unresolved(path, RepoSecretUnresolvedReason::NoReference, Some(id));
                continue;
            };
            self.declare(id, record, class, &env_name);
            edited.splice(literal.clone(), reference.into_bytes());
            floor = literal.start;
            env_names.insert(env_name);
            moved.push(id);
        }
        if moved.is_empty() {
            return Ok(());
        }
        if custody.withholds(path, &edited).is_some() {
            for id in moved {
                self.unresolved(path, RepoSecretUnresolvedReason::StillSecret, Some(id));
            }
            return Ok(());
        }
        self.examples
            .entry(ROOT_EXAMPLE_PATH.to_owned())
            .or_default()
            .extend(env_names.iter().cloned());
        self.files.insert(
            path.to_owned(),
            Staged {
                content: Some(edited),
                action: RepoSecretRemediationAction::ReplaceLiterals {
                    path: path.to_owned(),
                    env_names: env_names.into_iter().collect(),
                },
                custody: moved,
            },
        );
        Ok(())
    }

    /// Each example file gains the names it lacks, blank.
    fn write_examples(&mut self, files: &BTreeMap<String, CommitFile>) {
        let examples = std::mem::take(&mut self.examples);
        for (path, names) in examples {
            let staged = self.files.remove(&path);
            let mut text = match &staged {
                Some(staged) => staged.content.clone().unwrap_or_default(),
                None => files
                    .get(&path)
                    .map(|file| file.content.clone())
                    .unwrap_or_default(),
            };
            let present: BTreeSet<String> = repo_env_entries(&text)
                .into_iter()
                .map(|entry| entry.name)
                .collect();
            let missing: Vec<String> = names
                .into_iter()
                .filter(|name| !present.contains(name))
                .collect();
            if !text.is_empty() && !text.ends_with(b"\n") && !missing.is_empty() {
                text.push(b'\n');
            }
            for name in &missing {
                text.extend_from_slice(name.as_bytes());
                text.extend_from_slice(b"=\n");
            }
            let custody = staged.map(|staged| staged.custody).unwrap_or_default();
            if missing.is_empty() && custody.is_empty() {
                continue;
            }
            self.files.insert(
                path.clone(),
                Staged {
                    content: Some(text),
                    action: RepoSecretRemediationAction::WriteExample {
                        path,
                        names: missing,
                    },
                    custody,
                },
            );
        }
    }

    /// The ignore file gains `.env` and each removed dotenv file's exact
    /// path, unless a line already names it.
    fn write_ignore(&mut self, files: &BTreeMap<String, CommitFile>) {
        let mut text = files
            .get(IGNORE_PATH)
            .map(|file| file.content.clone())
            .unwrap_or_default();
        let present: BTreeSet<String> = text
            .split(|byte| *byte == b'\n')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .map(|line| line.trim().trim_start_matches('/').to_owned())
            .collect();
        let mut wanted = std::mem::take(&mut self.ignored);
        wanted.insert(".env".to_owned());
        let missing: Vec<String> = wanted
            .into_iter()
            .filter(|entry| !present.contains(entry))
            .collect();
        if missing.is_empty() {
            return;
        }
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.push(b'\n');
        }
        for entry in &missing {
            text.extend_from_slice(entry.as_bytes());
            text.push(b'\n');
        }
        self.files.insert(
            IGNORE_PATH.to_owned(),
            Staged {
                content: Some(text),
                action: RepoSecretRemediationAction::IgnoreDotenv { entries: missing },
                custody: Vec::new(),
            },
        );
    }

    /// The manifest gains one entry per secret it does not declare yet,
    /// mapping its env name onto its custody record's name.
    fn write_manifest(&mut self, manifest: Manifest) {
        let mut text = match manifest {
            Manifest::Unreadable => return,
            Manifest::Absent => format!("schema_version = {SECRET_MANIFEST_SCHEMA_VERSION}\n"),
            Manifest::Text(text) => text,
        };
        let mut added = Vec::new();
        let mut kept = Vec::new();
        for (custody, declaration) in &self.declared {
            match self.names.declared.get(&declaration.record) {
                Some(Some(_)) => continue,
                Some(None) => {
                    kept.push(*custody);
                    continue;
                }
                None => {}
            }
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "\n[[secrets]]\nname = {}\nclass = {}\nenv_name = {}\ndeclared_paths = []\n",
                toml_string(&declaration.record),
                toml_string(declaration.class),
                toml_string(&declaration.env_name),
            ));
            added.push(declaration.env_name.clone());
        }
        for custody in kept {
            self.unresolved(
                SECRET_MANIFEST_PATH,
                RepoSecretUnresolvedReason::DeclaredWithoutEnvName,
                Some(custody),
            );
        }
        if added.is_empty() {
            return;
        }
        self.files.insert(
            SECRET_MANIFEST_PATH.to_owned(),
            Staged {
                content: Some(text.into_bytes()),
                action: RepoSecretRemediationAction::DeclareEnvNames { env_names: added },
                custody: Vec::new(),
            },
        );
    }
}

/// Each span mark in a blob's own bytes, by its byte span, once each, in
/// byte order, with its custody record.
fn top_level_spans(marks: &RepoBlobMarks) -> Result<Vec<(Range<usize>, EntityId)>> {
    let mut spans = BTreeMap::new();
    for mark in marks.marks() {
        if let RepoSecretPlacement::Span {
            member,
            start,
            end,
            custody,
            ..
        } = &mark.placement
            && member.is_empty()
        {
            let at = |offset: u64| {
                usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow("a mark span"))
            };
            spans.entry((at(*start)?, at(*end)?)).or_insert(*custody);
        }
    }
    Ok(spans
        .into_iter()
        .map(|((start, end), custody)| (start..end, custody))
        .collect())
}

/// Each custody record's handle, as its marks name it.
fn handles_of(marks: &RepoBlobMarks) -> BTreeMap<EntityId, String> {
    marks
        .marks()
        .iter()
        .filter_map(|mark| match &mark.placement {
            RepoSecretPlacement::Span {
                custody, handle, ..
            } => Some((*custody, handle.clone())),
            RepoSecretPlacement::Opaque => None,
        })
        .collect()
}

/// The example file beside the dotenv file at `path`.
fn example_beside(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{ROOT_EXAMPLE_PATH}"),
        None => ROOT_EXAMPLE_PATH.to_owned(),
    }
}
