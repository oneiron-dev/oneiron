//! The dependencies of a publication a push lands on again: rooted before the
//! backend can move the ref, and kept while that push is pending.

use std::io::Read;
use std::path::Path;

use super::door_window::parse_optional_oid;
use super::evidence::local_repo_ref;
use super::intent::ReceivePackRefStatus;
use super::paths::now_secs;
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitRefName, GitWire};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::{OriginPublicationRecord, OriginPublicationStatus};

impl Vault {
    /// Roots again the independent dependencies of each `Published`
    /// publication that already made a move this push proposes.
    ///
    /// A ref deleted and pushed again at its tip lands on the publication that
    /// made that move, and that publication's proof needs every object it
    /// certified, ones no commit reaches included, which the census may have
    /// released since. Rooted only at the landing, they could be collected
    /// after the backend moves the ref and before the landing runs, which is
    /// what a crash between the two leaves, and the ref could then never be
    /// certified. So they are rooted here, before the backend starts, on the
    /// serving thread: it holds the repository coordinator that pinning takes,
    /// which the door's hook thread must never wait for. An object already
    /// gone is not restored, and such a push waits at its landing as before.
    /// The roots stay while the push is pending; the census releases them
    /// once nothing needs them.
    ///
    /// `commands` is the push's command section, read and checked whole
    /// before this runs. A line that names no move is passed over, and the
    /// flush that ends the section ends the walk.
    pub(super) fn repin_pushed_move_owners(
        &self,
        repo_dir: &Path,
        commands: &mut dyn Read,
    ) -> Result<()> {
        let wire = GitWire::new(self)?;
        let mut repo_id = None;
        let mut line = Vec::new();
        loop {
            line.clear();
            (&mut *commands).take(4).read_to_end(&mut line)?;
            let Some(length) = std::str::from_utf8(&line)
                .ok()
                .and_then(|hex| usize::from_str_radix(hex, 16).ok())
                .filter(|length| *length > 4)
            else {
                return Ok(());
            };
            line.clear();
            (&mut *commands)
                .take((length - 4) as u64)
                .read_to_end(&mut line)?;
            let command = line.split(|byte| *byte == 0).next().unwrap_or_default();
            let command = command.strip_suffix(b"\n").unwrap_or(command);
            let Some((old, new, name)) = std::str::from_utf8(command).ok().and_then(|text| {
                let mut fields = text.splitn(3, ' ');
                Some((fields.next()?, fields.next()?, fields.next()?))
            }) else {
                continue;
            };
            let (Ok(old), Ok(Some(new)), Ok(name)) = (
                parse_optional_oid(old),
                parse_optional_oid(new),
                GitRefName::parse_full(name.to_owned()),
            ) else {
                continue;
            };
            let repo_id = match repo_id {
                Some(repo_id) => repo_id,
                None => {
                    *repo_id.insert(lfs_repo_id(&wire.repository_identity(repo_dir)?.as_hex())?)
                }
            };
            let Some(owner) = self.origin_move_owner(repo_id, &name, old.as_ref(), &new)? else {
                continue;
            };
            if owner.status != OriginPublicationStatus::Published
                || owner
                    .required_objects
                    .iter()
                    .all(|oid| oid == &owner.new_oid)
            {
                continue;
            }
            let repo = wire.open_repo(local_repo_ref(repo_dir, &owner.new_oid)?, repo_dir)?;
            self.repin_origin_dependencies(&wire, &repo, &owner, now_secs())?;
        }
    }

    /// Whether an accepted push of exactly `record`'s move is still pending:
    /// it may yet land on `record`, so what `record` needs stays rooted until
    /// it settles. Callers hold the repository coordinator.
    pub(in crate::origin) fn receive_pack_move_pending(
        &self,
        repo_root: &Path,
        record: &OriginPublicationRecord,
    ) -> Result<bool> {
        let pending = self.receive_pack_intents(repo_root)?;
        Ok(pending
            .iter()
            .flat_map(|(_, intent)| &intent.refs)
            .any(|entry| {
                entry.status == ReceivePackRefStatus::Pending
                    && entry.update().is_ok_and(|update| {
                        update.name == record.ref_name.as_str()
                            && update.old_oid == record.expected_old_oid
                            && update.new_oid.as_ref() == Some(&record.new_oid)
                    })
            }))
    }
}
