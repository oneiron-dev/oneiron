use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, readlinkat_raw, statat};

use super::EntryKind;

pub(crate) struct Directory(File);

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

impl Directory {
    pub(crate) fn open_root(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "capture root must be absolute",
            ));
        }
        let mut dir = Self(File::from(open("/", directory_flags(), Mode::empty())?));
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => dir = dir.open_dir(name)?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "capture root must be absolute",
                    ));
                }
            }
        }
        Ok(dir)
    }

    pub(crate) fn names(&self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(&self.0)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(OsStr::from_bytes(name).to_owned());
            }
        }
        Ok(names)
    }

    pub(crate) fn entry_kind(&self, name: &OsStr) -> io::Result<(EntryKind, u64)> {
        let stat = statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => EntryKind::Directory,
            FileType::RegularFile => EntryKind::File,
            FileType::Symlink => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        let len = u64::try_from(stat.st_size)
            .map_err(|_| io::Error::other("negative capture entry length"))?;
        Ok((kind, len))
    }

    pub(crate) fn has_git_marker(&self) -> io::Result<bool> {
        match statat(&self.0, ".git", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self(File::from(openat(
            &self.0,
            name,
            directory_flags(),
            Mode::empty(),
        )?)))
    }

    pub(crate) fn open_file(&self, name: &OsStr) -> io::Result<File> {
        // NONBLOCK prevents a raced-in FIFO from waiting before the type check.
        Ok(File::from(openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }

    pub(crate) fn read_link(&self, name: &OsStr, buffer: &mut [u8]) -> io::Result<usize> {
        Ok(readlinkat_raw(&self.0, name, buffer)?)
    }
}
