//! Snapshot caller-selected directories without following descendant host links.
use crate::Result;
use oneiron_container::GuestSpec;
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{Read, Seek},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

pub(super) struct MountArchive {
    pub file: File,
    pub bytes: u64,
    pub digest: [u8; 32],
}

pub(super) fn prepare(spec: &GuestSpec) -> Result<MountArchive> {
    let mut builder = tar::Builder::new(tempfile::tempfile()?);
    let destinations = spec
        .read_only_mounts
        .iter()
        .map(|(host, guest)| {
            if !host.is_absolute() || !guest.is_absolute() {
                return Err(super::refused("native mount paths must be absolute"));
            }
            Ok(guest.as_os_str().as_bytes().to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = serde_json::to_vec(&destinations)
        .map_err(|_| super::refused("native mount destinations"))?;
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_mode(0o600);
    manifest_header.set_size(manifest.len() as u64);
    manifest_header.set_cksum();
    builder.append_data(
        &mut manifest_header,
        "destinations.json",
        manifest.as_slice(),
    )?;
    for (index, (host, _)) in spec.read_only_mounts.iter().enumerate() {
        // The root is the directory explicitly selected by the caller. All
        // descendant lookup is anchored to this descriptor, never a host link.
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(host)?;
        let prefix = PathBuf::from(index.to_string());
        append_directory(&mut builder, &prefix, &directory.metadata()?)?;
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
        let mut pending = vec![(directory, prefix, entries)];
        while let Some((directory, prefix, entries)) = pending.last_mut() {
            let Some(entry) = entries.next() else {
                pending.pop();
                continue;
            };
            let entry = entry?;
            let anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            let name = entry.file_name();
            let path = prefix.join(&name);
            if entry.file_type()?.is_symlink() {
                let target = std::fs::read_link(anchored.join(&name))?;
                let mut header = header(&entry.metadata()?, tar::EntryType::Symlink);
                builder.append_link(&mut header, &path, target)?;
                continue;
            }
            let name = std::ffi::CString::new(name.as_bytes())
                .map_err(|_| super::refused("native mount filename"))?;
            // SAFETY: the live directory descriptor and single filename
            // are owned here. NOFOLLOW never opens a descendant link;
            // NONBLOCK prevents a raced FIFO from blocking the host.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: openat returned a fresh descriptor, now owned once.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if metadata.is_dir() {
                append_directory(&mut builder, &path, &metadata)?;
                let entries = std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
                pending.push((file, path, entries));
            } else if metadata.is_file() {
                let mut header = header(&metadata, tar::EntryType::Regular);
                header.set_size(metadata.len());
                header.set_cksum();
                builder.append_data(&mut header, path, file.take(metadata.len()))?;
            } else {
                return Err(super::refused(
                    "native mount entry is not a file, directory or link",
                ));
            }
        }
    }
    let mut file = builder.into_inner()?;
    let bytes = file.metadata()?.len();
    file.rewind()?;
    let mut digest = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        digest.update(&buffer[..len]);
    }
    file.rewind()?;
    Ok(MountArchive {
        file,
        bytes,
        digest: *digest.finalize().as_bytes(),
    })
}

fn header(metadata: &Metadata, kind: tar::EntryType) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(metadata.mode() & 0o777);
    header.set_uid(u64::from(metadata.uid()));
    header.set_gid(u64::from(metadata.gid()));
    header.set_mtime(metadata.mtime() as u64);
    header.set_size(0);
    header.set_cksum();
    header
}
fn append_directory(
    builder: &mut tar::Builder<File>,
    path: &Path,
    metadata: &Metadata,
) -> std::io::Result<()> {
    builder.append_data(
        &mut header(metadata, tar::EntryType::Directory),
        path,
        std::io::empty(),
    )
}
