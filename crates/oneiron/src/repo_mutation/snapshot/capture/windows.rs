//! Windows child names are resolved by NtCreateFile against a held parent.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx, GetFileType,
    MAXIMUM_REPARSE_DATA_BUFFER_SIZE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

use super::EntryKind;

// NT reparse tags and their name-surrogate bit (the Windows SDK contract).
const SYMLINK_TAG: u32 = 0xa000_000c;
const MOUNT_POINT_TAG: u32 = 0xa000_0003;
const NAME_SURROGATE: u32 = 0x2000_0000;

pub(crate) struct Directory(File);

impl Directory {
    pub(crate) fn open_root(path: &Path) -> io::Result<Self> {
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(invalid("capture root must be absolute"));
        };
        if components.next() != Some(Component::RootDir) {
            return Err(invalid("capture root must be absolute"));
        }
        // Only the volume/share root is opened by an absolute name. Every
        // filesystem component below it is opened relative to its parent.
        let mut volume = PathBuf::from(prefix.as_os_str());
        volume.push(r"\");
        let file = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(volume)?;
        check_directory(&file)?;
        let mut dir = Self(file);
        for component in components {
            let Component::Normal(name) = component else {
                return Err(invalid("capture root must contain normal components"));
            };
            dir = dir.open_dir(name)?;
        }
        Ok(dir)
    }

    pub(crate) fn names(&self) -> io::Result<Vec<OsString>> {
        // Same aligned, paged enumeration as std's Windows ReadDir. This is
        // query scratch space, not a file-count or filename policy limit.
        let mut buffer = [0u64; 128];
        let mut names = Vec::new();
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            // SAFETY: buffer is writable and 8-aligned for the native records.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.0.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    break;
                }
                return Err(error);
            }
            class = FileIdBothDirectoryInfo;
            let mut cursor = 0;
            loop {
                let header = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if cursor + header > size_of_val(&buffer) {
                    return Err(invalid("invalid directory enumeration record"));
                }
                // SAFETY: the native call initialized each record and its name.
                // Read fields unaligned, as std does for filesystem drivers.
                let (next, length, name) = unsafe {
                    let info = buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(cursor)
                        .cast::<FILE_ID_BOTH_DIR_INFO>();
                    (
                        (&raw const (*info).NextEntryOffset).read_unaligned() as usize,
                        (&raw const (*info).FileNameLength).read_unaligned() as usize,
                        (&raw const (*info).FileName).cast::<u16>(),
                    )
                };
                if length % 2 != 0 || cursor + header + length > size_of_val(&buffer) {
                    return Err(invalid("invalid directory entry name"));
                }
                // SAFETY: the checked name is initialized, possibly unaligned.
                let wide: Vec<_> = (0..length / 2)
                    .map(|i| unsafe { name.add(i).read_unaligned() })
                    .collect();
                if wide != [b'.' as u16] && wide != [b'.' as u16, b'.' as u16] {
                    names.push(OsString::from_wide(&wide));
                }
                if next == 0 {
                    break;
                }
                if next < header || next > size_of_val(&buffer) - cursor {
                    return Err(invalid("invalid directory record offset"));
                }
                cursor += next;
            }
        }
        Ok(names)
    }

    pub(crate) fn entry_kind(&self, name: &OsStr) -> io::Result<(EntryKind, u64)> {
        let file = open_child(&self.0, name, 0, 0)?;
        let info = attributes(&file)?;
        let kind = if info.ReparseTag & NAME_SURROGATE != 0 {
            if matches!(info.ReparseTag, SYMLINK_TAG | MOUNT_POINT_TAG) {
                EntryKind::Symlink
            } else {
                EntryKind::Other
            }
        } else if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        Ok((kind, file.metadata()?.len()))
    }

    pub(crate) fn has_git_marker(&self) -> io::Result<bool> {
        match open_child(&self.0, OsStr::new(".git"), 0, 0) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        let file = open_child(
            &self.0,
            name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_DIRECTORY_FILE,
        )?;
        check_directory(&file)?;
        Ok(Self(file))
    }

    pub(crate) fn open_file(&self, name: &OsStr) -> io::Result<File> {
        let file = open_child(
            &self.0,
            name,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            FILE_NON_DIRECTORY_FILE,
        )?;
        let info = attributes(&file)?;
        if info.ReparseTag & NAME_SURROGATE != 0 || !file.metadata()?.is_file() {
            return Err(invalid("capture file changed type"));
        }
        Ok(file)
    }

    pub(crate) fn read_link(&self, name: &OsStr, output: &mut [u8]) -> io::Result<usize> {
        let file = open_child(&self.0, name, 0, 0)?;
        let mut buffer = [0u64; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize / 8];
        let mut returned = 0;
        // SAFETY: the held reparse-point handle is not followed. Native output
        // writes only into the aligned, SDK-sized scratch buffer.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_GET_REPARSE_POINT,
                ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer) as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: buffer is fully initialized; returned bounds the native data.
        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(&buffer))
        }
        .get(..returned as usize)
        .ok_or_else(|| invalid("invalid reparse data length"))?;
        let word = |offset| -> io::Result<u16> {
            let pair = bytes
                .get(offset..offset + 2)
                .ok_or_else(|| invalid("invalid reparse data"))?;
            Ok(u16::from_le_bytes([pair[0], pair[1]]))
        };
        let tag = u32::from(word(0)?) | (u32::from(word(2)?) << 16);
        let (base, relative) = match tag {
            SYMLINK_TAG => (20, word(16)? & 1 != 0),
            MOUNT_POINT_TAG => (16, false),
            _ => return Err(invalid("unsupported reparse point type")),
        };
        let offset = usize::from(word(8)?);
        let length = usize::from(word(10)?);
        if offset % 2 != 0 || length % 2 != 0 {
            return Err(invalid("invalid reparse target"));
        }
        let target = bytes
            .get(base + offset..base + offset + length)
            .ok_or_else(|| invalid("invalid reparse target"))?;
        let mut written = 0;
        let wide = target.chunks_exact(2).enumerate().map(|(i, pair)| {
            let ch = u16::from_le_bytes([pair[0], pair[1]]);
            // Match std read_link's NT-internal -> public verbatim prefix.
            if !relative && i == 1 && target.starts_with(&[92, 0, 63, 0, 63, 0, 92, 0]) {
                b'\\' as u16
            } else {
                ch
            }
        });
        for decoded in std::char::decode_utf16(wide) {
            let ch = decoded.map_err(|_| invalid("capture symlink target must be UTF-8"))?;
            let mut encoded = [0; 4];
            let encoded = ch.encode_utf8(&mut encoded).as_bytes();
            if encoded.len() > output.len() - written {
                return Ok(output.len());
            }
            output[written..written + encoded.len()].copy_from_slice(encoded);
            written += encoded.len();
        }
        Ok(written)
    }
}

fn open_child(parent: &File, name: &OsStr, access: u32, options: u32) -> io::Result<File> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty()
        || name.iter().any(|ch| matches!(*ch, 0 | 47 | 58 | 92))
        || name == [46]
        || name == [46, 46]
    {
        return Err(invalid("capture child must be one normal component"));
    }
    let length =
        u16::try_from(name.len() * 2).map_err(|_| invalid("capture child name too long"))?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: these structs are POD; every pointer stays live across this call.
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: this maps an NTSTATUS value, with no pointer arguments.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: successful synchronous NtCreateFile returns one owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    // Reparse points open as themselves, never as a pipe/device target. A
    // regular-filesystem parent plus one child name cannot resolve a pipe path.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid("capture supports only filesystem entries"));
    }
    Ok(file)
}

fn attributes(file: &File) -> io::Result<FILE_ATTRIBUTE_TAG_INFO> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: info has the ABI type and size required by FileAttributeTagInfo.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn check_directory(file: &File) -> io::Result<()> {
    let info = attributes(file)?;
    if info.ReparseTag & NAME_SURROGATE != 0 || !file.metadata()?.is_dir() {
        return Err(invalid("capture directory changed type"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
