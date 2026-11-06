//! The original launch bytes on the private bootstrap socket.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

pub(crate) const MARKER: &str = "__oneiron_worker_bootstrap_v1";
pub(crate) const JOINED: u8 = 1;
pub(crate) const ACK: u8 = 2;
pub(crate) const ARMED: u8 = 3;
pub(crate) const EXEC: u8 = 4;

pub(crate) struct ExecSpec {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
    pub(crate) dir: PathBuf,
    pub(crate) env: Vec<(OsString, OsString)>,
}

impl ExecSpec {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        field(&mut bytes, self.program.as_os_str().as_bytes())?;
        field(&mut bytes, self.dir.as_os_str().as_bytes())?;
        number(&mut bytes, self.args.len())?;
        for arg in &self.args {
            field(&mut bytes, arg.as_bytes())?;
        }
        number(&mut bytes, self.env.len())?;
        for (name, value) in &self.env {
            field(&mut bytes, name.as_bytes())?;
            field(&mut bytes, value.as_bytes())?;
        }
        Ok(bytes)
    }

    pub(crate) fn read(reader: &mut impl Read) -> io::Result<Self> {
        let program = PathBuf::from(read_field(reader)?);
        let dir = PathBuf::from(read_field(reader)?);
        let mut args = Vec::new();
        for _ in 0..read_number(reader)? {
            args.push(read_field(reader)?);
        }
        let mut env = Vec::new();
        for _ in 0..read_number(reader)? {
            env.push((read_field(reader)?, read_field(reader)?));
        }
        Ok(Self {
            program,
            args,
            dir,
            env,
        })
    }
}

fn number(writer: &mut impl Write, value: usize) -> io::Result<()> {
    let value = u64::try_from(value).map_err(io::Error::other)?;
    writer.write_all(&value.to_be_bytes())
}

fn field(writer: &mut impl Write, value: &[u8]) -> io::Result<()> {
    number(writer, value.len())?;
    writer.write_all(value)
}

fn read_number(reader: &mut impl Read) -> io::Result<usize> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    usize::try_from(u64::from_be_bytes(bytes)).map_err(io::Error::other)
}

fn read_field(reader: &mut impl Read) -> io::Result<OsString> {
    let length = read_number(reader)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(OsString::from_vec(bytes))
}

pub(crate) fn byte(reader: &mut impl Read, expected: u8) -> io::Result<()> {
    let mut got = [0];
    reader.read_exact(&mut got)?;
    if got[0] == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid worker bootstrap reply",
        ))
    }
}
