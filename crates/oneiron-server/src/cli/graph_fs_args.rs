//! Named CLI bindings for the typed file-face rows, using the same paired
//! credential and transport as `oneiron api call`, never the raw API door.
use clap::Subcommand;

#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum GraphFsCommand {
    /// `mount` with its typed request JSON.
    Mount {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.readdir` with its typed request JSON.
    Readdir {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.read_file` with its typed request JSON.
    ReadFile {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.read_link` with its typed request JSON.
    ReadLink {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.ls` with its typed request JSON.
    Ls {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.find` with its typed request JSON.
    Find {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.grep` with its typed request JSON.
    Grep {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.cat` with its typed request JSON.
    Cat {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.head` with its typed request JSON.
    Head {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
    /// `graph_fs.wc` with its typed request JSON.
    Wc {
        /// Request JSON, @FILE, or - for stdin.
        #[arg(long, value_name = "@FILE|-|JSON")]
        data: String,
    },
}

impl GraphFsCommand {
    pub(crate) fn request(
        self,
        read: impl Fn(&str) -> anyhow::Result<Vec<u8>>,
    ) -> anyhow::Result<(&'static str, Vec<u8>)> {
        use oneiron::memory::graph_fs_doors::*;
        fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(
            bytes: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            let input: T = serde_json::from_slice(bytes)?;
            Ok(serde_json::to_vec(&input)?)
        }
        match self {
            Self::Mount { data } => Ok(("mount", typed::<GraphFsMountRequest>(&read(&data)?)?)),
            Self::Readdir { data } => Ok((
                "graph_fs.readdir",
                typed::<GraphFsPathRequest>(&read(&data)?)?,
            )),
            Self::ReadFile { data } => Ok((
                "graph_fs.read_file",
                typed::<GraphFsPathRequest>(&read(&data)?)?,
            )),
            Self::ReadLink { data } => Ok((
                "graph_fs.read_link",
                typed::<GraphFsLinkRequest>(&read(&data)?)?,
            )),
            Self::Ls { data } => Ok(("graph_fs.ls", typed::<GraphFsLsRequest>(&read(&data)?)?)),
            Self::Find { data } => {
                Ok(("graph_fs.find", typed::<GraphFsFindRequest>(&read(&data)?)?))
            }
            Self::Grep { data } => {
                Ok(("graph_fs.grep", typed::<GraphFsGrepRequest>(&read(&data)?)?))
            }
            Self::Cat { data } => Ok(("graph_fs.cat", typed::<GraphFsPathRequest>(&read(&data)?)?)),
            Self::Head { data } => {
                Ok(("graph_fs.head", typed::<GraphFsHeadRequest>(&read(&data)?)?))
            }
            Self::Wc { data } => Ok(("graph_fs.wc", typed::<GraphFsLinkRequest>(&read(&data)?)?)),
        }
    }
}
