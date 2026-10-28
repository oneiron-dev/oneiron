//! `[models.broker]` as the file writes it, and its check into the
//! [`BrokerConfig`] this server runs its credential broker by.

use std::path::PathBuf;

use serde::Deserialize;

use super::BrokerConfig;

/// `[models.broker]`: where the credential broker listens and the OS user it
/// runs as, or, with neither, how this server starts its same-user child.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerFile {
    socket: Option<PathBuf>,
    uid: Option<u32>,
    program: Option<PathBuf>,
    #[serde(default)]
    extra_roots: Vec<PathBuf>,
}

impl BrokerFile {
    pub(super) fn resolve(self) -> anyhow::Result<BrokerConfig> {
        let absolute = |path: &PathBuf, field: &str| {
            anyhow::ensure!(
                path.is_absolute(),
                "models.broker.{field} must be an absolute path"
            );
            Ok(())
        };
        match (self.socket, self.uid) {
            (Some(socket), Some(uid)) => {
                absolute(&socket, "socket")?;
                anyhow::ensure!(
                    self.program.is_none() && self.extra_roots.is_empty(),
                    "models.broker.program and extra_roots are for the same-user child; a separate-user broker takes its own flags"
                );
                Ok(BrokerConfig::SeparateUser { socket, uid })
            }
            (None, None) => {
                if let Some(program) = &self.program {
                    absolute(program, "program")?;
                }
                for roots in &self.extra_roots {
                    absolute(roots, "extra_roots")?;
                }
                Ok(BrokerConfig::SameUser {
                    program: self.program,
                    extra_roots: self.extra_roots,
                })
            }
            _ => anyhow::bail!(
                "models.broker.socket and uid name a separate-user broker together; with neither, this server starts a same-user child"
            ),
        }
    }
}
