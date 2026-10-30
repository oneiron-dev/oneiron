//! A restore's custody read from the residence home (FIX 5846,
//! `--custody-home`): a new host that holds the kit and no machine of the
//! vault's reads the sealed head and log frames of the backup's custody
//! lineage from the home the owner names, from the first frame admission
//! may chain through (FIX 12045), signed with the kit's owner anchor, and
//! the restore admits them as it admits the folder's. Only an explicit home
//! is asked: there is no implicit network, and a fetch that fails fails the
//! restore, never falling back to the folder beside the backup.

use std::path::Path;

use oneiron::recovery::checkpoint::{CheckpointKey, CustodyRecovery};
use oneiron::sync::client::fetch_custody_with_kit;
use oneiron::world_keys::RecoveryRootSeed;

/// `recovery`, its head and frames read from the residence home at `home`
/// in place of the folder beside the backup at `backup`, fetched with the
/// world kit's `seed` alone; without `home`, `recovery` as it was. The
/// backup's custody lineage and vault id come from its clear head and tail,
/// and the first frame asked for from those and `recovery`'s anchor (FIX
/// 12045). A backup that names no custody asks the home nothing: its restore
/// reads no head anywhere. A home that refuses the kit, holds no head of the
/// lineage or does not answer fails the restore.
pub(crate) fn custody_from_home<'a>(
    recovery: CustodyRecovery<'a>,
    backup: &Path,
    home: Option<&str>,
    seed: Option<&RecoveryRootSeed>,
) -> anyhow::Result<CustodyRecovery<'a>> {
    let Some(home) = home else {
        return Ok(recovery);
    };
    let seed = seed.ok_or_else(|| {
        anyhow::anyhow!("--custody-home reads the home's custody with a world kit: --unlock kit")
    })?;
    let read = |error: oneiron::Error| anyhow::anyhow!("read backup {}: {error}", backup.display());
    let Some((lineage, from_seq)) = recovery.custody_wanted(backup).map_err(read)? else {
        return Ok(recovery);
    };
    let vault_id = CheckpointKey::unlocks(backup).map_err(read)?.vault_id;
    // The command runs on the CLI's runtime, so the fetch gets a thread and a
    // runtime of its own.
    let fetched = std::thread::scope(|scope| {
        scope
            .spawn(|| -> anyhow::Result<_> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let fetch = fetch_custody_with_kit(home, &vault_id, seed, lineage, from_seq);
                runtime
                    .block_on(fetch)
                    .map_err(|error| anyhow::anyhow!("fetch custody from {home}: {error}"))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("the custody fetch stopped"))?
    })?;
    let fetched = fetched.ok_or_else(|| {
        anyhow::anyhow!("{home} holds no custody head of this backup that this kit may read")
    })?;
    Ok(recovery.fetched_from_home(fetched))
}
