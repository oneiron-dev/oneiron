//! The tables of installed packs (design pass 34, section 3.2; row L1). A pack the owner put, or
//! one installed from an admitted hub, may carry a table of setting defaults
//! ([`crate::skill_hub::pack_catalog::SETTING_DEFAULTS_FILE`]). Its install proposes every default,
//! tighter or not, and changes nothing in force until the owner's yes
//! (`vault.settings.accept_defaults`); an update proposes again. Only the `engine` pack's tighter
//! defaults land by themselves: its table is the build's own.
//!
//! An installed table is proven here as the engine pack's is, by its digest: the source of the
//! pack's Active install holds its bytes ([`installed_table`]), so the door's head act carries
//! them and the owner's yes to it travels with them.

use super::*;

/// `table`'s defaults as the layer holds them: each key a catalogue key of this build, each value
/// checked and encoded by the key's kind.
///
/// # Errors
///
/// `InvalidConfig` for a key this build does not know, or a value the key's kind refuses.
pub(crate) fn pack_defaults_from_json(
    table: &[(String, serde_json::Value)],
) -> Result<Vec<(&'static SettingSpec, EncodedValue)>> {
    table
        .iter()
        .map(|(name, json)| {
            let spec = spec_named(name)?;
            Ok((spec, spec.kind.from_json(json.clone())?))
        })
        .collect()
}

/// The pack door over installed `pack`'s `table`, as `version` of the pack ships it, in the
/// install's write. The layer it names is empty, so every default the vault does not already
/// hold from this pack is a proposal: nothing in force moves until the owner's yes. Answers the
/// keys that moved anyway, which only an owner's yes another machine carried to this table can
/// land.
///
/// # Errors
///
/// `InvalidConfig` for the `engine` pack's name or a table [`pack_defaults_from_json`] refuses;
/// as [`door::apply_pack_defaults_in_txn`].
pub(crate) fn propose_installed_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, version): (&str, &str),
    table: &[(String, serde_json::Value)],
) -> Result<Vec<String>> {
    if pack == ENGINE_PACK {
        return Err(Error::InvalidConfig(
            "an installed pack's table is never the engine pack's".into(),
        ));
    }
    let defaults = pack_defaults_from_json(table)?;
    Ok(
        door::apply_pack_defaults_in_txn(vault, txn, pack, (version, &defaults), Some(&[]))?
            .map(|applied| applied.moved)
            .unwrap_or_default(),
    )
}

/// Closes removed `pack`'s waiting proposal, in the removal's write: no yes lands a default of a
/// pack that is gone. The rows an earlier yes accepted stay, since they are the owner's. The head
/// forgets the table it weighed, so the pack installed again proposes again.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn close_pack_proposal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
) -> Result<()> {
    if pack == ENGINE_PACK {
        return Ok(());
    }
    let Some(mut head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(());
    };
    head.proposal = None;
    head.digest.clear();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)
}

/// The bytes of installed `pack`'s table whose digest is `digest`, read from the source of its
/// Active install; `None` where no such install carries that table, or this build no longer
/// reads one of its keys.
///
/// # Errors
///
/// Storage errors; a catalog row that does not read.
pub(super) fn installed_table(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pack: &str,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let Some(table) = vault.installed_setting_defaults_in_txn(txn, pack)? else {
        return Ok(None);
    };
    let Ok(defaults) = pack_defaults_from_json(&table.defaults) else {
        return Ok(None);
    };
    if defaults_digest(pack, &defaults).into_bytes() != *digest {
        return Ok(None);
    }
    table_bytes(pack, &defaults).map(Some)
}
