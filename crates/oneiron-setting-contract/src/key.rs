//! The stored key of one setting row: `name 0x00 item 0x00 mode scope`.

use oneiron_contracts::error::{Error, Result};

use crate::{SettingMode, SettingScope};

/// One row's key: which catalogue key, which item of a family key (none for the item-less
/// row), value or pin, and the scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowKey {
    pub name: String,
    pub item: Option<String>,
    pub mode: SettingMode,
    pub scope: SettingScope,
}

impl RowKey {
    /// The key bytes. The name and item hold no NUL ([`check_name`], [`check_item`]), so the
    /// two NULs split them.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Self::item_prefix(&self.name, self.item.as_deref());
        out.push(self.mode.tag());
        out.extend_from_slice(&self.scope.key_bytes());
        out
    }

    /// The key a stored row's bytes name; `None` for bytes no key encodes to.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let name_end = bytes.iter().position(|byte| *byte == 0)?;
        let rest = &bytes[name_end + 1..];
        let item_end = rest.iter().position(|byte| *byte == 0)?;
        let (&mode, scope) = rest[item_end + 1..].split_first()?;
        let name = std::str::from_utf8(&bytes[..name_end]).ok()?;
        let item = std::str::from_utf8(&rest[..item_end]).ok()?;
        check_name(name).ok()?;
        Some(Self {
            name: name.to_owned(),
            item: (!item.is_empty()).then(|| item.to_owned()),
            mode: SettingMode::from_tag(mode)?,
            scope: SettingScope::from_key_bytes(scope)?,
        })
    }

    /// The prefix every row of `name` shares.
    #[must_use]
    pub fn name_prefix(name: &str) -> Vec<u8> {
        let mut out = name.as_bytes().to_vec();
        out.push(0);
        out
    }

    /// The prefix every row of `name` for `item` (the item-less rows for `None`) shares.
    #[must_use]
    pub fn item_prefix(name: &str, item: Option<&str>) -> Vec<u8> {
        let mut out = Self::name_prefix(name);
        out.extend_from_slice(item.unwrap_or_default().as_bytes());
        out.push(0);
        out
    }
}

/// A key name is dotted lowercase ASCII: segments of `a-z`, `0-9` and `_`, joined by `.`.
///
/// # Errors
///
/// `InvalidConfig` for any other name.
pub fn check_name(name: &str) -> Result<()> {
    let well_formed = !name.is_empty()
        && name.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
    if well_formed {
        Ok(())
    } else {
        Err(Error::InvalidConfig(format!(
            "a setting key is dotted lowercase ASCII, not `{name}`"
        )))
    }
}

/// An item is a non-empty name of at most 256 bytes with no control character.
///
/// # Errors
///
/// `InvalidConfig` for any other item.
pub fn check_item(item: &str) -> Result<()> {
    if item.is_empty() || item.len() > 256 || item.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "a setting item is a non-empty name of at most 256 bytes with no control character"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RowKey, check_item, check_name};
    use crate::{SettingMode, SettingScope};
    use oneiron_contracts::entity_id::EntityId;

    #[test]
    fn a_key_round_trips_and_sits_under_its_prefixes() {
        let key = RowKey {
            name: "outbound.undo_send".to_owned(),
            item: Some("mail".to_owned()),
            mode: SettingMode::Pin,
            scope: SettingScope::Project(EntityId::from_bytes_unchecked([4; 16])),
        };
        let bytes = key.encode();
        assert_eq!(RowKey::decode(&bytes), Some(key.clone()));
        assert!(bytes.starts_with(&RowKey::name_prefix("outbound.undo_send")));
        assert!(bytes.starts_with(&RowKey::item_prefix("outbound.undo_send", Some("mail"))));
        assert!(!bytes.starts_with(&RowKey::item_prefix("outbound.undo_send", None)));
        assert!(!bytes.starts_with(&RowKey::name_prefix("outbound.undo")));
        let itemless = RowKey { item: None, ..key };
        assert_eq!(RowKey::decode(&itemless.encode()), Some(itemless));
    }

    #[test]
    fn names_and_items_are_checked() {
        assert!(check_name("housekeeping.symbol_lease_expiry.every").is_ok());
        for bad in ["", "Outbound.x", "a..b", ".a", "a.", "a b", "a\0b"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_item("mail").is_ok());
        assert!(check_item("").is_err());
        assert!(check_item("a\0b").is_err());
        assert!(check_item(&"x".repeat(257)).is_err());
    }
}
