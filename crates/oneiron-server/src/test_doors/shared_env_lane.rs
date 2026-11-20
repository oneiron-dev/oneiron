//! Door for `tests/shared_env_lane_reach.rs` (MEMBER-SELECTOR-SOCKET): the
//! lane a shared env's paired slip opens.

/// The lane a slip naming `grant_ref` and `holder_ref` opens on `vault`:
/// `"full"` when it names no member grant, `"member <grant hex> <holder
/// hex>"` when this env holds a live copy of the grant it names, and
/// `"grant-missing"` when it holds none.
///
/// # Errors
///
/// A `grant_ref` or `holder_ref` that is not an entity id, and the vault's.
pub fn lane_reach(
    vault: &oneiron::Vault,
    grant_ref: Option<&str>,
    holder_ref: &str,
) -> Result<String, String> {
    Ok(
        match crate::shared_envs::lane_reach_of(vault, grant_ref, holder_ref)? {
            crate::shared_envs::LaneReach::Full => "full".to_owned(),
            crate::shared_envs::LaneReach::Member(selector) => format!(
                "member {} {}",
                selector.grant_id.to_hex(),
                selector.member_ref.to_hex()
            ),
            crate::shared_envs::LaneReach::GrantMissing => "grant-missing".to_owned(),
        },
    )
}
