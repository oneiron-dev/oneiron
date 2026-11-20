//! Door for `tests/shared_env_lane_reach.rs` (MEMBER-SELECTOR-SOCKET): the
//! lane a shared env's paired slip opens.

/// The lane a slip naming `grant_ref` and `holder_ref` opens: `"full"` when
/// it names no member grant, else `"member <grant hex> <holder hex>"` from
/// the slip's own claims (MEMBER-SYNC D8: HOME proves the grant, so no local
/// copy is needed). The vault stays in the signature so this door's shape is
/// unchanged.
///
/// # Errors
///
/// A `grant_ref` or `holder_ref` that is not an entity id.
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
        },
    )
}
