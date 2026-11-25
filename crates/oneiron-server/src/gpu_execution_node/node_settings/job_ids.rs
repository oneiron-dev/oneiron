//! The node file's job ids (FIX EXEC-UNIT-CROSS-JOB-SAME-UID, ruling A): the
//! range each job unit's own uid comes from, and the job device group.

/// Default of `job_uid_first`: the first id of the range systemd leaves
/// unused after the container range (systemd's UIDS-GIDS.md: 1879048192 to
/// 2147352575), clear of the system and login accounts, of `DynamicUser=`
/// (61184 to 65519) and of the subordinate ids `useradd` hands out (from
/// 100000 up to 600100000).
pub const JOB_UID_FIRST_DEFAULT: u32 = 1_879_048_192;

/// Default of `job_uid_count`: one 16-bit block, far more than the jobs that
/// run at once.
pub const JOB_UID_COUNT_DEFAULT: u32 = 65_536;

/// Default of `job_device_group`.
pub const JOB_DEVICE_GROUP_DEFAULT: &str = "oneiron-job-devices";

/// The lowest `job_uid_first`: the 16-bit ids are the system's, the login
/// accounts', `DynamicUser=`'s and `nobody`'s.
pub const JOB_UID_FIRST_MIN: u32 = 65_536;

/// One past the highest id a job may get: ids from 2^31 up are read as
/// negative by tools that keep them in a signed 32-bit number.
pub const JOB_UID_END_MAX: u64 = 1 << 31;

pub(super) fn job_uid_first_default() -> u32 {
    JOB_UID_FIRST_DEFAULT
}
pub(super) fn job_uid_count_default() -> u32 {
    JOB_UID_COUNT_DEFAULT
}
pub(super) fn job_device_group_default() -> String {
    JOB_DEVICE_GROUP_DEFAULT.to_owned()
}

/// Checks `job_uid_first`, `job_uid_count` and `job_device_group`: the range
/// inside `JOB_UID_FIRST_MIN..JOB_UID_END_MAX`, and the group a plain name.
///
/// # Errors
///
/// The first setting that is out of bounds.
pub(super) fn check(first: u32, count: u32, device_group: &str) -> Result<(), String> {
    if first < JOB_UID_FIRST_MIN {
        return Err(format!(
            "execution_node.job_uid_first must be at least {JOB_UID_FIRST_MIN}"
        ));
    }
    if count == 0 {
        return Err("execution_node.job_uid_count must be at least 1".to_owned());
    }
    if !(1..=32).contains(&device_group.len())
        || !device_group.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        || device_group.starts_with('-')
    {
        return Err(
            "execution_node.job_device_group must be 1 to 32 of a-z, 0-9, '-' and '_'".to_owned(),
        );
    }
    if u64::from(first) + u64::from(count) > JOB_UID_END_MAX {
        return Err(format!(
            "execution_node.job_uid_first + job_uid_count must be at most {JOB_UID_END_MAX}"
        ));
    }
    Ok(())
}
