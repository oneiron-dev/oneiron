//! What the platform says of this process's descriptors: the probe the
//! process's descriptor floor is sized from (`oneiron_base::host_descriptors`,
//! FIX 6299).

/// Descriptors this process may hold open at once, when the platform says.
pub fn open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct on the stack and nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
            return None;
        }
        if limit.rlim_cur == libc::RLIM_INFINITY {
            return Some(u64::MAX);
        }
        Some(limit.rlim_cur)
    }
    #[cfg(not(unix))]
    {
        None
    }
}
