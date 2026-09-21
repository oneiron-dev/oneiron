/* Denied libc platform operations. These link-time wrappers are entirely
   inside guest linear memory. They do not add a WASI linker or a capability. */
#include <wasi/api.h>
#include <stddef.h>
#include <stdint.h>

__wasi_errno_t __wrap___wasi_fd_write(__wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t count, __wasi_size_t *written) {
    (void)fd; (void)iov; (void)count; *written = 0; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_fd_read(__wasi_fd_t fd, const __wasi_iovec_t *iov, size_t count, __wasi_size_t *read) {
    (void)fd; (void)iov; (void)count; *read = 0; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_fd_close(__wasi_fd_t fd) {
    (void)fd; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_fd_seek(__wasi_fd_t fd, __wasi_filedelta_t offset, __wasi_whence_t whence, __wasi_filesize_t *position) {
    (void)fd; (void)offset; (void)whence; *position = 0; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_fd_fdstat_get(__wasi_fd_t fd, __wasi_fdstat_t *stat) {
    (void)fd; (void)stat; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_environ_sizes_get(__wasi_size_t *count, __wasi_size_t *size) {
    *count = 0; *size = 0; return 0;
}
__wasi_errno_t __wrap___wasi_environ_get(uint8_t **entries, uint8_t *buffer) {
    (void)entries; (void)buffer; return 0;
}
__wasi_errno_t __wrap___wasi_args_sizes_get(__wasi_size_t *count, __wasi_size_t *size) {
    *count = 0; *size = 0; return 0;
}
__wasi_errno_t __wrap___wasi_args_get(uint8_t **entries, uint8_t *buffer) {
    (void)entries; (void)buffer; return 0;
}
__wasi_errno_t __wrap___wasi_clock_time_get(__wasi_clockid_t clock, __wasi_timestamp_t precision, __wasi_timestamp_t *time) {
    (void)clock; (void)precision; (void)time; return __WASI_ERRNO_NOTCAPABLE;
}
__wasi_errno_t __wrap___wasi_random_get(uint8_t *buffer, __wasi_size_t length) {
    (void)buffer; (void)length; return __WASI_ERRNO_NOTCAPABLE;
}
_Noreturn void __wrap___wasi_proc_exit(__wasi_exitcode_t code) {
    (void)code; __builtin_trap();
}
