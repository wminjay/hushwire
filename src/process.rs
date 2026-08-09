//! Process-lifecycle helpers used by privileged GUI launchers.

use std::io;

/// Identifiers recorded after successfully creating an independent session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachedSession {
    pub pid: libc::pid_t,
    pub previous_process_group: libc::pid_t,
    pub session_id: libc::pid_t,
}

/// Detach the current process from its launcher's session and process group.
///
/// The macOS GUI starts HushWire through AppleScript's `authtrampoline`.
/// Merely disowning a background job reparents it to launchd but leaves it in
/// the authorization helper's process group. When macOS reclaims that helper,
/// the remaining group members receive SIGTERM. `setsid` makes HushWire the
/// sole member and leader of a new session, so its lifecycle is independent.
pub fn detach_session() -> io::Result<DetachedSession> {
    // SAFETY: getpid, getpgrp, and setsid take no pointers and have no Rust
    // aliasing requirements. This runs before HushWire starts worker threads
    // or opens its TUN device.
    unsafe {
        let pid = libc::getpid();
        let previous_process_group = libc::getpgrp();
        let session_id = libc::setsid();
        if session_id == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(DetachedSession {
            pid,
            previous_process_group,
            session_id,
        })
    }
}
