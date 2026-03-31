use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub fn set_child_pid(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
}

extern "C" fn forward_signal(sig: nix::libc::c_int) {
    if sig == nix::libc::SIGWINCH {
        // PTY proxy: defer to IO loop which resizes vt100 first.
        // No PTY proxy: SIGWINCH reaches the child directly from
        // the kernel (we don't use --new-session for interactive
        // terminals, so the child shares the session).
        crate::pty::set_sigwinch_pending();
        return;
    }

    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            nix::libc::kill(pid, sig);
        }
    }
}

pub fn install_handlers() {
    let action = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );

    // SIGWINCH must NOT use SA_RESTART so that poll() returns
    // EINTR immediately, allowing the IO loop to process the
    // resize without waiting for the poll timeout.
    let winch_action = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::empty(),
        SigSet::empty(),
    );

    for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        unsafe {
            let _ = signal::sigaction(sig, &action);
        }
    }
    unsafe {
        let _ = signal::sigaction(Signal::SIGWINCH, &winch_action);
    }
}

pub fn wait_child(pid: i32) -> i32 {
    let pid = nix::unistd::Pid::from_raw(pid);
    loop {
        match waitpid(pid, Some(WaitPidFlag::empty())) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i32,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return 1,
        }
    }
}
