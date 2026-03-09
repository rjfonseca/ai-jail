use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub fn set_child_pid(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
}

extern "C" fn forward_signal(sig: nix::libc::c_int) {
    if sig == nix::libc::SIGWINCH {
        // Do NOT resize the PTY here.  The IO loop will:
        //   1. redraw the status bar (correct scroll region)
        //   2. THEN resize the PTY (child gets SIGWINCH)
        // This mirrors tmux/mtm: set up terminal state first,
        // notify child second.
        //
        // SIGWINCH is installed WITHOUT SA_RESTART so poll()
        // returns EINTR immediately and the IO loop processes
        // the resize without delay.
        crate::statusbar::request_redraw(true);
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
    // Most signals: SA_RESTART so read/write loops are not
    // interrupted spuriously.
    let restart = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        unsafe {
            let _ = signal::sigaction(sig, &restart);
        }
    }

    // SIGWINCH: deliberately NO SA_RESTART so that poll()
    // returns EINTR immediately, letting the IO loop process
    // the resize without waiting for the 100 ms timeout.
    let no_restart = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe {
        let _ = signal::sigaction(Signal::SIGWINCH, &no_restart);
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
