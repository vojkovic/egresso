use std::time::Duration;

use egresso::{containers, docker_available, EventWatch, Loader};

fn die(err: impl std::fmt::Display) -> ! {
    eprintln!("{err}");
    std::process::exit(1);
}

fn main() {
    if !docker_available() {
        die("need /var/run/docker.sock");
    }
    eprintln!("watching label egresso.prefixes");

    let mut loader = Loader::new();
    let mut events = EventWatch::new();
    let mask = block_quit_signals();
    let quit_fd = quit_signalfd(&mask);
    loop {
        match containers() {
            Ok(found) => {
                if loader.sync(&found) {
                    if loader.is_empty() {
                        eprintln!("no labeled containers running; detached");
                    } else {
                        eprintln!("attached to {}", loader.names().join(", "));
                    }
                }
            }
            Err(e) => eprintln!("{e}"),
        }
        if events.wait(quit_fd, Duration::from_secs(2)) {
            break;
        }
    }
}

fn block_quit_signals() -> libc::sigset_t {
    unsafe {
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(mask.as_mut_ptr());
        libc::sigaddset(mask.as_mut_ptr(), libc::SIGINT);
        libc::sigaddset(mask.as_mut_ptr(), libc::SIGTERM);
        libc::sigprocmask(libc::SIG_BLOCK, mask.as_ptr(), std::ptr::null_mut());
        mask.assume_init()
    }
}

fn quit_signalfd(mask: &libc::sigset_t) -> i32 {
    let fd = unsafe { libc::signalfd(-1, mask, libc::SFD_CLOEXEC) };
    if fd < 0 {
        die(format!("signalfd: {}", std::io::Error::last_os_error()));
    }
    fd
}
