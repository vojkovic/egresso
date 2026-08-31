use egresso::{containers, docker_available, Loader};

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
    let mut mask = block_quit_signals();
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
        if wait_quit(&mut mask) {
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

fn wait_quit(mask: &mut libc::sigset_t) -> bool {
    let ts = libc::timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    unsafe { libc::sigtimedwait(mask, std::ptr::null_mut(), &ts) > 0 }
}
