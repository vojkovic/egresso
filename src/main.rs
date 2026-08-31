use egresso::Config;

fn die(err: impl std::fmt::Display) -> ! {
    eprintln!("{err}");
    std::process::exit(1);
}

fn main() {
    let cfg = Config::load().unwrap_or_else(|e| die(e));
    egresso::bpf::validate(&cfg.prefixes)
        .unwrap_or_else(|e| die(format!("prefix check failed: {e}")));
    if !egresso::docker_available() {
        die("need /var/run/docker.sock");
    }

    eprintln!("{} prefix(es) ok", cfg.prefixes.len());
    if cfg.host_fallback {
        eprintln!("host fallback enabled");
    }
    eprintln!("watching label egresso=true");

    let mut loader = egresso::bpf::Loader::new(&cfg).unwrap_or_else(|e| die(e));
    let mut mask = block_quit_signals();
    loop {
        match egresso::containers() {
            Ok(found) if found.is_empty() => {
                if !loader.attached().is_empty() {
                    let _ = loader.sync(&[]);
                    eprintln!("no labeled containers running; detached");
                }
            }
            Ok(found) => {
                let paths: Vec<_> = found.iter().map(|c| c.cgroup.clone()).collect();
                match loader.sync(&paths) {
                    Ok(true) => {
                        let names: Vec<_> = found.iter().map(|c| c.name.as_str()).collect();
                        eprintln!("attached to {}", names.join(", "));
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("attach: {e}"),
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
