use std::fs::File;
use std::io;
use std::mem::size_of_val;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;
use ipnet::IpNet;

use crate::docker::Container;

const PROGRAMS: &[&str] = &["connect4", "connect6", "bind4", "bind6"];
const FLAG_HOST_FALLBACK: u32 = 1;

struct Instance {
    name: String,
    cgroup: PathBuf,
    prefixes: Vec<IpNet>,
    host_fallback: bool,
    _bpf: Ebpf,
    _links: Vec<CgroupSockAddrLink>,
}

impl Instance {
    fn same_as(&self, c: &Container) -> bool {
        self.cgroup == c.cgroup
            && self.prefixes == c.prefixes
            && self.host_fallback == c.host_fallback
    }
}

#[derive(Default)]
pub struct Loader {
    attached: Vec<Instance>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.attached.is_empty()
    }

    pub fn names(&self) -> Vec<&str> {
        self.attached.iter().map(|i| i.name.as_str()).collect()
    }

    pub fn sync(&mut self, targets: &[Container]) -> bool {
        if targets.len() == self.attached.len()
            && self
                .attached
                .iter()
                .zip(targets)
                .all(|(a, t)| a.same_as(t) && a.name == t.name)
        {
            return false;
        }

        let mut old = std::mem::take(&mut self.attached);
        let mut next = Vec::new();
        for t in targets {
            if let Some(i) = old.iter().position(|a| a.same_as(t)) {
                let mut inst = old.remove(i);
                inst.name.clone_from(&t.name);
                next.push(inst);
            } else {
                match attach_one(t) {
                    Ok(inst) => next.push(inst),
                    Err(e) => eprintln!("{}: {e}", t.name),
                }
            }
        }
        self.attached = next;
        true
    }
}

fn attach_one(c: &Container) -> Result<Instance, String> {
    validate(&c.prefixes).map_err(|e| format!("prefix check failed: {e}"))?;
    let mut bpf = load_object(&c.prefixes, c.host_fallback)?;
    for name in PROGRAMS {
        load_prog(&mut bpf, name)?;
    }
    let file =
        File::open(&c.cgroup).map_err(|e| format!("open cgroup {}: {e}", c.cgroup.display()))?;
    let mut links = Vec::new();
    for name in PROGRAMS {
        links.push(attach_prog(&mut bpf, name, &file, &c.cgroup)?);
    }
    Ok(Instance {
        name: c.name.clone(),
        cgroup: c.cgroup.clone(),
        prefixes: c.prefixes.clone(),
        host_fallback: c.host_fallback,
        _bpf: bpf,
        _links: links,
    })
}

fn load_object(prefixes: &[IpNet], host_fallback: bool) -> Result<Ebpf, String> {
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/egresso.bpf.o"
    )))
    .map_err(|e| format!("load BPF: {e}"))?;
    fill_maps(&mut bpf, prefixes, host_fallback)?;
    Ok(bpf)
}

fn sock_addr<'a>(bpf: &'a mut Ebpf, name: &str) -> Result<&'a mut CgroupSockAddr, String> {
    bpf.program_mut(name)
        .ok_or_else(|| format!("missing program {name}"))?
        .try_into()
        .map_err(|e| format!("{name}: {e}"))
}

fn load_prog(bpf: &mut Ebpf, name: &str) -> Result<(), String> {
    sock_addr(bpf, name)?
        .load()
        .map_err(|e| format!("load {name}: {e}"))
}

fn attach_prog(
    bpf: &mut Ebpf,
    name: &str,
    cgroup: &File,
    path: &Path,
) -> Result<CgroupSockAddrLink, String> {
    let prog = sock_addr(bpf, name)?;
    let id = prog
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|e| format!("attach {name} to {}: {e}", path.display()))?;
    prog.take_link(id)
        .map_err(|e| format!("take {name} link: {e}"))
}

fn fill_maps(bpf: &mut Ebpf, prefixes: &[IpNet], host_fallback: bool) -> Result<(), String> {
    let (v4, v6): (Vec<IpNet>, Vec<IpNet>) =
        prefixes.iter().copied().partition(|n| n.addr().is_ipv4());
    set_prefixes(bpf, "prefixes_v4", &v4)?;
    set_prefixes(bpf, "prefixes_v6", &v6)?;
    set_u32(bpf, "n_v4", v4.len() as u32)?;
    set_u32(bpf, "n_v6", v6.len() as u32)?;
    set_u32(
        bpf,
        "flags",
        if host_fallback { FLAG_HOST_FALLBACK } else { 0 },
    )?;
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MapPrefix {
    family: u8,
    prefix_len: u8,
    pad: [u8; 2],
    addr: [u8; 16],
}

unsafe impl aya::Pod for MapPrefix {}

impl MapPrefix {
    fn from_net(net: IpNet) -> Self {
        let mut addr = [0u8; 16];
        match net.addr() {
            IpAddr::V4(v) => addr[..4].copy_from_slice(&v.octets()),
            IpAddr::V6(v) => addr.copy_from_slice(&v.octets()),
        }
        Self {
            family: if net.addr().is_ipv6() { 6 } else { 4 },
            prefix_len: net.prefix_len(),
            pad: [0; 2],
            addr,
        }
    }
}

fn set_prefixes(bpf: &mut Ebpf, name: &str, nets: &[IpNet]) -> Result<(), String> {
    let mut map: Array<_, MapPrefix> = Array::try_from(
        bpf.map_mut(name)
            .ok_or_else(|| format!("missing map {name}"))?,
    )
    .map_err(|e| format!("{name}: {e}"))?;
    for (i, net) in nets.iter().enumerate() {
        map.set(i as u32, MapPrefix::from_net(*net), 0)
            .map_err(|e| format!("set {name}[{i}]: {e}"))?;
    }
    Ok(())
}

fn set_u32(bpf: &mut Ebpf, name: &str, value: u32) -> Result<(), String> {
    let mut map: Array<_, u32> = Array::try_from(
        bpf.map_mut(name)
            .ok_or_else(|| format!("missing map {name}"))?,
    )
    .map_err(|e| format!("{name}: {e}"))?;
    map.set(0, value, 0).map_err(|e| format!("set {name}: {e}"))
}

pub fn validate(prefixes: &[IpNet]) -> io::Result<()> {
    for prefix in prefixes {
        can_bind(sample(*prefix)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{prefix} not routable (check local routes and ip_nonlocal_bind): {e}"),
            )
        })?;
    }
    Ok(())
}

fn sample(net: IpNet) -> IpAddr {
    match net {
        IpNet::V4(n) if n.prefix_len() >= 31 => n.addr().into(),
        IpNet::V4(n) => Ipv4Addr::from(u32::from(n.network()) + 1).into(),
        IpNet::V6(n) if n.prefix_len() >= 127 => n.addr().into(),
        IpNet::V6(n) => {
            let mut o = n.network().octets();
            o[15] |= 1;
            Ipv6Addr::from(o).into()
        }
    }
}

fn can_bind(addr: IpAddr) -> io::Result<()> {
    struct Fd(libc::c_int);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    unsafe {
        let fd = match addr {
            IpAddr::V4(_) => libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0),
            IpAddr::V6(_) => {
                libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
            }
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Fd(fd);
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            size_of_val(&one) as libc::socklen_t,
        );
        let (level, opt) = match addr {
            IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_FREEBIND),
            IpAddr::V6(_) => (libc::SOL_IPV6, libc::IPV6_FREEBIND),
        };
        if libc::setsockopt(
            fd.0,
            level,
            opt,
            &one as *const _ as *const libc::c_void,
            size_of_val(&one) as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let rc = match addr {
            IpAddr::V4(ip) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from(ip).to_be(),
                };
                libc::bind(
                    fd.0,
                    &sa as *const _ as *const libc::sockaddr,
                    size_of_val(&sa) as libc::socklen_t,
                )
            }
            IpAddr::V6(ip) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: ip.octets(),
                };
                libc::bind(
                    fd.0,
                    &sa as *const _ as *const libc::sockaddr,
                    size_of_val(&sa) as libc::socklen_t,
                )
            }
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skip_without_bpf(err: &str) -> bool {
        let e = err.to_ascii_lowercase();
        e.contains("permission")
            || e.contains("not permitted")
            || e.contains("not supported")
            || e.contains("no such file")
            || e.contains("function not implemented")
            || e.contains("failed to create map")
            || e.contains("map error")
    }

    #[test]
    fn skips_ci_without_bpf_maps() {
        assert!(skip_without_bpf(
            "load BPF: map error: failed to create map `flags`"
        ));
    }

    #[test]
    fn map_prefix_layout() {
        let p = MapPrefix::from_net("192.0.2.0/24".parse().unwrap());
        assert_eq!(p.family, 4);
        assert_eq!(p.prefix_len, 24);
        assert_eq!(&p.addr[..4], &[192, 0, 2, 0]);
        assert_eq!(std::mem::size_of::<MapPrefix>(), 20);
    }

    #[test]
    fn object_has_programs_and_maps() {
        match load_object(&["192.0.2.0/24".parse().unwrap()], false) {
            Ok(bpf) => {
                for name in PROGRAMS {
                    assert!(bpf.program(name).is_some(), "missing {name}");
                }
            }
            Err(e) if skip_without_bpf(&e) => {}
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn programs_pass_verifier() {
        let mut bpf = match load_object(
            &[
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/48".parse().unwrap(),
            ],
            false,
        ) {
            Ok(bpf) => bpf,
            Err(e) if skip_without_bpf(&e) => return,
            Err(e) => panic!("{e}"),
        };
        for name in PROGRAMS {
            let prog: &mut CgroupSockAddr = bpf.program_mut(name).unwrap().try_into().unwrap();
            if let Err(e) = prog.load() {
                let s = e.to_string();
                if skip_without_bpf(&s) {
                    return;
                }
                panic!("load {name}: {s}");
            }
        }
    }
}
