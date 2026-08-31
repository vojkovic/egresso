use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use aya::maps::Array;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;
use ipnet::IpNet;
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Config;

const PROGRAMS: &[&str] = &[
    "connect4", "connect6", "sendmsg4", "sendmsg6", "bind4", "bind6",
];
const FLAG_HOST_FALLBACK: u32 = 1;

pub struct Loader {
    bpf: Ebpf,
    links: Vec<CgroupSockAddrLink>,
    attached: Vec<PathBuf>,
}

impl Loader {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let mut bpf = load_object(&cfg.prefixes, cfg.host_fallback)?;
        for name in PROGRAMS {
            load_prog(&mut bpf, name)?;
        }
        Ok(Self {
            bpf,
            links: Vec::new(),
            attached: Vec::new(),
        })
    }

    pub fn sync(&mut self, cgroups: &[PathBuf]) -> Result<bool, String> {
        if cgroups == self.attached.as_slice() {
            return Ok(false);
        }
        let mut links = Vec::new();
        for path in cgroups {
            let file =
                File::open(path).map_err(|e| format!("open cgroup {}: {e}", path.display()))?;
            for name in PROGRAMS {
                links.push(attach_prog(&mut self.bpf, name, &file, path)?);
            }
        }
        self.links = links;
        self.attached = cgroups.to_vec();
        Ok(true)
    }

    pub fn attached(&self) -> &[PathBuf] {
        &self.attached
    }
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
    let v4: Vec<_> = prefixes
        .iter()
        .filter(|n| n.addr().is_ipv4())
        .copied()
        .collect();
    let v6: Vec<_> = prefixes
        .iter()
        .filter(|n| n.addr().is_ipv6())
        .copied()
        .collect();

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
        IpNet::V4(n) => {
            if n.prefix_len() >= 32 {
                return n.addr().into();
            }
            let host_bits = 32 - u32::from(n.prefix_len());
            let mask = if host_bits == 32 {
                u32::MAX
            } else {
                (1u32 << host_bits) - 1
            };
            Ipv4Addr::from((u32::from(n.network()) & !mask) | 1).into()
        }
        IpNet::V6(n) => {
            if n.prefix_len() >= 128 {
                return n.addr().into();
            }
            let mut o = n.network().octets();
            o[15] |= 1;
            Ipv6Addr::from(o).into()
        }
    }
}

fn can_bind(addr: IpAddr) -> io::Result<()> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    let fd = sock.as_fd().as_raw_fd();
    let val: libc::c_int = 1;
    let (level, opt) = if addr.is_ipv6() {
        (libc::SOL_IPV6, libc::IPV6_FREEBIND)
    } else {
        (libc::IPPROTO_IP, libc::IP_FREEBIND)
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    sock.bind(&SocketAddr::new(addr, 0).into())?;
    Ok(())
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
        let mut bpf = match load_object(&["192.0.2.0/24".parse().unwrap()], false) {
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
