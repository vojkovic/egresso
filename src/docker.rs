use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;

use crate::config::{parse_bool, parse_prefixes};

const DOCKER_SOCK: &str = "/var/run/docker.sock";
const CGROUP_FS: &str = "/sys/fs/cgroup";
const PREFIXES: &str = "egresso.prefixes";
const HOST_FALLBACK: &str = "egresso.host-fallback";
const LIST: &str = "/containers/json?filters=%7B%22label%22%3A%5B%22egresso.prefixes%22%5D%7D";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub cgroup: PathBuf,
    pub prefixes: Vec<IpNet>,
    pub host_fallback: bool,
}

pub fn available() -> bool {
    Path::new(DOCKER_SOCK).exists()
}

pub fn containers() -> Result<Vec<Container>, String> {
    let mut out = Vec::new();
    for listed in list_labeled()? {
        match listed.into_container() {
            Ok(c) if is_root_cgroup(&c.cgroup) => {
                eprintln!("{}: root cgroup, skipping", c.name);
            }
            Ok(c) if out.iter().any(|x: &Container| x.cgroup == c.cgroup) => {}
            Ok(c) => out.push(c),
            Err(e) => eprintln!("{e}"),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

struct Listed {
    id: String,
    name: String,
    prefixes: Option<String>,
    host_fallback: Option<String>,
}

impl Listed {
    fn into_container(self) -> Result<Container, String> {
        let prefixes = parse_prefixes(
            self.prefixes
                .as_deref()
                .ok_or_else(|| format!("{}: missing {PREFIXES}", self.name))?,
        )
        .map_err(|e| format!("{}: {e}", self.name))?;
        let host_fallback = match &self.host_fallback {
            Some(v) => parse_bool(v).map_err(|e| format!("{}: {HOST_FALLBACK}: {e}", self.name))?,
            None => false,
        };
        Ok(Container {
            cgroup: cgroup(&self.name, &self.id)?,
            name: self.name,
            prefixes,
            host_fallback,
        })
    }
}

fn list_labeled() -> Result<Vec<Listed>, String> {
    Ok(parse_list(&docker_get(LIST)?))
}

fn parse_list(json: &str) -> Vec<Listed> {
    json_objects(json)
        .into_iter()
        .filter_map(|obj| {
            let id = json_str(obj, "Id")?
                .trim_start_matches("sha256:")
                .to_string();
            if id.is_empty() {
                return None;
            }
            let name = first_name(obj).unwrap_or_else(|| id.chars().take(12).collect());
            Some(Listed {
                prefixes: json_str(obj, PREFIXES).map(str::to_string),
                host_fallback: json_str(obj, HOST_FALLBACK).map(str::to_string),
                id,
                name,
            })
        })
        .collect()
}

fn first_name(obj: &str) -> Option<String> {
    let rest = obj.split("\"Names\":").nth(1)?;
    let start = rest.find('[')?;
    let end = rest[start..].find(']')?;
    let n = rest[start + 1..start + end]
        .split(',')
        .next()?
        .trim()
        .trim_matches('"')
        .trim_start_matches('/');
    (!n.is_empty()).then(|| n.to_string())
}

fn cgroup(name: &str, id: &str) -> Result<PathBuf, String> {
    if let Some(path) = cgroup_from_id(id) {
        return Ok(path);
    }
    let body = docker_get(&format!("/containers/{}/json", encode_query(name))).map_err(|e| {
        if e.contains("HTTP 404") {
            format!("no such container {name}")
        } else {
            e
        }
    })?;
    let (id, pid) = parse_inspect(&body).ok_or("docker inspect: missing Id/Pid")?;
    if pid <= 0 {
        return Err(format!("{name} is not running"));
    }
    if let Some(path) = cgroup_from_id(&id) {
        return Ok(path);
    }
    proc_cgroup(pid as u32)
        .ok_or_else(|| format!("no cgroup for {name} (is /sys/fs/cgroup mounted?)"))
}

fn parse_inspect(json: &str) -> Option<(String, i64)> {
    let id = json_str(json, "Id")?
        .trim_start_matches("sha256:")
        .to_string();
    if id.is_empty() {
        return None;
    }
    let state = json.find("\"State\"")?;
    let pid = json_i64(&json[state..], "Pid")?;
    Some((id, pid))
}

fn cgroup_from_id(id: &str) -> Option<PathBuf> {
    let id = id.trim_start_matches("sha256:");
    [
        PathBuf::from(format!("{CGROUP_FS}/system.slice/docker-{id}.scope")),
        PathBuf::from(format!("{CGROUP_FS}/docker/{id}")),
    ]
    .into_iter()
    .find(|p| p.exists())
}

fn proc_cgroup(pid: u32) -> Option<PathBuf> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    path_from_proc_cgroup(&raw).filter(|p| p.exists())
}

fn path_from_proc_cgroup(raw: &str) -> Option<PathBuf> {
    raw.lines().find_map(|line| {
        line.strip_prefix("0::")
            .map(|rest| Path::new(CGROUP_FS).join(rest.trim().trim_start_matches('/')))
    })
}

fn is_root_cgroup(p: &Path) -> bool {
    p.as_os_str().to_string_lossy().trim_end_matches('/') == CGROUP_FS
}

fn docker_get(path: &str) -> Result<String, String> {
    let mut stream =
        UnixStream::connect(DOCKER_SOCK).map_err(|e| format!("connect {DOCKER_SOCK}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    write!(stream, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")
        .map_err(|e| format!("write docker.sock: {e}"))?;
    let (status, body) = read_http(&mut stream)?;
    if !(200..300).contains(&status) {
        return Err(format!("docker API HTTP {status}"));
    }
    Ok(body)
}

fn json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let start = json.find(&pat)? + pat.len();
    json[start..].split('"').next()
}

fn json_i64(json: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat)? + pat.len();
    json[start..]
        .trim_start()
        .split(|c: char| !c.is_ascii_digit() && c != '-')
        .next()?
        .parse()
        .ok()
}

fn json_objects(json: &str) -> Vec<&str> {
    let bytes = json.as_bytes();
    let Some(mut i) = json.find('[').map(|i| i + 1) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t' | b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 0;
        let mut in_str = false;
        let mut escape = false;
        while i < bytes.len() {
            let c = bytes[i];
            if in_str {
                if escape {
                    escape = false;
                } else if c == b'\\' {
                    escape = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    out.push(&json[start..=i]);
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
    }
    out
}

fn encode_query(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn read_http(stream: &mut UnixStream) -> Result<(u16, String), String> {
    let mut r = BufReader::new(stream);
    let mut status_line = String::new();
    r.read_line(&mut status_line)
        .map_err(|e| format!("docker.sock: {e}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("docker.sock: bad status {status_line:?}"))?;
    loop {
        let mut line = String::new();
        r.read_line(&mut line)
            .map_err(|e| format!("docker.sock: {e}"))?;
        if line.is_empty() || line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut body = Vec::new();
    r.take(8 * 1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| format!("docker.sock body: {e}"))?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_inspect_json() {
        let json = r#"{"Id":"34930211daa3abc","Created":"x","State":{"Status":"running","Running":true,"Pid":4321}}"#;
        let (id, pid) = parse_inspect(json).unwrap();
        assert_eq!(id, "34930211daa3abc");
        assert_eq!(pid, 4321);
    }

    #[test]
    fn proc_cgroup_line() {
        let p = path_from_proc_cgroup("0::/system.slice/docker-abc.scope\n").unwrap();
        assert_eq!(
            p,
            PathBuf::from("/sys/fs/cgroup/system.slice/docker-abc.scope")
        );
    }

    #[test]
    fn root_cgroup() {
        assert!(is_root_cgroup(Path::new("/sys/fs/cgroup")));
        assert!(is_root_cgroup(Path::new("/sys/fs/cgroup/")));
        assert!(!is_root_cgroup(Path::new(
            "/sys/fs/cgroup/system.slice/docker-abc.scope"
        )));
    }

    #[test]
    fn list_parses_prefix_labels() {
        let json = r#"[{
            "Id":"aaa111",
            "Names":["/searxng-1"],
            "Labels":{"egresso.prefixes":"2001:db8:a::/48"}
        },{
            "Id":"bbb222",
            "Names":["/searxng-3","/alias"],
            "Labels":{"egresso.prefixes":"2001:db8:c::/48,192.0.2.0/24","egresso.host-fallback":"true"}
        }]"#;
        let listed = parse_list(json);
        assert_eq!(listed[0].name, "searxng-1");
        assert_eq!(listed[0].prefixes.as_deref().unwrap(), "2001:db8:a::/48");
        assert_eq!(listed[1].name, "searxng-3");
        assert_eq!(
            listed[1].prefixes.as_deref().unwrap(),
            "2001:db8:c::/48,192.0.2.0/24"
        );
        assert_eq!(listed[1].host_fallback.as_deref().unwrap(), "true");
    }

    #[test]
    fn query_encodes_container_name() {
        assert_eq!(encode_query("searxng-1"), "searxng-1");
        assert_eq!(encode_query("a b"), "a%20b");
    }
}
